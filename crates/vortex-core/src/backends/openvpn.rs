use crate::backend::Backend;
use crate::model::Profile;
use crate::tunnel::{bytes, now, Session};
use anyhow::{bail, Result};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use std::thread::sleep;
use std::time::Duration;

/// OpenVPN backend managing OpenVPN subprocess with management interface or signal lifecycle.
pub struct OpenVpnBackend;

impl OpenVpnBackend {
    pub fn new() -> Self {
        Self
    }

    fn have_tool(&self) -> bool {
        ["/usr/bin", "/usr/local/bin", "/bin", "/usr/sbin", "/sbin"]
            .iter()
            .any(|d| Path::new(d).join("openvpn").is_file())
    }

    fn is_alive(pid: u32) -> bool {
        Path::new(&format!("/proc/{pid}")).exists()
    }

    fn kill_process(pid: u32) {
        unsafe {
            libc::kill(pid as i32, libc::SIGTERM);
        }
        for _ in 0..30 {
            if !Self::is_alive(pid) {
                return;
            }
            sleep(Duration::from_millis(50));
        }
        unsafe {
            libc::kill(pid as i32, libc::SIGKILL);
        }
    }
}

impl Default for OpenVpnBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl Backend for OpenVpnBackend {
    fn name(&self) -> &'static str {
        "openvpn"
    }

    fn is_available(&self) -> bool {
        self.have_tool()
    }

    fn version(&self) -> Option<String> {
        if let Ok(out) = Command::new("openvpn").arg("--version").output() {
            if out.status.success() {
                let s = String::from_utf8_lossy(&out.stdout);
                if let Some(line) = s.lines().next() {
                    return line.split_whitespace().nth(1).map(String::from);
                }
            }
        }
        None
    }

    fn validate_config(&self, config_content: &str) -> Result<()> {
        let has_remote = config_content
            .lines()
            .any(|l| l.trim().starts_with("remote "));
        if !has_remote {
            bail!("OpenVPN config missing 'remote' server specification");
        }
        Ok(())
    }

    fn start(&self, profile: &Profile, runtime_dir: &Path) -> Result<Session> {
        if !self.is_available() {
            bail!("openvpn binary not found (install via `pacman -S openvpn`)");
        }
        self.validate_config(&profile.data)?;

        let conf_path = runtime_dir.join("ovpn.conf");
        let pid_path = runtime_dir.join("ovpn.pid");
        let log_path = runtime_dir.join("core.log");
        let auth_path = runtime_dir.join("ovpn.auth");

        fs::write(&conf_path, &profile.data)?;
        let _ = fs::set_permissions(&conf_path, fs::Permissions::from_mode(0o600));

        if let Some(ref a) = profile.auth {
            fs::write(&auth_path, format!("{}\n{}\n", a.username, a.password))?;
            let _ = fs::set_permissions(&auth_path, fs::Permissions::from_mode(0o600));
        }

        let mut cmd = Command::new("openvpn");
        cmd.args([
            "--config",
            conf_path.to_str().unwrap(),
            "--daemon",
            "vortex-ovpn",
            "--writepid",
            pid_path.to_str().unwrap(),
            "--log",
            log_path.to_str().unwrap(),
        ]);

        if auth_path.exists() {
            cmd.args(["--auth-user-pass", auth_path.to_str().unwrap()]);
        }

        let out = cmd.output()?;
        if !out.status.success() {
            let _ = fs::remove_file(&auth_path);
            let err = String::from_utf8_lossy(&out.stderr);
            bail!("openvpn launch failed: {}", err.trim());
        }

        let pid: u32 = fs::read_to_string(&pid_path)
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);

        let iface = "tun0".to_string();

        Ok(Session {
            id: profile.id.clone(),
            name: profile.name.clone(),
            kind: profile.kind,
            server: profile.server.clone(),
            iface,
            pid: if pid > 0 { Some(pid) } else { None },
            since: now(),
            conf: conf_path.to_string_lossy().to_string(),
        })
    }

    fn stop(&self, session: &Session) -> Result<()> {
        if let Some(pid) = session.pid {
            Self::kill_process(pid);
        }
        let _ = fs::remove_file(&session.conf);
        Ok(())
    }

    fn query_traffic(&self, session: &Session) -> Result<(u64, u64)> {
        if let Some((rx, tx)) = bytes(&session.iface) {
            return Ok((rx, tx));
        }
        Ok((0, 0))
    }
}

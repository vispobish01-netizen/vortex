use crate::backend::Backend;
use crate::model::Profile;
use crate::tunnel::{bytes, now, Session};
use anyhow::{bail, Result};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::Duration;

/// Hysteria2 backend using hysteria client binary or sing-box/xray engine.
pub struct Hysteria2Backend;

impl Hysteria2Backend {
    pub fn new() -> Self {
        Self
    }

    fn have_hy2(&self) -> bool {
        ["/usr/bin", "/usr/local/bin", "/bin", "/usr/sbin", "/sbin"]
            .iter()
            .any(|d| Path::new(d).join("hysteria").is_file())
    }

    fn is_alive(pid: u32) -> bool {
        Path::new(&format!("/proc/{pid}")).exists()
    }

    fn kill_process(pid: u32) {
        unsafe {
            libc::kill(pid as i32, libc::SIGTERM);
        }
        for _ in 0..20 {
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

impl Default for Hysteria2Backend {
    fn default() -> Self {
        Self::new()
    }
}

impl Backend for Hysteria2Backend {
    fn name(&self) -> &'static str {
        "hysteria2"
    }

    fn is_available(&self) -> bool {
        self.have_hy2()
            || crate::xray::resolve_xray_binary().is_ok()
            || crate::privilege::resolve_singbox_binary().is_some()
    }

    fn version(&self) -> Option<String> {
        if let Ok(out) = Command::new("hysteria").arg("version").output() {
            if out.status.success() {
                let s = String::from_utf8_lossy(&out.stdout);
                return s.lines().next().map(String::from);
            }
        }
        crate::xray::active_xray_version()
    }

    fn validate_config(&self, config_content: &str) -> Result<()> {
        if config_content.trim().is_empty() {
            bail!("Hysteria2 configuration cannot be empty");
        }
        if !config_content.starts_with("hy2://")
            && !config_content.starts_with("hysteria2://")
            && !config_content.contains("server:")
            && !config_content.contains("\"server\"")
        {
            bail!("Invalid Hysteria2 configuration syntax");
        }
        Ok(())
    }

    fn start(&self, profile: &Profile, runtime_dir: &Path) -> Result<Session> {
        self.validate_config(&profile.data)?;

        // If Xray-core is available and profile is hy2 share link, drive via XrayBackend
        if crate::xray::resolve_xray_binary().is_ok() {
            let xray = crate::xray::XrayBackend::new();
            return xray.start(profile, runtime_dir);
        }

        // Native hysteria client fallback
        if self.have_hy2() {
            let conf_path = runtime_dir.join("hy2.yaml");
            let log_path = runtime_dir.join("core.log");

            fs::write(&conf_path, &profile.data)?;
            let _ = fs::set_permissions(&conf_path, fs::Permissions::from_mode(0o600));

            let log_file = fs::File::create(&log_path)?;
            let mut cmd = Command::new("hysteria");
            cmd.args(["client", "-c", conf_path.to_str().unwrap()]);
            cmd.stdin(Stdio::null())
                .stdout(Stdio::from(log_file.try_clone()?))
                .stderr(Stdio::from(log_file));

            let child = cmd.spawn()?;
            let pid = child.id();

            return Ok(Session {
                id: profile.id.clone(),
                name: profile.name.clone(),
                kind: profile.kind,
                server: profile.server.clone(),
                iface: "vx0".into(),
                pid: Some(pid),
                since: now(),
                conf: conf_path.to_string_lossy().to_string(),
            });
        }

        bail!("Neither hysteria client nor Xray/sing-box cores are available for Hysteria2")
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

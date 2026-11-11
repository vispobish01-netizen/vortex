use crate::backend::Backend;
use crate::model::Profile;
use crate::tunnel::{
    active_run_dir, bytes, have, iface_exists, ifaces, kill_pid, now, ovpn_needs_auth, tail_log,
    write_secret_path, Session,
};
use anyhow::{bail, Result};
use std::fs;
use std::path::Path;
use std::process::Command;
use std::thread::sleep;
use std::time::Duration;

/// OpenVPN backend managing OpenVPN subprocess with credential injection and readiness polling.
pub struct OpenVpnBackend;

impl OpenVpnBackend {
    pub fn new() -> Self {
        Self
    }

    /// Starts OpenVPN with optional interactive credentials overriding profile stored auth.
    pub fn start_with_credentials(
        &self,
        profile: &Profile,
        runtime_dir: &Path,
        credentials: Option<(&str, &str)>,
    ) -> Result<Session> {
        if !self.is_available() {
            bail!("openvpn binary not found (install via `pacman -S openvpn`)");
        }
        self.validate_config(&profile.data)?;

        let needs_auth = ovpn_needs_auth(profile);
        let saved_creds = profile
            .auth
            .as_ref()
            .map(|a| (a.username.as_str(), a.password.as_str()));
        let effective_creds = credentials.or(saved_creds);
        if needs_auth && effective_creds.is_none() {
            bail!(
                "OpenVPN profile '{}' requires username and password (run `vortex auth {}` or connect with credentials)",
                profile.name,
                profile.name
            );
        }

        let conf_path = runtime_dir.join("ovpn.conf");
        let pid_path = runtime_dir.join("ovpn.pid");
        let log_path = runtime_dir.join("core.log");
        let auth_path = runtime_dir.join("ovpn.auth");

        let mut conf_content = String::new();
        for l in profile.data.lines() {
            let t = l.trim();
            if t == "auth-user-pass"
                || t.starts_with("auth-user-pass ")
                || t.starts_with("auth-user-pass\t")
            {
                continue;
            }
            conf_content.push_str(l);
            conf_content.push('\n');
        }
        write_secret_path(&conf_path, &conf_content)?;

        if let Some((user, pass)) = effective_creds {
            write_secret_path(&auth_path, &format!("{user}\n{pass}\n"))?;
        }
        let _ = fs::remove_file(&pid_path);
        let _ = fs::remove_file(&log_path);

        let before = ifaces();
        let mut cmd = Command::new("openvpn");
        cmd.args([
            "--config",
            &conf_path.to_string_lossy(),
            "--daemon",
            "vortex-ovpn",
            "--writepid",
            &pid_path.to_string_lossy(),
            "--log",
            &log_path.to_string_lossy(),
        ]);
        if !conf_content.contains("redirect-gateway") && !conf_content.contains("route-nopull") {
            cmd.args(["--redirect-gateway", "def1"]);
        }
        if effective_creds.is_some() {
            cmd.args(["--auth-user-pass", &auth_path.to_string_lossy()]);
        }

        let out = cmd.output()?;
        if !out.status.success() {
            let _ = fs::remove_file(&auth_path);
            bail!(
                "openvpn failed to start: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }

        let pid: Option<u32> = fs::read_to_string(&pid_path)
            .ok()
            .and_then(|s| s.trim().parse().ok());

        for _ in 0..100 {
            let log = fs::read_to_string(&log_path).unwrap_or_default();
            if log.contains("Initialization Sequence Completed") {
                let iface = ifaces()
                    .into_iter()
                    .find(|i| !before.contains(i) && (i.starts_with("tun") || i.starts_with("tap")))
                    .unwrap_or_else(|| "tun0".into());
                if !iface_exists(&iface) {
                    if let Some(p) = pid {
                        kill_pid(p);
                    }
                    let _ = fs::remove_file(&auth_path);
                    bail!("OpenVPN initialized but tunnel interface was not found");
                }
                for _ in 0..10 {
                    let route_ok = Command::new("ip")
                        .args(["route", "show", "table", "all", "dev", &iface])
                        .output()
                        .map(|o| {
                            o.status.success()
                                && !String::from_utf8_lossy(&o.stdout).trim().is_empty()
                        })
                        .unwrap_or(false);
                    if route_ok {
                        break;
                    }
                    sleep(Duration::from_millis(100));
                }
                let _ = fs::remove_file(&auth_path);
                return Ok(Session {
                    id: profile.id.clone(),
                    name: profile.name.clone(),
                    kind: profile.kind,
                    server: profile.server.clone(),
                    iface,
                    pid,
                    sidecar_pid: None,
                    backend: Some("openvpn".to_string()),
                    since: now(),
                    conf: conf_path.to_string_lossy().to_string(),
                });
            }
            if log.contains("AUTH_FAILED") || log.contains("Exiting due to fatal error") {
                if let Some(p) = pid {
                    kill_pid(p);
                }
                let _ = fs::remove_file(&auth_path);
                bail!("openvpn: {}", tail_log(2).join(" · "));
            }
            sleep(Duration::from_millis(250));
        }

        if let Some(p) = pid {
            kill_pid(p);
        }
        let _ = fs::remove_file(&auth_path);
        bail!("openvpn timed out waiting for connection")
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
        have("openvpn")
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
        self.start_with_credentials(profile, runtime_dir, None)
    }

    fn stop(&self, session: &Session) -> Result<()> {
        if let Some(pid) = session.pid {
            kill_pid(pid);
        }
        let _ = fs::remove_file(&session.conf);
        let r_dir = active_run_dir();
        let _ = fs::remove_file(r_dir.join("ovpn.pid"));
        let _ = fs::remove_file(r_dir.join("ovpn.auth"));
        Ok(())
    }

    fn query_traffic(&self, session: &Session) -> Result<(u64, u64)> {
        if let Some((rx, tx)) = bytes(&session.iface) {
            return Ok((rx, tx));
        }
        Ok((0, 0))
    }
}

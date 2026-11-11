use crate::backend::Backend;
use crate::backends::singbox::SingBoxBackend;
use crate::model::Profile;
use crate::tunnel::{
    bytes, have, kill_pid, now, spawn_detached_with_log, write_secret_path, Session,
};
use anyhow::{bail, Result};
use std::fs;
use std::path::Path;
use std::process::Command;

/// Hysteria2 backend delegating share URIs / JSON to `SingBoxBackend`, or native `hysteria` for YAML configs.
pub struct Hysteria2Backend;

impl Hysteria2Backend {
    pub fn new() -> Self {
        Self
    }

    fn have_hy2(&self) -> bool {
        have("hysteria")
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
        self.have_hy2() || SingBoxBackend::new().is_available()
    }

    fn version(&self) -> Option<String> {
        if let Ok(out) = Command::new("hysteria").arg("version").output() {
            if out.status.success() {
                let s = String::from_utf8_lossy(&out.stdout);
                return s.lines().next().map(|l| l.trim().to_string());
            }
        }
        SingBoxBackend::new().version()
    }

    fn validate_config(&self, config_content: &str) -> Result<()> {
        let trimmed = config_content.trim();
        if trimmed.is_empty() {
            bail!("Hysteria2 configuration cannot be empty");
        }
        if !trimmed.starts_with("hy2://")
            && !trimmed.starts_with("hysteria2://")
            && !trimmed.contains("server:")
            && !trimmed.contains("\"server\"")
            && !trimmed.starts_with('{')
        {
            bail!("Invalid Hysteria2 configuration syntax");
        }
        Ok(())
    }

    fn start(&self, profile: &Profile, runtime_dir: &Path) -> Result<Session> {
        self.validate_config(&profile.data)?;

        let trimmed = profile.data.trim();
        let is_yaml = !trimmed.starts_with("hy2://")
            && !trimmed.starts_with("hysteria2://")
            && !trimmed.starts_with('{');

        if is_yaml && self.have_hy2() {
            let conf_path = runtime_dir.join("hy2.yaml");
            let log_path = runtime_dir.join("core.log");

            write_secret_path(&conf_path, trimmed)?;
            let log_file = fs::File::create(&log_path)?;
            let mut cmd = Command::new("hysteria");
            cmd.args(["client", "-c", &conf_path.to_string_lossy()]);
            let pid = spawn_detached_with_log(&mut cmd, log_file)?;

            return Ok(Session {
                id: profile.id.clone(),
                name: profile.name.clone(),
                kind: profile.kind,
                server: profile.server.clone(),
                iface: "vx0".into(),
                pid: Some(pid),
                sidecar_pid: None,
                backend: Some("hysteria2".to_string()),
                since: now(),
                conf: conf_path.to_string_lossy().to_string(),
            });
        }

        if SingBoxBackend::new().is_available() {
            return SingBoxBackend::new().start(profile, runtime_dir);
        }

        bail!(
            "Hysteria2 requires either `sing-box` (recommended) or native `hysteria` client binary"
        )
    }

    fn stop(&self, session: &Session) -> Result<()> {
        if session.backend.as_deref() == Some("sing-box") || session.conf.ends_with("singbox.json")
        {
            return SingBoxBackend::new().stop(session);
        }
        if let Some(pid) = session.pid {
            kill_pid(pid);
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

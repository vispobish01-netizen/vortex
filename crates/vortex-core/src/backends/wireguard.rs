use crate::backend::Backend;
use crate::model::Profile;
use crate::tunnel::{bytes, now, Session};
use anyhow::{bail, Result};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

/// WireGuard backend using wg-quick / kernel WireGuard interfaces.
pub struct WireGuardBackend {
    pub iface: String,
}

impl WireGuardBackend {
    pub fn new() -> Self {
        Self {
            iface: "vxwg0".into(),
        }
    }

    pub fn with_iface(iface: impl Into<String>) -> Self {
        Self {
            iface: iface.into(),
        }
    }

    fn tool(&self) -> &'static str {
        "wg-quick"
    }

    fn have_tool(&self) -> bool {
        ["/usr/bin", "/usr/local/bin", "/bin", "/usr/sbin", "/sbin"]
            .iter()
            .any(|d| Path::new(d).join(self.tool()).is_file())
    }
}

impl Default for WireGuardBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl Backend for WireGuardBackend {
    fn name(&self) -> &'static str {
        "wireguard"
    }

    fn is_available(&self) -> bool {
        self.have_tool()
    }

    fn version(&self) -> Option<String> {
        if let Ok(out) = Command::new("wg").arg("--version").output() {
            if out.status.success() {
                let s = String::from_utf8_lossy(&out.stdout);
                return s.split_whitespace().nth(1).map(String::from);
            }
        }
        None
    }

    fn validate_config(&self, config_content: &str) -> Result<()> {
        if !config_content.contains("[Interface]") {
            bail!("WireGuard configuration missing [Interface] block");
        }
        if !config_content.contains("[Peer]") {
            bail!("WireGuard configuration missing [Peer] block");
        }
        Ok(())
    }

    fn start(&self, profile: &Profile, runtime_dir: &Path) -> Result<Session> {
        if !self.is_available() {
            bail!("wg-quick is not installed (install wireguard-tools)");
        }
        self.validate_config(&profile.data)?;

        let iface = &self.iface;
        let conf_path = runtime_dir.join(format!("{iface}.conf"));

        // Clean any stale interface before start
        if Path::new(&format!("/sys/class/net/{iface}")).exists() {
            let _ = Command::new(self.tool())
                .args(["down", &conf_path.to_string_lossy()])
                .output();
            let _ = Command::new("ip")
                .args(["link", "delete", "dev", iface])
                .output();
        }

        fs::write(&conf_path, &profile.data)?;
        let _ = fs::set_permissions(&conf_path, fs::Permissions::from_mode(0o600));

        let out = Command::new(self.tool())
            .args(["up", &conf_path.to_string_lossy()])
            .output()?;

        if !out.status.success() {
            let _ = fs::remove_file(&conf_path);
            let err = String::from_utf8_lossy(&out.stderr);
            bail!("wg-quick up failed: {}", err.trim());
        }

        Ok(Session {
            id: profile.id.clone(),
            name: profile.name.clone(),
            kind: profile.kind,
            server: profile.server.clone(),
            iface: iface.clone(),
            pid: None,
            since: now(),
            conf: conf_path.to_string_lossy().to_string(),
        })
    }

    fn stop(&self, session: &Session) -> Result<()> {
        let conf = &session.conf;
        let _ = Command::new(self.tool()).args(["down", conf]).output();
        if Path::new(&format!("/sys/class/net/{}", session.iface)).exists() {
            let _ = Command::new("ip")
                .args(["link", "delete", "dev", &session.iface])
                .output();
        }
        let _ = fs::remove_file(conf);
        Ok(())
    }

    fn query_traffic(&self, session: &Session) -> Result<(u64, u64)> {
        // Query WireGuard traffic counters via sysfs or wg show
        if let Some((rx, tx)) = bytes(&session.iface) {
            return Ok((rx, tx));
        }

        if let Ok(out) = Command::new("wg")
            .args(["show", &session.iface, "transfer"])
            .output()
        {
            if out.status.success() {
                let s = String::from_utf8_lossy(&out.stdout);
                // format: <public_key>\t<rx_bytes>\t<tx_bytes>
                if let Some(line) = s.lines().next() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 3 {
                        let rx: u64 = parts[1].parse().unwrap_or(0);
                        let tx: u64 = parts[2].parse().unwrap_or(0);
                        return Ok((rx, tx));
                    }
                }
            }
        }
        Ok((0, 0))
    }
}

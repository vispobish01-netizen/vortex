use crate::backend::Backend;
use crate::backends::wireguard::start_wg_family;
use crate::model::Profile;
use crate::tunnel::{bytes, have, iface_exists, Session};
use anyhow::{bail, Result};
use std::fs;
use std::path::Path;
use std::process::Command;

/// AmneziaWG backend implementing obfuscated WireGuard tunnels.
pub struct AmneziaBackend {
    pub iface: String,
}

impl AmneziaBackend {
    pub fn new() -> Self {
        Self {
            iface: "vxawg0".into(),
        }
    }

    fn tool(&self) -> &'static str {
        "awg-quick"
    }
}

impl Default for AmneziaBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl Backend for AmneziaBackend {
    fn name(&self) -> &'static str {
        "amnezia"
    }

    fn is_available(&self) -> bool {
        have(self.tool())
    }

    fn version(&self) -> Option<String> {
        if let Ok(out) = Command::new("awg").arg("--version").output() {
            if out.status.success() {
                let s = String::from_utf8_lossy(&out.stdout);
                return s.split_whitespace().nth(1).map(String::from);
            }
        }
        None
    }

    fn validate_config(&self, config_content: &str) -> Result<()> {
        if !config_content.contains("[Interface]") {
            bail!("AmneziaWG config missing [Interface] block");
        }
        if !config_content.contains("[Peer]") {
            bail!("AmneziaWG config missing [Peer] block");
        }
        let has_obfs = config_content.contains("Jc =")
            || config_content.contains("Jmin =")
            || config_content.contains("S1 =")
            || config_content.contains("H1 =");
        if !has_obfs {
            bail!("AmneziaWG config missing Amnezia parameters (Jc, Jmin, S1, or H1)");
        }
        Ok(())
    }

    fn start(&self, profile: &Profile, runtime_dir: &Path) -> Result<Session> {
        self.validate_config(&profile.data)?;
        start_wg_family(
            self.tool(),
            &self.iface,
            "amneziawg-tools (AUR)",
            "amnezia",
            profile,
            runtime_dir,
        )
    }

    fn stop(&self, session: &Session) -> Result<()> {
        let conf = &session.conf;
        let _ = Command::new(self.tool()).args(["down", conf]).output();
        if iface_exists(&session.iface) {
            let _ = Command::new("ip")
                .args(["link", "delete", "dev", &session.iface])
                .output();
        }
        let _ = fs::remove_file(conf);
        Ok(())
    }

    fn query_traffic(&self, session: &Session) -> Result<(u64, u64)> {
        if let Some((rx, tx)) = bytes(&session.iface) {
            return Ok((rx, tx));
        }

        if let Ok(out) = Command::new("awg")
            .args(["show", &session.iface, "transfer"])
            .output()
        {
            if out.status.success() {
                let s = String::from_utf8_lossy(&out.stdout);
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

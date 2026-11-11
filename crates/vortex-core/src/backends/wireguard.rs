use crate::backend::Backend;
use crate::model::Profile;
use crate::tunnel::{
    bytes, have, iface_exists, now, sanitize_wg_conf, write_secret_path, Session, RUN,
};
use anyhow::{bail, Result};
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::process::Command;

/// Shared runner for WireGuard (`wg-quick`) and AmneziaWG (`awg-quick`) tunnels.
pub(crate) fn start_wg_family(
    quick_tool: &str,
    iface: &str,
    pkg_hint: &str,
    backend_name: &str,
    profile: &Profile,
    runtime_dir: &Path,
) -> Result<Session> {
    if !have(quick_tool) {
        bail!("`{quick_tool}` not found — install {pkg_hint}");
    }

    let conf_path = runtime_dir.join(format!("{iface}.conf"));
    let legacy_conf = format!("{RUN}/{iface}.conf");

    if iface_exists(iface) {
        let _ = Command::new(quick_tool)
            .args(["down", &conf_path.to_string_lossy()])
            .output();
        let _ = Command::new(quick_tool)
            .args(["down", &legacy_conf])
            .output();
        let _ = Command::new("ip")
            .args(["link", "delete", "dev", iface])
            .output();
    }

    let mut conf = sanitize_wg_conf(&profile.data);
    let mut dns: Option<String> = None;
    if !have("resolvconf") {
        let mut kept = Vec::new();
        for l in conf.lines() {
            if let Some((k, v)) = l.split_once('=') {
                if k.trim().eq_ignore_ascii_case("dns") {
                    dns = Some(v.trim().to_string());
                    continue;
                }
            }
            kept.push(l);
        }
        conf = kept.join("\n");
    }

    write_secret_path(&conf_path, &conf)?;
    let out = Command::new(quick_tool)
        .args(["up", &conf_path.to_string_lossy()])
        .output()?;
    if !out.status.success() {
        let _ = fs::remove_file(&conf_path);
        let e = String::from_utf8_lossy(&out.stderr);
        bail!(
            "{quick_tool} failed: {}",
            e.trim().lines().last().unwrap_or("unknown error")
        );
    }

    if let Some(d) = dns {
        let servers: Vec<&str> = d
            .split(',')
            .map(str::trim)
            .filter(|x| x.parse::<IpAddr>().is_ok())
            .collect();
        if !servers.is_empty() && have("resolvectl") {
            let _ = Command::new("resolvectl")
                .arg("dns")
                .arg(iface)
                .args(&servers)
                .output();
            let _ = Command::new("resolvectl")
                .args(["domain", iface, "~."])
                .output();
        }
    }

    Ok(Session {
        id: profile.id.clone(),
        name: profile.name.clone(),
        kind: profile.kind,
        server: profile.server.clone(),
        iface: iface.to_string(),
        pid: None,
        sidecar_pid: None,
        backend: Some(backend_name.to_string()),
        since: now(),
        conf: conf_path.to_string_lossy().to_string(),
    })
}

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
        have(self.tool())
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
        self.validate_config(&profile.data)?;
        start_wg_family(
            self.tool(),
            &self.iface,
            "wireguard-tools",
            "wireguard",
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

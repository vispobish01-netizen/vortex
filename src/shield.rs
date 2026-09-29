use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{fs, os::unix::fs::PermissionsExt, process::Command};

pub const SHIELD_STATE: &str = "/run/vortex/shield.json";
pub const SHIELD_ENABLED_FLAG: &str = "/etc/vortex/shield_enabled";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ShieldStatus {
    pub armed: bool,
    pub iface: Option<String>,
    pub server: Option<String>,
}

fn have(bin: &str) -> bool {
    std::path::Path::new(&format!("/usr/bin/{bin}")).exists()
        || std::path::Path::new(&format!("/usr/sbin/{bin}")).exists()
        || std::path::Path::new(&format!("/bin/{bin}")).exists()
}

pub fn is_enabled_preference() -> bool {
    std::path::Path::new(SHIELD_ENABLED_FLAG).exists()
}

pub fn set_enabled_preference(enabled: bool) {
    if enabled {
        let _ = fs::write(SHIELD_ENABLED_FLAG, "1");
    } else {
        let _ = fs::remove_file(SHIELD_ENABLED_FLAG);
    }
}

pub fn is_armed() -> bool {
    if let Ok(s) = fs::read_to_string(SHIELD_STATE) {
        if let Ok(st) = serde_json::from_str::<ShieldStatus>(&s) {
            if st.armed {
                return true;
            }
        }
    }
    if !have("iptables") {
        return false;
    }
    Command::new("iptables")
        .args(["-C", "OUTPUT", "-j", "VORTEX_SHIELD"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

pub fn status() -> ShieldStatus {
    if let Ok(s) = fs::read_to_string(SHIELD_STATE) {
        if let Ok(st) = serde_json::from_str::<ShieldStatus>(&s) {
            return st;
        }
    }
    ShieldStatus {
        armed: is_armed(),
        iface: None,
        server: None,
    }
}

/// Arm the Stealth Kill Switch firewall rules.
/// Restricts all non-loopback, non-tunnel, and non-LAN traffic from exiting cleartext.
pub fn arm(iface: Option<&str>, server_endpoint: Option<&str>) -> Result<()> {
    if !have("iptables") {
        bail!("iptables not found — stealth shield requires iptables");
    }

    // Parse server IP and port if given
    let (server_ip, server_port) = match server_endpoint {
        Some(s) if !s.is_empty() => {
            let (h, p) = match s.rsplit_once(':') {
                Some((host, port)) => (host.trim_matches(|c| c == '[' || c == ']'), port.parse::<u16>().ok()),
                None => (s.trim_matches(|c| c == '[' || c == ']'), None),
            };
            (Some(h.to_string()), p)
        }
        _ => (None, None),
    };

    // Clean up any old chain first to start fresh
    let _ = disarm();

    // 1. IPv4 Rules
    let run_ip4 = |args: &[&str]| -> Result<()> {
        let o = Command::new("iptables").args(args).output().context("iptables execution failed")?;
        if !o.status.success() {
            let err = String::from_utf8_lossy(&o.stderr);
            bail!("iptables {} failed: {}", args.join(" "), err.trim());
        }
        Ok(())
    };

    run_ip4(&["-N", "VORTEX_SHIELD"])?;
    run_ip4(&["-F", "VORTEX_SHIELD"])?;

    // Allow loopback
    run_ip4(&["-A", "VORTEX_SHIELD", "-o", "lo", "-j", "ACCEPT"])?;

    // Allow active tunnel interface if specified
    if let Some(ifc) = iface.filter(|s| !s.is_empty()) {
        run_ip4(&["-A", "VORTEX_SHIELD", "-o", ifc, "-j", "ACCEPT"])?;
    }

    // Allow DHCP client requests
    let _ = run_ip4(&["-A", "VORTEX_SHIELD", "-p", "udp", "--sport", "68", "--dport", "67", "-j", "ACCEPT"]);

    // Allow local RFC1918 subnets and multicast so LAN / local services remain functional
    run_ip4(&["-A", "VORTEX_SHIELD", "-d", "127.0.0.0/8", "-j", "ACCEPT"])?;
    run_ip4(&["-A", "VORTEX_SHIELD", "-d", "10.0.0.0/8", "-j", "ACCEPT"])?;
    run_ip4(&["-A", "VORTEX_SHIELD", "-d", "172.16.0.0/12", "-j", "ACCEPT"])?;
    run_ip4(&["-A", "VORTEX_SHIELD", "-d", "192.168.0.0/16", "-j", "ACCEPT"])?;
    run_ip4(&["-A", "VORTEX_SHIELD", "-d", "224.0.0.0/4", "-j", "ACCEPT"])?;
    run_ip4(&["-A", "VORTEX_SHIELD", "-d", "255.255.255.255/32", "-j", "ACCEPT"])?;

    // Allow outbound connection to the remote VPN server IP and port
    if let Some(ref sip) = server_ip {
        if let Ok(ip) = sip.parse::<std::net::IpAddr>() {
            if ip.is_ipv4() {
                if let Some(port) = server_port {
                    let port_str = port.to_string();
                    let _ = run_ip4(&["-A", "VORTEX_SHIELD", "-d", sip, "-p", "tcp", "--dport", &port_str, "-j", "ACCEPT"]);
                    let _ = run_ip4(&["-A", "VORTEX_SHIELD", "-d", sip, "-p", "udp", "--dport", &port_str, "-j", "ACCEPT"]);
                } else {
                    let _ = run_ip4(&["-A", "VORTEX_SHIELD", "-d", sip, "-j", "ACCEPT"]);
                }
            }
        }
    }

    // Drop all other non-tunnel IPv4 traffic
    run_ip4(&["-A", "VORTEX_SHIELD", "-j", "DROP"])?;

    // Insert jump into OUTPUT
    run_ip4(&["-I", "OUTPUT", "1", "-j", "VORTEX_SHIELD"])?;

    // 2. IPv6 Rules (drop all non-loopback / non-tunnel IPv6 traffic to block IPv6 leaks)
    if have("ip6tables") {
        let run_ip6 = |args: &[&str]| -> Result<()> {
            let o = Command::new("ip6tables").args(args).output().context("ip6tables execution failed")?;
            if !o.status.success() {
                let err = String::from_utf8_lossy(&o.stderr);
                bail!("ip6tables {} failed: {}", args.join(" "), err.trim());
            }
            Ok(())
        };

        let _ = run_ip6(&["-N", "VORTEX_SHIELD"]);
        let _ = run_ip6(&["-F", "VORTEX_SHIELD"]);
        let _ = run_ip6(&["-A", "VORTEX_SHIELD", "-o", "lo", "-j", "ACCEPT"]);
        if let Some(ifc) = iface.filter(|s| !s.is_empty()) {
            let _ = run_ip6(&["-A", "VORTEX_SHIELD", "-o", ifc, "-j", "ACCEPT"]);
        }
        let _ = run_ip6(&["-A", "VORTEX_SHIELD", "-j", "DROP"]);
        let _ = run_ip6(&["-I", "OUTPUT", "1", "-j", "VORTEX_SHIELD"]);
    }

    let status = ShieldStatus {
        armed: true,
        iface: iface.map(String::from),
        server: server_endpoint.map(String::from),
    };
    let _ = fs::create_dir_all("/run/vortex");
    let _ = fs::set_permissions("/run/vortex", fs::Permissions::from_mode(0o755));
    let _ = fs::write(SHIELD_STATE, serde_json::to_string_pretty(&status)?);
    let _ = fs::set_permissions(SHIELD_STATE, fs::Permissions::from_mode(0o644));
    Ok(())
}

/// Disarm and tear down the Stealth Kill Switch rules cleanly.
pub fn disarm() -> Result<()> {
    if !have("iptables") {
        return Ok(());
    }

    // Remove IPv4 chain and rules
    while Command::new("iptables").args(["-D", "OUTPUT", "-j", "VORTEX_SHIELD"]).status().map(|s| s.success()).unwrap_or(false) {}
    let _ = Command::new("iptables").args(["-F", "VORTEX_SHIELD"]).output();
    let _ = Command::new("iptables").args(["-X", "VORTEX_SHIELD"]).output();

    // Remove IPv6 chain and rules
    if have("ip6tables") {
        while Command::new("ip6tables").args(["-D", "OUTPUT", "-j", "VORTEX_SHIELD"]).status().map(|s| s.success()).unwrap_or(false) {}
        let _ = Command::new("ip6tables").args(["-F", "VORTEX_SHIELD"]).output();
        let _ = Command::new("ip6tables").args(["-X", "VORTEX_SHIELD"]).output();
    }

    let _ = fs::remove_file(SHIELD_STATE);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shield_status_serialization() {
        let st = ShieldStatus {
            armed: true,
            iface: Some("vx0".into()),
            server: Some("203.0.113.7:443".into()),
        };
        let js = serde_json::to_string(&st).unwrap();
        let st2: ShieldStatus = serde_json::from_str(&js).unwrap();
        assert_eq!(st, st2);
    }
}

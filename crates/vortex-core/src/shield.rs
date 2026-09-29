use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Write,
    net::{IpAddr, ToSocketAddrs},
    os::unix::fs::PermissionsExt,
    process::{Command, Stdio},
};
use tracing::{info, warn};

pub const SHIELD_STATE: &str = "/run/vortex/shield.json";
pub const SHIELD_ENABLED_FLAG: &str = "/etc/vortex/shield_enabled";
pub const NFT_TABLE_NAME: &str = "vortex_shield";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ShieldStatus {
    pub armed: bool,
    pub iface: Option<String>,
    pub server: Option<String>,
    #[serde(default = "default_true")]
    pub allow_lan: bool,
    #[serde(default)]
    pub backend: String,
}

fn default_true() -> bool {
    true
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

/// Checks whether the nftables table `table inet vortex_shield` is currently active.
pub fn is_nftables_active() -> bool {
    if !have("nft") {
        return false;
    }
    Command::new("nft")
        .args(["list", "table", "inet", NFT_TABLE_NAME])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Checks whether legacy iptables `VORTEX_SHIELD` chain is currently active in OUTPUT.
pub fn is_iptables_active() -> bool {
    if !have("iptables") {
        return false;
    }
    Command::new("iptables")
        .args(["-C", "OUTPUT", "-j", "VORTEX_SHIELD"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub fn is_armed() -> bool {
    if let Ok(s) = fs::read_to_string(SHIELD_STATE) {
        if let Ok(st) = serde_json::from_str::<ShieldStatus>(&s) {
            if st.armed {
                return true;
            }
        }
    }
    is_nftables_active() || is_iptables_active()
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
        allow_lan: true,
        backend: if have("nft") { "nftables" } else { "iptables" }.into(),
    }
}

/// Parses "host:port", "[v6]:port", or defaults to port 443.
pub fn parse_endpoint(server: &str) -> (String, Option<u16>) {
    let s = server.trim();
    if let Some((h, p)) = s.rsplit_once(':') {
        let host = h.trim_matches(|c| c == '[' || c == ']');
        let port = p.split('/').next().and_then(|x| x.parse::<u16>().ok());
        (host.to_string(), port)
    } else {
        (s.trim_matches(|c| c == '[' || c == ']').to_string(), None)
    }
}

/// Resolves a host to valid IPv4 and IPv6 addresses.
pub fn resolve_server_ips(host: &str, port: u16) -> Vec<IpAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return vec![ip];
    }
    if let Ok(iter) = (host, port).to_socket_addrs() {
        let mut ips: Vec<IpAddr> = iter.map(|sa| sa.ip()).collect();
        ips.sort();
        ips.dedup();
        return ips;
    }
    Vec::new()
}

/// Generates an atomic nftables ruleset for `table inet vortex_shield`.
pub fn generate_nftables_ruleset(
    iface: Option<&str>,
    server_endpoint: Option<&str>,
    allow_lan: bool,
) -> String {
    let mut out = String::new();
    out.push_str("# Vortex Stealth Kill Switch — Strict Leak Protection Ruleset\n");
    out.push_str("table inet vortex_shield\n");
    out.push_str("delete table inet vortex_shield\n");
    out.push_str("table inet vortex_shield {\n");
    out.push_str("    chain output {\n");
    out.push_str("        type filter hook output priority 0; policy drop;\n\n");

    out.push_str("        # 1. Allow loopback\n");
    out.push_str("        oifname \"lo\" accept\n\n");

    out.push_str("        # 2. Allow established and related packets\n");
    out.push_str("        ct state established,related accept\n\n");

    out.push_str("        # 3. Allow DHCP client negotiation\n");
    out.push_str("        udp sport 68 udp dport 67 accept\n");
    out.push_str("        udp sport 546 udp dport 547 accept\n\n");

    if allow_lan {
        out.push_str("        # 4. Allow local RFC1918 subnets and multicast (LAN discovery)\n");
        out.push_str("        ip daddr { 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 255.255.255.255/32 } accept\n");
        out.push_str("        ip6 daddr { ::1/128, fe80::/10, ff00::/8 } accept\n\n");
    }

    out.push_str("        # 5. Allow authorized tunnel interfaces\n");
    let mut ifaces = vec!["tun*".to_string(), "wg*".to_string(), "vx*".to_string()];
    if let Some(ifc) = iface.filter(|s| !s.is_empty()) {
        let s = ifc.to_string();
        if !ifaces.contains(&s) {
            ifaces.push(s);
        }
    }
    let iface_list = ifaces
        .iter()
        .map(|i| format!("\"{i}\""))
        .collect::<Vec<_>>()
        .join(", ");
    out.push_str(&format!("        oifname {{ {iface_list} }} accept\n\n"));

    if let Some(endpoint) = server_endpoint.filter(|s| !s.is_empty()) {
        let (host, port_opt) = parse_endpoint(endpoint);
        let port = port_opt.unwrap_or(443);
        let ips = resolve_server_ips(&host, port);

        out.push_str("        # 6. Exempt remote VPN server endpoint\n");
        if ips.is_empty() {
            // Unresolved hostname fallback
            out.push_str(&format!(
                "        # Host: {host} (unresolved at ruleset generation)\n"
            ));
        } else {
            for ip in ips {
                match ip {
                    IpAddr::V4(v4) => {
                        out.push_str(&format!("        ip daddr {v4} tcp dport {port} accept\n"));
                        out.push_str(&format!("        ip daddr {v4} udp dport {port} accept\n"));
                    }
                    IpAddr::V6(v6) => {
                        out.push_str(&format!("        ip6 daddr {v6} tcp dport {port} accept\n"));
                        out.push_str(&format!("        ip6 daddr {v6} udp dport {port} accept\n"));
                    }
                }
            }
        }
        out.push('\n');
    }

    out.push_str("        # 7. Unconditionally drop all cleartext traffic\n");
    out.push_str("        drop\n");
    out.push_str("    }\n");
    out.push_str("}\n");

    out
}

/// Applies an nftables ruleset atomically by piping to `nft -f -`.
pub fn apply_nftables(ruleset: &str) -> Result<()> {
    if !have("nft") {
        bail!("nftables binary 'nft' not found in PATH");
    }

    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Failed to spawn 'nft'")?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(ruleset.as_bytes())
            .context("Failed to write ruleset to nft stdin")?;
    }

    let output = child.wait_with_output().context("nft failed to finish")?;
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        bail!("nft error (exit status {}): {}", output.status, err.trim());
    }

    info!("Applied atomic nftables table '{NFT_TABLE_NAME}'");
    Ok(())
}

/// Deletes the `table inet vortex_shield` atomically.
pub fn disarm_nftables() -> Result<()> {
    if !have("nft") {
        return Ok(());
    }

    let out = Command::new("nft")
        .args(["delete", "table", "inet", NFT_TABLE_NAME])
        .output();

    if let Ok(o) = out {
        if o.status.success() {
            info!("Deleted nftables table '{NFT_TABLE_NAME}'");
        }
    }
    Ok(())
}

/// Cleans up any stale rules from an earlier crash or aborted daemon session.
pub fn cleanup_stale_rules() -> Result<()> {
    let _ = disarm_nftables();

    if have("iptables") {
        while Command::new("iptables")
            .args(["-D", "OUTPUT", "-j", "VORTEX_SHIELD"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {}
        let _ = Command::new("iptables")
            .args(["-F", "VORTEX_SHIELD"])
            .output();
        let _ = Command::new("iptables")
            .args(["-X", "VORTEX_SHIELD"])
            .output();
    }

    if have("ip6tables") {
        while Command::new("ip6tables")
            .args(["-D", "OUTPUT", "-j", "VORTEX_SHIELD"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {}
        let _ = Command::new("ip6tables")
            .args(["-F", "VORTEX_SHIELD"])
            .output();
        let _ = Command::new("ip6tables")
            .args(["-X", "VORTEX_SHIELD"])
            .output();
    }

    let _ = fs::remove_file(SHIELD_STATE);
    Ok(())
}

/// Arm the Stealth Kill Switch firewall rules with options.
pub fn arm_with_options(
    iface: Option<&str>,
    server_endpoint: Option<&str>,
    allow_lan: bool,
) -> Result<()> {
    // 1. Clean previous state
    let _ = cleanup_stale_rules();

    let backend = if have("nft") {
        let ruleset = generate_nftables_ruleset(iface, server_endpoint, allow_lan);
        match apply_nftables(&ruleset) {
            Ok(_) => "nftables",
            Err(e) => {
                warn!("nftables application failed: {e:#}; falling back to iptables");
                arm_iptables_fallback(iface, server_endpoint, allow_lan)?;
                "iptables"
            }
        }
    } else {
        arm_iptables_fallback(iface, server_endpoint, allow_lan)?;
        "iptables"
    };

    let status = ShieldStatus {
        armed: true,
        iface: iface.map(String::from),
        server: server_endpoint.map(String::from),
        allow_lan,
        backend: backend.to_string(),
    };
    let _ = fs::create_dir_all("/run/vortex");
    let _ = fs::set_permissions("/run/vortex", fs::Permissions::from_mode(0o755));
    let _ = fs::write(SHIELD_STATE, serde_json::to_string_pretty(&status)?);
    let _ = fs::set_permissions(SHIELD_STATE, fs::Permissions::from_mode(0o644));
    Ok(())
}

/// Fallback arming via legacy iptables if nft is unavailable.
fn arm_iptables_fallback(
    iface: Option<&str>,
    server_endpoint: Option<&str>,
    allow_lan: bool,
) -> Result<()> {
    if !have("iptables") {
        bail!("Neither 'nft' nor 'iptables' found — kill-switch requires firewall tooling");
    }

    let run_ip4 = |args: &[&str]| -> Result<()> {
        let o = Command::new("iptables")
            .args(args)
            .output()
            .context("iptables execution failed")?;
        if !o.status.success() {
            let err = String::from_utf8_lossy(&o.stderr);
            bail!("iptables {} failed: {}", args.join(" "), err.trim());
        }
        Ok(())
    };

    run_ip4(&["-N", "VORTEX_SHIELD"])?;
    run_ip4(&["-F", "VORTEX_SHIELD"])?;
    run_ip4(&["-A", "VORTEX_SHIELD", "-o", "lo", "-j", "ACCEPT"])?;

    if let Some(ifc) = iface.filter(|s| !s.is_empty()) {
        run_ip4(&["-A", "VORTEX_SHIELD", "-o", ifc, "-j", "ACCEPT"])?;
    }

    if allow_lan {
        run_ip4(&["-A", "VORTEX_SHIELD", "-d", "127.0.0.0/8", "-j", "ACCEPT"])?;
        run_ip4(&["-A", "VORTEX_SHIELD", "-d", "10.0.0.0/8", "-j", "ACCEPT"])?;
        run_ip4(&["-A", "VORTEX_SHIELD", "-d", "172.16.0.0/12", "-j", "ACCEPT"])?;
        run_ip4(&[
            "-A",
            "VORTEX_SHIELD",
            "-d",
            "192.168.0.0/16",
            "-j",
            "ACCEPT",
        ])?;
        run_ip4(&["-A", "VORTEX_SHIELD", "-d", "224.0.0.0/4", "-j", "ACCEPT"])?;
        run_ip4(&[
            "-A",
            "VORTEX_SHIELD",
            "-d",
            "255.255.255.255/32",
            "-j",
            "ACCEPT",
        ])?;
    }

    if let Some(endpoint) = server_endpoint.filter(|s| !s.is_empty()) {
        let (host, port_opt) = parse_endpoint(endpoint);
        let port = port_opt.unwrap_or(443);
        let ips = resolve_server_ips(&host, port);
        for ip in ips {
            if let IpAddr::V4(v4) = ip {
                let v4_s = v4.to_string();
                let p_s = port.to_string();
                let _ = run_ip4(&[
                    "-A",
                    "VORTEX_SHIELD",
                    "-d",
                    &v4_s,
                    "-p",
                    "tcp",
                    "--dport",
                    &p_s,
                    "-j",
                    "ACCEPT",
                ]);
                let _ = run_ip4(&[
                    "-A",
                    "VORTEX_SHIELD",
                    "-d",
                    &v4_s,
                    "-p",
                    "udp",
                    "--dport",
                    &p_s,
                    "-j",
                    "ACCEPT",
                ]);
            }
        }
    }

    run_ip4(&["-A", "VORTEX_SHIELD", "-j", "DROP"])?;
    run_ip4(&["-I", "OUTPUT", "1", "-j", "VORTEX_SHIELD"])?;

    if have("ip6tables") {
        let run_ip6 = |args: &[&str]| -> Result<()> {
            let o = Command::new("ip6tables")
                .args(args)
                .output()
                .context("ip6tables execution failed")?;
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

    Ok(())
}

pub fn arm(iface: Option<&str>, server_endpoint: Option<&str>) -> Result<()> {
    arm_with_options(iface, server_endpoint, true)
}

pub fn disarm() -> Result<()> {
    cleanup_stale_rules()
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
            allow_lan: true,
            backend: "nftables".into(),
        };
        let js = serde_json::to_string(&st).unwrap();
        let st2: ShieldStatus = serde_json::from_str(&js).unwrap();
        assert_eq!(st, st2);
    }

    #[test]
    fn test_generate_nftables_ruleset_structure() {
        let ruleset = generate_nftables_ruleset(Some("tun0"), Some("198.51.100.25:8443"), true);

        assert!(ruleset.contains("table inet vortex_shield"));
        assert!(ruleset.contains("delete table inet vortex_shield"));
        assert!(ruleset.contains("policy drop"));
        assert!(ruleset.contains("oifname \"lo\" accept"));
        assert!(ruleset.contains("ct state established,related accept"));
        assert!(ruleset.contains("udp sport 68 udp dport 67 accept"));
        assert!(ruleset.contains("\"tun0\""));
        assert!(ruleset.contains("198.51.100.25 tcp dport 8443 accept"));
        assert!(ruleset.contains("198.51.100.25 udp dport 8443 accept"));
        assert!(ruleset.contains("192.168.0.0/16"));
        assert!(ruleset.ends_with("drop\n    }\n}\n"));
    }

    #[test]
    fn test_generate_nftables_ruleset_lan_disabled() {
        let ruleset = generate_nftables_ruleset(None, Some("203.0.113.50:443"), false);

        assert!(ruleset.contains("table inet vortex_shield"));
        assert!(
            !ruleset.contains("192.168.0.0/16"),
            "LAN subnets should not be present when allow_lan is false"
        );
        assert!(ruleset.contains("203.0.113.50 tcp dport 443 accept"));
    }

    #[test]
    fn test_parse_endpoint() {
        assert_eq!(parse_endpoint("1.2.3.4:443"), ("1.2.3.4".into(), Some(443)));
        assert_eq!(
            parse_endpoint("[2001:db8::1]:8443"),
            ("2001:db8::1".into(), Some(8443))
        );
        assert_eq!(parse_endpoint("example.com"), ("example.com".into(), None));
    }
}

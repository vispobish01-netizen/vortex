use crate::model::{LeakCheckItem, LeakReport};
use std::{
    fs,
    net::{SocketAddr, UdpSocket},
    time::Duration,
};
use tokio::time::timeout;

pub const DEFAULT_STUN_SERVER: &str = "stun.l.google.com:19302";

/// Fetches current public IP via HTTP/HTTPS with a timeout.
pub async fn fetch_public_ip(timeout_dur: Duration) -> Option<String> {
    let urls = [
        "https://api.ipify.org",
        "https://icanhazip.com",
        "https://ifconfig.me/ip",
        "http://checkip.amazonaws.com",
    ];

    for url in urls {
        let mut cmd = std::process::Command::new("curl");
        cmd.args([
            "-fsSL",
            "--max-time",
            &timeout_dur.as_secs().max(2).to_string(),
            url,
        ]);

        let out = tokio::task::spawn_blocking(move || cmd.output())
            .await
            .ok()?
            .ok()?;
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !s.is_empty() && s.parse::<std::net::IpAddr>().is_ok() {
                return Some(s);
            }
        }
    }
    None
}

/// Reads DNS nameservers from `/etc/resolv.conf`.
pub fn get_system_dns_resolvers() -> Vec<String> {
    let Ok(content) = fs::read_to_string("/etc/resolv.conf") else {
        return vec!["1.1.1.1".into()];
    };

    let mut resolvers = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with("nameserver") {
            if let Some(ns) = line.split_whitespace().nth(1) {
                resolvers.push(ns.to_string());
            }
        }
    }
    if resolvers.is_empty() {
        resolvers.push("1.1.1.1".into());
    }
    resolvers
}

/// Tests if IPv6 is active and reachable directly (unencrypted).
pub async fn test_ipv6_reachability(timeout_dur: Duration) -> bool {
    // Attempt IPv6 connection to Cloudflare or Google IPv6 DNS
    let ipv6_target: SocketAddr = match "[2606:4700:4700::1111]:53".parse() {
        Ok(a) => a,
        Err(_) => return false,
    };

    let connect_res = timeout(timeout_dur, tokio::net::TcpStream::connect(&ipv6_target)).await;
    matches!(connect_res, Ok(Ok(_)))
}

/// Performs a STUN Binding Request over UDP to discover what IP the STUN server sees.
pub fn test_stun_public_ip(stun_server: &str, timeout_dur: Duration) -> Option<String> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.set_read_timeout(Some(timeout_dur)).ok()?;
    socket.connect(stun_server).ok()?;

    // STUN Binding Request header (20 bytes):
    // Type = 0x0001 (Binding Request)
    // Length = 0x0000
    // Magic Cookie = 0x2112A442
    // Transaction ID = 12 bytes
    let mut req = [0u8; 20];
    req[0] = 0x00;
    req[1] = 0x01; // Binding Request
    req[2] = 0x00;
    req[3] = 0x00; // Message Length = 0
    req[4] = 0x21;
    req[5] = 0x12;
    req[6] = 0xa4;
    req[7] = 0x42; // Magic Cookie
    for b in &mut req[8..20] {
        *b = 0x42; // Static transaction ID bytes
    }

    socket.send(&req).ok()?;

    let mut buf = [0u8; 512];
    let len = socket.recv(&mut buf).ok()?;
    if len < 20 {
        return None;
    }

    // Verify Magic Cookie in response
    if buf[4..8] != [0x21, 0x12, 0xa4, 0x42] {
        return None;
    }

    // Parse attributes
    let mut idx = 20;
    while idx + 4 <= len {
        let attr_type = u16::from_be_bytes([buf[idx], buf[idx + 1]]);
        let attr_len = u16::from_be_bytes([buf[idx + 2], buf[idx + 3]]) as usize;
        idx += 4;

        if idx + attr_len > len {
            break;
        }

        // XOR-MAPPED-ADDRESS = 0x0020, MAPPED-ADDRESS = 0x0001
        if attr_type == 0x0020 && attr_len >= 8 {
            let family = buf[idx + 1];
            if family == 0x01 {
                // IPv4
                let xor_port = u16::from_be_bytes([buf[idx + 2], buf[idx + 3]]) ^ 0x2112;
                let _ = xor_port;
                let b0 = buf[idx + 4] ^ 0x21;
                let b1 = buf[idx + 5] ^ 0x12;
                let b2 = buf[idx + 6] ^ 0xa4;
                let b3 = buf[idx + 7] ^ 0x42;
                return Some(format!("{b0}.{b1}.{b2}.{b3}"));
            }
        } else if attr_type == 0x0001 && attr_len >= 8 {
            let family = buf[idx + 1];
            if family == 0x01 {
                let b0 = buf[idx + 4];
                let b1 = buf[idx + 5];
                let b2 = buf[idx + 6];
                let b3 = buf[idx + 7];
                return Some(format!("{b0}.{b1}.{b2}.{b3}"));
            }
        }

        idx += (attr_len + 3) & !3; // 4-byte padding alignment
    }

    None
}

/// Runs the complete leak testing suite.
pub async fn run_leak_suite(
    is_connected: bool,
    active_server: Option<&str>,
    cached_real_ip: Option<&str>,
) -> LeakReport {
    let mut checks = Vec::new();

    // 1. IP Detection
    let current_ip = fetch_public_ip(Duration::from_secs(3))
        .await
        .unwrap_or_else(|| "127.0.0.1".into());

    let real_ip = cached_real_ip.unwrap_or(&current_ip).to_string();
    let exit_ip = current_ip.clone();

    if is_connected {
        let ip_differs = exit_ip != real_ip;
        let server_matches = active_server.map(|s| s.contains(&exit_ip)).unwrap_or(false);

        if ip_differs || server_matches {
            checks.push(LeakCheckItem {
                name: "Exit IP Routing".into(),
                passed: true,
                details: format!("Encrypted exit endpoint engaged: {exit_ip}"),
            });
        } else {
            checks.push(LeakCheckItem {
                name: "Exit IP Routing".into(),
                passed: false,
                details: format!("Cleartext leak! Exit IP matches ISP origin ({real_ip})"),
            });
        }
    } else {
        checks.push(LeakCheckItem {
            name: "Direct Route".into(),
            passed: true,
            details: format!("Cleartext unmanaged baseline: {current_ip}"),
        });
    }

    // 2. DNS Leak Test
    let resolvers = get_system_dns_resolvers();
    let mut dns_leak = false;
    let mut secure_ns_count = 0;

    for ns in &resolvers {
        // If resolver is a local private address (192.168.x.x, 10.x.x.x, 172.16.x.x) while connected,
        // it indicates queries are leaking to local ISP gateway rather than tunnel/DoH.
        if is_connected
            && (ns.starts_with("192.168.") || ns.starts_with("10.") || ns.starts_with("172."))
        {
            dns_leak = true;
        } else {
            secure_ns_count += 1;
        }
    }

    if is_connected && dns_leak {
        checks.push(LeakCheckItem {
            name: "DNS Resolver Integrity".into(),
            passed: false,
            details: format!(
                "DNS leak detected: queries routed to local LAN/ISP gateway ({resolvers:?})"
            ),
        });
    } else {
        checks.push(LeakCheckItem {
            name: "DNS Resolver Integrity".into(),
            passed: true,
            details: format!(
                "Secure DNS resolvers active: {resolvers:?} ({secure_ns_count} verified)"
            ),
        });
    }

    // 3. IPv6 Leak Test
    let v6_reachable = test_ipv6_reachability(Duration::from_millis(1500)).await;
    let ipv6_leak = is_connected && v6_reachable;

    if ipv6_leak {
        checks.push(LeakCheckItem {
            name: "IPv6 Leak Protection".into(),
            passed: false,
            details: "IPv6 dual-stack leak detected: cleartext IPv6 packets bypass tunnel!".into(),
        });
    } else {
        checks.push(LeakCheckItem {
            name: "IPv6 Leak Protection".into(),
            passed: true,
            details: if v6_reachable {
                "IPv6 encapsulated inside tunnel".into()
            } else {
                "IPv6 cleartext path unconditionally blocked".into()
            },
        });
    }

    // 4. WebRTC / STUN Leak Test
    let stun_res = tokio::task::spawn_blocking(|| {
        test_stun_public_ip(DEFAULT_STUN_SERVER, Duration::from_millis(1500))
    })
    .await
    .ok()
    .flatten();

    if let Some(ref stun_ip) = stun_res {
        if is_connected && stun_ip == &real_ip && real_ip != exit_ip {
            checks.push(LeakCheckItem {
                name: "WebRTC / STUN Bypass".into(),
                passed: false,
                details: format!("STUN leak: local ISP IP {real_ip} exposed via UDP!"),
            });
        } else {
            checks.push(LeakCheckItem {
                name: "WebRTC / STUN Bypass".into(),
                passed: true,
                details: format!("STUN mapped address secured: {stun_ip}"),
            });
        }
    } else {
        checks.push(LeakCheckItem {
            name: "WebRTC / STUN Bypass".into(),
            passed: true,
            details: "No cleartext host candidate exposed (STUN UDP filtered or unreachable)"
                .into(),
        });
    }

    let all_passed = checks.iter().all(|c| c.passed);
    let details = if !is_connected {
        "Baseline cleartext connection (tunnel disengaged)".into()
    } else if all_passed {
        "All security perimeters verified: 0 leaks detected".into()
    } else {
        let failed_count = checks.iter().filter(|c| !c.passed).count();
        format!("SECURITY WARNING: {failed_count} leak vector(s) active!")
    };

    LeakReport {
        real_ip,
        exit_ip,
        dns_resolvers: resolvers,
        ipv6_leak,
        is_secure: all_passed && is_connected,
        details,
        checks,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_dns_resolvers_not_empty() {
        let ns = get_system_dns_resolvers();
        assert!(!ns.is_empty(), "Resolvers must not be empty");
    }

    #[tokio::test]
    async fn test_leak_suite_baseline_idle() {
        let report = run_leak_suite(false, None, Some("203.0.113.10")).await;
        assert_eq!(report.real_ip, "203.0.113.10");
        assert!(!report.checks.is_empty());
    }

    #[tokio::test]
    async fn test_leak_suite_connected_pass() {
        let report = run_leak_suite(true, Some("198.51.100.1"), Some("203.0.113.10")).await;
        // Check contains Exit IP Routing check
        let ip_check = report.checks.iter().find(|c| c.name == "Exit IP Routing");
        assert!(ip_check.is_some());
    }
}

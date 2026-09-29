use crate::store::Profile;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    process::Command,
    time::{Duration, Instant},
};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ReconReport {
    pub node_name: String,
    pub kind: String,
    pub target_endpoint: String,
    pub host: String,
    pub port: u16,
    pub resolved_ips: Vec<String>,
    pub reverse_dns: Option<String>,
    pub asn: Option<String>,
    pub org: Option<String>,
    pub city: Option<String>,
    pub country: Option<String>,
    pub loc: Option<String>,
    pub rtt_min: u32,
    pub rtt_avg: u32,
    pub rtt_max: u32,
    pub jitter: u32,
    pub tls_version: Option<String>,
    pub tls_cipher: Option<String>,
    pub tls_cert_subject: Option<String>,
    pub tls_cert_issuer: Option<String>,
    pub exit_ip: Option<String>,
    pub exit_colo: Option<String>,
}

fn parse_host_port(server: &str) -> (String, u16) {
    if let Some((h, p)) = server.rsplit_once(':') {
        let host = h.trim_matches(|c| c == '[' || c == ']').to_string();
        let port = p.parse::<u16>().unwrap_or(443);
        (host, port)
    } else {
        (server.trim_matches(|c| c == '[' || c == ']').to_string(), 443)
    }
}

pub fn probe_recon(p: &Profile) -> Result<ReconReport> {
    let (host, port) = parse_host_port(&p.server);

    // 1. Resolve host to IP addresses
    let mut resolved_ips = vec![];
    if let Ok(addrs) = format!("{host}:{port}").to_socket_addrs() {
        for a in addrs {
            let ip_s = a.ip().to_string();
            if !resolved_ips.contains(&ip_s) {
                resolved_ips.push(ip_s);
            }
        }
    }

    let primary_ip = resolved_ips.first().cloned().unwrap_or_else(|| host.clone());

    // 2. Reverse DNS lookup
    let reverse_dns = Command::new("host")
        .args(["-W", "2", &primary_ip])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                let out = String::from_utf8_lossy(&o.stdout);
                out.lines()
                    .find(|l| l.contains("domain name pointer"))
                    .and_then(|l| l.split_whitespace().last())
                    .map(|s| s.trim_end_matches('.').to_string())
            } else {
                None
            }
        });

    // 3. Multi-probe TCP latency & Jitter (3 probes)
    let mut pings = vec![];
    let probe_addr: Option<SocketAddr> = format!("{primary_ip}:{port}").to_socket_addrs().ok().and_then(|mut it| it.next());
    if let Some(target) = probe_addr {
        for _ in 0..3 {
            let start = Instant::now();
            if TcpStream::connect_timeout(&target, Duration::from_millis(1500)).is_ok() {
                pings.push(start.elapsed().as_millis() as u32);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    let (rtt_min, rtt_avg, rtt_max, jitter) = if !pings.is_empty() {
        let min = *pings.iter().min().unwrap_or(&0);
        let max = *pings.iter().max().unwrap_or(&0);
        let avg = pings.iter().sum::<u32>() / pings.len() as u32;
        let jit = max.saturating_sub(min);
        (min, avg, max, jit)
    } else {
        (0, 0, 0, 0)
    };

    // 4. GeoIP & ASN Intelligence (via ipinfo.io)
    let geo_out = Command::new("curl")
        .args(["-s", "--max-time", "3", &format!("https://ipinfo.io/{primary_ip}/json")])
        .output()
        .ok()
        .and_then(|o| serde_json::from_slice::<Value>(&o.stdout).ok());

    let (asn, org, city, country, loc) = match geo_out {
        Some(v) => {
            let full_org = v["org"].as_str().unwrap_or("").to_string();
            let (asn_part, org_part) = if let Some((a, o)) = full_org.split_once(' ') {
                (Some(a.to_string()), Some(o.to_string()))
            } else if !full_org.is_empty() {
                (Some(full_org.clone()), Some(full_org))
            } else {
                (None, None)
            };
            let city = v["city"].as_str().map(String::from);
            let country = v["country"].as_str().map(String::from);
            let loc = v["loc"].as_str().map(String::from);
            (asn_part, org_part, city, country, loc)
        }
        None => (None, None, None, None, None),
    };

    // 5. TLS Fingerprint & Certificate inspection (for TLS nodes)
    let is_tls = port == 443 || p.kind.is_singbox();
    let (tls_version, tls_cipher, tls_cert_subject, tls_cert_issuer) = if is_tls {
        let sni = if let Ok((_, ob, _, _)) = crate::store::outbound(&p.data) {
            ob["tls"]["server_name"].as_str().map(String::from).unwrap_or_else(|| host.clone())
        } else {
            host.clone()
        };

        let tls_cmd = Command::new("openssl")
            .args([
                "s_client",
                "-connect",
                &format!("{primary_ip}:{port}"),
                "-servername",
                &sni,
                "-brief",
            ])
            .stdin(std::process::Stdio::null())
            .output();

        match tls_cmd {
            Ok(o) => {
                let text = format!("{}\n{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
                let mut proto = None;
                let mut cipher = None;
                let mut subj = None;
                let mut iss = None;

                for l in text.lines() {
                    let t = l.trim();
                    if t.starts_with("Protocol:") {
                        proto = t.split_once(':').map(|(_, v)| v.trim().to_string());
                    } else if t.starts_with("Cipher:") || t.contains("Cipher is ") {
                        cipher = if let Some((_, c)) = t.split_once("Cipher is ") {
                            Some(c.trim().to_string())
                        } else {
                            t.split_once(':').map(|(_, v)| v.trim().to_string())
                        };
                    } else if t.starts_with("subject=") {
                        subj = Some(t.trim_start_matches("subject=").trim().to_string());
                    } else if t.starts_with("issuer=") {
                        iss = Some(t.trim_start_matches("issuer=").trim().to_string());
                    } else if t.contains("CONNECTION ESTABLISHED") {
                        // parsed from brief mode e.g. "Protocol version: TLSv1.3"
                    }
                }
                (proto, cipher, subj, iss)
            }
            Err(_) => (None, None, None, None),
        }
    } else {
        (None, None, None, None)
    };

    // 6. Trace Exit Info
    let trace_out = Command::new("curl")
        .args(["-s", "--max-time", "3", "https://cloudflare.com/cdn-cgi/trace"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string());

    let (exit_ip, exit_colo) = match trace_out {
        Some(t) => {
            let mut ip = None;
            let mut colo = None;
            for l in t.lines() {
                if let Some((k, v)) = l.split_once('=') {
                    if k == "ip" {
                        ip = Some(v.to_string());
                    } else if k == "colo" {
                        colo = Some(v.to_string());
                    }
                }
            }
            (ip, colo)
        }
        None => (None, None),
    };

    Ok(ReconReport {
        node_name: p.name.clone(),
        kind: p.kind.tag().to_string(),
        target_endpoint: p.server.clone(),
        host,
        port,
        resolved_ips,
        reverse_dns,
        asn,
        org,
        city,
        country,
        loc,
        rtt_min,
        rtt_avg,
        rtt_max,
        jitter,
        tls_version,
        tls_cipher,
        tls_cert_subject,
        tls_cert_issuer,
        exit_ip,
        exit_colo,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_host_port() {
        assert_eq!(parse_host_port("1.2.3.4:443"), ("1.2.3.4".into(), 443));
        assert_eq!(parse_host_port("[2001:db8::1]:8443"), ("2001:db8::1".into(), 8443));
        assert_eq!(parse_host_port("example.com"), ("example.com".into(), 443));
    }
}

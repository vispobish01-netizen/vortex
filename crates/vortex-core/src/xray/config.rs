use crate::model::{Kind, Profile, Security, Transport};
use crate::shield::{parse_endpoint, resolve_server_ips};
use crate::tunnel::load_routing;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::net::IpAddr;
use std::path::Path;
use std::process::Command;

pub const DEFAULT_XRAY_TUN_IFACE: &str = "vx0";
pub const DEFAULT_XRAY_PROXY_PORT: u16 = 1080;

/// Generates valid Xray outbound settings for a Profile
pub fn generate_xray_outbound(p: &Profile) -> Result<Value> {
    let trimmed_data = p.data.trim();
    // Check if profile data is already a complete or partial Xray JSON outbound
    if trimmed_data.starts_with('{') {
        if let Ok(mut val) = serde_json::from_str::<Value>(trimmed_data) {
            if let Some(mut first_ob) = val["outbounds"].as_array().and_then(|a| a.first()).cloned() {
                if first_ob.get("tag").is_none() {
                    first_ob["tag"] = json!("proxy");
                }
                return Ok(first_ob);
            }
            if val.get("protocol").is_some() || val.get("type").is_some() {
                if val.get("tag").is_none() {
                    val["tag"] = json!("proxy");
                }
                return Ok(val);
            }
        }
    }

    let (host, port_opt) = parse_endpoint(&p.server);
    let port = p.port.or(port_opt).unwrap_or(443);

    // Stream settings (transport and security)
    let stream_settings = generate_stream_settings(p)?;

    let outbound = match p.kind {
        Kind::Vless => {
            let uuid = extract_credential_from_uri(&p.data).unwrap_or_else(|| p.id.clone());
            let flow = p.flow.clone().unwrap_or_else(|| {
                // If XTLS or Vision is detected or profile security is Reality/TLS
                if p.data.contains("xtls-rprx-vision") {
                    "xtls-rprx-vision".to_string()
                } else {
                    "".to_string()
                }
            });

            json!({
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": host,
                        "port": port,
                        "users": [{
                            "id": uuid,
                            "encryption": "none",
                            "flow": flow
                        }]
                    }]
                },
                "streamSettings": stream_settings
            })
        }
        Kind::Vmess => {
            let uuid = extract_credential_from_uri(&p.data).unwrap_or_else(|| p.id.clone());
            json!({
                "tag": "proxy",
                "protocol": "vmess",
                "settings": {
                    "vnext": [{
                        "address": host,
                        "port": port,
                        "users": [{
                            "id": uuid,
                            "alterId": 0,
                            "security": "auto"
                        }]
                    }]
                },
                "streamSettings": stream_settings
            })
        }
        Kind::Trojan => {
            let password = extract_credential_from_uri(&p.data).unwrap_or_else(|| p.id.clone());
            json!({
                "tag": "proxy",
                "protocol": "trojan",
                "settings": {
                    "servers": [{
                        "address": host,
                        "port": port,
                        "password": password
                    }]
                },
                "streamSettings": stream_settings
            })
        }
        Kind::Ss => {
            let (method, password) = extract_shadowsocks_auth(&p.data)
                .unwrap_or_else(|| ("chacha20-ietf-poly1305".to_string(), p.id.clone()));
            json!({
                "tag": "proxy",
                "protocol": "shadowsocks",
                "settings": {
                    "servers": [{
                        "address": host,
                        "port": port,
                        "method": method,
                        "password": password,
                        "uot": true
                    }]
                },
                "streamSettings": stream_settings
            })
        }
        Kind::Hy2 => {
            let password = extract_credential_from_uri(&p.data).unwrap_or_else(|| p.id.clone());
            json!({
                "tag": "proxy",
                "protocol": "hysteria2",
                "settings": {
                    "servers": [{
                        "address": host,
                        "port": port,
                        "password": password
                    }]
                },
                "streamSettings": stream_settings
            })
        }
        Kind::Xray => {
            // Already handled above if JSON, otherwise wrap as custom outbound
            if let Ok(val) = serde_json::from_str::<Value>(&p.data) {
                val
            } else {
                bail!("Xray profile data must be valid JSON or standard proxy URI");
            }
        }
        _ => bail!("Unsupported protocol {:?} for Xray backend", p.kind),
    };

    Ok(outbound)
}

/// Generates Xray streamSettings (network, security, TLS/REALITY settings)
fn generate_stream_settings(p: &Profile) -> Result<Value> {
    let mut stream = json!({});

    // Network / Transport
    let network = match p.transport {
        Transport::Xhttp => "xhttp",
        Transport::Ws => "ws",
        Transport::Grpc => "grpc",
        Transport::H2 => "h2",
        Transport::HttpUpgrade => "httpupgrade",
        Transport::Tcp | Transport::Unknown => "tcp",
        Transport::Quic | Transport::Udp => "quic",
    };
    stream["network"] = json!(network);

    // Transport specific settings
    match p.transport {
        Transport::Xhttp => {
            let mut xhttp_settings = json!({
                "mode": "auto"
            });
            if let Some(path) = extract_query_param(&p.data, "path") {
                xhttp_settings["path"] = json!(path);
            }
            if let Some(host) = extract_query_param(&p.data, "host").or_else(|| p.sni.clone()) {
                xhttp_settings["host"] = json!(host);
            }
            stream["xhttpSettings"] = xhttp_settings;
        }
        Transport::Ws => {
            let path = extract_query_param(&p.data, "path").unwrap_or_else(|| "/".to_string());
            let host = extract_query_param(&p.data, "host").or_else(|| p.sni.clone());
            let mut ws_settings = json!({ "path": path });
            if let Some(h) = host {
                ws_settings["headers"] = json!({ "Host": h });
            }
            stream["wsSettings"] = ws_settings;
        }
        Transport::Grpc => {
            let service_name = extract_query_param(&p.data, "serviceName")
                .or_else(|| extract_query_param(&p.data, "path"))
                .unwrap_or_default();
            stream["grpcSettings"] = json!({
                "serviceName": service_name,
                "multiMode": false
            });
        }
        Transport::H2 => {
            let path = extract_query_param(&p.data, "path").unwrap_or_else(|| "/".to_string());
            let host = extract_query_param(&p.data, "host").or_else(|| p.sni.clone());
            stream["httpSettings"] = json!({
                "path": path,
                "host": host.map(|h| vec![h]).unwrap_or_default()
            });
        }
        _ => {}
    }

    // Security Settings
    let security = match p.security {
        Security::Reality => "reality",
        Security::Tls => "tls",
        Security::None => "none",
        Security::Unknown => {
            if p.data.contains("security=reality") {
                "reality"
            } else if p.data.contains("security=tls") || p.data.contains("tls=1") {
                "tls"
            } else {
                "none"
            }
        }
    };
    stream["security"] = json!(security);

    if security == "reality" {
        let (host, _) = parse_endpoint(&p.server);
        let sni = p
            .sni
            .clone()
            .or_else(|| extract_query_param(&p.data, "sni"))
            .unwrap_or(host);
        let pbk = p
            .reality_public_key
            .clone()
            .or_else(|| extract_query_param(&p.data, "pbk"))
            .unwrap_or_default();
        let sid = p
            .reality_short_id
            .clone()
            .or_else(|| extract_query_param(&p.data, "sid"))
            .unwrap_or_default();
        let fp = p
            .fingerprint
            .clone()
            .or_else(|| extract_query_param(&p.data, "fp"))
            .unwrap_or_else(|| "chrome".to_string());
        let spx = p
            .reality_spider_x
            .clone()
            .or_else(|| extract_query_param(&p.data, "spx"))
            .unwrap_or_default();

        let mut reality_settings = json!({
            "serverName": sni,
            "fingerprint": fp,
            "show": false,
            "publicKey": pbk,
            "shortId": sid
        });
        if !spx.is_empty() {
            reality_settings["spiderX"] = json!(spx);
        }
        stream["realitySettings"] = reality_settings;
    } else if security == "tls" {
        let (host, _) = parse_endpoint(&p.server);
        let sni = p
            .sni
            .clone()
            .or_else(|| extract_query_param(&p.data, "sni"))
            .unwrap_or(host);
        let fp = p
            .fingerprint
            .clone()
            .or_else(|| extract_query_param(&p.data, "fp"))
            .unwrap_or_else(|| "chrome".to_string());

        let mut alpn = Vec::new();
        if let Some(a) = &p.alpn {
            alpn.extend(a.split(',').map(|s| s.trim().to_string()));
        } else if let Some(a) = extract_query_param(&p.data, "alpn") {
            alpn.extend(a.split(',').map(|s| s.trim().to_string()));
        } else {
            alpn.push("h2".to_string());
            alpn.push("http/1.1".to_string());
        }

        let mut tls_settings = json!({
            "serverName": sni,
            "alpn": alpn,
            "fingerprint": fp
        });

        // ECH support
        if let Some(ech) = p
            .ech
            .clone()
            .or_else(|| extract_query_param(&p.data, "ech"))
        {
            tls_settings["echConfig"] = json!(ech);
        }

        // Certificate Pinning
        if let Some(pin) = p
            .pinned_peer_cert
            .clone()
            .or_else(|| extract_query_param(&p.data, "pinnedPeerCertificateChainSha256"))
        {
            tls_settings["pinnedPeerCertificateChainSha256"] = json!([pin]);
        }

        // Post-quantum cipher support (e.g. mlkem768x25519plus)
        if let Some(pq) = p
            .post_quantum
            .clone()
            .or_else(|| extract_query_param(&p.data, "pq"))
        {
            tls_settings["cipherSuites"] = json!(pq);
        } else if p.data.contains("mlkem768x25519plus") {
            tls_settings["cipherSuites"] =
                json!("TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256");
        }

        stream["tlsSettings"] = tls_settings;
    }

    Ok(stream)
}

/// Generates a complete, production-grade Xray JSON configuration
pub fn generate_xray_config(
    profile: &Profile,
    tun_interface: &str,
    mixed_proxy_port: u16,
    api_port: u16,
    log_path: Option<&Path>,
) -> Result<Value> {
    let outbound = generate_xray_outbound(profile)?;
    let (host, port_opt) = parse_endpoint(&profile.server);
    let port = profile.port.or(port_opt).unwrap_or(443);

    // Resolve server endpoint to avoid routing loops
    let server_ips = resolve_server_ips(&host, port);
    let mut server_ip_strings: Vec<String> = server_ips.iter().map(|ip| ip.to_string()).collect();
    if server_ip_strings.is_empty() && host.parse::<IpAddr>().is_ok() {
        server_ip_strings.push(host.clone());
    }

    let rules_cfg = crate::routing::RulesConfig::load();
    let legacy_routing = load_routing();

    let mut routing_rules = Vec::new();

    // 1. API traffic rule
    routing_rules.push(json!({
        "type": "field",
        "inboundTag": ["api-in"],
        "outboundTag": "api"
    }));

    // 2. Prevent routing loops: exempt remote VPN server endpoint
    if !server_ip_strings.is_empty() {
        routing_rules.push(json!({
            "type": "field",
            "ip": server_ip_strings,
            "outboundTag": "direct"
        }));
    }

    // 3. DNS server exemption
    routing_rules.push(json!({
        "type": "field",
        "ip": ["1.1.1.1", "8.8.8.8"],
        "port": "53,853",
        "outboundTag": "direct"
    }));

    // 4. LAN bypass
    if legacy_routing.bypass_lan || rules_cfg.presets.bypass_lan {
        routing_rules.push(json!({
            "type": "field",
            "ip": ["geoip:private"],
            "outboundTag": "direct"
        }));
    }

    // 5. Block ads preset
    if rules_cfg.presets.block_ads {
        routing_rules.push(json!({
            "type": "field",
            "domain": ["geosite:category-ads-all"],
            "outboundTag": "block"
        }));
    }

    // 6. Direct domestic preset
    if rules_cfg.presets.direct_domestic {
        routing_rules.push(json!({
            "type": "field",
            "ip": ["geoip:cn", "geoip:ir"],
            "outboundTag": "direct"
        }));
    }

    // 7. Blocked domains
    if !legacy_routing.blocked_domains.is_empty() {
        routing_rules.push(json!({
            "type": "field",
            "domain": legacy_routing.blocked_domains,
            "outboundTag": "block"
        }));
    }

    // 8. Direct domains
    if !legacy_routing.direct_domains.is_empty() {
        routing_rules.push(json!({
            "type": "field",
            "domain": legacy_routing.direct_domains,
            "outboundTag": "direct"
        }));
    }

    // 7. Default proxy rule
    routing_rules.push(json!({
        "type": "field",
        "network": "tcp,udp",
        "outboundTag": "proxy"
    }));

    let log_level = "warning";
    let log_config = if let Some(lp) = log_path {
        json!({
            "access": "",
            "error": lp.to_string_lossy(),
            "loglevel": log_level
        })
    } else {
        json!({
            "loglevel": log_level
        })
    };

    let config = json!({
        "log": log_config,
        "stats": {},
        "api": {
            "tag": "api",
            "services": ["StatsService"]
        },
        "dns": {
            "servers": [
                {
                    "address": "https://1.1.1.1/dns-query",
                    "domains": ["geosite:geolocation-!cn"]
                },
                "1.1.1.1",
                "8.8.8.8",
                "localhost"
            ],
            "queryStrategy": "UseIPv4"
        },
        "inbounds": [
            // TUN Inbound for system-wide tunneling
            {
                "tag": "tun-in",
                "protocol": "tun",
                "settings": {
                    "name": tun_interface,
                    "mtu": 1500,
                    "gateway": ["172.19.0.1/30"],
                    "autoSystemRoutingTable": ["0.0.0.0/0"],
                    "autoOutboundsInterface": "auto"
                },
                "sniffing": {
                    "enabled": true,
                    "destOverride": ["http", "tls", "quic", "fakedns"]
                }
            },
            // Local SOCKS5 / mixed proxy
            {
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": mixed_proxy_port,
                "protocol": "socks",
                "settings": {
                    "udp": true
                }
            },
            // Local HTTP proxy
            {
                "tag": "http-in",
                "listen": "127.0.0.1",
                "port": mixed_proxy_port + 1,
                "protocol": "http"
            },
            // gRPC API inbound on random or fixed loopback port
            {
                "tag": "api-in",
                "listen": "127.0.0.1",
                "port": api_port,
                "protocol": "dokodemo-door",
                "settings": {
                    "address": "127.0.0.1"
                }
            }
        ],
        "outbounds": [
            outbound,
            {
                "tag": "direct",
                "protocol": "freedom",
                "settings": {
                    "domainStrategy": "UseIP"
                }
            },
            {
                "tag": "block",
                "protocol": "blackhole"
            }
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": routing_rules
        }
    });

    Ok(config)
}

/// Validates raw Xray JSON or generated config file via `xray run -test -config <file>`
pub fn validate_xray_config_file(xray_bin: &Path, config_path: &Path) -> Result<()> {
    let out = Command::new(xray_bin)
        .args(["run", "-test", "-config", config_path.to_str().unwrap()])
        .output()
        .or_else(|_| {
            // Fallback syntax for older versions: `xray -test -config <path>`
            Command::new(xray_bin)
                .args(["-test", "-config", config_path.to_str().unwrap()])
                .output()
        })
        .context("Failed to execute Xray test command")?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let error_msg = if !stderr.trim().is_empty() {
            stderr
        } else {
            stdout
        };

        // Extract most meaningful error message
        let lines: Vec<&str> = error_msg.lines().filter(|l| !l.trim().is_empty()).collect();
        let last_err = lines
            .last()
            .copied()
            .unwrap_or("Xray rejected the configuration");

        bail!("Xray configuration validation failed:\n{last_err}");
    }

    Ok(())
}

// ───────────────────────── Helpers ─────────────────────────

fn extract_query_param(uri: &str, param: &str) -> Option<String> {
    if let Ok(u) = url::Url::parse(uri) {
        for (k, v) in u.query_pairs() {
            if k == param {
                return Some(v.into_owned());
            }
        }
    }
    None
}

fn extract_credential_from_uri(uri: &str) -> Option<String> {
    if let Ok(u) = url::Url::parse(uri) {
        if !u.username().is_empty() {
            return Some(u.username().to_string());
        }
    }
    None
}

fn extract_shadowsocks_auth(uri: &str) -> Option<(String, String)> {
    let clean = uri.strip_prefix("ss://").unwrap_or(uri);
    let (body, _) = clean.split_once('#').unwrap_or((clean, ""));
    let (body, _) = body.split_once('?').unwrap_or((body, ""));

    if let Some((user_info, _)) = body.split_once('@') {
        if let Ok(decoded) = crate::parser::decode_base64_flexible(user_info) {
            if let Ok(s) = String::from_utf8(decoded) {
                if let Some((m, p)) = s.split_once(':') {
                    return Some((m.to_string(), p.to_string()));
                }
            }
        }
        if let Some((m, p)) = user_info.split_once(':') {
            return Some((m.to_string(), p.to_string()));
        }
    } else {
        // Classic base64 payload: base64(method:password@host:port)
        if let Ok(decoded) = crate::parser::decode_base64_flexible(body) {
            if let Ok(s) = String::from_utf8(decoded) {
                if let Some((user_info, _)) = s.rsplit_once('@') {
                    if let Some((m, p)) = user_info.split_once(':') {
                        return Some((m.to_string(), p.to_string()));
                    }
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vless_reality_xray_config_generation() {
        let uri = "vless://b6a03649-61f4-41aa-a51b-402c3cc6c547@example.com:443?security=reality&sni=example.com&pbk=1111222233334444555566667777888899990000111=&sid=1234&type=xhttp&path=/xhttp#test-node";
        let mut p = Profile::new("test", "test-node", Kind::Vless, "example.com:443", uri);
        p.transport = Transport::Xhttp;
        p.security = Security::Reality;
        p.sni = Some("example.com".into());
        p.reality_public_key = Some("1111222233334444555566667777888899990000111=".into());
        p.reality_short_id = Some("1234".into());

        let cfg = generate_xray_config(&p, "vx0", 1080, 54321, None).unwrap();

        assert_eq!(cfg["log"]["loglevel"], "warning");
        assert!(cfg["stats"].is_object());
        assert_eq!(cfg["api"]["services"], json!(["StatsService"]));

        let inbounds = cfg["inbounds"].as_array().unwrap();
        assert!(inbounds.iter().any(|i| i["tag"] == "tun-in"));
        assert!(inbounds.iter().any(|i| i["tag"] == "socks-in"));
        assert!(inbounds.iter().any(|i| i["tag"] == "api-in"));

        let outbounds = cfg["outbounds"].as_array().unwrap();
        let proxy_ob = outbounds.iter().find(|o| o["tag"] == "proxy").unwrap();
        assert_eq!(proxy_ob["protocol"], "vless");
        assert_eq!(proxy_ob["streamSettings"]["network"], "xhttp");
        assert_eq!(proxy_ob["streamSettings"]["security"], "reality");
        assert_eq!(
            proxy_ob["streamSettings"]["realitySettings"]["publicKey"],
            "1111222233334444555566667777888899990000111="
        );
    }

    #[test]
    fn test_vless_post_quantum_and_ech() {
        let uri = "vless://b6a03649-61f4-41aa-a51b-402c3cc6c547@example.com:443?security=tls&sni=example.com&ech=AEX123&pq=mlkem768x25519plus#test-pq";
        let mut p = Profile::new("test-pq", "test-pq", Kind::Vless, "example.com:443", uri);
        p.security = Security::Tls;
        p.ech = Some("AEX123".into());
        p.post_quantum = Some("mlkem768x25519plus".into());

        let ob = generate_xray_outbound(&p).unwrap();
        let tls = &ob["streamSettings"]["tlsSettings"];
        assert_eq!(tls["echConfig"], "AEX123");
        assert_eq!(tls["cipherSuites"], "mlkem768x25519plus");
    }
}

use crate::error::VortexError;
use crate::model::{Kind, Profile, Security, Transport};
use base64::{engine::general_purpose as b64_engine, Engine};
use percent_encoding::percent_decode_str;
use serde_json::Value;
use std::fs;
use std::io::Read;
use std::path::Path;
use url::Url;

/// Decodes standard or URL-safe base64 with flexible padding.
pub fn decode_base64_flexible(s: &str) -> Result<Vec<u8>, VortexError> {
    let clean = s.trim().replace(['\n', '\r', ' '], "");
    if clean.is_empty() {
        return Err(VortexError::Parse("Empty base64 payload".into()));
    }

    // Try standard base64
    if let Ok(data) = b64_engine::STANDARD.decode(&clean) {
        return Ok(data);
    }
    if let Ok(data) = b64_engine::STANDARD_NO_PAD.decode(&clean) {
        return Ok(data);
    }
    // Try URL-safe base64
    if let Ok(data) = b64_engine::URL_SAFE.decode(&clean) {
        return Ok(data);
    }
    if let Ok(data) = b64_engine::URL_SAFE_NO_PAD.decode(&clean) {
        return Ok(data);
    }

    // Attempt with manual padding
    let pad_len = (4 - (clean.len() % 4)) % 4;
    let padded = format!("{}{}", clean, "=".repeat(pad_len));
    if let Ok(data) = b64_engine::STANDARD.decode(&padded) {
        return Ok(data);
    }
    if let Ok(data) = b64_engine::URL_SAFE.decode(&padded) {
        return Ok(data);
    }

    Err(VortexError::Parse(format!(
        "Failed to decode base64 string (length {})",
        clean.len()
    )))
}

fn pct_decode(s: &str) -> String {
    percent_decode_str(s).decode_utf8_lossy().to_string()
}

/// Parses a VLESS share URL: vless://uuid@host:port?params#name
pub fn parse_vless(uri: &str) -> Result<Profile, VortexError> {
    let u = Url::parse(uri).map_err(|e| VortexError::Parse(format!("Invalid VLESS URL: {e}")))?;
    if u.scheme() != "vless" {
        return Err(VortexError::Parse(format!(
            "Expected vless:// scheme, got {}://",
            u.scheme()
        )));
    }
    let uuid = u.username();
    if uuid.is_empty() {
        return Err(VortexError::Parse(
            "VLESS link is missing UUID / credentials".into(),
        ));
    }
    let host = u
        .host_str()
        .ok_or_else(|| VortexError::Parse("VLESS link is missing host".into()))?;
    let port = u.port().unwrap_or(443);
    let name = u
        .fragment()
        .map(pct_decode)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("VLESS · {host}"));

    let mut p = Profile::new("", name, Kind::Vless, format!("{host}:{port}"), uri.trim());
    derive_metadata_for_profile(&mut p);
    Ok(p)
}

/// Parses a VMess share link: vmess://base64(json)
pub fn parse_vmess(uri: &str) -> Result<Profile, VortexError> {
    let payload = uri
        .strip_prefix("vmess://")
        .ok_or_else(|| VortexError::Parse("Expected vmess:// prefix".into()))?;
    let decoded = decode_base64_flexible(payload)?;
    let js_str = String::from_utf8(decoded)
        .map_err(|e| VortexError::Parse(format!("VMess JSON is not UTF-8: {e}")))?;
    let val: Value = serde_json::from_str(&js_str)
        .map_err(|e| VortexError::Parse(format!("Invalid VMess JSON: {e}")))?;

    let host = val["add"]
        .as_str()
        .ok_or_else(|| VortexError::Parse("VMess JSON missing 'add' (server host)".into()))?;
    let port = match &val["port"] {
        Value::Number(n) => n.as_u64().unwrap_or(443) as u16,
        Value::String(s) => s.parse::<u16>().unwrap_or(443),
        _ => 443,
    };
    let name = val["ps"]
        .as_str()
        .filter(|s| !s.is_empty())
        .unwrap_or("VMess Node")
        .to_string();

    let mut p = Profile::new("", name, Kind::Vmess, format!("{host}:{port}"), uri.trim());
    derive_metadata_for_profile(&mut p);
    Ok(p)
}

/// Parses a Trojan share URL: trojan://password@host:port?params#name
pub fn parse_trojan(uri: &str) -> Result<Profile, VortexError> {
    let u = Url::parse(uri).map_err(|e| VortexError::Parse(format!("Invalid Trojan URL: {e}")))?;
    if u.scheme() != "trojan" {
        return Err(VortexError::Parse(format!(
            "Expected trojan:// scheme, got {}://",
            u.scheme()
        )));
    }
    let password = u.username();
    if password.is_empty() {
        return Err(VortexError::Parse("Trojan link is missing password".into()));
    }
    let host = u
        .host_str()
        .ok_or_else(|| VortexError::Parse("Trojan link is missing host".into()))?;
    let port = u.port().unwrap_or(443);
    let name = u
        .fragment()
        .map(pct_decode)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("Trojan · {host}"));

    let mut p = Profile::new("", name, Kind::Trojan, format!("{host}:{port}"), uri.trim());
    derive_metadata_for_profile(&mut p);
    Ok(p)
}

/// Parses Shadowsocks link: ss://base64(method:password@host:port)#name or ss://base64(method:password)@host:port#name
pub fn parse_shadowsocks(uri: &str) -> Result<Profile, VortexError> {
    let raw = uri
        .strip_prefix("ss://")
        .ok_or_else(|| VortexError::Parse("Expected ss:// prefix".into()))?;
    let (body, fragment) = match raw.split_once('#') {
        Some((b, f)) => (b, Some(pct_decode(f))),
        None => (raw, None),
    };

    let (server, name) = if let Some((_user_info_b64, host_port)) = body.split_once('@') {
        let (host, port_str) = host_port
            .split_once(':')
            .ok_or_else(|| VortexError::Parse("SS link missing port".into()))?;
        let port = port_str
            .split('?')
            .next()
            .unwrap_or(port_str)
            .parse::<u16>()
            .map_err(|e| VortexError::Parse(format!("Invalid port: {e}")))?;
        let name = fragment.unwrap_or_else(|| format!("SS · {host}"));
        (format!("{host}:{port}"), name)
    } else {
        // Base64 decoded whole body
        let decoded = decode_base64_flexible(body)?;
        let s = String::from_utf8(decoded)
            .map_err(|e| VortexError::Parse(format!("SS base64 not UTF-8: {e}")))?;
        let (_, host_port) = s
            .rsplit_once('@')
            .ok_or_else(|| VortexError::Parse("SS format missing @ delimiter".into()))?;
        let (host, port_str) = host_port
            .split_once(':')
            .ok_or_else(|| VortexError::Parse("SS missing port".into()))?;
        let port: u16 = port_str
            .trim()
            .parse()
            .map_err(|e| VortexError::Parse(format!("Invalid port: {e}")))?;
        let name = fragment.unwrap_or_else(|| format!("SS · {host}"));
        (format!("{host}:{port}"), name)
    };

    let mut p = Profile::new("", name, Kind::Ss, server, uri.trim());
    derive_metadata_for_profile(&mut p);
    Ok(p)
}

/// Parses Hysteria2 link: hy2://password@host:port?params#name or hysteria2://
pub fn parse_hysteria2(uri: &str) -> Result<Profile, VortexError> {
    let normalized = if uri.starts_with("hysteria2://") {
        uri.replacen("hysteria2://", "hy2://", 1)
    } else {
        uri.to_string()
    };
    let u = Url::parse(&normalized)
        .map_err(|e| VortexError::Parse(format!("Invalid Hysteria2 URL: {e}")))?;
    let host = u
        .host_str()
        .ok_or_else(|| VortexError::Parse("Hysteria2 link missing host".into()))?;
    let port = u.port().unwrap_or(443);
    let name = u
        .fragment()
        .map(pct_decode)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("HY2 · {host}"));

    let mut p = Profile::new("", name, Kind::Hy2, format!("{host}:{port}"), uri.trim());
    derive_metadata_for_profile(&mut p);
    Ok(p)
}

/// Parses TUIC link: tuic://uuid:password@host:port?params#name
pub fn parse_tuic(uri: &str) -> Result<Profile, VortexError> {
    let u = Url::parse(uri).map_err(|e| VortexError::Parse(format!("Invalid TUIC URL: {e}")))?;
    let host = u
        .host_str()
        .ok_or_else(|| VortexError::Parse("TUIC link missing host".into()))?;
    let port = u.port().unwrap_or(443);
    let name = u
        .fragment()
        .map(pct_decode)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("TUIC · {host}"));

    let mut p = Profile::new("", name, Kind::Tuic, format!("{host}:{port}"), uri.trim());
    derive_metadata_for_profile(&mut p);
    Ok(p)
}

/// Parses WireGuard or AmneziaWG configuration text.
pub fn parse_wireguard_conf(
    text: &str,
    default_name: Option<&str>,
) -> Result<Profile, VortexError> {
    if !text.contains("[Interface]") {
        return Err(VortexError::Parse(
            "WireGuard config missing [Interface] section".into(),
        ));
    }
    let is_awg = text.contains("Jc =")
        || text.contains("Jmin =")
        || text.contains("S1 =")
        || text.contains("H1 =");
    let kind = if is_awg { Kind::Awg } else { Kind::Wg };

    let mut endpoint = String::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some((k, v)) = trimmed.split_once('=') {
            if k.trim().eq_ignore_ascii_case("endpoint") {
                endpoint = v.trim().to_string();
                break;
            }
        }
    }

    let name = default_name.map(|s| s.to_string()).unwrap_or_else(|| {
        format!(
            "Config · {}",
            if is_awg { "AmneziaWG" } else { "WireGuard" }
        )
    });

    let mut p = Profile::new("", name, kind, endpoint, text.trim());
    derive_metadata_for_profile(&mut p);
    Ok(p)
}

/// Parses OpenVPN configuration text.
pub fn parse_openvpn_conf(text: &str, default_name: Option<&str>) -> Result<Profile, VortexError> {
    let mut server = String::new();
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.first() == Some(&"remote") {
            if parts.len() >= 3 {
                let host = parts[1];
                let port = parts[2];
                server = format!("{host}:{port}");
                break;
            } else if parts.len() == 2 {
                let host = parts[1];
                server = format!("{host}:1194");
                break;
            }
        }
    }

    let name = default_name
        .map(|s| s.to_string())
        .unwrap_or_else(|| "Config · OpenVPN".to_string());

    let mut p = Profile::new("", name, Kind::Ovpn, server, text.trim());
    derive_metadata_for_profile(&mut p);
    Ok(p)
}

/// Parses sing-box JSON configuration: extracts outbounds and server endpoints.
pub fn parse_singbox_json(json_text: &str) -> Result<Vec<Profile>, VortexError> {
    let val: Value = serde_json::from_str(json_text)
        .map_err(|e| VortexError::Parse(format!("Invalid sing-box JSON: {e}")))?;

    let mut profiles = vec![];
    let outbounds = if let Some(arr) = val["outbounds"].as_array() {
        arr.clone()
    } else if val.is_object() && val.get("type").is_some() {
        vec![val]
    } else {
        return Err(VortexError::Parse(
            "sing-box JSON has no 'outbounds' array or outbound object".into(),
        ));
    };

    for ob in outbounds {
        let ob_type = ob["type"].as_str().unwrap_or("");
        let kind = match ob_type {
            "vless" => Kind::Vless,
            "vmess" => Kind::Vmess,
            "trojan" => Kind::Trojan,
            "shadowsocks" => Kind::Ss,
            "hysteria2" => Kind::Hy2,
            "tuic" => Kind::Tuic,
            "wireguard" => Kind::Wg,
            _ => continue,
        };

        let tag = ob["tag"].as_str().unwrap_or("sing-box");
        let server = ob["server"].as_str().unwrap_or("");
        let port = ob["server_port"].as_u64().unwrap_or(443);
        let endpoint = if !server.is_empty() {
            format!("{server}:{port}")
        } else {
            "0.0.0.0:443".into()
        };

        let data = serde_json::to_string_pretty(&ob).unwrap_or_default();
        let mut p = Profile::new("", tag, kind, endpoint, data);
        derive_metadata_for_profile(&mut p);
        profiles.push(p);
    }

    if profiles.is_empty() {
        return Err(VortexError::Parse(
            "No supported proxy outbounds found in sing-box JSON".into(),
        ));
    }

    Ok(profiles)
}

/// Parses an Xray JSON configuration or outbound definition into Profiles.
pub fn parse_xray_json(json_text: &str) -> Result<Vec<Profile>, VortexError> {
    let val: Value = serde_json::from_str(json_text)
        .map_err(|e| VortexError::Parse(format!("Invalid Xray JSON: {e}")))?;

    let mut profiles = vec![];

    let outbounds = if let Some(arr) = val["outbounds"].as_array() {
        arr.clone()
    } else if val.is_object() && val.get("protocol").is_some() {
        vec![val.clone()]
    } else if val.is_object() && val.get("inbounds").is_some() {
        // Full Xray configuration file
        let mut p = Profile::new(
            "",
            "Xray Tunnel Config",
            Kind::Xray,
            "127.0.0.1:1080",
            json_text.trim(),
        );
        p.backend_type = Some("xray".into());
        derive_metadata_for_profile(&mut p);
        return Ok(vec![p]);
    } else {
        return Err(VortexError::Parse(
            "Xray JSON missing 'outbounds' or 'protocol' definition".into(),
        ));
    };

    for ob in outbounds {
        let proto = ob["protocol"].as_str().unwrap_or("").to_ascii_lowercase();
        let kind = match proto.as_str() {
            "vless" => Kind::Vless,
            "vmess" => Kind::Vmess,
            "trojan" => Kind::Trojan,
            "shadowsocks" => Kind::Ss,
            "hysteria2" => Kind::Hy2,
            _ => continue,
        };

        let tag = ob["tag"].as_str().unwrap_or("xray-proxy");

        // Try extracting address and port
        let mut host = "0.0.0.0";
        let mut port = 443u16;

        if let Some(vnext) = ob["settings"]["vnext"].as_array().and_then(|a| a.first()) {
            if let Some(h) = vnext["address"].as_str() {
                host = h;
            }
            if let Some(p) = vnext["port"].as_u64() {
                port = p as u16;
            }
        } else if let Some(servers) = ob["settings"]["servers"].as_array().and_then(|a| a.first()) {
            if let Some(h) = servers["address"].as_str() {
                host = h;
            }
            if let Some(p) = servers["port"].as_u64() {
                port = p as u16;
            }
        }

        let endpoint = format!("{host}:{port}");
        let data = serde_json::to_string_pretty(&ob).unwrap_or_default();
        let mut p = Profile::new("", tag, kind, endpoint, data);
        p.backend_type = Some("xray".into());
        derive_metadata_for_profile(&mut p);
        profiles.push(p);
    }

    if profiles.is_empty() {
        return Err(VortexError::Parse(
            "No supported proxy outbounds found in Xray JSON".into(),
        ));
    }

    Ok(profiles)
}

/// Derives Transport, Security, and other metadata from the PARSED config text/data.
/// Never guesses from the protocol name alone. If it cannot be determined, uses Unknown (`--`).
pub fn derive_metadata_for_profile(p: &mut Profile) {
    let data = p.data.trim();
    if data.is_empty() {
        p.transport = Transport::Unknown;
        p.security = Security::Unknown;
        return;
    }

    // 1. VLESS share link
    if data.starts_with("vless://") {
        if let Ok(u) = Url::parse(data) {
            let q: std::collections::HashMap<String, String> = u
                .query_pairs()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            p.port = u.port().or(Some(443));
            let net = q
                .get("type")
                .or_else(|| q.get("network"))
                .map(|s| s.to_ascii_lowercase())
                .unwrap_or_default();
            p.transport = match net.as_str() {
                "xhttp" => Transport::Xhttp,
                "tcp" | "" => Transport::Tcp,
                "ws" | "websocket" => Transport::Ws,
                "grpc" => Transport::Grpc,
                "h2" | "http" => Transport::H2,
                "httpupgrade" => Transport::HttpUpgrade,
                "quic" => Transport::Quic,
                _ => Transport::Unknown,
            };
            let sec = q
                .get("security")
                .map(|s| s.to_ascii_lowercase())
                .unwrap_or_default();
            p.security = match sec.as_str() {
                "reality" => Security::Reality,
                "tls" => Security::Tls,
                "none" | "" => Security::None,
                _ => Security::Unknown,
            };
            p.sni = q.get("sni").or_else(|| q.get("peer")).cloned();
            p.alpn = q.get("alpn").cloned();
            p.obfs = q.get("obfs").cloned();
            p.flow = q.get("flow").cloned();
            p.fingerprint = q.get("fp").cloned();
            p.reality_public_key = q.get("pbk").cloned();
            p.reality_short_id = q.get("sid").cloned();
            p.reality_spider_x = q.get("spx").cloned();
            p.ech = q.get("ech").cloned();
            p.pinned_peer_cert = q.get("pinnedPeerCertificateChainSha256").cloned();
            p.post_quantum = q.get("pq").cloned();
            return;
        }
    }

    // 2. VMess share link
    if let Some(payload) = data.strip_prefix("vmess://") {
        let payload = payload.split('#').next().unwrap_or(payload);
        if let Ok(decoded) = decode_base64_flexible(payload) {
            if let Ok(val) = serde_json::from_slice::<Value>(&decoded) {
                let port = match &val["port"] {
                    Value::Number(n) => n.as_u64().map(|x| x as u16),
                    Value::String(s) => s.parse::<u16>().ok(),
                    _ => None,
                };
                if let Some(port) = port {
                    p.port = Some(port);
                }
                let net = val["net"].as_str().unwrap_or("tcp").to_ascii_lowercase();
                p.transport = match net.as_str() {
                    "tcp" | "" | "none" => Transport::Tcp,
                    "ws" => Transport::Ws,
                    "grpc" => Transport::Grpc,
                    "h2" | "http" => Transport::H2,
                    "httpupgrade" => Transport::HttpUpgrade,
                    "quic" => Transport::Quic,
                    _ => Transport::Unknown,
                };
                let tls = val["tls"].as_str().unwrap_or("none").to_ascii_lowercase();
                p.security = match tls.as_str() {
                    "tls" => Security::Tls,
                    "reality" => Security::Reality,
                    "none" | "" => Security::None,
                    _ => Security::None,
                };
                p.sni = val["sni"]
                    .as_str()
                    .or_else(|| val["host"].as_str())
                    .map(String::from);
                p.alpn = val["alpn"].as_str().map(String::from);
                return;
            }
        }
        if let Ok(u) = Url::parse(data) {
            let q: std::collections::HashMap<String, String> = u
                .query_pairs()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            p.port = u.port().or(Some(443));
            let net = q
                .get("type")
                .or_else(|| q.get("network"))
                .map(|s| s.to_ascii_lowercase())
                .unwrap_or_default();
            p.transport = match net.as_str() {
                "tcp" | "" => Transport::Tcp,
                "ws" => Transport::Ws,
                "grpc" => Transport::Grpc,
                "h2" | "http" => Transport::H2,
                "httpupgrade" => Transport::HttpUpgrade,
                _ => Transport::Unknown,
            };
            let sec = q
                .get("security")
                .map(|s| s.to_ascii_lowercase())
                .unwrap_or_default();
            p.security = match sec.as_str() {
                "tls" => Security::Tls,
                "reality" => Security::Reality,
                "none" | "" => Security::None,
                _ => Security::None,
            };
            p.sni = q.get("sni").or_else(|| q.get("host")).cloned();
            p.alpn = q.get("alpn").cloned();
            return;
        }
    }

    // 3. Trojan share link
    if data.starts_with("trojan://") {
        if let Ok(u) = Url::parse(data) {
            let q: std::collections::HashMap<String, String> = u
                .query_pairs()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            p.port = u.port().or(Some(443));
            let net = q
                .get("type")
                .or_else(|| q.get("network"))
                .map(|s| s.to_ascii_lowercase())
                .unwrap_or_default();
            p.transport = match net.as_str() {
                "tcp" | "" => Transport::Tcp,
                "ws" | "websocket" => Transport::Ws,
                "grpc" => Transport::Grpc,
                "h2" | "http" => Transport::H2,
                "httpupgrade" => Transport::HttpUpgrade,
                _ => Transport::Unknown,
            };
            let sec = q
                .get("security")
                .map(|s| s.to_ascii_lowercase())
                .unwrap_or_else(|| "tls".to_string());
            p.security = match sec.as_str() {
                "reality" => Security::Reality,
                "none" => Security::None,
                _ => Security::Tls,
            };
            p.sni = q.get("sni").or_else(|| q.get("peer")).cloned();
            p.alpn = q.get("alpn").cloned();
            return;
        }
    }

    // 4. Hysteria 2 share link
    if data.starts_with("hy2://") || data.starts_with("hysteria2://") {
        let norm = if data.starts_with("hysteria2://") {
            data.replacen("hysteria2://", "hy2://", 1)
        } else {
            data.to_string()
        };
        if let Ok(u) = Url::parse(&norm) {
            let q: std::collections::HashMap<String, String> = u
                .query_pairs()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            p.transport = Transport::Quic;
            p.security = Security::Tls;
            p.tls_version = Some("1.3".into());
            p.alpn = Some("h3".into());
            p.port = u.port().or(Some(443));
            p.sni = q.get("sni").cloned();
            p.obfs = q
                .get("obfs")
                .filter(|s| !s.is_empty() && *s != "none")
                .cloned();
            return;
        }
    }

    // 5. TUIC share link
    if data.starts_with("tuic://") {
        if let Ok(u) = Url::parse(data) {
            let q: std::collections::HashMap<String, String> = u
                .query_pairs()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            p.transport = Transport::Quic;
            p.security = Security::Tls;
            p.alpn = Some("h3".into());
            p.port = u.port().or(Some(443));
            p.sni = q.get("sni").cloned();
            return;
        }
    }

    // 6. Shadowsocks share link
    if data.starts_with("ss://") {
        let query_part = data
            .split_once('?')
            .map(|(_, q)| q.split('#').next().unwrap_or(q))
            .unwrap_or("");
        let q: std::collections::HashMap<String, String> =
            url::form_urlencoded::parse(query_part.as_bytes())
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
        let plugin = q
            .get("plugin")
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_default();
        let is_udp = q
            .get("udp")
            .map(|v| v == "1" || v == "true")
            .unwrap_or(false)
            || q.get("uot").map(|v| v == "1").unwrap_or(false)
            || q.get("mode").map(|v| v.contains("udp")).unwrap_or(false);

        if is_udp {
            p.transport = Transport::Udp;
        } else if plugin.contains("mode=websocket") || plugin.contains("websocket") {
            p.transport = Transport::Ws;
        } else {
            p.transport = Transport::Tcp;
        }

        if plugin.contains("obfs=tls") || (plugin.contains("tls") && !plugin.contains("tls=none")) {
            p.security = Security::Tls;
            if plugin.contains("obfs=tls") {
                p.obfs = Some("tls".into());
            }
        } else {
            p.security = Security::None;
            if plugin.contains("obfs=http") {
                p.obfs = Some("http".into());
            }
        }
        if p.port.is_none() {
            p.port = p
                .server
                .rsplit_once(':')
                .and_then(|(_, s)| s.split('/').next().unwrap_or("").parse().ok());
        }
        return;
    }

    // 7. WireGuard / AmneziaWG
    if data.contains("[Interface]") {
        p.transport = Transport::Udp;
        p.security = Security::None;
        if data.contains("Jc =")
            || data.contains("Jmin =")
            || data.contains("S1 =")
            || data.contains("H1 =")
        {
            p.obfs = Some("amnezia".into());
        }
        for l in data.lines() {
            let t = l.trim();
            if let Some((k, v)) = t.split_once('=') {
                if k.trim().eq_ignore_ascii_case("endpoint") {
                    if let Some((_, prt)) = v.trim().rsplit_once(':') {
                        p.port = prt.trim().parse::<u16>().ok();
                    }
                }
            }
        }
        return;
    }

    // 8. OpenVPN
    if data
        .lines()
        .any(|l| l.trim_start().starts_with("remote ") || l.trim_start().starts_with("proto "))
    {
        let mut found_proto = false;
        for l in data.lines() {
            let t = l.trim();
            if let Some(rest) = t.strip_prefix("proto ") {
                found_proto = true;
                let val = rest.trim().to_ascii_lowercase();
                if val.starts_with("udp") {
                    p.transport = Transport::Udp;
                } else if val.starts_with("tcp") {
                    p.transport = Transport::Tcp;
                } else {
                    p.transport = Transport::Unknown;
                }
            } else if t.starts_with("remote ") {
                let parts: Vec<&str> = t.split_whitespace().collect();
                if parts.len() >= 3 {
                    p.port = parts[2].parse::<u16>().ok();
                }
            }
        }
        if !found_proto {
            p.transport = Transport::Unknown;
        }

        if data.contains("tls-client")
            || data.contains("tls-auth")
            || data.contains("tls-crypt")
            || data.contains("ca ")
            || data.contains("<ca>")
        {
            p.security = Security::Tls;
        } else if data.contains("secret ") {
            p.security = Security::None;
        } else {
            p.security = Security::Unknown;
        }
        return;
    }

    // 9. JSON config or outbound (sing-box or Xray)
    if let Ok(val) = serde_json::from_str::<Value>(data) {
        let ob = if let Some(arr) = val["outbounds"].as_array().and_then(|a| a.first()) {
            arr
        } else if val.is_object() && (val.get("type").is_some() || val.get("protocol").is_some()) {
            &val
        } else {
            p.transport = Transport::Unknown;
            p.security = Security::Unknown;
            return;
        };

        // Handle Xray outbound: has "protocol" and optionally "streamSettings"
        if let Some(proto) = ob.get("protocol").and_then(|v| v.as_str()) {
            if let Some(stream) = ob.get("streamSettings") {
                let net = stream["network"]
                    .as_str()
                    .or_else(|| stream["transport"].as_str())
                    .unwrap_or("tcp");
                p.transport = match net {
                    "ws" => Transport::Ws,
                    "grpc" => Transport::Grpc,
                    "xhttp" | "splithttp" => Transport::Xhttp,
                    "http" | "h2" => Transport::H2,
                    "httpupgrade" => Transport::HttpUpgrade,
                    "quic" => Transport::Quic,
                    "kcp" => Transport::Udp,
                    "tcp" | "" => Transport::Tcp,
                    _ => Transport::Unknown,
                };

                let sec = stream["security"].as_str().unwrap_or("none");
                p.security = match sec {
                    "reality" => Security::Reality,
                    "tls" => Security::Tls,
                    "none" | "" => Security::None,
                    _ => Security::Unknown,
                };

                if sec == "reality" {
                    let r = &stream["realitySettings"];
                    p.sni = r["serverName"].as_str().map(String::from);
                    p.reality_public_key = r["publicKey"].as_str().map(String::from);
                    p.reality_short_id = r["shortId"].as_str().map(String::from);
                    p.reality_spider_x = r["spiderX"].as_str().map(String::from);
                    p.fingerprint = r["fingerprint"].as_str().map(String::from);
                } else if sec == "tls" {
                    let t = &stream["tlsSettings"];
                    p.sni = t["serverName"].as_str().map(String::from);
                    p.fingerprint = t["fingerprint"].as_str().map(String::from);
                    p.ech = t["echConfig"].as_str().map(String::from);
                    p.post_quantum = t["cipherSuites"].as_str().map(String::from);
                    if let Some(arr) = t["alpn"].as_array() {
                        let alpns: Vec<String> = arr
                            .iter()
                            .filter_map(|x| x.as_str().map(String::from))
                            .collect();
                        if !alpns.is_empty() {
                            p.alpn = Some(alpns.join(","));
                        }
                    }
                }
            } else {
                p.transport = match proto {
                    "hysteria2" => Transport::Quic,
                    "wireguard" => Transport::Udp,
                    _ => Transport::Tcp,
                };
                p.security = match proto {
                    "trojan" | "hysteria2" => Security::Tls,
                    _ => Security::None,
                };
            }

            if p.port.is_none() {
                if let Some(vnext) = ob["settings"]["vnext"].as_array().and_then(|a| a.first()) {
                    p.port = vnext["port"].as_u64().map(|x| x as u16);
                } else if let Some(servers) =
                    ob["settings"]["servers"].as_array().and_then(|a| a.first())
                {
                    p.port = servers["port"].as_u64().map(|x| x as u16);
                }
            }
            return;
        }

        let ty = ob["type"].as_str().unwrap_or("");
        p.port = ob["server_port"].as_u64().map(|p| p as u16);
        match ty {
            "hysteria2" => {
                p.transport = Transport::Quic;
                p.security = Security::Tls;
                p.tls_version = Some("1.3".into());
                p.alpn = Some("h3".into());
                p.obfs = ob["obfs"]["type"].as_str().map(String::from);
                p.sni = ob["tls"]["server_name"].as_str().map(String::from);
            }
            "wireguard" => {
                p.transport = Transport::Udp;
                p.security = Security::None;
            }
            "tuic" => {
                p.transport = Transport::Quic;
                p.security = Security::Tls;
                p.alpn = Some("h3".into());
                p.sni = ob["tls"]["server_name"].as_str().map(String::from);
            }
            "vless" | "vmess" | "trojan" => {
                let tr = ob["transport"]["type"].as_str().unwrap_or("tcp");
                p.transport = match tr {
                    "ws" => Transport::Ws,
                    "grpc" => Transport::Grpc,
                    "http" | "h2" => Transport::H2,
                    "httpupgrade" => Transport::HttpUpgrade,
                    "quic" => Transport::Quic,
                    "tcp" | "" => Transport::Tcp,
                    _ => Transport::Unknown,
                };
                if ob["tls"]["reality"]["enabled"].as_bool() == Some(true) {
                    p.security = Security::Reality;
                } else if ob["tls"]["enabled"].as_bool() == Some(true) || ty == "trojan" {
                    p.security = Security::Tls;
                } else {
                    p.security = Security::None;
                }
                p.sni = ob["tls"]["server_name"].as_str().map(String::from);
                if let Some(arr) = ob["tls"]["alpn"].as_array() {
                    let alpns: Vec<String> = arr
                        .iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect();
                    if !alpns.is_empty() {
                        p.alpn = Some(alpns.join(","));
                    }
                }
            }
            "shadowsocks" => {
                let net = ob["network"].as_str().unwrap_or("tcp");
                p.transport = if net.contains("udp") {
                    Transport::Udp
                } else {
                    Transport::Tcp
                };
                p.security = Security::None;
            }
            _ => {
                p.transport = Transport::Unknown;
                p.security = Security::Unknown;
            }
        }
        return;
    }

    // Fallback: cannot determine
    p.transport = Transport::Unknown;
    p.security = Security::Unknown;
}

/// Parses an Amnezia vpn:// payload.
pub fn parse_amnezia(uri: &str) -> Result<Vec<Profile>, VortexError> {
    let raw_b64 = uri
        .strip_prefix("vpn://")
        .ok_or_else(|| VortexError::Parse("Expected vpn:// prefix".into()))?;
    let raw = decode_base64_flexible(raw_b64)?;
    if raw.len() < 5 {
        return Err(VortexError::Parse(
            "Amnezia payload too short (< 5 bytes)".into(),
        ));
    }

    let mut js = String::new();
    flate2::read::ZlibDecoder::new(&raw[4..])
        .read_to_string(&mut js)
        .map_err(|e| VortexError::Parse(format!("Failed to decompress Amnezia payload: {e}")))?;

    let v: Value = serde_json::from_str(&js)
        .map_err(|e| VortexError::Parse(format!("Invalid Amnezia JSON payload: {e}")))?;

    let desc = v["description"]
        .as_str()
        .filter(|s| !s.is_empty())
        .unwrap_or("amnezia")
        .to_string();
    let mut profiles = vec![];

    if let Some(containers) = v["containers"].as_array() {
        for c in containers {
            let cname = c["container"].as_str().unwrap_or("");
            let (key, kind) = if cname.contains("awg") {
                ("awg", Kind::Awg)
            } else if cname == "amnezia-wireguard" {
                ("wireguard", Kind::Wg)
            } else if cname == "amnezia-openvpn" {
                ("openvpn", Kind::Ovpn)
            } else {
                continue;
            };

            let lc = c[key]["last_config"].as_str().unwrap_or("");
            if lc.is_empty() {
                continue;
            }

            let cfg = serde_json::from_str::<Value>(lc)
                .ok()
                .and_then(|j| j["config"].as_str().map(String::from))
                .unwrap_or_else(|| lc.to_string());

            let name = format!("{desc} · {}", kind.tag());
            let prof = if kind == Kind::Ovpn {
                parse_openvpn_conf(&cfg, Some(&name))?
            } else {
                parse_wireguard_conf(&cfg, Some(&name))?
            };
            profiles.push(prof);
        }
    }

    if profiles.is_empty() {
        return Err(VortexError::Parse(
            "No supported VPN containers in Amnezia payload".into(),
        ));
    }

    Ok(profiles)
}

/// Decodes QR code image from file path using rqrr and image.
pub fn parse_qr_image(path: &Path) -> Result<Vec<Profile>, VortexError> {
    let img = image::open(path)
        .map_err(|e| VortexError::Parse(format!("Failed to open image {:?}: {e}", path)))?
        .to_luma8();

    let mut prepared = rqrr::PreparedImage::prepare(img);
    let grids = prepared.detect_grids();
    if grids.is_empty() {
        return Err(VortexError::Parse("No QR code detected in image".into()));
    }

    let mut content = String::new();
    for grid in grids {
        let mut bytes = Vec::new();
        if grid.decode_to(&mut bytes).is_ok() && !bytes.is_empty() {
            content = String::from_utf8_lossy(&bytes).to_string();
            break;
        }
    }

    if content.is_empty() {
        return Err(VortexError::Parse(
            "Failed to decode QR code payload from image".into(),
        ));
    }

    parse_any(&content)
}

/// Parses clipboard content (either text passed in or queried from system tools).
pub fn parse_clipboard(text: &str) -> Result<Vec<Profile>, VortexError> {
    let clean = text.trim();
    if clean.is_empty() {
        return Err(VortexError::Parse("Clipboard is empty".into()));
    }
    parse_any(clean)
}

/// General entry point that automatically detects and parses any input format.
pub fn parse_any(input: &str) -> Result<Vec<Profile>, VortexError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(VortexError::Parse("Input is empty".into()));
    }

    // 1. File path check
    let p = Path::new(trimmed);
    if p.exists() && p.is_file() {
        if let Some(ext) = p.extension().and_then(|x| x.to_str()) {
            match ext.to_ascii_lowercase().as_str() {
                "png" | "jpg" | "jpeg" | "webp" => return parse_qr_image(p),
                "conf" => {
                    let content = fs::read_to_string(p)?;
                    let stem = p.file_stem().and_then(|x| x.to_str());
                    return Ok(vec![parse_wireguard_conf(&content, stem)?]);
                }
                "ovpn" => {
                    let content = fs::read_to_string(p)?;
                    let stem = p.file_stem().and_then(|x| x.to_str());
                    return Ok(vec![parse_openvpn_conf(&content, stem)?]);
                }
                "json" => {
                    let content = fs::read_to_string(p)?;
                    if let Ok(profiles) = parse_xray_json(&content) {
                        return Ok(profiles);
                    }
                    return parse_singbox_json(&content);
                }
                _ => {}
            }
        }
    }

    // 2. URI Scheme checks
    if trimmed.starts_with("vless://") {
        return Ok(vec![parse_vless(trimmed)?]);
    }
    if trimmed.starts_with("vmess://") {
        return Ok(vec![parse_vmess(trimmed)?]);
    }
    if trimmed.starts_with("trojan://") {
        return Ok(vec![parse_trojan(trimmed)?]);
    }
    if trimmed.starts_with("ss://") {
        return Ok(vec![parse_shadowsocks(trimmed)?]);
    }
    if trimmed.starts_with("hy2://") || trimmed.starts_with("hysteria2://") {
        return Ok(vec![parse_hysteria2(trimmed)?]);
    }
    if trimmed.starts_with("tuic://") {
        return Ok(vec![parse_tuic(trimmed)?]);
    }
    if trimmed.starts_with("vpn://") {
        return parse_amnezia(trimmed);
    }

    // 3. Raw Config Checks
    if trimmed.contains("[Interface]") {
        return Ok(vec![parse_wireguard_conf(trimmed, None)?]);
    }
    if trimmed
        .lines()
        .any(|l| l.trim_start().starts_with("remote "))
    {
        return Ok(vec![parse_openvpn_conf(trimmed, None)?]);
    }
    if trimmed.starts_with('{') {
        if trimmed.contains("\"protocol\"")
            || trimmed.contains("\"streamSettings\"")
            || trimmed.contains("\"vnext\"")
        {
            if let Ok(profiles) = parse_xray_json(trimmed) {
                return Ok(profiles);
            }
        }
        if trimmed.contains("\"outbounds\"") {
            if let Ok(profiles) = parse_xray_json(trimmed) {
                return Ok(profiles);
            }
            return parse_singbox_json(trimmed);
        }
        if trimmed.contains("\"inbounds\"") {
            if let Ok(profiles) = parse_xray_json(trimmed) {
                return Ok(profiles);
            }
        }
    }

    // 4. Base64 multi-link list (e.g. subscription body)
    if let Ok(decoded) = decode_base64_flexible(trimmed) {
        if let Ok(text) = String::from_utf8(decoded) {
            let mut list = vec![];
            for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
                if let Ok(mut sub_profiles) = parse_any(line) {
                    list.append(&mut sub_profiles);
                }
            }
            if !list.is_empty() {
                return Ok(list);
            }
        }
    }

    // 5. Plain line-delimited links
    let mut list = vec![];
    for line in trimmed.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if let Ok(mut sub_profiles) = parse_any(line) {
            list.append(&mut sub_profiles);
        }
    }
    if !list.is_empty() {
        return Ok(list);
    }

    Err(VortexError::Parse(format!(
        "Unrecognized configuration format or link: '{}'",
        if trimmed.len() > 60 {
            &trimmed[..60]
        } else {
            trimmed
        }
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_vless_reality() {
        let uri = "vless://b6a03649-61f4-41aa-a51b-402c3cc6c547@203.0.113.7:443?security=reality&sni=example.com&pbk=1234567890abcdef1234567890abcdef1234567890a&type=grpc#Frankfurt%20Reality";
        let p = parse_vless(uri).unwrap();
        assert_eq!(p.kind, Kind::Vless);
        assert_eq!(p.server, "203.0.113.7:443");
        assert_eq!(p.name, "Frankfurt Reality");
        assert_eq!(p.transport, Transport::Grpc);
        assert_eq!(p.security, Security::Reality);
        assert_eq!(p.display_transport(), "TCP+gRPC");
        assert_eq!(p.sni.as_deref(), Some("example.com"));
        assert_eq!(p.port, Some(443));
    }

    #[test]
    fn test_parse_vless_reality_tcp() {
        let uri = "vless://b6a03649-61f4-41aa-a51b-402c3cc6c547@203.0.113.7:443?security=reality&sni=example.com&pbk=1234567890abcdef1234567890abcdef1234567890a&type=tcp#Frankfurt%20Reality%20TCP";
        let p = parse_vless(uri).unwrap();
        assert_eq!(p.kind, Kind::Vless);
        assert_eq!(p.transport, Transport::Tcp);
        assert_eq!(p.security, Security::Reality);
        assert_eq!(p.display_transport(), "TCP+Reality");
        assert_eq!(p.sni.as_deref(), Some("example.com"));
        assert_eq!(p.port, Some(443));
    }

    #[test]
    fn test_parse_vless_ws() {
        let uri = "vless://b6a03649-61f4-41aa-a51b-402c3cc6c547@cdn.example.com:443?type=ws&security=tls&sni=cdn.example.com#VlessWS";
        let p = parse_vless(uri).unwrap();
        assert_eq!(p.kind, Kind::Vless);
        assert_eq!(p.transport, Transport::Ws);
        assert_eq!(p.security, Security::Tls);
        assert_eq!(p.display_transport(), "TCP+WS");
        assert_eq!(p.sni.as_deref(), Some("cdn.example.com"));
    }

    #[test]
    fn test_parse_vmess_fixture() {
        let vmess_json = r#"{"v":"2","ps":"Tokyo VMess","add":"198.51.100.20","port":443,"id":"a1b2c3d4-e5f6-7890-abcd-ef1234567890","aid":0,"net":"ws","type":"none","host":"cdn.example.com","path":"/vmess","tls":"tls"}"#;
        let b64 = b64_engine::STANDARD.encode(vmess_json);
        let link = format!("vmess://{b64}");
        let p = parse_vmess(&link).unwrap();
        assert_eq!(p.kind, Kind::Vmess);
        assert_eq!(p.name, "Tokyo VMess");
        assert_eq!(p.server, "198.51.100.20:443");
        assert_eq!(p.transport, Transport::Ws);
        assert_eq!(p.security, Security::Tls);
        assert_eq!(p.display_transport(), "TCP+WS");
        assert_eq!(p.port, Some(443));
    }

    #[test]
    fn test_parse_trojan_fixture() {
        let link =
            "trojan://secret_password_123@trojan.node.net:443?sni=trojan.node.net#London%20Trojan";
        let p = parse_trojan(link).unwrap();
        assert_eq!(p.kind, Kind::Trojan);
        assert_eq!(p.name, "London Trojan");
        assert_eq!(p.server, "trojan.node.net:443");
        assert_eq!(p.transport, Transport::Tcp);
        assert_eq!(p.security, Security::Tls);
        assert_eq!(p.display_transport(), "TCP");
        assert_eq!(p.port, Some(443));
    }

    #[test]
    fn test_parse_shadowsocks_sip002() {
        // chacha20-ietf-poly1305:mypassword
        let b64 = b64_engine::STANDARD.encode("chacha20-ietf-poly1305:mypassword");
        let link = format!("ss://{b64}@198.51.100.30:8388#Singapore%20SS");
        let p = parse_shadowsocks(&link).unwrap();
        assert_eq!(p.kind, Kind::Ss);
        assert_eq!(p.name, "Singapore SS");
        assert_eq!(p.server, "198.51.100.30:8388");
        assert_eq!(p.transport, Transport::Tcp);
        assert_eq!(p.display_transport(), "TCP");
        assert_eq!(p.port, Some(8388));
    }

    #[test]
    fn test_parse_shadowsocks_udp_flag() {
        let b64 = b64_engine::STANDARD.encode("aes-128-gcm:mypassword");
        let link = format!("ss://{b64}@198.51.100.30:8388?udp=1#Singapore%20UDP");
        let p = parse_shadowsocks(&link).unwrap();
        assert_eq!(p.kind, Kind::Ss);
        assert_eq!(p.transport, Transport::Udp);
        assert_eq!(p.display_transport(), "UDP");
    }

    #[test]
    fn test_parse_hysteria2_fixture() {
        let link = "hy2://auth_token@hy2.example.com:8443?sni=hy2.example.com#Hysteria2%20Fast";
        let p = parse_hysteria2(link).unwrap();
        assert_eq!(p.kind, Kind::Hy2);
        assert_eq!(p.name, "Hysteria2 Fast");
        assert_eq!(p.server, "hy2.example.com:8443");
        assert_eq!(p.transport, Transport::Quic);
        assert_eq!(p.display_transport(), "UDP/QUIC");
        assert_eq!(p.security, Security::Tls);
        assert_eq!(p.port, Some(8443));
    }

    #[test]
    fn test_parse_hysteria2_salamander_obfs() {
        let link = "hy2://auth_token@hy2.example.com:8443?obfs=salamander&obfs-password=supersecretpassword123#SalamanderNode";
        let p = parse_hysteria2(link).unwrap();
        assert_eq!(p.kind, Kind::Hy2);
        assert_eq!(p.transport, Transport::Quic);
        assert_eq!(p.display_transport(), "UDP/QUIC");
        assert_eq!(p.obfs.as_deref(), Some("salamander"));
        // Ensure secret password is never leaked into obfs
        assert_ne!(p.obfs.as_deref(), Some("supersecretpassword123"));
    }

    #[test]
    fn test_parse_wireguard_fixture() {
        let conf = "[Interface]\nPrivateKey = aW52YWxpZA==\nAddress = 10.0.0.2/24\n[Peer]\nEndpoint = 192.0.2.1:51820\nPublicKey = cHVibGlj\n";
        let p = parse_wireguard_conf(conf, Some("Home WG")).unwrap();
        assert_eq!(p.kind, Kind::Wg);
        assert_eq!(p.name, "Home WG");
        assert_eq!(p.server, "192.0.2.1:51820");
        assert_eq!(p.transport, Transport::Udp);
        assert_eq!(p.display_transport(), "UDP");
        assert_eq!(p.security, Security::None);
        assert_eq!(p.port, Some(51820));
    }

    #[test]
    fn test_parse_openvpn_fixture() {
        let conf = "client\ndev tun\nremote 192.0.2.2 1194\nproto udp\n";
        let p = parse_openvpn_conf(conf, Some("Office OVPN")).unwrap();
        assert_eq!(p.kind, Kind::Ovpn);
        assert_eq!(p.name, "Office OVPN");
        assert_eq!(p.server, "192.0.2.2:1194");
        assert_eq!(p.transport, Transport::Udp);
        assert_eq!(p.display_transport(), "UDP");
        assert_eq!(p.port, Some(1194));

        let conf_tcp = "client\ndev tun\nremote 192.0.2.2 443\nproto tcp\n";
        let p_tcp = parse_openvpn_conf(conf_tcp, Some("Office OVPN TCP")).unwrap();
        assert_eq!(p_tcp.transport, Transport::Tcp);
        assert_eq!(p_tcp.display_transport(), "TCP");
        assert_eq!(p_tcp.port, Some(443));

        let conf_none = "client\ndev tun\nremote 192.0.2.2 1194\n";
        let p_none = parse_openvpn_conf(conf_none, Some("Office OVPN NoProto")).unwrap();
        assert_eq!(p_none.transport, Transport::Unknown);
        assert_eq!(p_none.display_transport(), "--");
    }

    #[test]
    fn test_parse_singbox_json_fixture() {
        let json_text = r#"{
            "outbounds": [
                {
                    "type": "vless",
                    "tag": "singbox-vless",
                    "server": "singbox.example.com",
                    "server_port": 443,
                    "uuid": "b6a03649-61f4-41aa-a51b-402c3cc6c547"
                }
            ]
        }"#;
        let profs = parse_singbox_json(json_text).unwrap();
        assert_eq!(profs.len(), 1);
        assert_eq!(profs[0].name, "singbox-vless");
        assert_eq!(profs[0].kind, Kind::Vless);
        assert_eq!(profs[0].server, "singbox.example.com:443");
        assert_eq!(profs[0].transport, Transport::Tcp);
        assert_eq!(profs[0].display_transport(), "TCP");
        assert_eq!(profs[0].port, Some(443));
    }
}

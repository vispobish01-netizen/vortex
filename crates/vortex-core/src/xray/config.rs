use crate::model::{Kind, Profile, ProfilePayloadKind, Security, Transport};
use crate::routing::RulesConfig;
use crate::shield::{parse_endpoint, resolve_server_ips};
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::net::IpAddr;
use std::path::Path;
use std::process::Command;

pub const DEFAULT_XRAY_TUN_IFACE: &str = "vx0";
pub const DEFAULT_XRAY_PROXY_PORT: u16 = 1080;

/// Extracts server host/IP strings embedded in an Xray JSON config or outbound.
pub fn extract_xray_outbound_hosts(val: &Value) -> Vec<String> {
    let mut hosts = Vec::new();
    let mut collect_ob = |ob: &Value| {
        let proto = ob
            .get("protocol")
            .and_then(|p| p.as_str())
            .unwrap_or_default();
        if matches!(proto, "freedom" | "blackhole" | "dns" | "loopback") {
            return;
        }
        if let Some(addr) = ob["settings"]["vnext"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|v| v["address"].as_str())
            .or_else(|| {
                ob["settings"]["servers"]
                    .as_array()
                    .and_then(|a| a.first())
                    .and_then(|s| s["address"].as_str())
            })
            .or_else(|| ob["settings"]["address"].as_str())
        {
            let trimmed = addr.trim();
            if !trimmed.is_empty() && !hosts.iter().any(|h| h == trimmed) {
                hosts.push(trimmed.to_string());
            }
        }
    };

    if let Some(arr) = val.get("outbounds").and_then(|o| o.as_array()) {
        for ob in arr {
            collect_ob(ob);
        }
    } else {
        collect_ob(val);
    }
    hosts
}

fn extract_primary_xray_outbound(val: &Value) -> Option<Value> {
    if let Some(arr) = val.get("outbounds").and_then(|a| a.as_array()) {
        let chosen = arr
            .iter()
            .find(|ob| {
                let proto = ob
                    .get("protocol")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                !proto.is_empty() && !matches!(proto, "freedom" | "blackhole" | "dns" | "loopback")
            })
            .or_else(|| arr.first())
            .cloned();
        return chosen;
    }
    if val.get("protocol").is_some() || val.get("type").is_some() {
        return Some(val.clone());
    }
    None
}

/// Generates valid Xray outbound settings for a Profile
pub fn generate_xray_outbound(p: &Profile) -> Result<Value> {
    let trimmed_data = p.data.trim();
    // Preserve custom Xray outbound / config JSON losslessly when present
    if trimmed_data.starts_with('{') {
        if let Ok(val) = serde_json::from_str::<Value>(trimmed_data) {
            if let Some(mut ob) = extract_primary_xray_outbound(&val) {
                ob["tag"] = json!("proxy");
                return Ok(ob);
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
            let encryption = extract_query_param(&p.data, "encryption")
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "none".to_string());
            let allow_vision = matches!(p.transport, Transport::Tcp | Transport::Unknown)
                && matches!(
                    p.security,
                    Security::Tls | Security::Reality | Security::Unknown
                )
                && encryption == "none";
            let flow = if !allow_vision {
                String::new()
            } else {
                p.flow.clone().unwrap_or_else(|| {
                    if p.data.contains("xtls-rprx-vision") {
                        "xtls-rprx-vision".to_string()
                    } else {
                        String::new()
                    }
                })
            };

            json!({
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": host,
                        "port": port,
                        "users": [{
                            "id": uuid,
                            "encryption": encryption,
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
            bail!("Hysteria2 is handled by sing-box or native hysteria2, not Xray-core");
        }
        Kind::Xray => {
            if let Ok(mut val) = serde_json::from_str::<Value>(&p.data) {
                if val.get("tag").is_none() {
                    val["tag"] = json!("proxy");
                }
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
        Transport::Xdrive => "xdrive",
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
            let mode = extract_query_param(&p.data, "mode").unwrap_or_else(|| "auto".to_string());
            let mut xhttp_settings = json!({
                "mode": mode
            });
            let path = extract_query_param(&p.data, "path").unwrap_or_else(|| "/".to_string());
            xhttp_settings["path"] = json!(path);
            if let Some(host) = extract_query_param(&p.data, "host").or_else(|| p.sni.clone()) {
                xhttp_settings["host"] = json!(host);
            }
            if let Some(extra) = extract_query_param(&p.data, "extra") {
                if let Ok(extra_val) = serde_json::from_str::<Value>(&extra) {
                    xhttp_settings["extra"] = extra_val;
                }
            }
            stream["xhttpSettings"] = xhttp_settings;
        }
        Transport::Xdrive => {
            if let Some(extra) = extract_query_param(&p.data, "extra") {
                if let Ok(extra_val) = serde_json::from_str::<Value>(&extra) {
                    stream["xdriveSettings"] = extra_val;
                }
            }
        }
        Transport::HttpUpgrade => {
            let path = extract_query_param(&p.data, "path").unwrap_or_else(|| "/".to_string());
            let host = extract_query_param(&p.data, "host").or_else(|| p.sni.clone());
            let mut hu = json!({ "path": path });
            if let Some(h) = host {
                hu["host"] = json!(h);
            }
            stream["httpupgradeSettings"] = hu;
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
            .or_else(|| extract_query_param(&p.data, "password"))
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
        if let Some(pqv) = extract_query_param(&p.data, "pqv") {
            if !pqv.trim().is_empty() {
                reality_settings["mldsa65Verify"] = json!(pqv);
            }
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

fn resolve_profile_server_ip_strings(profile: &Profile) -> Vec<String> {
    fn push_host_ips(host: &str, port: u16, ips_out: &mut Vec<String>) {
        let trimmed = host.trim();
        if trimmed.is_empty() || trimmed == "custom" {
            return;
        }
        for ip in resolve_server_ips(trimmed, port) {
            let s = ip.to_string();
            if !ips_out.contains(&s) {
                ips_out.push(s);
            }
        }
        if let Ok(ip) = trimmed.parse::<IpAddr>() {
            let s = ip.to_string();
            if !ips_out.contains(&s) {
                ips_out.push(s);
            }
        }
    }

    let mut ips_out = Vec::new();
    let (host, port_opt) = parse_endpoint(&profile.server);
    let port = profile.port.or(port_opt).unwrap_or(443);
    push_host_ips(&host, port, &mut ips_out);

    if ips_out.is_empty() && profile.data.trim().starts_with('{') {
        if let Ok(val) = serde_json::from_str::<Value>(profile.data.trim()) {
            for h in extract_xray_outbound_hosts(&val) {
                push_host_ips(&h, port, &mut ips_out);
            }
        }
    }

    ips_out
}

fn build_xray_log_config(log_path: Option<&Path>) -> Value {
    let log_level = "warning";
    if let Some(lp) = log_path {
        json!({
            "access": "",
            "error": lp.to_string_lossy(),
            "loglevel": log_level
        })
    } else {
        json!({
            "loglevel": log_level
        })
    }
}

fn has_dialer_proxy(ob: &Value) -> bool {
    ob.get("streamSettings")
        .and_then(|s| s.get("sockopt"))
        .and_then(|so| so.get("dialerProxy"))
        .and_then(|dp| dp.as_str())
        .is_some_and(|s| !s.trim().is_empty())
}

fn apply_sockopt_interface(outbounds: &mut [Value], egress_iface: Option<&str>) {
    let Some(iface) = egress_iface.map(str::trim).filter(|s| !s.is_empty()) else {
        return;
    };
    for ob in outbounds {
        let proto = ob
            .get("protocol")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if matches!(proto, "blackhole" | "dns" | "api" | "loopback") || has_dialer_proxy(ob) {
            continue;
        }
        let Some(ob_obj) = ob.as_object_mut() else {
            continue;
        };
        let stream = ob_obj
            .entry("streamSettings")
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
        if !stream.is_object() {
            *stream = Value::Object(serde_json::Map::new());
        }
        let sockopt = stream
            .as_object_mut()
            .unwrap()
            .entry("sockopt")
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
        if !sockopt.is_object() {
            *sockopt = Value::Object(serde_json::Map::new());
        }
        let sockopt_map = sockopt.as_object_mut().unwrap();
        if !sockopt_map.contains_key("interface") {
            sockopt_map.insert("interface".to_string(), json!(iface));
        }
    }
}

fn patch_custom_xray_config(
    mut cfg: Value,
    inbounds: Vec<Value>,
    log_path: Option<&Path>,
    egress_iface: Option<&str>,
) -> Result<Value> {
    let obj = cfg
        .as_object_mut()
        .context("Custom Xray configuration must be a JSON object")?;

    // Preserve existing log fields while directing errors to Vortex log_path if provided
    let log_val = obj
        .entry("log")
        .or_insert_with(|| Value::Object(serde_json::Map::new()));
    if !log_val.is_object() {
        *log_val = build_xray_log_config(log_path);
    } else if let Some(log_obj) = log_val.as_object_mut() {
        log_obj
            .entry("loglevel")
            .or_insert_with(|| json!("warning"));
        if let Some(lp) = log_path {
            log_obj.insert("error".to_string(), json!(lp.to_string_lossy()));
        }
    }

    obj.entry("stats").or_insert_with(|| json!({}));

    let api_val = obj
        .entry("api")
        .or_insert_with(|| json!({"tag": "api", "services": ["StatsService"]}));
    let api_tag = api_val
        .get("tag")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("api")
        .to_string();
    if let Some(api_obj) = api_val.as_object_mut() {
        api_obj.entry("tag").or_insert_with(|| json!(api_tag));
        let services = api_obj
            .entry("services")
            .or_insert_with(|| json!(["StatsService"]));
        if let Some(arr) = services.as_array_mut() {
            if !arr.iter().any(|s| s.as_str() == Some("StatsService")) {
                arr.push(json!("StatsService"));
            }
        }
    }

    let policy_val = obj
        .entry("policy")
        .or_insert_with(|| Value::Object(serde_json::Map::new()));
    if let Some(policy_obj) = policy_val.as_object_mut() {
        let sys = policy_obj
            .entry("system")
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
        if let Some(sys_obj) = sys.as_object_mut() {
            for flag in [
                "statsInboundUplink",
                "statsInboundDownlink",
                "statsOutboundUplink",
                "statsOutboundDownlink",
            ] {
                sys_obj.entry(flag).or_insert_with(|| json!(true));
            }
        }
    }

    obj.insert("inbounds".to_string(), Value::Array(inbounds));

    if let Some(outbounds) = obj.get_mut("outbounds").and_then(|o| o.as_array_mut()) {
        apply_sockopt_interface(outbounds, egress_iface);
    }

    let routing = obj
        .entry("routing")
        .or_insert_with(|| json!({"domainStrategy": "AsIs", "rules": []}));
    if let Some(routing_obj) = routing.as_object_mut() {
        routing_obj
            .entry("domainStrategy")
            .or_insert_with(|| json!("AsIs"));
        let rules = routing_obj.entry("rules").or_insert_with(|| json!([]));
        if let Some(arr) = rules.as_array_mut() {
            let has_api_in = arr.iter().any(|r| {
                r.get("inboundTag")
                    .and_then(|v| v.as_array())
                    .is_some_and(|tags| tags.iter().any(|t| t.as_str() == Some("api-in")))
            });
            if !has_api_in {
                arr.insert(
                    0,
                    json!({
                        "type": "field",
                        "inboundTag": ["api-in"],
                        "outboundTag": api_tag
                    }),
                );
            }
        }
    }

    Ok(cfg)
}

fn build_xray_routing_rules(server_ip_strings: &[String], include_user_rules: bool) -> Vec<Value> {
    let mut routing_rules = Vec::new();
    let has_geo_assets = crate::xray::install::geo_assets_dir().is_some();

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

    if include_user_rules {
        let rules_cfg = RulesConfig::load();

        // 3. DNS server exemption
        routing_rules.push(json!({
            "type": "field",
            "ip": ["1.1.1.1", "8.8.8.8"],
            "port": "53,853",
            "outboundTag": "direct"
        }));

        // 4. LAN bypass
        if rules_cfg.presets.bypass_lan {
            let lan_ips = if has_geo_assets {
                vec!["geoip:private"]
            } else {
                vec![
                    "127.0.0.0/8",
                    "10.0.0.0/8",
                    "172.16.0.0/12",
                    "192.168.0.0/16",
                    "fc00::/7",
                    "::1/128",
                ]
            };
            routing_rules.push(json!({
                "type": "field",
                "ip": lan_ips,
                "outboundTag": "direct"
            }));
        }

        // 5. Block ads preset
        if rules_cfg.presets.block_ads && has_geo_assets {
            routing_rules.push(json!({
                "type": "field",
                "domain": ["geosite:category-ads-all"],
                "outboundTag": "block"
            }));
        }

        // 6. Direct domestic preset
        if rules_cfg.presets.direct_domestic && has_geo_assets {
            routing_rules.push(json!({
                "type": "field",
                "ip": ["geoip:cn", "geoip:ir"],
                "outboundTag": "direct"
            }));
        }

        // 7. Custom User Rules from RulesConfig
        for r in &rules_cfg.custom_rules {
            if !r.enabled {
                continue;
            }
            let tag = match r.action {
                crate::routing::RuleAction::Direct => "direct",
                crate::routing::RuleAction::Block => "block",
                crate::routing::RuleAction::Proxy | crate::routing::RuleAction::ProxyGroup => {
                    "proxy"
                }
            };
            let mut domains = Vec::new();
            for d in &r.domains {
                match d {
                    crate::routing::DomainMatcher::Exact(e) => domains.push(format!("full:{e}")),
                    crate::routing::DomainMatcher::Suffix(s) => domains.push(format!("domain:{s}")),
                    crate::routing::DomainMatcher::Keyword(k) => {
                        domains.push(format!("keyword:{k}"))
                    }
                    crate::routing::DomainMatcher::Regex(rx) => {
                        domains.push(format!("regexp:{rx}"))
                    }
                }
            }
            if has_geo_assets {
                for gs in &r.geosite {
                    domains.push(format!("geosite:{gs}"));
                }
            }
            let mut ips = r.ip_cidrs.clone();
            if has_geo_assets {
                for gi in &r.geoip {
                    ips.push(format!("geoip:{gi}"));
                }
            }

            let mut rule_obj = serde_json::Map::new();
            rule_obj.insert("type".into(), json!("field"));
            rule_obj.insert("outboundTag".into(), json!(tag));
            if !domains.is_empty() {
                rule_obj.insert("domain".into(), json!(domains));
            }
            if !ips.is_empty() {
                rule_obj.insert("ip".into(), json!(ips));
            }
            if !r.ports.is_empty() {
                rule_obj.insert("port".into(), json!(r.ports.join(",")));
            }
            if !r.protocols.is_empty() {
                rule_obj.insert("network".into(), json!(r.protocols.join(",")));
            }
            if !domains.is_empty()
                || !ips.is_empty()
                || !r.ports.is_empty()
                || !r.protocols.is_empty()
            {
                routing_rules.push(Value::Object(rule_obj));
            }
        }
    }

    // Default proxy rule
    routing_rules.push(json!({
        "type": "field",
        "network": "tcp,udp",
        "outboundTag": "proxy"
    }));

    routing_rules
}

/// Generates a local Xray SOCKS5 bridge sidecar config for Throne-style execution behind sing-box.
/// For `CustomConfig` profiles, preserves all outbounds/routing/balancers/fragment/dialerProxy
/// losslessly while binding local `vortex-bridge-in` and `api-in` inbounds.
pub fn generate_xray_bridge_config(
    profile: &Profile,
    socks_port: u16,
    api_port: u16,
    log_path: Option<&Path>,
    egress_iface: Option<&str>,
) -> Result<Value> {
    let inbounds = vec![
        json!({
            "tag": "vortex-bridge-in",
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": {
                "udp": true
            },
            "sniffing": {
                "enabled": false
            }
        }),
        json!({
            "tag": "api-in",
            "listen": "127.0.0.1",
            "port": api_port,
            "protocol": "dokodemo-door",
            "settings": {
                "address": "127.0.0.1"
            }
        }),
    ];

    if profile.payload_kind == ProfilePayloadKind::CustomConfig {
        let cfg: Value = serde_json::from_str(profile.data.trim())
            .context("Failed to parse custom Xray JSON config")?;
        return patch_custom_xray_config(cfg, inbounds, log_path, egress_iface);
    }

    let outbound = generate_xray_outbound(profile)?;
    let server_ip_strings = resolve_profile_server_ip_strings(profile);
    let routing_rules = build_xray_routing_rules(&server_ip_strings, false);
    let mut outbounds = vec![
        outbound,
        json!({
            "tag": "direct",
            "protocol": "freedom",
            "settings": {
                "domainStrategy": "UseIP"
            }
        }),
        json!({
            "tag": "block",
            "protocol": "blackhole"
        }),
    ];
    apply_sockopt_interface(&mut outbounds, egress_iface);

    Ok(json!({
        "log": build_xray_log_config(log_path),
        "stats": {},
        "api": {
            "tag": "api",
            "services": ["StatsService"]
        },
        "policy": {
            "system": {
                "statsInboundUplink": true,
                "statsInboundDownlink": true,
                "statsOutboundUplink": true,
                "statsOutboundDownlink": true
            }
        },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {
            "domainStrategy": "AsIs",
            "rules": routing_rules
        }
    }))
}

/// Generates a complete standalone Xray JSON configuration (TUN fallback / Proxy-only)
pub fn generate_xray_config(
    profile: &Profile,
    tun_interface: &str,
    mixed_proxy_port: u16,
    api_port: u16,
    log_path: Option<&Path>,
    is_proxy_only: bool,
) -> Result<Value> {
    let mut inbounds = Vec::new();
    if !is_proxy_only {
        inbounds.push(json!({
            "tag": "tun-in",
            "protocol": "tun",
            "settings": {
                "name": tun_interface,
                "mtu": 1500,
                "gateway": ["172.28.0.1/30"],
                "autoSystemRoutingTable": ["0.0.0.0/0"],
                "autoOutboundsInterface": "auto"
            },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls", "quic", "fakedns"]
            }
        }));
    }
    inbounds.push(json!({
        "tag": "socks-in",
        "listen": "127.0.0.1",
        "port": mixed_proxy_port,
        "protocol": "socks",
        "settings": {
            "udp": true
        }
    }));
    inbounds.push(json!({
        "tag": "http-in",
        "listen": "127.0.0.1",
        "port": mixed_proxy_port + 1,
        "protocol": "http"
    }));
    inbounds.push(json!({
        "tag": "api-in",
        "listen": "127.0.0.1",
        "port": api_port,
        "protocol": "dokodemo-door",
        "settings": {
            "address": "127.0.0.1"
        }
    }));

    if profile.payload_kind == ProfilePayloadKind::CustomConfig {
        let cfg: Value = serde_json::from_str(profile.data.trim())
            .context("Failed to parse custom Xray JSON config")?;
        return patch_custom_xray_config(cfg, inbounds, log_path, None);
    }

    let outbound = generate_xray_outbound(profile)?;
    let server_ip_strings = resolve_profile_server_ip_strings(profile);
    let routing_rules = build_xray_routing_rules(&server_ip_strings, true);

    let has_geo_assets = crate::xray::install::geo_assets_dir().is_some();
    let dns_config = if has_geo_assets {
        json!({
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
        })
    } else {
        json!({
            "servers": ["1.1.1.1", "8.8.8.8", "localhost"],
            "queryStrategy": "UseIPv4"
        })
    };

    let config = json!({
        "log": build_xray_log_config(log_path),
        "stats": {},
        "api": {
            "tag": "api",
            "services": ["StatsService"]
        },
        "policy": {
            "system": {
                "statsInboundUplink": true,
                "statsInboundDownlink": true,
                "statsOutboundUplink": true,
                "statsOutboundDownlink": true
            }
        },
        "dns": dns_config,
        "inbounds": inbounds,
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
    let geo_dir = crate::xray::install::geo_assets_dir();
    let run_test = |args: [&str; 4]| {
        let mut cmd = Command::new(xray_bin);
        cmd.args(args);
        if let Some(ref dir) = geo_dir {
            cmd.env("XRAY_LOCATION_ASSET", dir);
        }
        cmd.output()
    };

    let cfg_str = config_path.to_string_lossy().to_string();
    let out = run_test(["run", "-test", "-config", &cfg_str])
        .or_else(|_| {
            // Fallback syntax for older versions: `xray -test -config <path>`
            let mut cmd = Command::new(xray_bin);
            cmd.args(["-test", "-config", &cfg_str]);
            if let Some(ref dir) = geo_dir {
                cmd.env("XRAY_LOCATION_ASSET", dir);
            }
            cmd.output()
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

        let cfg = generate_xray_config(&p, "vx0", 1080, 54321, None, false).unwrap();

        assert_eq!(cfg["log"]["loglevel"], "warning");
        assert!(cfg["stats"].is_object());
        assert_eq!(cfg["api"]["services"], json!(["StatsService"]));

        let inbounds = cfg["inbounds"].as_array().unwrap();
        assert!(inbounds.iter().any(|i| i["tag"] == "tun-in"));
        assert!(inbounds.iter().any(|i| i["tag"] == "socks-in"));
        assert!(inbounds.iter().any(|i| i["tag"] == "api-in"));

        // Test proxy mode generation
        let proxy_cfg = generate_xray_config(&p, "vx0", 1080, 54321, None, true).unwrap();
        let proxy_inbounds = proxy_cfg["inbounds"].as_array().unwrap();
        assert!(!proxy_inbounds.iter().any(|i| i["tag"] == "tun-in"));
        assert!(proxy_inbounds.iter().any(|i| i["tag"] == "socks-in"));

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

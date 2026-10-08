use sha2::{Digest, Sha256, Sha512};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use vortex_core::model::{Kind, Security, Transport};
use vortex_core::parser::{parse_any, parse_vless, parse_vmess, parse_xray_json};
use vortex_core::xray::config::{generate_xray_config, validate_xray_config_file};
use vortex_core::xray::install::{
    fetch_latest_release_info, get_binary_version, parse_dgst, verify_checksum,
};

// ───────────────────────── 1. Link Parsing Tests ─────────────────────────

#[test]
fn test_vless_reality_xhttp_and_quantum_parsing() {
    let link = "vless://a1b2c3d4-e5f6-7890-abcd-ef0123456789@vpn.example.org:8443?type=xhttp&security=reality&sni=cdn.example.org&fp=chrome&pbk=Z1Y2X3W4V5U6T7S8R9Q0P1O2N3M4L5K6J7I8H9G0F1E=&sid=0123456789abcdef&spx=%2Ftest%2Fpath&flow=xtls-rprx-vision&ech=AEX1928374&pq=mlkem768x25519plus#%F0%9F%9A%80%20Elite%20XHTTP%20Reality";
    let p = parse_vless(link).expect("Valid VLESS reality link should parse");

    assert_eq!(p.kind, Kind::Vless);
    assert_eq!(p.server, "vpn.example.org:8443");
    assert_eq!(p.name, "🚀 Elite XHTTP Reality");
    assert_eq!(p.transport, Transport::Xhttp);
    assert_eq!(p.security, Security::Reality);
    assert_eq!(p.sni.as_deref(), Some("cdn.example.org"));
    assert_eq!(p.fingerprint.as_deref(), Some("chrome"));
    assert_eq!(
        p.reality_public_key.as_deref(),
        Some("Z1Y2X3W4V5U6T7S8R9Q0P1O2N3M4L5K6J7I8H9G0F1E=")
    );
    assert_eq!(p.reality_short_id.as_deref(), Some("0123456789abcdef"));
    assert_eq!(p.reality_spider_x.as_deref(), Some("/test/path"));
    assert_eq!(p.flow.as_deref(), Some("xtls-rprx-vision"));
    assert_eq!(p.ech.as_deref(), Some("AEX1928374"));
    assert_eq!(p.post_quantum.as_deref(), Some("mlkem768x25519plus"));
}

#[test]
fn test_malformed_and_odd_encoding_links() {
    // Missing credentials
    assert!(parse_vless("vless://@example.com:443?type=tcp").is_err());

    // Bad scheme
    assert!(parse_vless("https://example.com:443").is_err());

    // Odd percent encoding in fragment and query params
    let odd_link = "vless://uuid-1234@server.com:443?sni=%74%65%73%74%2E%63%6F%6D&security=tls#%D8%AA%D8%B3%D8%AA%20%D8%B3%D8%B1%D9%88%D8%B1";
    let p =
        parse_vless(odd_link).expect("Should handle percent encoded params and unicode fragment");
    assert_eq!(p.name, "تست سرور");

    // VMess invalid base64 padding
    assert!(parse_vmess("vmess://!!!broken_base64!!!").is_err());

    // Empty payload
    assert!(parse_any("   ").is_err());
}

#[test]
fn test_raw_xray_json_parsing() {
    let raw_json = r#"{
        "outbounds": [
            {
                "tag": "my-xray-outbound",
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": "198.51.100.1",
                        "port": 443,
                        "users": [{"id": "uuid-0000"}]
                    }]
                },
                "streamSettings": {
                    "network": "ws",
                    "security": "tls"
                }
            }
        ]
    }"#;

    let profiles = parse_xray_json(raw_json).expect("Xray JSON outbounds should parse");
    assert_eq!(profiles.len(), 1);
    let p = &profiles[0];
    assert_eq!(p.name, "my-xray-outbound");
    assert_eq!(p.kind, Kind::Vless);
    assert_eq!(p.server, "198.51.100.1:443");
    assert_eq!(p.backend_type.as_deref(), Some("xray"));
    assert_eq!(p.transport, Transport::Ws);
    assert_eq!(p.security, Security::Tls);
}

#[test]
fn test_classic_shadowsocks_outbound_generation() {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use vortex_core::xray::config::generate_xray_outbound;

    // Classic format: ss://base64(method:password@host:port)#tag
    let encoded = STANDARD.encode("aes-256-gcm:supersecret@vpn.shadow.org:8388");
    let link = format!("ss://{encoded}#ShadowNode");
    let p = vortex_core::parser::parse_shadowsocks(&link).unwrap();
    let ob = generate_xray_outbound(&p).unwrap();

    assert_eq!(ob["protocol"], "shadowsocks");
    let servers = ob["settings"]["servers"].as_array().unwrap();
    assert_eq!(servers[0]["address"], "vpn.shadow.org");
    assert_eq!(servers[0]["port"], 8388);
    assert_eq!(servers[0]["method"], "aes-256-gcm");
    assert_eq!(servers[0]["password"], "supersecret");
}

// ───────────────────────── 2. Config Snapshot Test ─────────────────────────

#[test]
fn test_xray_config_generation_full_snapshot() {
    let link = "vless://00000000-1111-2222-3333-444444444444@gateway.internal:443?type=xhttp&security=reality&sni=dl.google.com&pbk=AAAA&sid=1234&flow=xtls-rprx-vision#Node1";
    let p = parse_vless(link).unwrap();

    let cfg = generate_xray_config(&p, "vx0", 1080, 49152, None)
        .expect("Config generation should succeed");

    // Validate top-level keys
    assert_eq!(cfg["log"]["loglevel"], "warning");
    assert!(cfg["stats"].is_object());
    assert_eq!(cfg["api"]["tag"], "api");
    assert_eq!(cfg["api"]["services"], serde_json::json!(["StatsService"]));

    // Validate inbounds
    let inbounds = cfg["inbounds"]
        .as_array()
        .expect("Inbounds must be an array");
    let tun_in = inbounds
        .iter()
        .find(|i| i["tag"] == "tun-in")
        .expect("Must contain tun-in");
    assert_eq!(tun_in["protocol"], "tun");
    assert_eq!(tun_in["settings"]["name"], "vx0");

    let socks_in = inbounds
        .iter()
        .find(|i| i["tag"] == "socks-in")
        .expect("Must contain socks-in");
    assert_eq!(socks_in["port"], 1080);

    let api_in = inbounds
        .iter()
        .find(|i| i["tag"] == "api-in")
        .expect("Must contain api-in");
    assert_eq!(api_in["port"], 49152);

    // Validate outbounds
    let outbounds = cfg["outbounds"]
        .as_array()
        .expect("Outbounds must be an array");
    let proxy_ob = outbounds
        .iter()
        .find(|o| o["tag"] == "proxy")
        .expect("Must contain proxy outbound");
    assert_eq!(proxy_ob["protocol"], "vless");
    assert_eq!(proxy_ob["streamSettings"]["network"], "xhttp");
    assert_eq!(proxy_ob["streamSettings"]["security"], "reality");
    assert_eq!(
        proxy_ob["settings"]["vnext"][0]["users"][0]["flow"],
        "xtls-rprx-vision"
    );

    assert!(outbounds.iter().any(|o| o["tag"] == "direct"));
    assert!(outbounds.iter().any(|o| o["tag"] == "block"));

    // Validate routing rules
    let rules = cfg["routing"]["rules"]
        .as_array()
        .expect("Routing rules must be an array");
    assert!(rules
        .iter()
        .any(|r| r["outboundTag"] == "api" && r["inboundTag"] == serde_json::json!(["api-in"])));
    assert!(rules.iter().any(|r| r["outboundTag"] == "proxy"));
}

// ───────────────────────── 3. Checksum Verification Tests ─────────────────────────

#[test]
fn test_dgst_and_checksum_verification() {
    let zip_content = b"PK\x03\x04test_zip_payload_with_random_data_123456789";

    let mut sha256_hasher = Sha256::new();
    sha256_hasher.update(zip_content);
    let sha256_hex = format!("{:x}", sha256_hasher.finalize());

    let mut sha512_hasher = Sha512::new();
    sha512_hasher.update(zip_content);
    let sha512_hex = format!("{:x}", sha512_hasher.finalize());

    let dgst = format!(
        "MD5= 00000000000000000000000000000000\nSHA1= 0000000000000000000000000000000000000000\nSHA2-256= {sha256_hex}\nSHA2-512= {sha512_hex}\n"
    );

    let (p_sha256, p_sha512) = parse_dgst(&dgst);
    assert_eq!(p_sha256.as_deref(), Some(sha256_hex.as_str()));
    assert_eq!(p_sha512.as_deref(), Some(sha512_hex.as_str()));

    assert!(verify_checksum(zip_content, &dgst).is_ok());

    // Corrupted payload must be rejected
    let corrupted = b"corrupted payload";
    assert!(verify_checksum(corrupted, &dgst).is_err());
}

// ───────────────────────── 4. Integration Test: Mock Release Server ─────────────────────────

#[test]
fn test_integration_mock_release_server() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let mock_api_url = format!("http://127.0.0.1:{port}/releases");

    // Spawn mock HTTP server thread
    let server_thread = std::thread::spawn(move || {
        use std::io::{Read, Write};
        if let Ok((mut socket, _)) = listener.accept() {
            let mut buf = [0u8; 1024];
            let _ = socket.read(&mut buf);

            let json_body = serde_json::json!([
                {
                    "tag_name": "v26.7.28",
                    "prerelease": true,
                    "assets": [
                        {
                            "name": "Xray-linux-64.zip",
                            "browser_download_url": "http://127.0.0.1/fake_v26.7.28.zip"
                        },
                        {
                            "name": "Xray-linux-64.zip.dgst",
                            "browser_download_url": "http://127.0.0.1/fake_v26.7.28.zip.dgst"
                        }
                    ]
                },
                {
                    "tag_name": "v26.9.30",
                    "prerelease": false,
                    "assets": [
                        {
                            "name": "Xray-linux-64.zip",
                            "browser_download_url": "http://127.0.0.1/fake_v26.9.30.zip"
                        },
                        {
                            "name": "Xray-linux-64.zip.dgst",
                            "browser_download_url": "http://127.0.0.1/fake_v26.9.30.zip.dgst"
                        }
                    ]
                }
            ]);

            let body_str = json_body.to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body_str.len(),
                body_str
            );
            let _ = socket.write_all(response.as_bytes());
            let _ = socket.flush();
        }
    });

    let release_info =
        fetch_latest_release_info(Some(&mock_api_url)).expect("Should fetch from mock API");
    // Verify it picks the highest version tag (v26.9.30 > v26.7.28)
    assert_eq!(release_info.tag, "v26.9.30");
    assert_eq!(release_info.zip_url, "http://127.0.0.1/fake_v26.9.30.zip");

    let _ = server_thread.join();
}

// ───────────────────────── 5. Integration Test: Fake Xray Binary ─────────────────────────

#[test]
fn test_integration_fake_xray_binary() {
    let tmp_dir = std::env::temp_dir().join(format!("vortex_fake_xray_{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp_dir);
    fs::create_dir_all(&tmp_dir).unwrap();

    let fake_bin = tmp_dir.join("xray");

    // Create a shell script acting as xray
    let script = r#"#!/bin/sh
if [ "$1" = "version" ]; then
    echo "Xray 26.9.30 (Xray, Penetrates Everything.) Custom Build"
    exit 0
elif [ "$1" = "run" ] && [ "$2" = "-test" ] && [ "$3" = "-config" ]; then
    # Test valid JSON
    cat "$4" | grep -q "outbounds" || exit 1
    exit 0
elif [ "$1" = "-test" ] && [ "$2" = "-config" ]; then
    cat "$3" | grep -q "outbounds" || exit 1
    exit 0
elif [ "$1" = "api" ] && [ "$2" = "statsquery" ]; then
    echo '{"stat":[{"name":"inbound>>>proxy>>>traffic>>>downlink","value":1048576},{"name":"inbound>>>proxy>>>traffic>>>uplink","value":524288}]}'
    exit 0
fi
exit 0
"#;

    fs::write(&fake_bin, script).unwrap();
    let mut perms = fs::metadata(&fake_bin).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&fake_bin, perms).unwrap();

    // 1. Verify get_binary_version
    let ver = get_binary_version(&fake_bin);
    assert_eq!(ver.as_deref(), Some("v26.9.30"));

    // 2. Verify validate_xray_config_file with fake binary
    let valid_cfg_path = tmp_dir.join("valid.json");
    fs::write(&valid_cfg_path, r#"{"outbounds":[{"protocol":"vless"}]}"#).unwrap();
    assert!(validate_xray_config_file(&fake_bin, &valid_cfg_path).is_ok());

    let invalid_cfg_path = tmp_dir.join("invalid.json");
    fs::write(&invalid_cfg_path, r#"{"broken": true}"#).unwrap();
    assert!(validate_xray_config_file(&fake_bin, &invalid_cfg_path).is_err());

    // Clean up
    let _ = fs::remove_dir_all(&tmp_dir);
}

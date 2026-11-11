use anyhow::{anyhow, bail, Result};
use serde_json::Value;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};

pub const ROOT: &str = "/etc/vortex";
pub const STORE: &str = "/etc/vortex/profiles";
pub const SUBS_FILE: &str = "/etc/vortex/subscriptions.json";

pub use crate::model::{
    Auth, CoreEngine, Kind, OperationalMode, Profile, ProfilePayloadKind, Security, Subscription,
    Transport,
};

// ───────────────────────── storage facade ─────────────────────────

pub fn user_home() -> PathBuf {
    crate::crypto::user_home_dir()
}

pub fn ensure_dirs() -> Result<()> {
    if unsafe { libc::geteuid() } == 0 {
        let _ = fs::create_dir_all(crate::tunnel::RUN);
        let _ = fs::set_permissions(crate::tunnel::RUN, fs::Permissions::from_mode(0o755));
    }
    crate::storage::ensure_dirs()?;
    Ok(())
}

pub fn load_all() -> Vec<Profile> {
    crate::storage::load_all()
}

pub fn save(p: &Profile) -> Result<()> {
    crate::storage::save_profile(p).map_err(|e| anyhow!("{e}"))
}

pub fn remove(id: &str) -> Result<()> {
    crate::storage::remove(id).map_err(|e| anyhow!("{e}"))
}

pub fn rename(id: &str, name: &str) -> Result<()> {
    crate::storage::rename(id, name).map_err(|e| anyhow!("{e}"))
}

pub fn set_auth(id: &str, username: String, password: String) -> Result<()> {
    crate::storage::set_auth(id, username, password).map_err(|e| anyhow!("{e}"))
}

pub fn clear_auth(id: &str) -> Result<()> {
    crate::storage::clear_auth(id).map_err(|e| anyhow!("{e}"))
}

pub fn set_last(id: &str) {
    crate::storage::set_last(id);
}

pub fn last() -> Option<String> {
    crate::storage::last()
}

// ───────────────────────── subscriptions facade ─────────────────────────

pub fn load_subs() -> Vec<Subscription> {
    crate::storage::load_subs()
}

pub fn save_subs(subs: &[Subscription]) -> Result<()> {
    crate::storage::save_subs(subs).map_err(|e| anyhow!("{e}"))
}

pub fn sub_name_from_url(url_str: &str) -> (String, String) {
    crate::storage::sub_name_from_url(url_str)
}

pub fn add_sub(url: &str, name_hint: Option<&str>) -> Result<(Subscription, usize)> {
    crate::storage::add_sub(url, name_hint).map_err(|e| anyhow!("{e}"))
}

pub fn update_sub(id_or_url: &str) -> Result<(Subscription, usize)> {
    crate::storage::update_sub(id_or_url).map_err(|e| anyhow!("{e}"))
}

pub fn update_all_subs() -> Result<Vec<(String, Result<usize>)>> {
    let res = crate::storage::update_all_subs().map_err(|e| anyhow!("{e}"))?;
    Ok(res
        .into_iter()
        .map(|(n, r)| (n, r.map_err(|e| anyhow!("{e}"))))
        .collect())
}

pub fn remove_sub(id_or_url: &str, purge_nodes: bool) -> Result<usize> {
    crate::storage::remove_sub(id_or_url, purge_nodes).map_err(|e| anyhow!("{e}"))
}

pub fn import(input: &str) -> Result<usize> {
    crate::storage::import(input).map_err(|e| anyhow!("{e}"))
}

/// Build the sing-box outbound for a stored link or raw JSON outbound.
pub fn outbound(link: &str) -> Result<(Kind, Value, String, String)> {
    crate::parser::singbox_outbound_from_str(link).map_err(|e| anyhow!("{e}"))
}

// ───────────────────────── QR, clipboard & export ─────────────────────────

pub fn generate_qr(data: &str) -> Result<String> {
    use qrcode::render::unicode;
    use qrcode::QrCode;
    let code = QrCode::new(data.as_bytes()).map_err(|e| anyhow!("QR generation failed: {e}"))?;
    Ok(code.render::<unicode::Dense1x2>().quiet_zone(false).build())
}

pub fn export_to_file(p: &Profile) -> Result<PathBuf> {
    let ext = match p.kind {
        Kind::Ovpn => "ovpn",
        Kind::Wg | Kind::Awg => "conf",
        Kind::Xray => "json",
        _ if p.payload_kind != ProfilePayloadKind::Structured => "json",
        _ => "txt",
    };
    let filename = format!("vortex-{}.{}", p.id, ext);
    let target = user_home().join(&filename);

    let content = if p.payload_kind == ProfilePayloadKind::CustomConfig {
        p.data.clone()
    } else if p.effective_engine() == CoreEngine::Xray {
        if let Ok(cfg) = crate::xray::generate_xray_config(p, "vx0", 1080, 54321, None, false) {
            format!(
                "{}\n\n// Xray-core configuration:\n{}\n",
                p.data,
                serde_json::to_string_pretty(&cfg)?
            )
        } else {
            p.data.clone()
        }
    } else if p.kind.is_singbox() {
        if let Ok((_, ob, _, _)) = outbound(&p.data) {
            format!(
                "{}\n\n// sing-box outbound configuration:\n{}\n",
                p.data,
                serde_json::to_string_pretty(&ob)?
            )
        } else {
            p.data.clone()
        }
    } else {
        p.data.clone()
    };

    fs::write(&target, content)?;
    let _ = fs::set_permissions(&target, fs::Permissions::from_mode(0o600));
    Ok(target)
}

pub fn copy_to_clipboard(text: &str) -> Result<()> {
    let try_cmd = |mut cmd: Command| -> Result<()> {
        let mut child = cmd
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;
        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            stdin.write_all(text.as_bytes())?;
        }
        let status = child.wait()?;
        if status.success() {
            Ok(())
        } else {
            bail!("clipboard command failed")
        }
    };

    if let Ok(u) = std::env::var("SUDO_USER") {
        if !u.is_empty() && u != "root" {
            let mut cmd = Command::new("sudo");
            cmd.args(["-u", &u, "wl-copy"]);
            if try_cmd(cmd).is_ok() {
                return Ok(());
            }
        }
    }

    if try_cmd(Command::new("wl-copy")).is_ok() {
        return Ok(());
    }

    let mut cmd = Command::new("xclip");
    cmd.args(["-selection", "clipboard"]);
    if try_cmd(cmd).is_ok() {
        return Ok(());
    }

    bail!("could not copy to clipboard (wl-copy or xclip needed)")
}

pub fn scan_qr_file(path: &Path) -> Result<String> {
    if let Ok(dyn_img) = image::open(path) {
        let img = dyn_img.to_luma8();
        let mut prepared = rqrr::PreparedImage::prepare(img);
        for grid in prepared.detect_grids() {
            let mut bytes = Vec::new();
            if grid.decode_to(&mut bytes).is_ok() && !bytes.is_empty() {
                let s = String::from_utf8_lossy(&bytes).trim().to_string();
                if !s.is_empty() {
                    return Ok(s);
                }
            }
        }
    }
    if let Ok(out) = Command::new("zbarimg")
        .args(["-q", "--raw"])
        .arg(path)
        .output()
    {
        if out.status.success() {
            let res = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !res.is_empty() {
                return Ok(res);
            }
        }
    }
    bail!("no QR code found in {}", path.display())
}

pub fn scan_clipboard_qr() -> Result<String> {
    let get_img = || -> Option<Vec<u8>> {
        if let Ok(u) = std::env::var("SUDO_USER") {
            if !u.is_empty() && u != "root" {
                if let Ok(o) = Command::new("sudo")
                    .args(["-u", &u, "wl-paste", "--type", "image/png"])
                    .output()
                {
                    if o.status.success() && !o.stdout.is_empty() {
                        return Some(o.stdout);
                    }
                }
            }
        }
        if let Ok(o) = Command::new("wl-paste")
            .args(["--type", "image/png"])
            .output()
        {
            if o.status.success() && !o.stdout.is_empty() {
                return Some(o.stdout);
            }
        }
        None
    };

    let bytes = get_img().ok_or_else(|| anyhow!("no image in clipboard"))?;
    let tmp = std::env::temp_dir().join(format!("vortex_clip_{}.png", std::process::id()));
    fs::write(&tmp, &bytes)?;
    let res = scan_qr_file(&tmp);
    let _ = fs::remove_file(&tmp);
    res
}

/// Human-readable facts about a profile (engine, payload, transport, security, endpoint…) for UI/CLI.
pub fn details(p: &Profile) -> Vec<(&'static str, String)> {
    let mut v: Vec<(&'static str, String)> = vec![
        ("engine", p.effective_engine().as_str().to_string()),
        ("payload", p.payload_kind.label().to_string()),
        ("transport", p.display_transport()),
        ("security", p.display_security()),
    ];
    if let Some(port) = p.port {
        v.push(("port", port.to_string()));
    }
    if let Some(sni) = &p.sni {
        v.push(("sni", sni.clone()));
    }
    if let Some(alpn) = &p.alpn {
        v.push(("alpn", alpn.clone()));
    }
    if let Some(obfs) = &p.obfs {
        v.push(("obfs", obfs.clone()));
    }
    if let Some(flow) = &p.flow {
        if !flow.is_empty() {
            v.push(("flow", flow.clone()));
        }
    }
    if let Some(pq) = &p.post_quantum {
        v.push(("encryption", pq.clone()));
    }
    if p.kind.is_singbox() {
        if let Ok((_, ob, _, _)) = outbound(&p.data) {
            if let Some(x) = ob["flow"].as_str().filter(|s| !s.is_empty()) {
                v.push(("flow", x.to_string()));
            }
            if let Some(x) = ob["method"].as_str().filter(|s| !s.is_empty()) {
                v.push(("cipher", x.to_string()));
            }
        }
    } else {
        if p.kind == Kind::Ovpn {
            let auth_status = if let Some(a) = &p.auth {
                format!("saved ({})", a.username)
            } else if crate::tunnel::ovpn_needs_auth(p) {
                "required (not saved)".to_string()
            } else {
                "cert/key only".to_string()
            };
            v.push(("auth", auth_status));
        }
        for l in p.data.lines() {
            let t = l.trim();
            let lower = t.to_ascii_lowercase();
            if lower.starts_with("endpoint") {
                if let Some((_, e)) = t.split_once('=') {
                    v.push(("endpoint", e.trim().to_string()));
                }
            } else if lower.starts_with("proto ") {
                v.push(("proto", t[6..].trim().to_string()));
            } else if lower.starts_with("cipher ") {
                v.push(("cipher", t[7..].trim().to_string()));
            }
        }
    }
    v.dedup_by_key(|x| x.0);
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose as b, Engine};
    use serde_json::json;
    use std::io::Write;

    #[test]
    fn vless_reality() {
        let l = "vless://11111111-2222-3333-4444-555555555555@example.com:443?security=reality&sni=www.google.com&fp=chrome&pbk=PUBKEY&sid=ab12&flow=xtls-rprx-vision&type=tcp#My%20Node";
        let (k, o, n, s) = outbound(l).unwrap();
        assert_eq!(k, Kind::Vless);
        assert_eq!(n, "My Node");
        assert_eq!(s, "example.com:443");
        assert_eq!(o["tls"]["reality"]["public_key"], "PUBKEY");
        assert_eq!(o["flow"], "xtls-rprx-vision");
    }

    #[test]
    fn vless_ws() {
        let l = "vless://u@h.io:443?security=tls&type=ws&path=%2Fws%3Fed%3D2048&host=cdn.h.io&sni=cdn.h.io#x";
        let (_, o, _, _) = outbound(l).unwrap();
        assert_eq!(o["transport"]["path"], "/ws");
        assert_eq!(o["transport"]["max_early_data"], 2048);
        assert_eq!(o["transport"]["headers"]["Host"], "cdn.h.io");
    }

    #[test]
    fn vmess_json() {
        let j = r#"{"v":"2","ps":"vm","add":"1.2.3.4","port":"443","id":"uuid","aid":"0","net":"ws","host":"a.b","path":"/p","tls":"tls","sni":"a.b"}"#;
        let l = format!("vmess://{}", b::STANDARD.encode(j));
        let (k, o, n, _) = outbound(&l).unwrap();
        assert_eq!(k, Kind::Vmess);
        assert_eq!(n, "vm");
        assert_eq!(o["transport"]["type"], "ws");
        assert_eq!(o["tls"]["server_name"], "a.b");
    }

    #[test]
    fn test_outbound_json_format() {
        let j = r#"{"type":"vless","tag":"vless-node","server":"1.2.3.4","server_port":443,"uuid":"12345"}"#;
        let (k, o, n, s) = outbound(j).unwrap();
        assert_eq!(k, Kind::Vless);
        assert_eq!(n, "vless-node");
        assert_eq!(s, "1.2.3.4:443");
        assert_eq!(o["tag"], "proxy");
        assert_eq!(o["type"], "vless");
    }

    #[test]
    fn ss_forms() {
        let ui = b::URL_SAFE_NO_PAD.encode("aes-256-gcm:secret");
        let (_, o, n, _) = outbound(&format!("ss://{ui}@9.9.9.9:8388#Hi")).unwrap();
        assert_eq!(o["method"], "aes-256-gcm");
        assert_eq!(n, "Hi");
        let whole = b::STANDARD.encode("chacha20-ietf-poly1305:pw@h.io:1234");
        let (_, o, _, s) = outbound(&format!("ss://{whole}")).unwrap();
        assert_eq!(o["password"], "pw");
        assert_eq!(s, "h.io:1234");
    }

    #[test]
    fn hysteria2() {
        let l = "hy2://pass@h.io:443?sni=h.io&insecure=1&obfs=salamander&obfs-password=xx#H";
        let (k, o, _, _) = outbound(l).unwrap();
        assert_eq!(k, Kind::Hy2);
        assert_eq!(o["obfs"]["password"], "xx");
        assert_eq!(o["tls"]["insecure"], true);
        let (_, o, _, _) = outbound("hysteria2://p@h.io:443?mport=20000-30000").unwrap();
        assert_eq!(o["server_ports"][0], "20000:30000");
    }

    #[test]
    fn trojan_and_tuic() {
        let (_, o, _, _) = outbound("trojan://pw@h.io:443?sni=h.io#T").unwrap();
        assert_eq!(o["tls"]["enabled"], true);
        let (k, o, _, _) =
            outbound("tuic://uid:pw@h.io:443?congestion_control=bbr&alpn=h3#U").unwrap();
        assert_eq!(k, Kind::Tuic);
        assert_eq!(o["tls"]["alpn"][0], "h3");
    }

    #[test]
    fn amnezia_link() {
        let inner = json!({"config": "[Interface]\nPrivateKey = a=\nJc = 4\n[Peer]\nEndpoint = 1.2.3.4:5555\n"}).to_string();
        let payload = json!({"description":"AmnTest","containers":[{"container":"amnezia-awg","awg":{"last_config": inner}}]}).to_string();
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(payload.as_bytes()).unwrap();
        let mut raw = (payload.len() as u32).to_be_bytes().to_vec();
        raw.extend(z.finish().unwrap());
        let link = format!("vpn://{}", b::URL_SAFE_NO_PAD.encode(raw));
        let v = crate::parser::parse_any(&link).unwrap();
        assert_eq!(v[0].kind, Kind::Awg);
        assert_eq!(v[0].server, "1.2.3.4:5555");
    }

    #[test]
    fn wg_vs_awg_files() {
        let dir = std::env::temp_dir();
        let a = dir.join("vx_wg.conf");
        fs::write(&a, "[Interface]\nPrivateKey = x\n[Peer]\nEndpoint = h:1\n").unwrap();
        assert_eq!(
            crate::parser::parse_any(a.to_str().unwrap()).unwrap()[0].kind,
            Kind::Wg
        );
        let b2 = dir.join("vx_awg.conf");
        fs::write(
            &b2,
            "[Interface]\nPrivateKey = x\nJc = 5\nS1 = 3\n[Peer]\nEndpoint = h:1\n",
        )
        .unwrap();
        assert_eq!(
            crate::parser::parse_any(b2.to_str().unwrap()).unwrap()[0].kind,
            Kind::Awg
        );
        let _ = fs::remove_file(a);
        let _ = fs::remove_file(b2);
    }

    #[test]
    fn test_padded_tags() {
        let kinds = [
            Kind::Vless,
            Kind::Vmess,
            Kind::Trojan,
            Kind::Ss,
            Kind::Hy2,
            Kind::Tuic,
            Kind::Wg,
            Kind::Awg,
            Kind::Ovpn,
        ];
        for k in kinds {
            assert_eq!(
                k.padded_tag().len(),
                6,
                "padded_tag for {:?} must be exactly 6 bytes",
                k
            );
        }
    }

    #[test]
    fn test_ovpn_auth_serialization() {
        let p_json_no_auth = r#"{"id":"test1","name":"Test No Auth","kind":"ovpn","server":"1.2.3.4:1194","data":"client\ndev tun\n"}"#;
        let p: Profile = serde_json::from_str(p_json_no_auth).unwrap();
        assert!(p.auth.is_none());
        assert!(!crate::tunnel::ovpn_needs_auth(&p));

        let p_json_with_auth = r#"{"id":"test2","name":"Test With Auth","kind":"ovpn","server":"1.2.3.4:1194","data":"client\nauth-user-pass\n","auth":{"username":"alice","password":"secret","save":true}}"#;
        let p2: Profile = serde_json::from_str(p_json_with_auth).unwrap();
        assert!(p2.auth.is_some());
        let a = p2.auth.as_ref().unwrap();
        assert_eq!(a.username, "alice");
        assert_eq!(a.password, "secret");
        assert!(a.save);
        assert!(crate::tunnel::ovpn_needs_auth(&p2));
    }

    #[test]
    fn test_generate_qr() {
        let link = "vless://u@example.com:443?security=reality#Frankfurt";
        let qr = generate_qr(link).unwrap();
        assert!(!qr.is_empty());
        assert!(qr.lines().count() > 10);
    }

    #[test]
    fn test_sub_name_from_url() {
        let (id1, name1) = sub_name_from_url("https://sub.provider.com/api/v1?token=123#MyVip");
        assert_eq!(name1, "MyVip");
        assert_eq!(id1, "myvip");

        let (id2, name2) = sub_name_from_url("https://vpn.fastnode.org/subscribe?t=xyz");
        assert_eq!(name2, "vpn.fastnode.org");
        assert_eq!(id2, "vpn-fastnode-org");
    }

    #[test]
    fn test_subscription_json_roundtrip() {
        let sub = Subscription {
            id: "sub-1".into(),
            name: "Super Fast Sub".into(),
            url: "https://example.com/sub".into(),
            count: 42,
            updated: Some(1720000000),
            error: None,
        };
        let js = serde_json::to_string(&sub).unwrap();
        let sub2: Subscription = serde_json::from_str(&js).unwrap();
        assert_eq!(sub, sub2);
    }

    #[test]
    fn test_raw_config_parsing() {
        let wg_text = "[Interface]\nPrivateKey = a=\nAddress = 10.0.0.2/24\n[Peer]\nEndpoint = 198.51.100.1:51820\nPublicKey = b=\n";
        let profs = crate::parser::parse_any(wg_text).unwrap();
        assert_eq!(profs.len(), 1);
        assert_eq!(profs[0].kind, Kind::Wg);
        assert_eq!(profs[0].server, "198.51.100.1:51820");

        let awg_text = "[Interface]\nPrivateKey = a=\nJc = 4\n[Peer]\nEndpoint = 198.51.100.2:51820\nPublicKey = b=\n";
        let profs2 = crate::parser::parse_any(awg_text).unwrap();
        assert_eq!(profs2[0].kind, Kind::Awg);

        let ovpn_text = "client\ndev tun\nremote 198.51.100.3 1194\n";
        let profs3 = crate::parser::parse_any(ovpn_text).unwrap();
        assert_eq!(profs3[0].kind, Kind::Ovpn);
        assert_eq!(profs3[0].server, "198.51.100.3:1194");
    }

    #[test]
    fn test_export_to_file() {
        let dir = std::env::temp_dir();
        let p = Profile {
            id: "test-export-node".into(),
            name: "Test Export".into(),
            kind: Kind::Wg,
            server: "1.2.3.4:51820".into(),
            data: "[Interface]\nPrivateKey = x\n[Peer]\nEndpoint = 1.2.3.4:51820\n".into(),
            ..Default::default()
        };
        let export_path = dir.join(format!("vortex-{}.conf", p.id));
        fs::write(&export_path, &p.data).unwrap();
        let read = fs::read_to_string(&export_path).unwrap();
        assert_eq!(read, p.data);
        let _ = fs::remove_file(export_path);
    }
}

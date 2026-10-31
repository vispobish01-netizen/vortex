use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose as b, Engine};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    fs,
    io::Read,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};
use url::Url;

pub const ROOT: &str = "/etc/vortex";
pub const STORE: &str = "/etc/vortex/profiles";
pub const SUBS_FILE: &str = "/etc/vortex/subscriptions.json";

pub use crate::model::{Auth, Kind, OperationalMode, Profile, Security, Subscription, Transport};

// ───────────────────────── storage ─────────────────────────

pub fn user_home() -> PathBuf {
    if let Ok(u) = std::env::var("SUDO_USER") {
        if !u.is_empty() && u != "root" {
            return PathBuf::from("/home").join(u);
        }
    }
    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/root".into()))
}

fn expand(s: &str) -> PathBuf {
    match s.strip_prefix("~/") {
        Some(r) => user_home().join(r),
        None => PathBuf::from(s),
    }
}

pub fn ensure_dirs() -> Result<()> {
    if unsafe { libc::geteuid() } == 0 {
        let _ = fs::create_dir_all(STORE);
        let _ = fs::set_permissions(ROOT, fs::Permissions::from_mode(0o755));
        let _ = fs::set_permissions(STORE, fs::Permissions::from_mode(0o755));
        let _ = fs::create_dir_all(crate::tunnel::RUN);
        let _ = fs::set_permissions(crate::tunnel::RUN, fs::Permissions::from_mode(0o755));
    }
    let _ = crate::storage::ensure_dirs();
    Ok(())
}

pub fn load_all() -> Vec<Profile> {
    let mut v: Vec<Profile> = fs::read_dir(STORE)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| fs::read_to_string(e.path()).ok())
        .filter_map(|s| serde_json::from_str(&s).ok())
        .collect();

    let user_prof_dir = crate::storage::profiles_dir();
    if user_prof_dir.as_path() != Path::new(STORE) {
        if let Ok(entries) = fs::read_dir(&user_prof_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Ok(p) = crate::storage::load_profile_from_path(&path) {
                    if !v.iter().any(|existing| existing.id == p.id) {
                        v.push(p);
                    }
                } else if let Ok(content) = fs::read_to_string(&path) {
                    if let Ok(p) = serde_json::from_str::<Profile>(&content) {
                        if !v.iter().any(|existing| existing.id == p.id) {
                            v.push(p);
                        }
                    }
                }
            }
        }
    }
    for p in &mut v {
        if p.transport == Transport::Unknown {
            p.populate_metadata();
        }
    }
    v.sort_by(|a, b| {
        a.name
            .bytes()
            .map(|c| c.to_ascii_lowercase())
            .cmp(b.name.bytes().map(|c| c.to_ascii_lowercase()))
    });
    v
}

pub fn save(p: &Profile) -> Result<()> {
    if unsafe { libc::geteuid() } == 0 {
        let path = Path::new(STORE).join(format!("{}.json", p.id));
        fs::write(&path, serde_json::to_string_pretty(p)?)?;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o644));
    } else {
        crate::storage::save_profile(p).map_err(|e| anyhow::anyhow!("{e}"))?;
    }
    Ok(())
}

pub fn remove(id: &str) -> Result<()> {
    let sys_path = Path::new(STORE).join(format!("{id}.json"));
    if sys_path.exists() {
        let _ = fs::remove_file(sys_path);
    }
    let user_path = crate::storage::profiles_dir().join(format!("{id}.json"));
    if user_path.exists() {
        let _ = fs::remove_file(user_path);
    }
    Ok(())
}

fn slug(s: &str) -> String {
    let o: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    let mut o = o
        .split('-')
        .filter(|x| !x.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    if o.is_empty() {
        o = "profile".into();
    }
    o.truncate(24);
    o
}

// ───────────────────────── subscriptions ─────────────────────────

pub fn load_subs() -> Vec<Subscription> {
    fs::read_to_string(SUBS_FILE)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save_subs(subs: &[Subscription]) -> Result<()> {
    let path = Path::new(SUBS_FILE);
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    fs::write(path, serde_json::to_string_pretty(subs)?)?;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    Ok(())
}

pub fn sub_name_from_url(url_str: &str) -> (String, String) {
    let parsed = Url::parse(url_str).ok();
    let fragment = parsed
        .as_ref()
        .and_then(|u| u.fragment())
        .map(pdec)
        .filter(|s| !s.trim().is_empty());
    let host = parsed
        .as_ref()
        .and_then(|u| u.host_str())
        .map(String::from)
        .unwrap_or_else(|| "subscription".into());
    let name = fragment.unwrap_or_else(|| host.clone());
    let mut base_id = slug(&name);
    if base_id.is_empty() {
        base_id = slug(&host);
    }
    (base_id, name)
}

fn save_sub_profiles(sub_id: &str, profiles: Vec<Profile>) -> Result<usize> {
    let existing = load_all();
    let active_id = crate::tunnel::load_session().map(|s| s.id);
    for p in &existing {
        if p.sub_id.as_deref() == Some(sub_id) && active_id.as_deref() != Some(&p.id) {
            let _ = remove(&p.id);
        }
    }
    let remaining = load_all();
    let mut ids: HashSet<String> = remaining.iter().map(|p| p.id.clone()).collect();
    let mut data_set: HashSet<String> = remaining.iter().map(|p| p.data.clone()).collect();
    let mut count = 0;
    for mut p in profiles {
        if data_set.contains(&p.data) {
            continue;
        }
        let base = slug(&p.name);
        let mut id = base.clone();
        let mut i = 2;
        while ids.contains(&id) {
            id = format!("{base}-{i}");
            i += 1;
        }
        ids.insert(id.clone());
        data_set.insert(p.data.clone());
        p.id = id;
        p.sub_id = Some(sub_id.to_string());
        save(&p)?;
        count += 1;
    }
    Ok(count)
}

pub fn add_sub(url: &str, name_hint: Option<&str>) -> Result<(Subscription, usize)> {
    let mut subs = load_subs();
    let (mut id, mut name) = sub_name_from_url(url);
    if let Some(h) = name_hint.filter(|s| !s.trim().is_empty()) {
        name = h.trim().to_string();
        id = slug(&name);
    }

    let existing_pos = subs.iter().position(|s| s.url == url);
    let sub_id = if let Some(pos) = existing_pos {
        subs[pos].id.clone()
    } else {
        let base = id.clone();
        let mut i = 2;
        while subs.iter().any(|s| s.id == id) {
            id = format!("{base}-{i}");
            i += 1;
        }
        id
    };

    let profiles = import_sub(url)?;
    let count = save_sub_profiles(&sub_id, profiles)?;
    let now_ts = crate::tunnel::now();
    let sub = Subscription {
        id: sub_id,
        name,
        url: url.to_string(),
        count,
        updated: Some(now_ts),
        error: None,
    };

    if let Some(pos) = existing_pos {
        subs[pos] = sub.clone();
    } else {
        subs.push(sub.clone());
    }
    save_subs(&subs)?;
    Ok((sub, count))
}

pub fn update_sub(id_or_url: &str) -> Result<(Subscription, usize)> {
    let subs = load_subs();
    let sub = subs
        .iter()
        .find(|s| s.id == id_or_url || s.url == id_or_url)
        .cloned()
        .ok_or_else(|| anyhow!("subscription '{id_or_url}' not found"))?;

    let profiles = import_sub(&sub.url)?;
    let count = save_sub_profiles(&sub.id, profiles)?;

    let mut subs = load_subs();
    let mut updated_sub = sub;
    updated_sub.count = count;
    updated_sub.updated = Some(crate::tunnel::now());
    if let Some(pos) = subs.iter().position(|s| s.id == updated_sub.id) {
        subs[pos] = updated_sub.clone();
    }
    save_subs(&subs)?;
    Ok((updated_sub, count))
}

pub fn update_all_subs() -> Result<Vec<(String, Result<usize>)>> {
    let subs = load_subs();
    if subs.is_empty() {
        bail!("no subscriptions configured — use `vortex sub add <url>`");
    }
    let mut results = vec![];
    for sub in subs {
        match import_sub(&sub.url) {
            Ok(profs) => match save_sub_profiles(&sub.id, profs) {
                Ok(count) => {
                    let mut all_subs = load_subs();
                    if let Some(pos) = all_subs.iter().position(|s| s.id == sub.id) {
                        all_subs[pos].count = count;
                        all_subs[pos].updated = Some(crate::tunnel::now());
                        let _ = save_subs(&all_subs);
                    }
                    results.push((sub.name, Ok(count)));
                }
                Err(e) => results.push((sub.name, Err(e))),
            },
            Err(e) => results.push((sub.name, Err(e))),
        }
    }
    Ok(results)
}

pub fn remove_sub(id_or_url: &str, purge_nodes: bool) -> Result<usize> {
    let mut subs = load_subs();
    let pos = subs
        .iter()
        .position(|s| s.id == id_or_url || s.url == id_or_url)
        .ok_or_else(|| anyhow!("subscription '{id_or_url}' not found"))?;
    let sub = subs.remove(pos);
    save_subs(&subs)?;

    let mut removed_count = 0;
    if purge_nodes {
        let all = load_all();
        let active_id = crate::tunnel::load_session().map(|s| s.id);
        for p in all {
            if p.sub_id.as_deref() == Some(&sub.id) {
                if active_id.as_deref() == Some(&p.id) {
                    continue;
                }
                if remove(&p.id).is_ok() {
                    removed_count += 1;
                }
            }
        }
    }
    Ok(removed_count)
}

// ───────────────────────── QR & export ─────────────────────────

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
        _ => "txt",
    };
    let filename = format!("vortex-{}.{}", p.id, ext);
    let target = user_home().join(&filename);

    let content = if p.kind == Kind::Xray || p.backend_type.as_deref() == Some("xray") {
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

fn is_image_path(p: &Path) -> bool {
    let ext = p
        .extension()
        .and_then(|x| x.to_str())
        .unwrap_or("")
        .to_lowercase();
    matches!(
        ext.as_str(),
        "png" | "jpg" | "jpeg" | "webp" | "bmp" | "gif" | "pbm" | "pgm" | "ppm" | "tiff"
    )
}

pub fn scan_qr_file(path: &Path) -> Result<String> {
    let out = Command::new("zbarimg")
        .args(["-q", "--raw"])
        .arg(path)
        .output()
        .context("zbarimg failed to execute — make sure zbar is installed")?;
    if !out.status.success() {
        bail!("no QR code or barcode found in {}", path.display());
    }
    let res = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if res.is_empty() {
        bail!("empty QR payload");
    }
    Ok(res)
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

// ───────────────────────── import ─────────────────────────

/// Import anything the user can paste: link(s), subscription URL, config file path, QR code image.
/// Returns how many *new* profiles were stored.
pub fn import(input: &str) -> Result<usize> {
    let s = input.trim().trim_matches(|c| c == '"' || c == '\'');
    if s.is_empty() {
        bail!("nothing to import");
    }
    if s.starts_with("http://") || s.starts_with("https://") {
        let (_, count) = add_sub(s, None)?;
        return Ok(count);
    }
    let found = parse_any(input)?;
    let existing = load_all();
    let mut ids: HashSet<String> = existing.iter().map(|p| p.id.clone()).collect();
    let mut data_set: HashSet<String> = existing.into_iter().map(|p| p.data).collect();
    let mut added = 0;
    for mut p in found {
        if data_set.contains(&p.data) {
            continue;
        }
        let base = slug(&p.name);
        let mut id = base.clone();
        let mut i = 2;
        while ids.contains(&id) {
            id = format!("{base}-{i}");
            i += 1;
        }
        ids.insert(id.clone());
        data_set.insert(p.data.clone());
        p.id = id;
        save(&p)?;
        added += 1;
    }
    Ok(added)
}

fn parse_any(input: &str) -> Result<Vec<Profile>> {
    let s = input.trim().trim_matches(|c| c == '"' || c == '\'');
    if s.is_empty() {
        bail!("nothing to import");
    }
    if s.starts_with("http://") || s.starts_with("https://") {
        return import_sub(s);
    }
    // Universal parser covers Xray/sing-box JSON, VLESS xhttp, etc.
    if let Ok(profs) = crate::parser::parse_any(s) {
        if !profs.is_empty() {
            return Ok(profs);
        }
    }
    let p = expand(s);
    if p.is_file() {
        if is_image_path(&p) {
            let qr_text = scan_qr_file(&p)?;
            return parse_any(&qr_text);
        }
        match import_file(s) {
            Ok(prof) => return Ok(vec![prof]),
            Err(e) => {
                if let Ok(qr_text) = scan_qr_file(&p) {
                    return parse_any(&qr_text);
                }
                return Err(e);
            }
        }
    }
    if s.contains("://") {
        let mut v = vec![];
        let mut first_err = None;
        for t in s.split_whitespace() {
            match parse_link(t) {
                Ok(mut p) => v.append(&mut p),
                Err(e) => {
                    if first_err.is_none() {
                        first_err = Some(e)
                    }
                }
            }
        }
        if v.is_empty() {
            return Err(first_err.unwrap_or_else(|| anyhow!("no links found")));
        }
        return Ok(v);
    }
    if s.contains("[Interface]") || s.contains("remote ") {
        return parse_raw_config(s);
    }
    Ok(vec![import_file(s)?])
}

fn parse_raw_config(text: &str) -> Result<Vec<Profile>> {
    if text.contains("[Interface]") {
        let awg = AWG_KEYS.iter().any(|k| kv_find(text, k).is_some());
        let server = kv_find(text, "Endpoint").unwrap_or_default();
        let name = format!("Config · {}", if awg { "AWG" } else { "WireGuard" });
        let mut p = Profile {
            id: String::new(),
            name,
            kind: if awg { Kind::Awg } else { Kind::Wg },
            server,
            data: text.to_string(),
            ..Default::default()
        };
        p.populate_metadata();
        return Ok(vec![p]);
    }
    if text.lines().any(|l| l.trim_start().starts_with("remote ")) {
        let mut p = Profile {
            id: String::new(),
            name: "Config · OpenVPN".to_string(),
            kind: Kind::Ovpn,
            server: ovpn_server(text),
            data: text.to_string(),
            ..Default::default()
        };
        p.populate_metadata();
        return Ok(vec![p]);
    }
    bail!("unrecognized raw config")
}

// ───────────────────────── helpers ─────────────────────────

fn pdec(s: &str) -> String {
    percent_encoding::percent_decode_str(s)
        .decode_utf8_lossy()
        .to_string()
}

fn b64(s: &str) -> Result<Vec<u8>> {
    let t: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let t = t.trim_end_matches('=');
    for e in [&b::STANDARD_NO_PAD, &b::URL_SAFE_NO_PAD] {
        if let Ok(v) = e.decode(t) {
            return Ok(v);
        }
    }
    bail!("bad base64")
}

fn q_of(u: &Url) -> HashMap<String, String> {
    u.query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn host_port(u: &Url) -> Result<(String, u16)> {
    let h = u
        .host_str()
        .ok_or_else(|| anyhow!("link has no host"))?
        .trim_matches(|c| c == '[' || c == ']')
        .to_string();
    let p = u.port().ok_or_else(|| anyhow!("link has no port"))?;
    Ok((h, p))
}

fn frag(u: &Url, h: &str, p: u16) -> String {
    u.fragment()
        .map(pdec)
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| format!("{h}:{p}"))
}

fn truthy(q: &HashMap<String, String>, keys: &[&str]) -> bool {
    keys.iter()
        .any(|k| q.get(*k).map(|v| v == "1" || v == "true").unwrap_or(false))
}

fn tls_block(q: &HashMap<String, String>, default_on: bool) -> Option<Value> {
    let sec = q
        .get("security")
        .map(String::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or(if default_on { "tls" } else { "none" });
    if sec != "tls" && sec != "reality" {
        return None;
    }
    let mut t = json!({"enabled": true});
    if let Some(s) = q
        .get("sni")
        .or_else(|| q.get("peer"))
        .filter(|s| !s.is_empty())
    {
        t["server_name"] = json!(s);
    }
    if let Some(a) = q.get("alpn").filter(|s| !s.is_empty()) {
        t["alpn"] = json!(a.split(',').collect::<Vec<_>>());
    }
    if truthy(q, &["allowInsecure", "insecure", "allow_insecure"]) {
        t["insecure"] = json!(true);
    }
    let fp = q
        .get("fp")
        .filter(|s| !s.is_empty())
        .cloned()
        .or_else(|| (sec == "reality").then(|| "chrome".to_string()));
    if let Some(fp) = fp {
        t["utls"] = json!({"enabled": true, "fingerprint": fp});
    }
    if sec == "reality" {
        t["reality"] = json!({
            "enabled": true,
            "public_key": q.get("pbk").cloned().unwrap_or_default(),
            "short_id": q.get("sid").cloned().unwrap_or_default(),
        });
    }
    Some(t)
}

fn transport(q: &HashMap<String, String>) -> Result<Option<Value>> {
    let ty = q.get("type").map(String::as_str).unwrap_or("tcp");
    let path = q.get("path").cloned().unwrap_or_default();
    let host = q.get("host").filter(|s| !s.is_empty()).cloned();
    let norm = |p: &str| {
        if p.is_empty() {
            "/".to_string()
        } else {
            p.to_string()
        }
    };
    Ok(match ty {
        "" | "tcp" | "none" => None,
        "ws" => {
            let (p, ed) = match path.split_once("?ed=") {
                Some((a, e)) => (a.to_string(), e.parse::<u32>().ok()),
                None => (path.clone(), None),
            };
            let p = norm(&p);
            let mut t = json!({"type": "ws", "path": p});
            if let Some(h) = host {
                t["headers"] = json!({"Host": h});
            }
            if let Some(n) = ed {
                t["max_early_data"] = json!(n);
                t["early_data_header_name"] = json!("Sec-WebSocket-Protocol");
            }
            Some(t)
        }
        "grpc" => {
            let sn = q.get("serviceName").cloned().unwrap_or_default();
            Some(json!({"type": "grpc", "service_name": sn}))
        }
        "http" | "h2" => {
            let p = norm(&path);
            let mut t = json!({"type": "http", "path": p});
            if let Some(h) = host {
                t["host"] = json!(h.split(',').collect::<Vec<_>>());
            }
            Some(t)
        }
        "httpupgrade" => {
            let p = norm(&path);
            let mut t = json!({"type": "httpupgrade", "path": p});
            if let Some(h) = host {
                t["host"] = json!(h);
            }
            Some(t)
        }
        "xhttp" | "splithttp" => {
            let p = norm(&path);
            let mut t = json!({"type": "xhttp", "path": p});
            if let Some(h) = host {
                t["host"] = json!(h);
            }
            Some(t)
        }
        other => bail!("transport '{other}' is not supported"),
    })
}

// ───────────────────── link → sing-box outbound ─────────────────────

type Parsed = (Value, String, String); // outbound, display name, server

fn uri_proxy(l: &str, kind: Kind) -> Result<Parsed> {
    let u = Url::parse(l).context("invalid link")?;
    let (h, p) = host_port(&u)?;
    let q = q_of(&u);
    let user = pdec(u.username());
    let mut o = if kind == Kind::Vless {
        json!({"type":"vless","tag":"proxy","server":h,"server_port":p,"uuid":user,"packet_encoding":"xudp"})
    } else {
        json!({"type":"trojan","tag":"proxy","server":h,"server_port":p,"password":user})
    };
    if kind == Kind::Vless {
        if let Some(f) = q.get("flow").filter(|s| !s.is_empty()) {
            o["flow"] = json!(f);
        }
    }
    if let Some(t) = tls_block(&q, kind == Kind::Trojan) {
        o["tls"] = t;
    }
    if let Some(t) = transport(&q)? {
        o["transport"] = t;
    }
    Ok((o, frag(&u, &h, p), format!("{h}:{p}")))
}

fn vmess(l: &str) -> Result<Parsed> {
    let body = &l["vmess://".len()..];
    let body = body.split('#').next().unwrap_or(body);
    if let Ok(raw) = b64(body) {
        if let Ok(v) = serde_json::from_slice::<Value>(&raw) {
            let s = |k: &str| -> String {
                match &v[k] {
                    Value::String(x) => x.clone(),
                    Value::Number(n) => n.to_string(),
                    _ => String::new(),
                }
            };
            let h = s("add");
            let port: u16 = s("port").parse().context("vmess: bad port")?;
            let scy = if s("scy").is_empty() {
                "auto".to_string()
            } else {
                s("scy")
            };
            let mut o = json!({
                "type":"vmess","tag":"proxy","server":h,"server_port":port,
                "uuid":s("id"),"security":scy,"alter_id":s("aid").parse::<u32>().unwrap_or(0),
            });
            let mut q: HashMap<String, String> = HashMap::new();
            let net = s("net");
            q.insert("type".into(), net.clone());
            q.insert("path".into(), s("path"));
            q.insert("host".into(), s("host"));
            if net == "grpc" {
                q.insert("serviceName".into(), s("path"));
            }
            q.insert(
                "security".into(),
                if s("tls") == "tls" {
                    "tls".into()
                } else {
                    "none".into()
                },
            );
            q.insert("sni".into(), s("sni"));
            q.insert("alpn".into(), s("alpn"));
            q.insert("fp".into(), s("fp"));
            if let Some(t) = tls_block(&q, false) {
                o["tls"] = t;
            }
            if let Some(t) = transport(&q)? {
                o["transport"] = t;
            }
            let name = if s("ps").is_empty() {
                format!("{h}:{port}")
            } else {
                s("ps")
            };
            return Ok((o, name, format!("{h}:{port}")));
        }
    }
    // URI style: vmess://uuid@host:port?...
    let (mut o, n, sv) = uri_proxy(l, Kind::Vless)?;
    o["type"] = json!("vmess");
    o["security"] = json!("auto");
    o["alter_id"] = json!(0);
    if let Some(m) = o.as_object_mut() {
        m.remove("flow");
        m.remove("packet_encoding");
    }
    Ok((o, n, sv))
}

fn shadowsocks(l: &str) -> Result<Parsed> {
    let mut rest = &l["ss://".len()..];
    let mut name = String::new();
    if let Some((a, f)) = rest.split_once('#') {
        name = pdec(f);
        rest = a;
    }
    let (rest, query) = rest.split_once('?').unwrap_or((rest, ""));
    let rest = rest.trim_end_matches('/');
    let (userinfo, hostport) = if let Some((ui, hp)) = rest.rsplit_once('@') {
        let ui = if ui.contains(':') {
            pdec(ui)
        } else {
            String::from_utf8(b64(&pdec(ui))?)?
        };
        (ui, hp.to_string())
    } else {
        let d = String::from_utf8(b64(rest)?)?;
        let (ui, hp) = d.rsplit_once('@').ok_or_else(|| anyhow!("bad ss link"))?;
        (ui.to_string(), hp.to_string())
    };
    let (method, pass) = userinfo
        .split_once(':')
        .ok_or_else(|| anyhow!("bad ss credentials"))?;
    let (h, p) = hostport
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("bad ss host"))?;
    let h = h.trim_matches(|c| c == '[' || c == ']');
    let port: u16 = p.trim_end_matches('/').parse().context("bad ss port")?;
    let mut o = json!({"type":"shadowsocks","tag":"proxy","server":h,"server_port":port,"method":method,"password":pass});
    for (k, v) in url::form_urlencoded::parse(query.as_bytes()) {
        if k == "plugin" {
            let v = v.to_string();
            let (n, opts) = v.split_once(';').unwrap_or((v.as_str(), ""));
            o["plugin"] = json!(n);
            if !opts.is_empty() {
                o["plugin_opts"] = json!(opts);
            }
        }
    }
    let sv = format!("{h}:{port}");
    Ok((o, if name.is_empty() { sv.clone() } else { name }, sv))
}

fn hy2(l: &str) -> Result<Parsed> {
    let l2 = l.replacen("hy2://", "hysteria2://", 1);
    let u = Url::parse(&l2).context("invalid link")?;
    let h = u
        .host_str()
        .ok_or_else(|| anyhow!("link has no host"))?
        .trim_matches(|c| c == '[' || c == ']')
        .to_string();
    let port = u.port().unwrap_or(443);
    let pass = match u.password() {
        Some(pw) => format!("{}:{}", pdec(u.username()), pdec(pw)),
        None => pdec(u.username()),
    };
    let q = q_of(&u);
    let mut tls = json!({"enabled": true, "alpn": ["h3"]});
    if let Some(s) = q.get("sni").filter(|s| !s.is_empty()) {
        tls["server_name"] = json!(s);
    }
    if truthy(&q, &["insecure", "allowInsecure"]) {
        tls["insecure"] = json!(true);
    }
    let mut o = json!({"type":"hysteria2","tag":"proxy","server":h,"server_port":port,"password":pass,"tls":tls});
    if let Some(t) = q.get("obfs").filter(|s| !s.is_empty() && *s != "none") {
        o["obfs"] =
            json!({"type": t, "password": q.get("obfs-password").cloned().unwrap_or_default()});
    }
    if let Some(m) = q.get("mport").filter(|s| !s.is_empty()) {
        o["server_ports"] = json!(m
            .split(',')
            .map(|x| x.replace('-', ":"))
            .collect::<Vec<_>>());
        if let Some(m) = o.as_object_mut() {
            m.remove("server_port");
        }
    }
    Ok((o, frag(&u, &h, port), format!("{h}:{port}")))
}

fn tuic(l: &str) -> Result<Parsed> {
    let u = Url::parse(l).context("invalid link")?;
    let (h, p) = host_port(&u)?;
    let q = q_of(&u);
    let cc = q
        .get("congestion_control")
        .cloned()
        .unwrap_or_else(|| "bbr".into());
    let um = q
        .get("udp_relay_mode")
        .cloned()
        .unwrap_or_else(|| "native".into());
    let mut o = json!({
        "type":"tuic","tag":"proxy","server":h,"server_port":p,
        "uuid":pdec(u.username()),"password":pdec(u.password().unwrap_or("")),
        "congestion_control":cc,"udp_relay_mode":um,
    });
    if let Some(t) = tls_block(&q, true) {
        o["tls"] = t;
    }
    Ok((o, frag(&u, &h, p), format!("{h}:{p}")))
}

/// Build the sing-box outbound for a stored link or raw JSON outbound.
pub fn outbound(link: &str) -> Result<(Kind, Value, String, String)> {
    let trimmed = link.trim();
    if trimmed.starts_with('{') {
        if let Ok(mut ob) = serde_json::from_str::<Value>(trimmed) {
            let ty = ob["type"].as_str().unwrap_or("").to_ascii_lowercase();
            let k = match ty.as_str() {
                "vless" => Kind::Vless,
                "vmess" => Kind::Vmess,
                "trojan" => Kind::Trojan,
                "shadowsocks" | "ss" => Kind::Ss,
                "hysteria2" | "hy2" => Kind::Hy2,
                "tuic" => Kind::Tuic,
                _ => bail!("unsupported sing-box outbound type '{ty}'"),
            };
            let name = ob["tag"].as_str().unwrap_or("proxy").to_string();
            let srv = ob["server"].as_str().unwrap_or("");
            let port = ob["server_port"].as_u64().unwrap_or(443);
            let server_str = format!("{srv}:{port}");
            ob["tag"] = json!("proxy");
            return Ok((k, ob, name, server_str));
        }
    }
    let scheme = link.split("://").next().unwrap_or("").to_ascii_lowercase();
    let (k, (o, n, s)) = match scheme.as_str() {
        "vless" => (Kind::Vless, uri_proxy(link, Kind::Vless)?),
        "trojan" => (Kind::Trojan, uri_proxy(link, Kind::Trojan)?),
        "vmess" => (Kind::Vmess, vmess(link)?),
        "ss" => (Kind::Ss, shadowsocks(link)?),
        "hy2" | "hysteria2" => (Kind::Hy2, hy2(link)?),
        "tuic" => (Kind::Tuic, tuic(link)?),
        _ => bail!("unsupported link scheme '{scheme}://'"),
    };
    Ok((k, o, n, s))
}

fn parse_link(l: &str) -> Result<Vec<Profile>> {
    let l = l.trim();
    if l.to_ascii_lowercase().starts_with("vpn://") {
        return amnezia(l);
    }
    if let Ok(profs) = crate::parser::parse_any(l) {
        if !profs.is_empty() {
            return Ok(profs);
        }
    }
    let (k, _, name, server) = outbound(l)?;
    let mut p = Profile {
        id: String::new(),
        name,
        kind: k,
        server,
        data: l.to_string(),
        ..Default::default()
    };
    p.populate_metadata();
    Ok(vec![p])
}

// ───────────────────────── profile helpers ─────────────────────────

pub fn rename(id: &str, name: &str) -> Result<()> {
    let name = name.trim();
    if name.is_empty() {
        bail!("name cannot be empty");
    }
    let mut p = load_all()
        .into_iter()
        .find(|p| p.id == id)
        .ok_or_else(|| anyhow!("profile not found"))?;
    p.name = name.to_string();
    save(&p)
}

pub fn set_auth(id: &str, username: String, password: String) -> Result<()> {
    let mut p = load_all()
        .into_iter()
        .find(|p| p.id == id)
        .ok_or_else(|| anyhow!("profile not found"))?;
    p.auth = Some(Auth {
        username,
        password,
        save: true,
    });
    save(&p)
}

pub fn clear_auth(id: &str) -> Result<()> {
    let mut p = load_all()
        .into_iter()
        .find(|p| p.id == id)
        .ok_or_else(|| anyhow!("profile not found"))?;
    p.auth = None;
    save(&p)
}

pub fn set_last(id: &str) {
    let _ = fs::write(format!("{ROOT}/last"), id);
}

pub fn last() -> Option<String> {
    fs::read_to_string(format!("{ROOT}/last"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Human-readable facts about a profile (transport, security, endpoint…) for the details pane.
pub fn details(p: &Profile) -> Vec<(&'static str, String)> {
    let mut v: Vec<(&'static str, String)> = vec![];
    v.push(("transport", p.display_transport()));
    v.push(("security", p.display_security()));
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
    if p.kind.is_singbox() {
        if let Ok((_, ob, _, _)) = outbound(&p.data) {
            let s = |x: &Value| x.as_str().map(String::from);
            if let Some(x) = s(&ob["flow"]) {
                v.push(("flow", x));
            }
            if let Some(x) = s(&ob["method"]) {
                v.push(("cipher", x));
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

// ───────────────────── subscription / files / amnezia ─────────────────────

fn import_sub(url: &str) -> Result<Vec<Profile>> {
    let out = Command::new("curl")
        .args(["-fsSL", "--max-time", "20", "-A", "vortex/0.1", url])
        .output()
        .context("curl not found")?;
    if !out.status.success() {
        bail!("could not download the subscription");
    }
    let mut text = String::from_utf8_lossy(&out.stdout).to_string();
    if !text.contains("://") {
        if let Ok(d) = b64(text.trim()) {
            text = String::from_utf8_lossy(&d).to_string();
        }
    }
    let mut v = vec![];
    for l in text.lines() {
        let l = l.trim();
        if l.contains("://") {
            if let Ok(mut p) = parse_link(l) {
                v.append(&mut p);
            }
        }
    }
    if v.is_empty() {
        bail!("no supported links found in subscription");
    }
    Ok(v)
}

const AWG_KEYS: [&str; 12] = [
    "Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "I1",
];

fn kv_find(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|l| {
        let (k, v) = l.split_once('=')?;
        k.trim()
            .eq_ignore_ascii_case(key)
            .then(|| v.trim().to_string())
    })
}

fn ovpn_server(text: &str) -> String {
    text.lines()
        .find(|l| l.trim_start().starts_with("remote "))
        .map(|l| {
            l.split_whitespace()
                .skip(1)
                .take(2)
                .collect::<Vec<_>>()
                .join(":")
        })
        .unwrap_or_default()
}

fn inline_ovpn(text: &str, dir: &Path) -> String {
    let mut out = String::new();
    for line in text.lines() {
        let mut it = line.split_whitespace();
        let key = it.next().unwrap_or("");
        let tag = match key {
            "ca" | "cert" | "key" | "tls-crypt" | "tls-auth" | "crl-verify" => key,
            _ => "",
        };
        if !tag.is_empty() {
            if let Some(f) = it.next() {
                if let Ok(c) = fs::read_to_string(dir.join(f)) {
                    out += &format!("<{tag}>\n{}\n</{tag}>\n", c.trim());
                    if tag == "tls-auth" {
                        if let Some(d) = it.next() {
                            out += &format!("key-direction {d}\n");
                        }
                    }
                    continue;
                }
            }
        }
        out += line;
        out.push('\n');
    }
    out
}

fn import_file(s: &str) -> Result<Profile> {
    let p = expand(s);
    let text = fs::read_to_string(&p).with_context(|| format!("cannot read {}", p.display()))?;
    let name = p
        .file_stem()
        .and_then(|x| x.to_str())
        .unwrap_or("profile")
        .to_string();

    if let Ok(parsed) = crate::parser::parse_any(s) {
        if let Some(mut first) = parsed.into_iter().next() {
            if first.name == "Config · WireGuard" || first.name == "Config · OpenVPN" {
                first.name = name;
            }
            first.populate_metadata();
            return Ok(first);
        }
    }

    if text.contains("[Interface]") {
        let awg = AWG_KEYS.iter().any(|k| kv_find(&text, k).is_some());
        let mut prof = Profile {
            id: String::new(),
            name,
            kind: if awg { Kind::Awg } else { Kind::Wg },
            server: kv_find(&text, "Endpoint").unwrap_or_default(),
            data: text,
            ..Default::default()
        };
        prof.populate_metadata();
        return Ok(prof);
    }
    if text.lines().any(|l| {
        let t = l.trim_start();
        t.starts_with("remote ") || t.starts_with("remote\t")
    }) {
        let dir = p.parent().unwrap_or(Path::new("."));
        let data = inline_ovpn(&text, dir);
        let mut prof = Profile {
            id: String::new(),
            name,
            kind: Kind::Ovpn,
            server: ovpn_server(&data),
            data,
            ..Default::default()
        };
        prof.populate_metadata();
        return Ok(prof);
    }
    bail!("unrecognized file (expected WireGuard, AmneziaWG, OpenVPN, or sing-box config)")
}

/// vpn:// = base64url( qCompress(json) ) — 4 byte BE length + zlib stream.
fn amnezia(l: &str) -> Result<Vec<Profile>> {
    let raw = b64(&l["vpn://".len()..])?;
    if raw.len() < 5 {
        bail!("bad Amnezia link");
    }
    let mut js = String::new();
    flate2::read::ZlibDecoder::new(&raw[4..])
        .read_to_string(&mut js)
        .context("bad Amnezia payload")?;
    let v: Value = serde_json::from_str(&js)?;
    let desc = v["description"]
        .as_str()
        .filter(|s| !s.is_empty())
        .unwrap_or("amnezia")
        .to_string();
    let mut out = vec![];
    for c in v["containers"].as_array().into_iter().flatten() {
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
        let cfg = serde_json::from_str::<Value>(lc)
            .ok()
            .and_then(|j| j["config"].as_str().map(String::from))
            .or_else(|| {
                Some(lc.to_string()).filter(|s| s.contains("[Interface]") || s.contains("remote "))
            });
        if let Some(cfg) = cfg {
            let server = if kind == Kind::Ovpn {
                ovpn_server(&cfg)
            } else {
                kv_find(&cfg, "Endpoint").unwrap_or_default()
            };
            out.push(Profile {
                id: String::new(),
                name: format!("{desc} · {}", kind.tag()),
                kind,
                server,
                data: cfg,
                ..Default::default()
            });
        }
    }
    if out.is_empty() {
        bail!("Amnezia link has no AWG/WireGuard/OpenVPN container (Xray/Cloak/SS containers aren't supported yet)");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        use std::io::Write;
        let inner = json!({"config": "[Interface]\nPrivateKey = a=\nJc = 4\n[Peer]\nEndpoint = 1.2.3.4:5555\n"}).to_string();
        let payload = json!({"description":"AmnTest","containers":[{"container":"amnezia-awg","awg":{"last_config": inner}}]}).to_string();
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(payload.as_bytes()).unwrap();
        let mut raw = (payload.len() as u32).to_be_bytes().to_vec();
        raw.extend(z.finish().unwrap());
        let link = format!("vpn://{}", b::URL_SAFE_NO_PAD.encode(raw));
        let v = parse_link(&link).unwrap();
        assert_eq!(v[0].kind, Kind::Awg);
        assert_eq!(v[0].server, "1.2.3.4:5555");
    }

    #[test]
    fn wg_vs_awg_files() {
        let dir = std::env::temp_dir();
        let a = dir.join("vx_wg.conf");
        fs::write(&a, "[Interface]\nPrivateKey = x\n[Peer]\nEndpoint = h:1\n").unwrap();
        assert_eq!(import_file(a.to_str().unwrap()).unwrap().kind, Kind::Wg);
        let b2 = dir.join("vx_awg.conf");
        fs::write(
            &b2,
            "[Interface]\nPrivateKey = x\nJc = 5\nS1 = 3\n[Peer]\nEndpoint = h:1\n",
        )
        .unwrap();
        assert_eq!(import_file(b2.to_str().unwrap()).unwrap().kind, Kind::Awg);
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
        let profs = parse_raw_config(wg_text).unwrap();
        assert_eq!(profs.len(), 1);
        assert_eq!(profs[0].kind, Kind::Wg);
        assert_eq!(profs[0].server, "198.51.100.1:51820");

        let awg_text = "[Interface]\nPrivateKey = a=\nJc = 4\n[Peer]\nEndpoint = 198.51.100.2:51820\nPublicKey = b=\n";
        let profs2 = parse_raw_config(awg_text).unwrap();
        assert_eq!(profs2[0].kind, Kind::Awg);

        let ovpn_text = "client\ndev tun\nremote 198.51.100.3 1194\n";
        let profs3 = parse_raw_config(ovpn_text).unwrap();
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

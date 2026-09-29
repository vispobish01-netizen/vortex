use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose as b, Engine};
use serde::{Deserialize, Serialize};
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

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Vless,
    Vmess,
    Trojan,
    Ss,
    Hy2,
    Tuic,
    Wg,
    Awg,
    Ovpn,
}

impl Kind {
    pub fn tag(self) -> &'static str {
        match self {
            Kind::Vless => "VLESS",
            Kind::Vmess => "VMESS",
            Kind::Trojan => "TROJAN",
            Kind::Ss => "SS",
            Kind::Hy2 => "HY2",
            Kind::Tuic => "TUIC",
            Kind::Wg => "WG",
            Kind::Awg => "AWG",
            Kind::Ovpn => "OVPN",
        }
    }
    pub fn padded_tag(self) -> &'static str {
        match self {
            Kind::Vless => "VLESS ",
            Kind::Vmess => "VMESS ",
            Kind::Trojan => "TROJAN",
            Kind::Ss => "SS    ",
            Kind::Hy2 => "HY2   ",
            Kind::Tuic => "TUIC  ",
            Kind::Wg => "WG    ",
            Kind::Awg => "AWG   ",
            Kind::Ovpn => "OVPN  ",
        }
    }
    /// Protocols that run inside the sing-box core (link based).
    pub fn is_singbox(self) -> bool {
        !matches!(self, Kind::Wg | Kind::Awg | Kind::Ovpn)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Auth {
    pub username: String,
    pub password: String,
    #[serde(default = "default_true")]
    pub save: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub kind: Kind,
    pub server: String,
    /// share link (sing-box kinds) or the raw config text (wg / awg / ovpn)
    pub data: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<Auth>,
}

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
    fs::create_dir_all(STORE)?;
    fs::set_permissions(ROOT, fs::Permissions::from_mode(0o700))?;
    fs::create_dir_all(crate::tunnel::RUN)?;
    fs::set_permissions(crate::tunnel::RUN, fs::Permissions::from_mode(0o700))?;
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
    v.sort_by(|a, b| a.name.bytes().map(|c| c.to_ascii_lowercase()).cmp(b.name.bytes().map(|c| c.to_ascii_lowercase())));
    v
}

pub fn save(p: &Profile) -> Result<()> {
    let path = Path::new(STORE).join(format!("{}.json", p.id));
    fs::write(&path, serde_json::to_string_pretty(p)?)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

pub fn remove(id: &str) -> Result<()> {
    fs::remove_file(Path::new(STORE).join(format!("{id}.json")))?;
    Ok(())
}

fn slug(s: &str) -> String {
    let o: String = s
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' })
        .collect();
    let mut o = o.split('-').filter(|x| !x.is_empty()).collect::<Vec<_>>().join("-");
    if o.is_empty() {
        o = "profile".into();
    }
    o.truncate(24);
    o
}

/// Import anything the user can paste: link(s), subscription URL, config file path.
/// Returns how many *new* profiles were stored.
pub fn import(input: &str) -> Result<usize> {
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
    Ok(vec![import_file(s)?])
}

// ───────────────────────── helpers ─────────────────────────

fn pdec(s: &str) -> String {
    percent_encoding::percent_decode_str(s).decode_utf8_lossy().to_string()
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
    u.query_pairs().map(|(k, v)| (k.to_string(), v.to_string())).collect()
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
    keys.iter().any(|k| q.get(*k).map(|v| v == "1" || v == "true").unwrap_or(false))
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
    if let Some(s) = q.get("sni").or_else(|| q.get("peer")).filter(|s| !s.is_empty()) {
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
    let norm = |p: &str| if p.is_empty() { "/".to_string() } else { p.to_string() };
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
        other => bail!("transport '{other}' is not supported by sing-box"),
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
            let scy = if s("scy").is_empty() { "auto".to_string() } else { s("scy") };
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
            q.insert("security".into(), if s("tls") == "tls" { "tls".into() } else { "none".into() });
            q.insert("sni".into(), s("sni"));
            q.insert("alpn".into(), s("alpn"));
            q.insert("fp".into(), s("fp"));
            if let Some(t) = tls_block(&q, false) {
                o["tls"] = t;
            }
            if let Some(t) = transport(&q)? {
                o["transport"] = t;
            }
            let name = if s("ps").is_empty() { format!("{h}:{port}") } else { s("ps") };
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
        let ui = if ui.contains(':') { pdec(ui) } else { String::from_utf8(b64(&pdec(ui))?)? };
        (ui, hp.to_string())
    } else {
        let d = String::from_utf8(b64(rest)?)?;
        let (ui, hp) = d.rsplit_once('@').ok_or_else(|| anyhow!("bad ss link"))?;
        (ui.to_string(), hp.to_string())
    };
    let (method, pass) = userinfo.split_once(':').ok_or_else(|| anyhow!("bad ss credentials"))?;
    let (h, p) = hostport.rsplit_once(':').ok_or_else(|| anyhow!("bad ss host"))?;
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
        o["obfs"] = json!({"type": t, "password": q.get("obfs-password").cloned().unwrap_or_default()});
    }
    if let Some(m) = q.get("mport").filter(|s| !s.is_empty()) {
        o["server_ports"] = json!(m.split(',').map(|x| x.replace('-', ":")).collect::<Vec<_>>());
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
    let cc = q.get("congestion_control").cloned().unwrap_or_else(|| "bbr".into());
    let um = q.get("udp_relay_mode").cloned().unwrap_or_else(|| "native".into());
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

/// Build the sing-box outbound for a stored link.
pub fn outbound(link: &str) -> Result<(Kind, Value, String, String)> {
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
    let (k, _, name, server) = outbound(l)?;
    Ok(vec![Profile { id: String::new(), name, kind: k, server, data: l.to_string(), auth: None }])
}


// ───────────────────────── profile helpers ─────────────────────────

pub fn rename(id: &str, name: &str) -> Result<()> {
    let name = name.trim();
    if name.is_empty() {
        bail!("name cannot be empty");
    }
    let mut p = load_all().into_iter().find(|p| p.id == id).ok_or_else(|| anyhow!("profile not found"))?;
    p.name = name.to_string();
    save(&p)
}

pub fn set_auth(id: &str, username: String, password: String) -> Result<()> {
    let mut p = load_all().into_iter().find(|p| p.id == id).ok_or_else(|| anyhow!("profile not found"))?;
    p.auth = Some(Auth {
        username,
        password,
        save: true,
    });
    save(&p)
}

pub fn clear_auth(id: &str) -> Result<()> {
    let mut p = load_all().into_iter().find(|p| p.id == id).ok_or_else(|| anyhow!("profile not found"))?;
    p.auth = None;
    save(&p)
}

pub fn set_last(id: &str) {
    let _ = fs::write(format!("{ROOT}/last"), id);
}

pub fn last() -> Option<String> {
    fs::read_to_string(format!("{ROOT}/last")).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

/// Human-readable facts about a profile (transport, security, endpoint…) for the details pane.
pub fn details(p: &Profile) -> Vec<(&'static str, String)> {
    let mut v: Vec<(&'static str, String)> = vec![];
    if p.kind.is_singbox() {
        if let Ok((_, ob, _, _)) = outbound(&p.data) {
            let s = |x: &Value| x.as_str().map(String::from);
            v.push(("transport", s(&ob["transport"]["type"]).unwrap_or_else(|| "tcp".into())));
            let sec = if ob["tls"]["reality"]["enabled"].as_bool() == Some(true) {
                "reality"
            } else if ob["tls"]["enabled"].as_bool() == Some(true) {
                "tls"
            } else {
                "none"
            };
            v.push(("security", sec.into()));
            if let Some(x) = s(&ob["tls"]["server_name"]) {
                v.push(("sni", x));
            }
            if let Some(x) = s(&ob["flow"]) {
                v.push(("flow", x));
            }
            if let Some(x) = s(&ob["method"]) {
                v.push(("cipher", x));
            }
            if let Some(x) = s(&ob["obfs"]["type"]) {
                v.push(("obfs", x));
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
        v.dedup_by_key(|x| x.0);
    }
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

const AWG_KEYS: [&str; 12] = ["Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "I1"];

fn kv_find(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|l| {
        let (k, v) = l.split_once('=')?;
        k.trim().eq_ignore_ascii_case(key).then(|| v.trim().to_string())
    })
}

fn ovpn_server(text: &str) -> String {
    text.lines()
        .find(|l| l.trim_start().starts_with("remote "))
        .map(|l| l.split_whitespace().skip(1).take(2).collect::<Vec<_>>().join(":"))
        .unwrap_or_default()
}

fn inline_ovpn(text: &str, dir: &Path) -> String {
    let mut out = String::new();
    for line in text.lines() {
        let mut it = line.trim().split_whitespace();
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
    let name = p.file_stem().and_then(|x| x.to_str()).unwrap_or("profile").to_string();
    if text.contains("[Interface]") {
        let awg = AWG_KEYS.iter().any(|k| kv_find(&text, k).is_some());
        return Ok(Profile {
            id: String::new(),
            name,
            kind: if awg { Kind::Awg } else { Kind::Wg },
            server: kv_find(&text, "Endpoint").unwrap_or_default(),
            data: text,
            auth: None,
        });
    }
    if text.lines().any(|l| l.trim_start().starts_with("remote ")) {
        let dir = p.parent().unwrap_or(Path::new("."));
        let data = inline_ovpn(&text, dir);
        return Ok(Profile { id: String::new(), name, kind: Kind::Ovpn, server: ovpn_server(&data), data, auth: None });
    }
    bail!("unrecognized file (expected WireGuard, AmneziaWG or OpenVPN config)")
}

/// vpn:// = base64url( qCompress(json) ) — 4 byte BE length + zlib stream.
fn amnezia(l: &str) -> Result<Vec<Profile>> {
    let raw = b64(&l["vpn://".len()..])?;
    if raw.len() < 5 {
        bail!("bad Amnezia link");
    }
    let mut js = String::new();
    flate2::read::ZlibDecoder::new(&raw[4..]).read_to_string(&mut js).context("bad Amnezia payload")?;
    let v: Value = serde_json::from_str(&js)?;
    let desc = v["description"].as_str().filter(|s| !s.is_empty()).unwrap_or("amnezia").to_string();
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
            .or_else(|| Some(lc.to_string()).filter(|s| s.contains("[Interface]") || s.contains("remote ")));
        if let Some(cfg) = cfg {
            let server = if kind == Kind::Ovpn { ovpn_server(&cfg) } else { kv_find(&cfg, "Endpoint").unwrap_or_default() };
            out.push(Profile {
                id: String::new(),
                name: format!("{desc} · {}", kind.tag()),
                kind,
                server,
                data: cfg,
                auth: None,
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
        let (k, o, _, _) = outbound("tuic://uid:pw@h.io:443?congestion_control=bbr&alpn=h3#U").unwrap();
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
        fs::write(&b2, "[Interface]\nPrivateKey = x\nJc = 5\nS1 = 3\n[Peer]\nEndpoint = h:1\n").unwrap();
        assert_eq!(import_file(b2.to_str().unwrap()).unwrap().kind, Kind::Awg);
    }

    #[test]
    fn test_padded_tags() {
        let kinds = [
            Kind::Vless, Kind::Vmess, Kind::Trojan, Kind::Ss,
            Kind::Hy2, Kind::Tuic, Kind::Wg, Kind::Awg, Kind::Ovpn,
        ];
        for k in kinds {
            assert_eq!(k.padded_tag().len(), 6, "padded_tag for {:?} must be exactly 6 bytes", k);
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
}

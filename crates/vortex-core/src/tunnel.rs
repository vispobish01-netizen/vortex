use crate::store::{outbound, Kind, Profile};
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Seek, SeekFrom, Write},
    net::IpAddr,
    os::unix::{fs::PermissionsExt, process::CommandExt},
    path::Path,
    process::{Command, Stdio},
    thread::sleep,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const RUN: &str = "/run/vortex";
const TUN_IF: &str = "vx0";

#[derive(Serialize, Deserialize, Clone)]
pub struct Session {
    pub id: String,
    pub name: String,
    pub kind: Kind,
    pub server: String,
    pub iface: String,
    pub pid: Option<u32>,
    pub since: u64,
    pub conf: String,
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn sess_path() -> String {
    format!("{RUN}/session.json")
}

fn write_session(s: &Session) -> Result<()> {
    let _ = fs::create_dir_all(RUN);
    let _ = fs::set_permissions(RUN, fs::Permissions::from_mode(0o755));
    let path = sess_path();
    fs::write(&path, serde_json::to_string(s)?)?;
    let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o644));
    Ok(())
}

fn write_secret(path: &str, content: &str) -> Result<()> {
    fs::write(path, content)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn have(bin: &str) -> bool {
    ["/usr/bin", "/usr/local/bin", "/bin", "/usr/sbin", "/sbin"]
        .iter()
        .any(|d| Path::new(d).join(bin).is_file())
}

fn need(bin: &str, pkg: &str) -> Result<()> {
    if have(bin) {
        Ok(())
    } else {
        bail!("`{bin}` not found — install {pkg}")
    }
}

fn proc_alive(pid: u32) -> bool {
    fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|s| {
            s.rsplit(')')
                .next()
                .and_then(|r| r.trim_start().chars().next())
        })
        .map(|c| c != 'Z')
        .unwrap_or(false)
}

fn ifaces() -> Vec<String> {
    fs::read_dir("/sys/class/net")
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect()
}

fn iface_exists(name: &str) -> bool {
    Path::new(&format!("/sys/class/net/{name}")).exists()
}

pub fn tail_log(n: usize) -> Vec<String> {
    let path = format!("{RUN}/core.log");
    let mut f = match fs::File::open(&path) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    let offset = len.saturating_sub(65536);
    if f.seek(SeekFrom::Start(offset)).is_err() {
        return Vec::new();
    }
    let mut buf = String::new();
    if f.read_to_string(&mut buf).is_err() {
        return Vec::new();
    }
    let lines: Vec<&str> = buf.lines().collect();
    let start = if offset > 0 && lines.len() > 1 { 1 } else { 0 };
    let valid_lines = &lines[start..];
    valid_lines[valid_lines.len().saturating_sub(n)..]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

fn last_lines(n: usize) -> String {
    tail_log(n).join("\n")
}

// ───────────────────────── session ─────────────────────────

fn read_session() -> Option<Session> {
    serde_json::from_str(&fs::read_to_string(sess_path()).ok()?).ok()
}

/// The active session, if its tunnel is actually still up.
pub fn load_session() -> Option<Session> {
    let s = read_session()?;
    let up = match s.pid {
        Some(p) => proc_alive(p),
        None => iface_exists(&s.iface),
    };
    if up {
        Some(s)
    } else {
        let _ = fs::remove_file(sess_path());
        None
    }
}

pub fn bytes(iface: &str) -> Option<(u64, u64)> {
    let r = |f: &str| -> Option<u64> {
        fs::read_to_string(format!("/sys/class/net/{iface}/statistics/{f}"))
            .ok()?
            .trim()
            .parse()
            .ok()
    };
    Some((r("rx_bytes")?, r("tx_bytes")?))
}

pub fn public_ip() -> String {
    Command::new("curl")
        .args(["-s", "--max-time", "6", "https://ipinfo.io/json"])
        .output()
        .ok()
        .and_then(|o| serde_json::from_slice::<Value>(&o.stdout).ok())
        .and_then(|v| {
            let ip = v["ip"].as_str()?;
            Some(
                format!("{ip}  {}", v["country"].as_str().unwrap_or(""))
                    .trim()
                    .to_string(),
            )
        })
        .unwrap_or_else(|| "unreachable".into())
}

pub use crate::model::ActiveFlow;

pub fn active_flows() -> Vec<ActiveFlow> {
    // 1. Try sing-box clash_api controller at 127.0.0.1:9090/connections
    if let Ok(o) = Command::new("curl")
        .args(["-s", "--max-time", "1", "http://127.0.0.1:9090/connections"])
        .output()
    {
        if o.status.success() {
            if let Ok(val) = serde_json::from_slice::<Value>(&o.stdout) {
                if let Some(conns) = val["connections"].as_array() {
                    let mut flows = vec![];
                    for c in conns {
                        let id = c["id"].as_str().unwrap_or("").to_string();
                        let net = c["metadata"]["network"]
                            .as_str()
                            .unwrap_or("tcp")
                            .to_string();
                        let host = c["metadata"]["host"].as_str().unwrap_or("").to_string();
                        let dst_ip = c["metadata"]["destinationIP"].as_str().unwrap_or("");
                        let dst_p = c["metadata"]["destinationPort"].as_str().unwrap_or("");
                        let destination = if !dst_ip.is_empty() {
                            format!("{dst_ip}:{dst_p}")
                        } else {
                            host.clone()
                        };
                        let src_ip = c["metadata"]["sourceIP"].as_str().unwrap_or("");
                        let src_p = c["metadata"]["sourcePort"].as_str().unwrap_or("");
                        let source = format!("{src_ip}:{src_p}");
                        let proc_path = c["metadata"]["processPath"].as_str().unwrap_or("");
                        let process = if !proc_path.is_empty() {
                            proc_path
                                .rsplit('/')
                                .next()
                                .unwrap_or(proc_path)
                                .to_string()
                        } else {
                            "system".to_string()
                        };
                        let upload = c["upload"].as_u64().unwrap_or(0);
                        let download = c["download"].as_u64().unwrap_or(0);

                        flows.push(ActiveFlow {
                            id,
                            network: net,
                            host,
                            destination,
                            source,
                            process,
                            upload,
                            download,
                        });
                    }
                    if !flows.is_empty() {
                        return flows;
                    }
                }
            }
        }
    }

    // 2. Fallback: Parse active established connections via `ss -ntp state established`
    let mut flows = vec![];
    if let Ok(o) = Command::new("ss")
        .args(["-ntp", "state", "established"])
        .output()
    {
        if o.status.success() {
            let text = String::from_utf8_lossy(&o.stdout);
            for l in text.lines().skip(1) {
                let parts: Vec<&str> = l.split_whitespace().collect();
                if parts.len() >= 4 {
                    let local = parts.get(2).unwrap_or(&"");
                    let peer = parts.get(3).unwrap_or(&"");
                    let proc_info = parts.get(4).unwrap_or(&"");
                    let proc_name = if let Some((_, rest)) = proc_info.split_once("users:((\"") {
                        rest.split_once('"').map(|(n, _)| n).unwrap_or("unknown")
                    } else {
                        "kernel"
                    };

                    flows.push(ActiveFlow {
                        id: format!("{local}->{peer}"),
                        network: "tcp".into(),
                        host: "".into(),
                        destination: peer.to_string(),
                        source: local.to_string(),
                        process: proc_name.to_string(),
                        upload: 0,
                        download: 0,
                    });
                }
            }
        }
    }
    flows
}

// ───────────────────────── connect / disconnect ─────────────────────────

#[derive(Clone, Debug)]
pub struct Credentials {
    pub username: String,
    pub password: String,
    pub save: bool,
}

pub fn ovpn_needs_auth(p: &Profile) -> bool {
    p.kind == Kind::Ovpn
        && (p.data.lines().any(|l| {
            let t = l.trim();
            t == "auth-user-pass"
                || t.starts_with("auth-user-pass ")
                || t.starts_with("auth-user-pass\t")
        }) || p.data.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----")
            || p.data.contains("Proc-Type: 4,ENCRYPTED"))
}

pub fn prompt_ovpn_credentials(default_user: Option<&str>) -> Result<Credentials> {
    let mut tty = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")?;
    writeln!(tty, "\n[vortex] OpenVPN Credentials Required")?;
    if let Some(du) = default_user.filter(|s| !s.is_empty()) {
        write!(tty, "Username [{du}]: ")?;
    } else {
        write!(tty, "Username: ")?;
    }
    tty.flush()?;
    let mut user = String::new();
    let mut reader = BufReader::new(tty.try_clone()?);
    reader.read_line(&mut user)?;
    let mut user = user.trim().to_string();
    if user.is_empty() {
        if let Some(du) = default_user {
            user = du.to_string();
        }
    }
    write!(tty, "Password: ")?;
    tty.flush()?;
    let _ = Command::new("stty")
        .args(["-F", "/dev/tty", "-echo"])
        .status();
    let mut pass = String::new();
    reader.read_line(&mut pass)?;
    let _ = Command::new("stty")
        .args(["-F", "/dev/tty", "echo"])
        .status();
    writeln!(tty)?;
    let pass = pass.trim_end().to_string();
    if user.is_empty() || pass.is_empty() {
        bail!("OpenVPN username and password cannot be empty");
    }
    write!(tty, "Save credentials for this profile? [Y/n]: ")?;
    tty.flush()?;
    let mut save_str = String::new();
    reader.read_line(&mut save_str)?;
    let s = save_str.trim().to_lowercase();
    let save = s.is_empty() || s == "y" || s == "yes";
    Ok(Credentials {
        username: user,
        password: pass,
        save,
    })
}

pub fn connect_with_credentials(p: &Profile, credentials: Option<(&str, &str)>) -> Result<Session> {
    let _ = disconnect();
    let mut s = if p.kind.is_singbox() {
        up_singbox(p)?
    } else if p.kind == Kind::Ovpn {
        up_ovpn(p, credentials)?
    } else {
        up_wg(p)?
    };
    s.since = now();
    write_session(&s)?;
    crate::store::set_last(&s.id);
    if crate::shield::is_enabled_preference() {
        let _ = crate::shield::arm(Some(&s.iface), Some(&s.server));
    }
    Ok(s)
}

pub fn disconnect() -> Result<()> {
    let Some(s) = read_session() else {
        return Ok(());
    };
    match s.kind {
        Kind::Wg | Kind::Awg => {
            let quick = if s.kind == Kind::Awg {
                "awg-quick"
            } else {
                "wg-quick"
            };
            let _ = Command::new(quick).args(["down", &s.conf]).output();
        }
        _ => {
            if let Some(pid) = s.pid {
                kill(pid);
            }
        }
    }
    let _ = fs::remove_file(&s.conf);
    let _ = fs::remove_file(sess_path());
    if crate::shield::is_armed() && !crate::shield::is_enabled_preference() {
        let _ = crate::shield::disarm();
    }
    Ok(())
}

fn kill(pid: u32) {
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }
    for _ in 0..40 {
        if !proc_alive(pid) {
            return;
        }
        sleep(Duration::from_millis(100));
    }
    unsafe {
        libc::kill(pid as i32, libc::SIGKILL);
    }
}

fn spawn_detached(cmd: &mut Command, log: fs::File) -> Result<u32> {
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log))
        .spawn()?;
    Ok(child.id())
}

fn session(p: &Profile, iface: &str, pid: Option<u32>, conf: &str) -> Session {
    Session {
        id: p.id.clone(),
        name: p.name.clone(),
        kind: p.kind,
        server: p.server.clone(),
        iface: iface.to_string(),
        pid,
        since: now(),
        conf: conf.to_string(),
    }
}

pub const PROXY_PORT: u16 = 1080;
pub const ROUTING_FILE: &str = "/etc/vortex/routing.json";

pub use crate::model::RoutingConfig;

pub fn load_routing() -> RoutingConfig {
    fs::read_to_string(ROUTING_FILE)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save_routing(cfg: &RoutingConfig) -> Result<()> {
    fs::write(ROUTING_FILE, serde_json::to_string_pretty(cfg)?)?;
    Ok(())
}

fn up_singbox(p: &Profile) -> Result<Session> {
    need("sing-box", "sing-box (pacman -S sing-box)")?;
    let (_, ob, _, _) = outbound(&p.data)?;
    let logp = format!("{RUN}/core.log");
    let rules_cfg = crate::routing::RulesConfig::load();
    let mut rules = rules_cfg.to_singbox_rules();

    let legacy_routing = load_routing();
    if !legacy_routing.blocked_domains.is_empty() {
        rules.push(json!({
            "domain_suffix": legacy_routing.blocked_domains,
            "action": "reject"
        }));
    }

    if !legacy_routing.direct_domains.is_empty() {
        rules.push(json!({
            "domain_suffix": legacy_routing.direct_domains,
            "outbound": "direct"
        }));
    }

    let cfg = json!({
        "log": {"level": "warn", "timestamp": true, "output": logp},
        "dns": {
            "servers": [
                {"type": "udp", "tag": "bootstrap", "server": "1.1.1.1"},
                {"type": "udp", "tag": "bootstrap-backup", "server": "8.8.8.8"},
                {"type": "https", "tag": "remote", "server": "1.1.1.1", "detour": "proxy"}
            ],
            "final": "remote",
            "strategy": "ipv4_only",
            "cache_capacity": 4096
        },
        "inbounds": [
            {
                "type": "tun", "tag": "tun-in", "interface_name": TUN_IF,
                "address": ["172.19.0.1/30"],
                "mtu": 9000,
                "auto_route": true, "auto_redirect": true, "strict_route": true, "stack": "mixed",
                "endpoint_independent_nat": true
            },
            {
                "type": "mixed", "tag": "mixed-in",
                "listen": "127.0.0.1", "listen_port": PROXY_PORT
            }
        ],
        "outbounds": [ob, {"type": "direct", "tag": "direct"}],
        "route": {
            "auto_detect_interface": true,
            "default_domain_resolver": "bootstrap",
            "final": "proxy",
            "rules": rules
        },
        "experimental": {
            "clash_api": {
                "external_controller": "127.0.0.1:9090",
                "secret": ""
            }
        }
    });
    let path = format!("{RUN}/singbox.json");
    write_secret(&path, &serde_json::to_string_pretty(&cfg)?)?;
    let chk = Command::new("sing-box")
        .args(["check", "-c", &path])
        .output()?;
    if !chk.status.success() {
        let e = String::from_utf8_lossy(&chk.stderr);
        bail!(
            "sing-box rejected the config: {}",
            e.trim().lines().last().unwrap_or("unknown error")
        );
    }
    let log = fs::File::create(&logp)?;
    let pid = spawn_detached(Command::new("sing-box").args(["run", "-c", &path]), log)?;
    for _ in 0..100 {
        if !proc_alive(pid) {
            bail!("sing-box exited: {}", last_lines(3));
        }
        if iface_exists(TUN_IF) {
            let route_ok = Command::new("ip")
                .args(["route", "show", "dev", TUN_IF])
                .output()
                .map(|o| {
                    o.status.success() && !String::from_utf8_lossy(&o.stdout).trim().is_empty()
                })
                .unwrap_or(false);
            if route_ok {
                return Ok(session(p, TUN_IF, Some(pid), &path));
            }
        }
        sleep(Duration::from_millis(50));
    }
    kill(pid);
    bail!("timed out waiting for the tunnel interface")
}

// ───────────────────────── wireguard / amneziawg ─────────────────────────

fn up_wg(p: &Profile) -> Result<Session> {
    let awg = p.kind == Kind::Awg;
    let (quick, iface) = if awg {
        ("awg-quick", "vxawg0")
    } else {
        ("wg-quick", "vxwg0")
    };
    need(
        quick,
        if awg {
            "amneziawg-tools (AUR)"
        } else {
            "wireguard-tools"
        },
    )?;
    let mut conf = p.data.clone();
    let mut dns: Option<String> = None;
    if !have("resolvconf") {
        // no resolvconf: strip DNS= and apply it with resolvectl afterwards
        let mut kept = vec![];
        for l in conf.lines() {
            if let Some((k, v)) = l.split_once('=') {
                if k.trim().eq_ignore_ascii_case("dns") {
                    dns = Some(v.trim().to_string());
                    continue;
                }
            }
            kept.push(l);
        }
        conf = kept.join("\n");
    }
    let path = format!("{RUN}/{iface}.conf");
    write_secret(&path, &conf)?;
    let out = Command::new(quick).args(["up", &path]).output()?;
    if !out.status.success() {
        let _ = fs::remove_file(&path);
        let e = String::from_utf8_lossy(&out.stderr);
        bail!(
            "{quick} failed: {}",
            e.trim().lines().last().unwrap_or("unknown error")
        );
    }
    if let Some(d) = dns {
        let servers: Vec<&str> = d
            .split(',')
            .map(str::trim)
            .filter(|x| x.parse::<IpAddr>().is_ok())
            .collect();
        if !servers.is_empty() && have("resolvectl") {
            let _ = Command::new("resolvectl")
                .arg("dns")
                .arg(iface)
                .args(&servers)
                .output();
            let _ = Command::new("resolvectl")
                .args(["domain", iface, "~."])
                .output();
        }
    }
    Ok(session(p, iface, None, &path))
}

// ───────────────────────── openvpn ─────────────────────────

fn up_ovpn(p: &Profile, credentials: Option<(&str, &str)>) -> Result<Session> {
    need("openvpn", "openvpn")?;
    let needs_auth = ovpn_needs_auth(p);
    let saved_creds = p
        .auth
        .as_ref()
        .map(|a| (a.username.as_str(), a.password.as_str()));
    let effective_creds = credentials.or(saved_creds);
    if needs_auth && effective_creds.is_none() {
        bail!("OpenVPN profile '{}' requires username and password (run `vortex auth {}` or connect with credentials)", p.name, p.name);
    }
    let conf = format!("{RUN}/ovpn.conf");
    let pidf = format!("{RUN}/ovpn.pid");
    let logp = format!("{RUN}/core.log");
    let authf = format!("{RUN}/ovpn.auth");

    // Cleanly strip existing auth-user-pass lines so --auth-user-pass controls auth
    let mut conf_content = String::new();
    for l in p.data.lines() {
        let t = l.trim();
        if t == "auth-user-pass"
            || t.starts_with("auth-user-pass ")
            || t.starts_with("auth-user-pass\t")
        {
            continue;
        }
        conf_content.push_str(l);
        conf_content.push('\n');
    }
    write_secret(&conf, &conf_content)?;

    if let Some((user, pass)) = effective_creds {
        write_secret(&authf, &format!("{user}\n{pass}\n"))?;
    }
    let _ = fs::remove_file(&pidf);
    let _ = fs::remove_file(&logp);
    let before = ifaces();
    let mut cmd = Command::new("openvpn");
    cmd.args([
        "--config",
        &conf,
        "--daemon",
        "vortex-ovpn",
        "--writepid",
        &pidf,
        "--log",
        &logp,
    ]);
    if effective_creds.is_some() {
        cmd.args(["--auth-user-pass", &authf]);
    }
    let out = cmd.output()?;
    if !out.status.success() {
        let _ = fs::remove_file(&authf);
        bail!(
            "openvpn failed to start: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let pid: Option<u32> = fs::read_to_string(&pidf)
        .ok()
        .and_then(|s| s.trim().parse().ok());
    for _ in 0..100 {
        let log = fs::read_to_string(&logp).unwrap_or_default();
        if log.contains("Initialization Sequence Completed") {
            let iface = ifaces()
                .into_iter()
                .find(|i| !before.contains(i) && (i.starts_with("tun") || i.starts_with("tap")))
                .unwrap_or_else(|| "tun0".into());
            if !iface_exists(&iface) {
                if let Some(pid) = pid {
                    kill(pid);
                }
                let _ = fs::remove_file(&authf);
                bail!("OpenVPN initialized but tunnel interface was not found");
            }
            let route_ok = Command::new("ip")
                .args(["route", "show", "dev", &iface])
                .output()
                .map(|o| {
                    o.status.success() && !String::from_utf8_lossy(&o.stdout).trim().is_empty()
                })
                .unwrap_or(false);
            if !route_ok {
                if let Some(pid) = pid {
                    kill(pid);
                }
                let _ = fs::remove_file(&authf);
                bail!("OpenVPN connected but no route was installed on {iface}");
            }
            let _ = fs::remove_file(&authf);
            return Ok(session(p, &iface, pid, &conf));
        }
        if log.contains("AUTH_FAILED") || log.contains("Exiting due to fatal error") {
            if let Some(pid) = pid {
                kill(pid);
            }
            let _ = fs::remove_file(&authf);
            bail!("openvpn: {}", last_lines(2).replace('\n', " · "));
        }
        sleep(Duration::from_millis(250));
    }
    if let Some(pid) = pid {
        kill(pid);
    }
    let _ = fs::remove_file(&authf);
    bail!("openvpn timed out waiting for connection")
}

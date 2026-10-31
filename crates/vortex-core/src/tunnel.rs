use crate::store::{outbound, Kind, Profile};
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Seek, SeekFrom, Write},
    net::IpAddr,
    os::unix::{fs::PermissionsExt, process::CommandExt},
    path::{Path, PathBuf},
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

pub fn active_run_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("VORTEX_RUN_DIR") {
        if !dir.is_empty() {
            let p = PathBuf::from(dir);
            let _ = fs::create_dir_all(&p);
            return p;
        }
    }
    let default_run = Path::new(RUN);
    if default_run.exists() {
        let probe = default_run.join(format!(".probe_{}", std::process::id()));
        if fs::write(&probe, b"1").is_ok() {
            let _ = fs::remove_file(probe);
            return default_run.to_path_buf();
        }
    } else if fs::create_dir_all(default_run).is_ok() {
        let _ = fs::set_permissions(default_run, fs::Permissions::from_mode(0o755));
        return default_run.to_path_buf();
    }
    if let Ok(dir) = std::env::var("XDG_RUNTIME_DIR") {
        if !dir.is_empty() {
            let user_run = PathBuf::from(dir).join("vortex");
            if fs::create_dir_all(&user_run).is_ok() {
                return user_run;
            }
        }
    }
    let tmp = PathBuf::from(format!("/tmp/vortex-{}", unsafe { libc::getuid() }));
    let _ = fs::create_dir_all(&tmp);
    tmp
}

pub fn run_path(file: &str) -> PathBuf {
    active_run_dir().join(file)
}

fn sess_path() -> PathBuf {
    run_path("session.json")
}

fn write_session(s: &Session) -> Result<()> {
    let path = sess_path();
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
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
    let path = run_path("core.log");
    let f = fs::File::open(&path).or_else(|_| fs::File::open(Path::new(RUN).join("core.log")));
    let mut f = match f {
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
    if let Ok(content) = fs::read_to_string(sess_path()) {
        if let Ok(s) = serde_json::from_str(&content) {
            return Some(s);
        }
    }
    let default_sess = Path::new(RUN).join("session.json");
    if default_sess != sess_path() {
        if let Ok(content) = fs::read_to_string(&default_sess) {
            if let Ok(s) = serde_json::from_str(&content) {
                return Some(s);
            }
        }
    }
    None
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
        let _ = fs::remove_file(Path::new(RUN).join("session.json"));
        None
    }
}

fn query_clash_traffic() -> Option<(u64, u64)> {
    use std::net::{SocketAddr, TcpStream};

    let addr: SocketAddr = "127.0.0.1:9090".parse().ok()?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(80)).ok()?;
    let _ = stream.set_read_timeout(Some(Duration::from_millis(150)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(80)));

    let req = b"GET /connections HTTP/1.1\r\nHost: 127.0.0.1:9090\r\nConnection: close\r\n\r\n";
    stream.write_all(req).ok()?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).ok()?;

    let body_start = response.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    let body = &response[body_start..];

    let val: Value = serde_json::from_slice(body).ok()?;
    let download = val["downloadTotal"].as_u64()?;
    let upload = val["uploadTotal"].as_u64()?;
    Some((download, upload))
}

fn query_xray_traffic() -> Option<(u64, u64)> {
    let r_dir = active_run_dir();
    let api_port = fs::read_to_string(r_dir.join("xray_api_port"))
        .ok()
        .and_then(|s| s.trim().parse::<u16>().ok())?;

    let xray_bin = crate::xray::resolve_xray_binary().ok()?;
    let output = Command::new(&xray_bin)
        .args([
            "api",
            "statsquery",
            &format!("--server=127.0.0.1:{api_port}"),
        ])
        .output()
        .ok()?;

    if output.status.success() {
        if let Ok(val) = serde_json::from_slice::<Value>(&output.stdout) {
            let mut rx = 0u64;
            let mut tx = 0u64;
            if let Some(stats) = val["stat"].as_array() {
                for s in stats {
                    let name = s["name"].as_str().unwrap_or("");
                    let value = s["value"].as_u64().unwrap_or(0);
                    if name.starts_with("outbound>>>") && !name.contains(">>>api>>>") {
                        if name.ends_with(">>>downlink") {
                            rx = rx.saturating_add(value);
                        } else if name.ends_with(">>>uplink") {
                            tx = tx.saturating_add(value);
                        }
                    }
                }
                return Some((rx, tx));
            }
        }
    }
    None
}

fn query_wg_traffic(iface: &str) -> Option<(u64, u64)> {
    let cmd = if iface.starts_with("awg") { "awg" } else { "wg" };
    if let Ok(out) = Command::new(cmd).args(["show", iface, "transfer"]).output() {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout);
            if let Some(line) = s.lines().next() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    let rx: u64 = parts[1].parse().unwrap_or(0);
                    let tx: u64 = parts[2].parse().unwrap_or(0);
                    return Some((rx, tx));
                }
            }
        }
    }
    None
}

pub fn bytes(iface: &str) -> Option<(u64, u64)> {
    // 1. If sysfs interface statistics exist, check them first
    if !iface.is_empty() && !iface.contains(':') && !iface.contains('/') {
        let r = |f: &str| -> Option<u64> {
            fs::read_to_string(format!("/sys/class/net/{iface}/statistics/{f}"))
                .ok()?
                .trim()
                .parse()
                .ok()
        };
        if let (Some(rx), Some(tx)) = (r("rx_bytes"), r("tx_bytes")) {
            if rx > 0 || tx > 0 {
                return Some((rx, tx));
            }
        }
    }

    // 2. Query sing-box Clash API (handles both Proxy Mode and TUN Mode)
    if let Some((rx, tx)) = query_clash_traffic() {
        if rx > 0 || tx > 0 || iface.contains(':') {
            return Some((rx, tx));
        }
    }

    // 3. Query Xray API if active
    if let Some((rx, tx)) = query_xray_traffic() {
        if rx > 0 || tx > 0 || iface.contains(':') {
            return Some((rx, tx));
        }
    }

    // 4. Query WireGuard / Amnezia CLI
    if iface.starts_with("wg") || iface.starts_with("awg") || iface == "vx0" {
        if let Some((rx, tx)) = query_wg_traffic(iface) {
            if rx > 0 || tx > 0 {
                return Some((rx, tx));
            }
        }
    }

    // 5. Fallback to sysfs even if 0
    if !iface.is_empty() && !iface.contains(':') && !iface.contains('/') {
        let r = |f: &str| -> Option<u64> {
            fs::read_to_string(format!("/sys/class/net/{iface}/statistics/{f}"))
                .ok()?
                .trim()
                .parse()
                .ok()
        };
        if let (Some(rx), Some(tx)) = (r("rx_bytes"), r("tx_bytes")) {
            return Some((rx, tx));
        }
    }

    // 6. Proxy mode (e.g. 127.0.0.1:1080) fallback when idle
    if iface.contains(':') {
        return Some((0, 0));
    }

    None
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
                            duration_secs: None,
                            rule: c["rule"].as_str().map(String::from),
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
                        duration_secs: None,
                        rule: None,
                    });
                }
            }
        }
    }
    flows
}

/// Terminates an active connection flow by ID via sing-box controller.
pub fn kill_flow(id: &str) -> Result<()> {
    if !id.is_empty() {
        let _ = Command::new("curl")
            .args([
                "-s",
                "-X",
                "DELETE",
                &format!("http://127.0.0.1:9090/connections/{id}"),
            ])
            .output();
    }
    Ok(())
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

pub fn up_xray(p: &Profile) -> Result<Session> {
    use crate::backend::Backend;
    let backend = crate::xray::XrayBackend::new();
    let r_dir = active_run_dir();
    backend.start(p, &r_dir)
}

pub fn connect_with_credentials(p: &Profile, credentials: Option<(&str, &str)>) -> Result<Session> {
    let _ = disconnect();
    let use_xray = p.kind == Kind::Xray
        || p.backend_type.as_deref() == Some("xray")
        || p.transport == crate::model::Transport::Xhttp
        || (p.kind.is_xray_capable()
            && (std::env::var("VORTEX_BACKEND")
                .map(|b| b.eq_ignore_ascii_case("xray"))
                .unwrap_or(false)
                || !have("sing-box")));

    let is_proxy_only = crate::storage::get_mode_preference().is_proxy()
        || p.backend_type.as_deref() == Some("proxy")
        || std::env::var("VORTEX_MODE")
            .map(|m| m.eq_ignore_ascii_case("proxy"))
            .unwrap_or(false);

    if is_proxy_only && (p.kind == Kind::Wg || p.kind == Kind::Awg || p.kind == Kind::Ovpn) {
        bail!("WireGuard and OpenVPN protocols only support TUNNEL mode (switch mode using `vortex mode tunnel`)");
    }

    let mut s = if use_xray {
        up_xray(p)?
    } else if p.kind.is_singbox() {
        up_singbox(p)?
    } else if p.kind == Kind::Ovpn {
        up_ovpn(p, credentials)?
    } else {
        up_wg(p)?
    };
    s.since = now();
    write_session(&s)?;
    crate::store::set_last(&s.id);
    if crate::shield::is_enabled_preference() && !is_proxy_only {
        let _ = crate::shield::arm(Some(&s.iface), Some(&s.server));
    }
    Ok(s)
}

pub fn disconnect() -> Result<()> {
    if let Some(s) = read_session() {
        match s.kind {
            Kind::Wg | Kind::Awg => {
                let quick = if s.kind == Kind::Awg {
                    "awg-quick"
                } else {
                    "wg-quick"
                };
                let _ = Command::new(quick).args(["down", &s.conf]).output();
            }
            Kind::Xray => {
                use crate::backend::Backend;
                let backend = crate::xray::XrayBackend::new();
                let _ = backend.stop(&s);
            }
            _ => {
                if s.conf.contains("xray") {
                    use crate::backend::Backend;
                    let backend = crate::xray::XrayBackend::new();
                    let _ = backend.stop(&s);
                } else if let Some(pid) = s.pid {
                    kill(pid);
                }
            }
        }
        let _ = fs::remove_file(&s.conf);
        let _ = fs::remove_file(run_path("xray_api_port"));
        let _ = fs::remove_file(run_path("xray.json"));
        let _ = fs::remove_file(sess_path());
        let _ = fs::remove_file(Path::new(RUN).join("session.json"));
    }
    // Clean up any lingering tunnel devices or processes
    if iface_exists("vxwg0") {
        let _ = Command::new("wg-quick")
            .args(["down", &run_path("vxwg0.conf").to_string_lossy()])
            .output();
        let _ = Command::new("wg-quick")
            .args(["down", &format!("{RUN}/vxwg0.conf")])
            .output();
        let _ = Command::new("ip")
            .args(["link", "delete", "dev", "vxwg0"])
            .output();
    }
    if iface_exists("vxawg0") {
        let _ = Command::new("awg-quick")
            .args(["down", &run_path("vxawg0.conf").to_string_lossy()])
            .output();
        let _ = Command::new("awg-quick")
            .args(["down", &format!("{RUN}/vxawg0.conf")])
            .output();
        let _ = Command::new("ip")
            .args(["link", "delete", "dev", "vxawg0"])
            .output();
    }
    if iface_exists(TUN_IF) {
        let _ = Command::new("ip")
            .args(["link", "delete", "dev", TUN_IF])
            .output();
        if iface_exists(TUN_IF) && unsafe { libc::geteuid() != 0 } {
            let _ = Command::new("sudo")
                .args(["-n", "ip", "link", "delete", "dev", TUN_IF])
                .output();
        }
    }
    for pidf in [
        run_path("ovpn.pid"),
        PathBuf::from(format!("{RUN}/ovpn.pid")),
    ] {
        if let Ok(pid_str) = fs::read_to_string(&pidf) {
            if let Ok(pid) = pid_str.trim().parse::<u32>() {
                kill(pid);
            }
            let _ = fs::remove_file(&pidf);
        }
    }
    let _ = fs::remove_file(sess_path());
    let _ = fs::remove_file(Path::new(RUN).join("session.json"));
    if crate::shield::is_armed() && !crate::shield::is_enabled_preference() {
        let _ = crate::shield::disarm();
    }
    Ok(())
}

fn kill(pid: u32) {
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }
    for _ in 0..20 {
        if !proc_alive(pid) {
            return;
        }
        sleep(Duration::from_millis(50));
    }
    unsafe {
        libc::kill(pid as i32, libc::SIGKILL);
    }
    if proc_alive(pid) && unsafe { libc::geteuid() != 0 } {
        let _ = Command::new("sudo")
            .args(["-n", "kill", "-TERM", &pid.to_string()])
            .output();
        sleep(Duration::from_millis(100));
        if proc_alive(pid) {
            let _ = Command::new("sudo")
                .args(["-n", "kill", "-KILL", &pid.to_string()])
                .output();
        }
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

pub fn default_routing_path() -> PathBuf {
    if let Ok(dir) = std::env::var("VORTEX_CONFIG_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir).join("routing.json");
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".config/vortex/routing.json")
    } else {
        PathBuf::from(ROUTING_FILE)
    }
}

pub fn load_routing() -> RoutingConfig {
    if let Ok(s) = fs::read_to_string(default_routing_path()) {
        if let Ok(cfg) = serde_json::from_str(&s) {
            return cfg;
        }
    }
    fs::read_to_string(ROUTING_FILE)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save_routing(cfg: &RoutingConfig) -> Result<()> {
    let p = if unsafe { libc::geteuid() } == 0 && Path::new("/etc/vortex").exists() {
        PathBuf::from(ROUTING_FILE)
    } else {
        default_routing_path()
    };
    if let Some(parent) = p.parent() {
        let _ = fs::create_dir_all(parent);
    }
    fs::write(&p, serde_json::to_string_pretty(cfg)?)?;
    Ok(())
}

/// Sanitizes sing-box route rules against defined rule-sets to prevent sing-box FATAL errors
/// during runtime initialization (e.g. `rule-set not found`).
pub fn sanitize_singbox_rules(rules: &mut Vec<Value>, rule_sets: &[Value]) {
    let defined_rule_sets: std::collections::HashSet<&str> = rule_sets
        .iter()
        .filter_map(|rs| rs.get("tag").and_then(|t| t.as_str()))
        .collect();

    rules.retain_mut(|rule| {
        if let Some(obj) = rule.as_object_mut() {
            if let Some(rs_val) = obj.get_mut("rule_set") {
                if let Some(arr) = rs_val.as_array_mut() {
                    arr.retain(|t| {
                        t.as_str()
                            .map(|s| defined_rule_sets.contains(s))
                            .unwrap_or(false)
                    });
                    if arr.is_empty() {
                        obj.remove("rule_set");
                    }
                }
            }
            // Discard rule if it only has routing action/outbound and no match criteria left
            let has_matchers = obj
                .keys()
                .any(|k| k != "action" && k != "outbound" && k != "tag" && k != "description");
            has_matchers
        } else {
            true
        }
    });
}

fn up_singbox(p: &Profile) -> Result<Session> {
    let singbox_bin = crate::privilege::resolve_singbox_binary().ok_or_else(|| {
        anyhow::anyhow!("sing-box binary not found (install via `pacman -S sing-box`)")
    })?;

    let is_proxy_only = crate::storage::get_mode_preference().is_proxy()
        || p.backend_type.as_deref() == Some("proxy")
        || std::env::var("VORTEX_MODE")
            .map(|m| m.eq_ignore_ascii_case("proxy"))
            .unwrap_or(false);

    let (_, ob, _, _) = outbound(&p.data)?;
    let logp = run_path("core.log").to_string_lossy().to_string();
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

    let mut rule_sets = vec![];
    if rules_cfg.presets.direct_domestic {
        rule_sets.push(json!({
            "tag": "geoip-cn",
            "type": "remote",
            "format": "binary",
            "url": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs"
        }));
        rule_sets.push(json!({
            "tag": "geoip-ir",
            "type": "remote",
            "format": "binary",
            "url": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-ir.srs"
        }));
    }

    sanitize_singbox_rules(&mut rules, &rule_sets);

    let inbounds = if is_proxy_only {
        vec![json!({
            "type": "mixed", "tag": "mixed-in",
            "listen": "127.0.0.1", "listen_port": PROXY_PORT
        })]
    } else {
        vec![
            json!({
                "type": "tun", "tag": "tun-in", "interface_name": TUN_IF,
                "address": ["172.19.0.1/30"],
                "mtu": 9000,
                "auto_route": true, "auto_redirect": true, "strict_route": true, "stack": "mixed",
                "endpoint_independent_nat": true
            }),
            json!({
                "type": "mixed", "tag": "mixed-in",
                "listen": "127.0.0.1", "listen_port": PROXY_PORT
            }),
        ]
    };

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
        "inbounds": inbounds,
        "outbounds": [ob, {"type": "direct", "tag": "direct"}],
        "route": {
            "auto_detect_interface": !is_proxy_only,
            "default_domain_resolver": "bootstrap",
            "final": "proxy",
            "rules": rules,
            "rule_set": rule_sets
        },
        "experimental": {
            "clash_api": {
                "external_controller": "127.0.0.1:9090",
                "secret": ""
            }
        }
    });
    let path = run_path("singbox.json").to_string_lossy().to_string();
    write_secret(&path, &serde_json::to_string_pretty(&cfg)?)?;
    let chk = Command::new(&singbox_bin)
        .args(["check", "-c", &path])
        .output()?;
    if !chk.status.success() {
        let e = String::from_utf8_lossy(&chk.stderr);
        bail!(
            "sing-box rejected the config: {}",
            e.trim().lines().last().unwrap_or("unknown error")
        );
    }

    let mut cmd = if is_proxy_only {
        Command::new(&singbox_bin)
    } else {
        let preflight = crate::privilege::run_preflight_check();
        if !preflight.tun_device_exists {
            bail!("Linux TUN device /dev/net/tun is missing (run `sudo modprobe tun` to enable the kernel TUN driver)");
        }

        match preflight.strategy {
            crate::privilege::PrivilegeStrategy::DirectRoot
            | crate::privilege::PrivilegeStrategy::FileCapabilities => Command::new(&singbox_bin),
            crate::privilege::PrivilegeStrategy::SudoPasswordless => {
                let mut c = Command::new("sudo");
                c.args(["-n", &singbox_bin.to_string_lossy()]);
                c
            }
            _ => {
                if crate::privilege::check_sudo_passwordless() {
                    let mut c = Command::new("sudo");
                    c.args(["-n", &singbox_bin.to_string_lossy()]);
                    c
                } else {
                    bail!(
                        "sing-box requires CAP_NET_ADMIN or root to configure TUN interface. Run `vortex setup` to grant passwordless capabilities, authenticate via sudo, or switch to proxy mode using `vortex mode proxy`."
                    );
                }
            }
        }
    };
    cmd.args(["run", "-c", &path]);

    let log = fs::File::create(&logp)?;
    let pid = spawn_detached(&mut cmd, log)?;

    if is_proxy_only {
        for _ in 0..40 {
            if !proc_alive(pid) {
                let err_str = last_lines(3);
                bail!("sing-box proxy exited: {}", err_str.trim());
            }
            if std::net::TcpStream::connect(format!("127.0.0.1:{PROXY_PORT}")).is_ok() {
                return Ok(session(p, "127.0.0.1:1080", Some(pid), &path));
            }
            sleep(Duration::from_millis(50));
        }
        return Ok(session(p, "127.0.0.1:1080", Some(pid), &path));
    }

    for count in 0..100 {
        if !proc_alive(pid) {
            let err_log = last_lines(5);
            let meaningful = err_log
                .lines()
                .rev()
                .find(|l| !l.trim().is_empty())
                .unwrap_or("sing-box terminated unexpectedly")
                .trim();
            if err_log.contains("TUNSETIFF: operation not permitted")
                || err_log.contains("permission denied")
            {
                bail!(
                    "PRIVILEGE ERROR: sing-box lacks CAP_NET_ADMIN for TUN interface. Run `vortex setup` or authenticate via sudo. (Details: {})",
                    meaningful
                );
            } else {
                bail!("sing-box exited: {}", meaningful);
            }
        }
        if iface_exists(TUN_IF) {
            let route_ok = Command::new("ip")
                .args(["route", "show", "table", "all", "dev", TUN_IF])
                .output()
                .map(|o| {
                    o.status.success() && !String::from_utf8_lossy(&o.stdout).trim().is_empty()
                })
                .unwrap_or(false);
            if route_ok || count >= 20 {
                return Ok(session(p, TUN_IF, Some(pid), &path));
            }
        }
        sleep(Duration::from_millis(50));
    }
    kill(pid);
    bail!("timed out waiting for the tunnel interface")
}

// ───────────────────────── wireguard / amneziawg ─────────────────────────

fn ipv6_supported() -> bool {
    if fs::read_to_string("/proc/sys/net/ipv6/conf/all/disable_ipv6")
        .ok()
        .map(|s| s.trim() == "1")
        .unwrap_or(false)
    {
        return false;
    }
    Path::new("/proc/sys/net/ipv6").exists()
}

fn sanitize_wg_conf(conf: &str) -> String {
    let ipv6_ok = ipv6_supported();
    let has_ipv6_addr = conf.lines().any(|l| {
        if let Some((k, v)) = l.split_once('=') {
            if k.trim().eq_ignore_ascii_case("address") {
                return v.contains(':');
            }
        }
        false
    });
    let allow_ipv6 = ipv6_ok && has_ipv6_addr;

    let mut out = Vec::new();
    for line in conf.lines() {
        if let Some((k, v)) = line.split_once('=') {
            let key = k.trim();
            if key.eq_ignore_ascii_case("allowedips") && !allow_ipv6 {
                let ips: Vec<&str> = v
                    .split(',')
                    .map(str::trim)
                    .filter(|item| !item.contains(':'))
                    .collect();
                if !ips.is_empty() {
                    out.push(format!("{key} = {}", ips.join(", ")));
                }
                continue;
            }
            if key.eq_ignore_ascii_case("dns") && !allow_ipv6 {
                let dns: Vec<&str> = v
                    .split(',')
                    .map(str::trim)
                    .filter(|item| !item.contains(':'))
                    .collect();
                if !dns.is_empty() {
                    out.push(format!("{key} = {}", dns.join(", ")));
                }
                continue;
            }
        }
        out.push(line.to_string());
    }
    out.join("\n")
}

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
    // Clean up stale device before starting if it already exists
    if iface_exists(iface) {
        let _ = Command::new(quick)
            .args([
                "down",
                &run_path(&format!("{iface}.conf")).to_string_lossy(),
            ])
            .output();
        let _ = Command::new(quick)
            .args(["down", &format!("{RUN}/{iface}.conf")])
            .output();
        let _ = Command::new("ip")
            .args(["link", "delete", "dev", iface])
            .output();
    }
    let mut conf = sanitize_wg_conf(&p.data);
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
    let path = run_path(&format!("{iface}.conf"))
        .to_string_lossy()
        .to_string();
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
    let conf = run_path("ovpn.conf").to_string_lossy().to_string();
    let pidf = run_path("ovpn.pid").to_string_lossy().to_string();
    let logp = run_path("core.log").to_string_lossy().to_string();
    let authf = run_path("ovpn.auth").to_string_lossy().to_string();

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
    if !conf_content.contains("redirect-gateway") && !conf_content.contains("route-nopull") {
        cmd.args(["--redirect-gateway", "def1"]);
    }
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
            // Settle check with table all
            for _ in 0..10 {
                let route_ok = Command::new("ip")
                    .args(["route", "show", "table", "all", "dev", &iface])
                    .output()
                    .map(|o| {
                        o.status.success() && !String::from_utf8_lossy(&o.stdout).trim().is_empty()
                    })
                    .unwrap_or(false);
                if route_ok {
                    break;
                }
                sleep(Duration::from_millis(100));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_wg_conf_ipv4_only() {
        let conf = "[Interface]\nAddress = 10.8.1.4/32\nDNS = 1.1.1.1, 2606:4700::\n[Peer]\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 1.2.3.4:51820\n";
        let sanitized = sanitize_wg_conf(conf);
        assert!(sanitized.contains("AllowedIPs = 0.0.0.0/0"));
        assert!(!sanitized.contains("::/0"));
        assert!(sanitized.contains("DNS = 1.1.1.1"));
        assert!(!sanitized.contains("2606:4700::"));
    }

    #[test]
    fn test_singbox_generated_config_passes_check() {
        if !have("sing-box") {
            return;
        }
        let rules_cfg = crate::routing::RulesConfig::default();
        let mut rules = rules_cfg.to_singbox_rules();
        let ob = json!({
            "type": "vless",
            "tag": "proxy",
            "server": "1.2.3.4",
            "server_port": 443,
            "uuid": "a0a0a0a0-a0a0-a0a0-a0a0-a0a0a0a0a0a0",
            "packet_encoding": "xudp"
        });
        let mut rule_sets = vec![];
        if rules_cfg.presets.direct_domestic {
            rule_sets.push(json!({
                "tag": "geoip-cn",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs"
            }));
            rule_sets.push(json!({
                "tag": "geoip-ir",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-ir.srs"
            }));
        }
        sanitize_singbox_rules(&mut rules, &rule_sets);

        // Verify that NO rule references an undefined rule_set tag
        let defined_tags: std::collections::HashSet<&str> = rule_sets
            .iter()
            .filter_map(|rs| rs.get("tag").and_then(|t| t.as_str()))
            .collect();
        for r in &rules {
            if let Some(rs_arr) = r.get("rule_set").and_then(|v| v.as_array()) {
                for tag in rs_arr {
                    if let Some(tag_str) = tag.as_str() {
                        assert!(
                            defined_tags.contains(tag_str),
                            "Rule references undefined rule_set: {tag_str}"
                        );
                    }
                }
            }
        }

        let cfg = json!({
            "log": {"level": "warn"},
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
                "rules": rules,
                "rule_set": rule_sets
            },
            "experimental": {
                "clash_api": {
                    "external_controller": "127.0.0.1:9090",
                    "secret": ""
                }
            }
        });

        let tmp = std::env::temp_dir().join(format!("singbox_test_{}.json", std::process::id()));
        fs::write(&tmp, serde_json::to_string_pretty(&cfg).unwrap()).unwrap();
        let chk = Command::new("sing-box")
            .args(["check", "-c", tmp.to_str().unwrap()])
            .output()
            .unwrap();
        let _ = fs::remove_file(&tmp);
        assert!(
            chk.status.success(),
            "sing-box check failed: {}",
            String::from_utf8_lossy(&chk.stderr)
        );
    }

    #[test]
    fn test_sanitize_singbox_rules_strips_undefined_rule_sets() {
        let rule_sets = vec![json!({"tag": "geoip-cn", "type": "inline", "rules": []})];
        let mut rules = vec![
            // 1. Rule with both valid and invalid rule-sets and domain matcher
            json!({
                "action": "reject",
                "domain_keyword": ["tracker"],
                "rule_set": ["geoip-cn", "geosite-category-ads-all"]
            }),
            // 2. Rule with ONLY invalid rule-set (should be completely dropped)
            json!({
                "action": "reject",
                "rule_set": ["geosite-category-ads-all"]
            }),
            // 3. Rule with valid rule-set only (should be kept)
            json!({
                "outbound": "direct",
                "rule_set": ["geoip-cn"]
            }),
            // 4. Rule with no rule_set at all (should be kept)
            json!({
                "outbound": "direct",
                "ip_is_private": true
            }),
        ];

        sanitize_singbox_rules(&mut rules, &rule_sets);

        assert_eq!(rules.len(), 3);
        // Rule 1 kept domain_keyword, stripped geosite-category-ads-all, kept geoip-cn
        assert_eq!(rules[0]["domain_keyword"], json!(["tracker"]));
        assert_eq!(rules[0]["rule_set"], json!(["geoip-cn"]));

        // Rule 2 was dropped!
        // Rule 3 kept geoip-cn
        assert_eq!(rules[1]["outbound"], "direct");
        assert_eq!(rules[1]["rule_set"], json!(["geoip-cn"]));

        // Rule 4 kept ip_is_private
        assert_eq!(rules[2]["ip_is_private"], true);
    }

    #[test]
    fn test_bytes_proxy_mode_fallback() {
        // Proxy mode uses an IP:port string like "127.0.0.1:1080"
        let res = bytes("127.0.0.1:1080");
        assert!(res.is_some(), "Proxy mode endpoint must return Some((rx, tx)) rather than failing sysfs read");
        let (rx, tx) = res.unwrap();
        let _ = (rx, tx);
    }

    #[test]
    fn test_bytes_invalid_iface_returns_none() {
        let res = bytes("nonexistent_device_xyz123");
        assert!(res.is_none());
    }
}

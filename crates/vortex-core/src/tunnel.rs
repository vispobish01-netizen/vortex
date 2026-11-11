use crate::backend::{resolve_backend, resolve_backend_for_session, Backend};
use crate::backends::OpenVpnBackend;
use crate::model::{Kind, Profile};
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs,
    io::{BufRead, BufReader, Read, Seek, SeekFrom, Write},
    os::unix::{fs::PermissionsExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread::sleep,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const RUN: &str = "/run/vortex";
const TUN_IF: &str = "vx0";
pub const PROXY_PORT: u16 = 1080;
pub const ROUTING_FILE: &str = "/etc/vortex/routing.json";

pub use crate::model::{ActiveFlow, RoutingConfig};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Session {
    pub id: String,
    pub name: String,
    pub kind: Kind,
    pub server: String,
    pub iface: String,
    pub pid: Option<u32>,
    #[serde(default)]
    pub sidecar_pid: Option<u32>,
    #[serde(default)]
    pub backend: Option<String>,
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

/// Writes a sensitive runtime file with `0600` permissions, creating parent directories if needed.
pub fn write_secret_path(path: &Path, content: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    fs::write(path, content)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

pub fn is_proxy_only_mode(p: &Profile) -> bool {
    crate::storage::get_mode_preference().is_proxy()
        || p.backend_type.as_deref() == Some("proxy")
        || std::env::var("VORTEX_MODE")
            .map(|m| m.eq_ignore_ascii_case("proxy"))
            .unwrap_or(false)
}

/// Checks if a binary exists in standard system directories or `PATH`.
pub fn have(bin: &str) -> bool {
    if ["/usr/bin", "/usr/local/bin", "/bin", "/usr/sbin", "/sbin"]
        .iter()
        .any(|d| Path::new(d).join(bin).is_file())
    {
        return true;
    }
    crate::xray::install::which_in_path(bin).is_some()
}

pub fn proc_alive(pid: u32) -> bool {
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

pub fn ifaces() -> Vec<String> {
    fs::read_dir("/sys/class/net")
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect()
}

pub fn iface_exists(name: &str) -> bool {
    Path::new(&format!("/sys/class/net/{name}")).exists()
}

/// Returns the name of the host's primary physical default-route interface (excluding virtual TUN/WG links).
pub fn default_egress_interface() -> Option<String> {
    let out = Command::new("ip")
        .args(["-o", "-4", "route", "show", "to", "default"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        for w in tokens.windows(2) {
            if w[0] == "dev" {
                let ifc = w[1];
                if !ifc.starts_with("vx")
                    && !ifc.starts_with("tun")
                    && !ifc.starts_with("tap")
                    && !ifc.starts_with("wg")
                    && !ifc.starts_with("awg")
                    && ifc != "lo"
                {
                    return Some(ifc.to_string());
                }
            }
        }
    }
    None
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

/// The active session, if its tunnel (and optional bridge sidecar) is actually still up.
pub fn load_session() -> Option<Session> {
    let s = read_session()?;
    let main_up = match s.pid {
        Some(p) => proc_alive(p),
        None => iface_exists(&s.iface),
    };
    let sidecar_up = s.sidecar_pid.map(proc_alive).unwrap_or(true);
    if main_up && sidecar_up {
        Some(s)
    } else {
        if main_up {
            if let Some(p) = s.pid {
                kill_pid(p);
            }
        }
        if let Some(sp) = s.sidecar_pid {
            if proc_alive(sp) {
                kill_pid(sp);
            }
        }
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

fn query_wg_traffic(iface: &str) -> Option<(u64, u64)> {
    let cmd = if iface.starts_with("awg") {
        "awg"
    } else {
        "wg"
    };
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
    // 1. Check sysfs interface statistics
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

    // 2 & 3. Query sing-box Clash API or Xray gRPC stats only for our TUN/proxy endpoint
    if iface == TUN_IF || iface.contains(':') {
        if let Some((rx, tx)) = query_clash_traffic() {
            if rx > 0 || tx > 0 || iface.contains(':') {
                return Some((rx, tx));
            }
        }

        if let Some((rx, tx)) = crate::xray::backend::query_xray_stats() {
            if rx > 0 || tx > 0 || iface.contains(':') {
                return Some((rx, tx));
            }
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

pub fn active_flows() -> Vec<ActiveFlow> {
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

/// Starts Xray standalone (TUN or local proxy). Used when sing-box is absent or standalone is forced.
pub fn up_xray(p: &Profile) -> Result<Session> {
    let backend = crate::xray::XrayBackend::new();
    let r_dir = active_run_dir();
    backend.start(p, &r_dir)
}

/// Connects to `profile`, tearing down any existing tunnel cleanly first.
pub fn connect_with_credentials(p: &Profile, credentials: Option<(&str, &str)>) -> Result<Session> {
    let _ = disconnect();
    let is_proxy_only = is_proxy_only_mode(p);

    if is_proxy_only && matches!(p.kind, Kind::Wg | Kind::Awg | Kind::Ovpn) {
        bail!(
            "WireGuard and OpenVPN protocols only support TUNNEL mode (switch mode using `vortex mode tunnel`)"
        );
    }

    let r_dir = active_run_dir();
    let mut s = if p.kind == Kind::Ovpn {
        OpenVpnBackend::new().start_with_credentials(p, &r_dir, credentials)?
    } else {
        resolve_backend(p).start(p, &r_dir)?
    };
    s.since = now();
    write_session(&s)?;
    crate::store::set_last(&s.id);
    if crate::shield::is_enabled_preference() && !is_proxy_only {
        let _ = crate::shield::arm(Some(&s.iface), Some(&s.server));
    }
    Ok(s)
}

/// Stops any active session and removes runtime state files & lingering tunnel interfaces.
pub fn disconnect() -> Result<()> {
    if let Some(s) = read_session() {
        let _ = resolve_backend_for_session(&s).stop(&s);
        let _ = fs::remove_file(&s.conf);
        let _ = fs::remove_file(run_path("xray_api_port"));
        let _ = fs::remove_file(run_path("xray.json"));
        let _ = fs::remove_file(run_path("singbox.json"));
        let _ = fs::remove_file(sess_path());
        let _ = fs::remove_file(Path::new(RUN).join("session.json"));
    }

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
                kill_pid(pid);
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

pub fn kill_pid(pid: u32) {
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

pub fn spawn_detached_with_log(cmd: &mut Command, log: fs::File) -> Result<u32> {
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

// ───────────────────────── config sanitizers & routing compat ─────────────────────────

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

pub fn sanitize_wg_conf(conf: &str) -> String {
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

pub fn default_routing_path() -> PathBuf {
    crate::crypto::user_config_dir().join("routing.json")
}

/// Compatibility view backed by unified `RulesConfig` (`rules.toml`).
pub fn load_routing() -> RoutingConfig {
    crate::routing::RulesConfig::load().to_legacy_routing_config()
}

/// Compatibility saver writing into unified `RulesConfig` (`rules.toml`).
pub fn save_routing(cfg: &RoutingConfig) -> Result<()> {
    let mut rules = crate::routing::RulesConfig::load();
    rules.presets.bypass_lan = cfg.bypass_lan;
    rules.clear_cli_domain_rules();
    for dom in &cfg.direct_domains {
        rules.add_bypass_domain(dom);
    }
    for dom in &cfg.blocked_domains {
        rules.add_block_domain(dom);
    }
    rules.save()
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
            let has_matchers = obj
                .keys()
                .any(|k| k != "action" && k != "outbound" && k != "tag" && k != "description");
            has_matchers
        } else {
            true
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backends::SingBoxBackend;
    use serde_json::json;

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
        let Some(sb) = crate::privilege::resolve_singbox_binary() else {
            return;
        };
        let ob = json!({
            "type": "vless",
            "tag": "proxy",
            "server": "1.2.3.4",
            "server_port": 443,
            "uuid": "a0a0a0a0-a0a0-a0a0-a0a0-a0a0a0a0a0a0",
            "packet_encoding": "xudp"
        });
        let cfg = SingBoxBackend::build_config_with_outbound(
            ob,
            &["1.2.3.4".to_string()],
            &["1.2.3.4/32".to_string()],
            Path::new("/tmp/test-core.log"),
            false,
        );

        let tmp = std::env::temp_dir().join(format!("singbox_test_{}.json", std::process::id()));
        fs::write(&tmp, serde_json::to_string_pretty(&cfg).unwrap()).unwrap();
        let chk = Command::new(sb)
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
            json!({
                "action": "reject",
                "domain_keyword": ["tracker"],
                "rule_set": ["geoip-cn", "geosite-category-ads-all"]
            }),
            json!({
                "action": "reject",
                "rule_set": ["geosite-category-ads-all"]
            }),
            json!({
                "outbound": "direct",
                "rule_set": ["geoip-cn"]
            }),
            json!({
                "outbound": "direct",
                "ip_is_private": true
            }),
        ];

        sanitize_singbox_rules(&mut rules, &rule_sets);

        assert_eq!(rules.len(), 3);
        assert_eq!(rules[0]["domain_keyword"], json!(["tracker"]));
        assert_eq!(rules[0]["rule_set"], json!(["geoip-cn"]));
        assert_eq!(rules[1]["outbound"], "direct");
        assert_eq!(rules[1]["rule_set"], json!(["geoip-cn"]));
        assert_eq!(rules[2]["ip_is_private"], true);
    }

    #[test]
    fn test_bytes_proxy_mode_fallback() {
        let res = bytes("127.0.0.1:1080");
        assert!(res.is_some());
    }

    #[test]
    fn test_bytes_invalid_iface_returns_none() {
        let res = bytes("nonexistent_device_xyz123");
        assert!(res.is_none());
    }
}

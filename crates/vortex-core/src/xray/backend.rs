use anyhow::{bail, Context, Result};
use std::fs;
use std::net::{SocketAddr, TcpListener};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread::sleep;
use std::time::{Duration, Instant};

use super::config::{
    generate_xray_config, validate_xray_config_file, DEFAULT_XRAY_PROXY_PORT,
    DEFAULT_XRAY_TUN_IFACE,
};
use super::install::{get_binary_version, resolve_xray_binary};
use crate::backend::Backend;
use crate::model::Profile;
use crate::tunnel::{active_run_dir, now, Session};

/// Backend implementation driving Xray-core as a first-class tunnel engine
pub struct XrayBackend {
    #[allow(dead_code)]
    supervisor_running: Arc<AtomicBool>,
}

impl XrayBackend {
    pub fn new() -> Self {
        Self {
            supervisor_running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Selects an unused random port on 127.0.0.1 for the Xray gRPC API
    pub fn pick_random_api_port() -> u16 {
        TcpListener::bind("127.0.0.1:0")
            .and_then(|l| l.local_addr())
            .map(|a| a.port())
            .unwrap_or(54321)
    }

    /// Safely writes runtime files with strict 0600 permissions
    fn write_secret(path: &Path, content: &str) -> Result<()> {
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
            let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
        }
        fs::write(path, content)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        Ok(())
    }

    /// Checks if a PID is still actively running (not zombie)
    pub fn is_alive(pid: u32) -> bool {
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

    /// Cleanly kills a process with SIGTERM, then SIGKILL fallback (no orphans)
    pub fn kill_cleanly(pid: u32) {
        unsafe {
            // Signal the entire process group if detached, or the PID directly
            let _ = libc::kill(pid as i32, libc::SIGTERM);
        }
        for _ in 0..40 {
            if !Self::is_alive(pid) {
                return;
            }
            sleep(Duration::from_millis(50));
        }
        unsafe {
            let _ = libc::kill(pid as i32, libc::SIGKILL);
        }
    }

    /// Spawns a detached child process with setsid so it doesn't get signal crosstalk
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

    /// Runs a latency test through a temporary isolated Xray client instance
    pub fn probe_real_delay(&self, profile: &Profile, timeout: Duration) -> Result<u32> {
        let xray_bin = resolve_xray_binary()?;
        let temp_port = TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
        let api_port = TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();

        let cfg = generate_xray_config(profile, "vxtmp0", temp_port, api_port, None)?;

        let temp_dir = std::env::temp_dir().join(format!(
            "vortex_probe_{}_{}",
            profile.id,
            std::process::id()
        ));
        fs::create_dir_all(&temp_dir)?;
        let conf_file = temp_dir.join("config.json");
        Self::write_secret(&conf_file, &serde_json::to_string(&cfg)?)?;

        let child = Command::new(&xray_bin)
            .args(["run", "-c", conf_file.to_str().unwrap()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("Failed to spawn probe Xray instance")?;

        let child_pid = child.id();

        // Wait for proxy port to accept connections
        let mut ready = false;
        for _ in 0..20 {
            if std::net::TcpStream::connect_timeout(
                &SocketAddr::from(([127, 0, 0, 1], temp_port)),
                Duration::from_millis(50),
            )
            .is_ok()
            {
                ready = true;
                break;
            }
            sleep(Duration::from_millis(50));
        }

        let res = if ready {
            let test_urls = [
                "http://cp.cloudflare.com/generate_204",
                "http://www.google.com/generate_204",
                "http://connectivitycheck.gstatic.com/generate_204",
            ];
            let mut probe_res = Err(anyhow::anyhow!("HTTP probe through Xray proxy timed out or failed"));

            for url in test_urls {
                let start = Instant::now();
                let curl_out = Command::new("curl")
                    .args([
                        "-s",
                        "--max-time",
                        &timeout.as_secs().to_string(),
                        "-x",
                        &format!("socks5://127.0.0.1:{temp_port}"),
                        url,
                    ])
                    .output();

                if let Ok(o) = curl_out {
                    if o.status.success() {
                        let elapsed = start.elapsed().as_millis() as u32;
                        probe_res = Ok(elapsed);
                        break;
                    }
                }
            }
            probe_res
        } else {
            bail!("Temporary probe Xray instance failed to bind")
        };

        Self::kill_cleanly(child_pid);
        let _ = fs::remove_dir_all(temp_dir);

        res
    }
}

impl Default for XrayBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl Backend for XrayBackend {
    fn name(&self) -> &'static str {
        "xray"
    }

    fn is_available(&self) -> bool {
        resolve_xray_binary().is_ok()
    }

    fn version(&self) -> Option<String> {
        resolve_xray_binary()
            .ok()
            .and_then(|p| get_binary_version(&p))
    }

    fn validate_config(&self, config_content: &str) -> Result<()> {
        let xray_bin = resolve_xray_binary()?;
        let temp_dir = std::env::temp_dir().join(format!("vortex_test_{}", std::process::id()));
        fs::create_dir_all(&temp_dir)?;
        let conf_path = temp_dir.join("test.json");
        Self::write_secret(&conf_path, config_content)?;

        let res = validate_xray_config_file(&xray_bin, &conf_path);
        let _ = fs::remove_dir_all(temp_dir);
        res
    }

    fn start(&self, profile: &Profile, runtime_dir: &Path) -> Result<Session> {
        let xray_bin = resolve_xray_binary().context("Cannot start Xray: binary not found")?;

        let tun_iface = DEFAULT_XRAY_TUN_IFACE;
        let mixed_port = DEFAULT_XRAY_PROXY_PORT;
        let api_port = Self::pick_random_api_port();

        let log_path = runtime_dir.join("core.log");
        let conf_path = runtime_dir.join("xray.json");
        let api_port_path = runtime_dir.join("xray_api_port");

        let cfg = generate_xray_config(profile, tun_iface, mixed_port, api_port, Some(&log_path))?;

        let cfg_str = serde_json::to_string_pretty(&cfg)?;
        Self::write_secret(&conf_path, &cfg_str)?;
        Self::write_secret(&api_port_path, &api_port.to_string())?;

        // Pre-flight test
        self.validate_config(&cfg_str)
            .context("Xray rejected configuration on startup")?;

        let log_file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&log_path)?;

        let mut cmd = Command::new(&xray_bin);
        cmd.args(["run", "-c", conf_path.to_str().unwrap()]);

        let pid = Self::spawn_detached(&mut cmd, log_file)?;

        // Wait for tunnel interface or sockets
        for count in 0..80 {
            if !Self::is_alive(pid) {
                let log_tail = fs::read_to_string(&log_path).unwrap_or_default();
                let last_err = log_tail.lines().rev().take(3).collect::<Vec<_>>().join(" ");
                bail!("Xray process exited unexpectedly (pid {pid}): {last_err}");
            }

            // Check if tun interface or local proxy is up
            if Path::new(&format!("/sys/class/net/{tun_iface}")).exists() || count >= 20 {
                let session = Session {
                    id: profile.id.clone(),
                    name: profile.name.clone(),
                    kind: profile.kind,
                    server: profile.server.clone(),
                    iface: tun_iface.to_string(),
                    pid: Some(pid),
                    since: now(),
                    conf: conf_path.to_string_lossy().to_string(),
                };
                return Ok(session);
            }
            sleep(Duration::from_millis(50));
        }

        Self::kill_cleanly(pid);
        bail!("Timed out waiting for Xray tunnel to initialize")
    }

    fn stop(&self, session: &Session) -> Result<()> {
        if let Some(pid) = session.pid {
            Self::kill_cleanly(pid);
        }

        // Clean up configuration file
        let _ = fs::remove_file(&session.conf);

        // Clean up api port marker
        let r_dir = active_run_dir();
        let _ = fs::remove_file(r_dir.join("xray_api_port"));

        // Clean up TUN interface if lingering
        let iface = &session.iface;
        if Path::new(&format!("/sys/class/net/{iface}")).exists() {
            let _ = Command::new("ip")
                .args(["link", "delete", "dev", iface])
                .output();
        }

        Ok(())
    }

    fn query_traffic(&self, session: &Session) -> Result<(u64, u64)> {
        // Query Xray gRPC API using `xray api statsquery`
        let r_dir = active_run_dir();
        let api_port = fs::read_to_string(r_dir.join("xray_api_port"))
            .ok()
            .and_then(|s| s.trim().parse::<u16>().ok())
            .unwrap_or(DEFAULT_XRAY_PROXY_PORT);

        if let Ok(xray_bin) = resolve_xray_binary() {
            let output = Command::new(&xray_bin)
                .args([
                    "api",
                    "statsquery",
                    &format!("--server=127.0.0.1:{api_port}"),
                ])
                .output();

            if let Ok(out) = output {
                if out.status.success() {
                    if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&out.stdout) {
                        let mut rx = 0u64;
                        let mut tx = 0u64;
                        if let Some(stats) = val["stat"].as_array() {
                            for s in stats {
                                let name = s["name"].as_str().unwrap_or("");
                                let value = s["value"].as_u64().unwrap_or(0);
                                if name.contains("downlink") {
                                    rx = rx.saturating_add(value);
                                } else if name.contains("uplink") {
                                    tx = tx.saturating_add(value);
                                }
                            }
                            if rx > 0 || tx > 0 {
                                return Ok((rx, tx));
                            }
                        }
                    }
                }
            }
        }

        // Fallback: Read sysfs network interface statistics
        if let Some((rx, tx)) = crate::tunnel::bytes(&session.iface) {
            return Ok((rx, tx));
        }

        Ok((0, 0))
    }
}

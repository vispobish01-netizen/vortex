use anyhow::{Context, Result};
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, Mutex};
use tracing::{error, info, warn};
use vortex_core::history::TrafficHistory;
use vortex_core::ipc::*;
use vortex_core::model::*;
use vortex_core::probe::{self, NodeMetrics, ScoringWeights, SelectionMode};
use vortex_core::{benchmark, ping, shield, store, tunnel};

fn session_backend_label(s: &tunnel::Session) -> String {
    if let Some(ref b) = s.backend {
        return b.clone();
    }
    if s.kind == Kind::Wg {
        "wireguard".to_string()
    } else if s.kind == Kind::Awg {
        "amneziawg".to_string()
    } else if s.kind == Kind::Ovpn {
        "openvpn".to_string()
    } else if s.conf.ends_with("singbox.json") {
        if s.sidecar_pid.is_some() {
            "sing-box+xray".to_string()
        } else {
            "sing-box".to_string()
        }
    } else if s.kind == Kind::Xray || s.conf.contains("xray") {
        "xray".to_string()
    } else {
        "sing-box".to_string()
    }
}

struct DaemonState {
    status: DaemonStatus,
    subscribers: broadcast::Sender<DaemonEvent>,
    selection_mode: SelectionMode,
    scoring_weights: ScoringWeights,
    metrics: std::collections::HashMap<String, NodeMetrics>,
    consecutive_probe_failures: u32,
    last_failover_ts: Option<std::time::Instant>,
    failover_attempt: u32,
    history: TrafficHistory,
}

impl DaemonState {
    fn new(tx: broadcast::Sender<DaemonEvent>) -> Self {
        let mut st = DaemonState {
            status: DaemonStatus {
                connected: false,
                active_profile: None,
                uptime_secs: 0,
                iface: None,
                server_endpoint: None,
                exit_ip: None,
                shield_armed: false,
                pid: None,
                xray_version: vortex_core::xray::active_xray_version(),
                backend: None,
                mode: vortex_core::storage::get_mode_preference(),
            },
            subscribers: tx,
            selection_mode: SelectionMode::Manual,
            scoring_weights: ScoringWeights::default(),
            metrics: std::collections::HashMap::new(),
            consecutive_probe_failures: 0,
            last_failover_ts: None,
            failover_attempt: 0,
            history: TrafficHistory::load(),
        };
        st.refresh_status();
        st
    }

    fn refresh_status(&mut self) {
        let current_sess = tunnel::load_session();
        let shield_armed = shield::is_armed();
        self.status.connected = current_sess.is_some();
        self.status.iface = current_sess.as_ref().map(|s| s.iface.clone());
        self.status.server_endpoint = current_sess.as_ref().map(|s| s.server.clone());
        self.status.shield_armed = shield_armed;
        self.status.pid = current_sess.as_ref().and_then(|s| s.pid);
        self.status.xray_version = vortex_core::xray::active_xray_version();
        self.status.backend = current_sess.as_ref().map(session_backend_label);
        self.status.mode = vortex_core::storage::get_mode_preference();
        if let Some(s) = &current_sess {
            self.status.uptime_secs = tunnel::now().saturating_sub(s.since);
            if self.status.active_profile.as_ref().map(|p| &p.id) != Some(&s.id) {
                self.status.active_profile = Some(
                    store::load_all()
                        .into_iter()
                        .find(|p| p.id == s.id)
                        .unwrap_or_else(|| Profile::new(&s.id, &s.name, s.kind, &s.server, "")),
                );
            }
        } else {
            self.status.active_profile = None;
            self.status.uptime_secs = 0;
            self.status.exit_ip = None;
        }
    }
}

type SharedState = Arc<Mutex<DaemonState>>;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if matches!(
        args.first().map(String::as_str),
        Some("-v" | "-V" | "--version" | "version")
    ) {
        println!("vortexd {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if matches!(
        args.first().map(String::as_str),
        Some("-h" | "--help" | "help")
    ) {
        println!("vortexd - Background daemon for Vortex VPN & Proxy");
        println!("Usage: vortexd [options]");
        println!();
        println!("Options:");
        println!("  -h, --help       Print help information");
        println!("  -V, --version    Print version information");
        return Ok(());
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    info!("Starting Vortex Daemon v{}", env!("CARGO_PKG_VERSION"));

    // Crash safety: clean any leftover firewall rules or stale routes
    info!("Running crash recovery: cleaning stale firewall rules...");
    let _ = shield::cleanup_stale_rules();

    let sock_path = default_socket_path();
    if let Some(parent) = sock_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if sock_path.exists() {
        let _ = std::fs::remove_file(&sock_path);
    }

    let listener = UnixListener::bind(&sock_path)
        .with_context(|| format!("Failed to bind Unix domain socket at {:?}", sock_path))?;

    // Set socket permissions (0660 with vortex group if available, else 0600)
    let perm_mode = if unsafe { libc::geteuid() == 0 } {
        0o660
    } else {
        0o600
    };
    if let Err(e) = std::fs::set_permissions(&sock_path, std::fs::Permissions::from_mode(perm_mode))
    {
        warn!("Could not set socket permissions to {:o}: {e}", perm_mode);
    }
    // Attempt to set group ownership to 'vortex' if group exists
    if unsafe { libc::geteuid() == 0 } {
        use std::ffi::CString;
        if let Ok(grp_name) = CString::new("vortex") {
            unsafe {
                let grp = libc::getgrnam(grp_name.as_ptr());
                if !grp.is_null() {
                    let gid = (*grp).gr_gid;
                    let cpath = CString::new(sock_path.to_string_lossy().as_bytes()).unwrap();
                    let _ = libc::chown(cpath.as_ptr(), libc::uid_t::MAX, gid);
                    info!("Set socket group ownership to 'vortex' (gid {gid})");
                }
            }
        }
    }

    info!("Vortex daemon listening on {:?}", sock_path);

    let (event_tx, _) = broadcast::channel::<DaemonEvent>(256);
    let state = Arc::new(Mutex::new(DaemonState::new(event_tx.clone())));

    // Background telemetry & traffic ticker task
    let bg_state = Arc::clone(&state);
    let bg_tx = event_tx.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        let mut last_bytes: Option<(u64, u64)> = None;
        let mut tick_counter: u64 = 0;
        let mut last_time = tokio::time::Instant::now();
        loop {
            interval.tick().await;
            tick_counter += 1;
            let elapsed_secs = last_time.elapsed().as_secs_f64().max(0.001);
            last_time = tokio::time::Instant::now();
            let (iface, is_connected) = {
                let mut st = bg_state.lock().await;
                st.refresh_status();
                (st.status.iface.clone(), st.status.connected)
            };

            if is_connected {
                if let Some(ifc) = iface {
                    let bytes_opt = tokio::task::spawn_blocking(move || tunnel::bytes(&ifc))
                        .await
                        .ok()
                        .flatten();
                    if let Some((rx, tx)) = bytes_opt {
                        let (rx_sec, tx_sec) = if let Some((prev_rx, prev_tx)) = last_bytes {
                            (
                                ((rx.saturating_sub(prev_rx) as f64) / elapsed_secs).round() as u64,
                                ((tx.saturating_sub(prev_tx) as f64) / elapsed_secs).round() as u64,
                            )
                        } else {
                            (0, 0)
                        };
                        last_bytes = Some((rx, tx));

                        {
                            let mut st = bg_state.lock().await;
                            let active_profile = st.status.active_profile.clone();
                            st.history.record_sample(
                                rx_sec,
                                tx_sec,
                                active_profile.as_ref().map(|p| p.id.as_str()),
                                active_profile.as_ref().map(|p| p.name.as_str()),
                                active_profile.as_ref().map(|p| p.kind.tag()),
                            );
                            if tick_counter.is_multiple_of(60) {
                                let _ = st.history.save();
                            }
                        }

                        let _ = bg_tx.send(DaemonEvent::TrafficStats {
                            rx_bytes_sec: rx_sec,
                            tx_bytes_sec: tx_sec,
                            total_rx: rx,
                            total_tx: tx,
                        });
                    }
                }

                // Check tunnel health and auto-failover every 5 seconds
                if tick_counter.is_multiple_of(5) {
                    let (mode, active_opt) = {
                        let st = bg_state.lock().await;
                        (st.selection_mode, st.status.active_profile.clone())
                    };

                    if mode != SelectionMode::Manual {
                        let probe_ok = tokio::task::spawn_blocking(ping::probe)
                            .await
                            .ok()
                            .flatten()
                            .is_some();

                        let failover_target: Option<(String, Profile)> = {
                            let mut st = bg_state.lock().await;
                            if probe_ok {
                                st.consecutive_probe_failures = 0;
                                st.failover_attempt = 0;
                                None
                            } else {
                                st.consecutive_probe_failures += 1;
                                warn!(
                                    "Health probe failed through active tunnel (failures: {})",
                                    st.consecutive_probe_failures
                                );
                                let now = std::time::Instant::now();
                                let cooldown_passed = st
                                    .last_failover_ts
                                    .map(|t| now.duration_since(t) > Duration::from_secs(15))
                                    .unwrap_or(true);
                                if st.consecutive_probe_failures >= 3
                                    && cooldown_passed
                                    && st.failover_attempt < 5
                                {
                                    st.failover_attempt += 1;
                                    st.last_failover_ts = Some(now);
                                    let active_id = active_opt
                                        .as_ref()
                                        .map(|p| p.id.clone())
                                        .unwrap_or_default();
                                    let candidates: Vec<Profile> = store::load_all()
                                        .into_iter()
                                        .filter(|p| p.id != active_id)
                                        .collect();
                                    probe::select_best_node(
                                        &candidates,
                                        &st.metrics,
                                        st.selection_mode,
                                        &st.scoring_weights,
                                    )
                                    .map(|target| {
                                        let reason = format!(
                                            "Health check failed {} consecutive times",
                                            st.consecutive_probe_failures
                                        );
                                        warn!("Auto-failover triggered: switching from {active_id} to {} ({reason})", target.id);
                                        let _ = bg_tx.send(DaemonEvent::FailoverTriggered {
                                            from_id: active_id.clone(),
                                            to_id: target.id.clone(),
                                            reason,
                                        });
                                        (active_id, target.clone())
                                    })
                                } else {
                                    None
                                }
                            }
                        };

                        if let Some((_from_id, target_clone)) = failover_target {
                            let ok = tokio::task::spawn_blocking(move || {
                                let creds = if tunnel::ovpn_needs_auth(&target_clone) {
                                    target_clone
                                        .auth
                                        .as_ref()
                                        .map(|a| (a.username.clone(), a.password.clone()))
                                } else {
                                    None
                                };
                                tunnel::connect_with_credentials(
                                    &target_clone,
                                    creds.as_ref().map(|(u, pw)| (u.as_str(), pw.as_str())),
                                )
                                .is_ok()
                            })
                            .await
                            .unwrap_or(false);

                            if ok {
                                let mut st = bg_state.lock().await;
                                st.refresh_status();
                                st.consecutive_probe_failures = 0;
                                let _ = bg_tx.send(DaemonEvent::StatusChanged(st.status.clone()));
                            }
                        }
                    }
                }
            } else {
                last_bytes = None;
            }
        }
    });

    // Handle shutdown gracefully
    let shutdown_sock = sock_path.clone();
    let shutdown_state = Arc::clone(&state);
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        info!("Received shutdown signal, cleaning up socket and firewall...");
        {
            let st = shutdown_state.lock().await;
            let _ = st.history.save();
        }
        let _ = shield::cleanup_stale_rules();
        let _ = std::fs::remove_file(&shutdown_sock);
        std::process::exit(0);
    });

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let client_state = Arc::clone(&state);
                let client_events = event_tx.subscribe();
                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, client_state, client_events).await {
                        error!("Client session error: {e}");
                    }
                });
            }
            Err(e) => {
                error!("Socket accept failed: {e}");
            }
        }
    }
}

async fn handle_client(
    mut stream: UnixStream,
    state: SharedState,
    mut event_rx: broadcast::Receiver<DaemonEvent>,
) -> Result<()> {
    loop {
        tokio::select! {
            req_res = read_frame_async::<_, IpcRequest>(&mut stream) => {
                match req_res {
                    Ok(req) => {
                        let resp = process_request(req, &state, &mut stream, &mut event_rx).await;
                        if let Some(r) = resp {
                            if let Err(e) = write_frame_async(&mut stream, &r).await {
                                warn!("Failed to write IPC response: {e}");
                                break;
                            }
                        }
                    }
                    Err(_e) => {
                        // EOF or disconnected
                        break;
                    }
                }
            }
            event_res = event_rx.recv() => {
                if let Ok(event) = event_res {
                    // Send event to streaming client if connection is in event subscription mode
                    // Notice: write_frame_async handles framing
                    let _ = write_frame_async(&mut stream, &event).await;
                }
            }
        }
    }
    Ok(())
}

async fn execute_connect(
    state: &SharedState,
    profile_id: String,
    override_creds: Option<(String, String)>,
) -> IpcResponse {
    let res = tokio::task::spawn_blocking(move || {
        let p = store::load_all()
            .into_iter()
            .find(|p| p.id == profile_id)
            .ok_or_else(|| anyhow::anyhow!("Node '{profile_id}' not found"))?;
        let creds = override_creds.or_else(|| {
            if tunnel::ovpn_needs_auth(&p) {
                p.auth
                    .as_ref()
                    .map(|a| (a.username.clone(), a.password.clone()))
            } else {
                None
            }
        });
        tunnel::connect_with_credentials(
            &p,
            creds.as_ref().map(|(u, pw)| (u.as_str(), pw.as_str())),
        )
    })
    .await;

    match res {
        Ok(Ok(_sess)) => {
            let mut st = state.lock().await;
            st.refresh_status();
            let _ = st
                .subscribers
                .send(DaemonEvent::StatusChanged(st.status.clone()));
            IpcResponse::Status(st.status.clone())
        }
        Ok(Err(e)) => IpcResponse::Error(format!("Connection failed: {e:#}")),
        Err(e) => IpcResponse::Error(format!("Connect task failed: {e}")),
    }
}

async fn run_blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T> + Send + 'static,
) -> std::result::Result<T, String> {
    match tokio::task::spawn_blocking(f).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(format!("{e:#}")),
        Err(e) => Err(format!("worker task panicked: {e}")),
    }
}

async fn process_request(
    req: IpcRequest,
    state: &SharedState,
    _stream: &mut UnixStream,
    _event_rx: &mut broadcast::Receiver<DaemonEvent>,
) -> Option<IpcResponse> {
    match req {
        IpcRequest::Ping => Some(IpcResponse::Ok),
        IpcRequest::Version => Some(IpcResponse::Version {
            version: PROTOCOL_VERSION,
            app_version: env!("CARGO_PKG_VERSION").into(),
        }),
        IpcRequest::GetStatus => {
            let mut st = state.lock().await;
            st.refresh_status();
            Some(IpcResponse::Status(st.status.clone()))
        }
        IpcRequest::GetProfiles => {
            let profiles = tokio::task::spawn_blocking(store::load_all)
                .await
                .unwrap_or_default();
            Some(IpcResponse::Profiles(profiles))
        }
        IpcRequest::Connect { profile_id } => Some(execute_connect(state, profile_id, None).await),
        IpcRequest::ConnectWithCredentials {
            profile_id,
            username,
            password,
        } => Some(execute_connect(state, profile_id, Some((username, password))).await),
        IpcRequest::Disconnect => match run_blocking(tunnel::disconnect).await {
            Ok(_) => {
                let mut st = state.lock().await;
                st.refresh_status();
                let _ = st
                    .subscribers
                    .send(DaemonEvent::StatusChanged(st.status.clone()));
                Some(IpcResponse::Status(st.status.clone()))
            }
            Err(e) => Some(IpcResponse::Error(format!("Disconnect failed: {e}"))),
        },
        IpcRequest::ToggleShield { enable } => {
            let res = run_blocking(move || {
                let cur = shield::is_armed();
                let target = enable.unwrap_or(!cur);
                if target {
                    shield::set_enabled_preference(true);
                    let sess = tunnel::load_session();
                    let iface = sess.as_ref().map(|s| s.iface.as_str());
                    let srv = sess.as_ref().map(|s| s.server.as_str());
                    shield::arm(iface, srv)
                } else {
                    shield::set_enabled_preference(false);
                    shield::disarm()
                }
            })
            .await;

            match res {
                Ok(_) => {
                    let mut st = state.lock().await;
                    st.refresh_status();
                    let armed = st.status.shield_armed;
                    let _ = st.subscribers.send(DaemonEvent::ShieldChanged { armed });
                    Some(IpcResponse::Status(st.status.clone()))
                }
                Err(e) => Some(IpcResponse::Error(format!("Shield toggle failed: {e}"))),
            }
        }
        IpcRequest::AddProfile { raw } => match run_blocking(move || store::import(&raw)).await {
            Ok(count) => Some(IpcResponse::ProfileAdded { count }),
            Err(e) => Some(IpcResponse::Error(format!("Import failed: {e}"))),
        },
        IpcRequest::RemoveProfile { id } => match run_blocking(move || store::remove(&id)).await {
            Ok(_) => Some(IpcResponse::Ok),
            Err(e) => Some(IpcResponse::Error(format!("Remove failed: {e}"))),
        },
        IpcRequest::RenameProfile { id, new_name } => {
            match run_blocking(move || store::rename(&id, &new_name)).await {
                Ok(_) => Some(IpcResponse::Ok),
                Err(e) => Some(IpcResponse::Error(format!("Rename failed: {e}"))),
            }
        }
        IpcRequest::SetAuth {
            profile_id,
            username,
            password,
        } => match run_blocking(move || store::set_auth(&profile_id, username, password)).await {
            Ok(_) => Some(IpcResponse::Ok),
            Err(e) => Some(IpcResponse::Error(format!("SetAuth failed: {e}"))),
        },
        IpcRequest::ClearAuth { profile_id } => {
            match run_blocking(move || store::clear_auth(&profile_id)).await {
                Ok(_) => Some(IpcResponse::Ok),
                Err(e) => Some(IpcResponse::Error(format!("ClearAuth failed: {e}"))),
            }
        }
        IpcRequest::GetSubs => {
            let subs = tokio::task::spawn_blocking(store::load_subs)
                .await
                .unwrap_or_default();
            Some(IpcResponse::Subs(subs))
        }
        IpcRequest::AddSub { url, name } => {
            match run_blocking(move || store::add_sub(&url, name.as_deref())).await {
                Ok((sub, count)) => Some(IpcResponse::SubAdded { sub, count }),
                Err(e) => Some(IpcResponse::Error(format!("Subscription add failed: {e}"))),
            }
        }
        IpcRequest::RemoveSub { id, cleanup } => {
            match run_blocking(move || store::remove_sub(&id, cleanup)).await {
                Ok(count) => Some(IpcResponse::ProfileAdded { count }),
                Err(e) => Some(IpcResponse::Error(format!(
                    "Subscription remove failed: {e}"
                ))),
            }
        }
        IpcRequest::UpdateSubscriptions { target } => {
            let res = run_blocking(move || {
                if let Some(t) = target.filter(|s| s != "all") {
                    store::update_sub(&t).map(|(_, c)| c)
                } else {
                    store::update_all_subs().map(|v| v.len())
                }
            })
            .await;

            match res {
                Ok(count) => Some(IpcResponse::ProfileAdded { count }),
                Err(e) => Some(IpcResponse::Error(format!(
                    "Subscription update failed: {e}"
                ))),
            }
        }
        IpcRequest::RunProbe { profile_id } => {
            let prober = probe::MultiLayerProber::new(16, Duration::from_millis(2000), None);
            let profiles = tokio::task::spawn_blocking(store::load_all)
                .await
                .unwrap_or_default();
            let to_probe: Vec<Profile> = if let Some(id) = profile_id {
                profiles.into_iter().filter(|x| x.id == id).collect()
            } else {
                profiles
            };

            let mut results = vec![];
            for p in to_probe {
                let (tcp_ms, tls_ms, real_delay) = prober.probe_profile(&p).await;
                let latency = tls_ms.or(tcp_ms);
                {
                    let mut st = state.lock().await;
                    let m = st.metrics.entry(p.id.clone()).or_default();
                    m.record_sample(latency);
                    m.last_tcp_ms = tcp_ms;
                    m.last_tls_ms = tls_ms;
                    m.last_real_delay_ms = real_delay;
                    let _ = st.subscribers.send(DaemonEvent::ProbeCompleted {
                        profile_id: p.id.clone(),
                        rtt_ms: latency,
                    });
                }
                results.push(ProbeResult {
                    profile_id: p.id,
                    rtt_ms: latency,
                    is_available: latency.is_some(),
                    real_delay_ms: real_delay,
                });
            }
            Some(IpcResponse::Probe(results))
        }
        IpcRequest::RunSpeedTest => {
            match run_blocking(|| benchmark::run_speed_test(benchmark::DEFAULT_TEST_DURATION_SECS))
                .await
            {
                Ok(res) => Some(IpcResponse::Speed(res)),
                Err(e) => Some(IpcResponse::Error(format!("Speed test failed: {e}"))),
            }
        }
        IpcRequest::RunLeakTest => {
            let (is_connected, srv_endpoint, exit_ip) = {
                let mut st = state.lock().await;
                st.refresh_status();
                (
                    st.status.connected,
                    st.status.server_endpoint.clone(),
                    st.status.exit_ip.clone(),
                )
            };
            let report = vortex_core::leak::run_leak_suite(
                is_connected,
                srv_endpoint.as_deref(),
                exit_ip.as_deref(),
            )
            .await;
            Some(IpcResponse::Leak(report))
        }
        IpcRequest::RunRecon { profile_id } => {
            let res = run_blocking(move || {
                let p = store::load_all()
                    .into_iter()
                    .find(|x| x.id == profile_id || x.name == profile_id)
                    .ok_or_else(|| anyhow::anyhow!("Profile not found"))?;
                vortex_core::recon::probe_recon(&p)
            })
            .await;
            match res {
                Ok(report) => Some(IpcResponse::Recon(report)),
                Err(e) => Some(IpcResponse::Error(format!("Recon failed: {e}"))),
            }
        }
        IpcRequest::GetFlows => {
            let flows = tokio::task::spawn_blocking(tunnel::active_flows)
                .await
                .unwrap_or_default();
            Some(IpcResponse::Flows(flows))
        }
        IpcRequest::KillFlow { id } => match run_blocking(move || tunnel::kill_flow(&id)).await {
            Ok(_) => Some(IpcResponse::Ok),
            Err(e) => Some(IpcResponse::Error(format!("Kill flow failed: {e}"))),
        },
        IpcRequest::GetHistory => {
            let st = state.lock().await;
            Some(IpcResponse::History(st.history.clone()))
        }
        IpcRequest::ExportHistory { format, since_secs } => {
            let st = state.lock().await;
            let out = match format.to_lowercase().as_str() {
                "csv" => st.history.export_csv(since_secs),
                _ => st.history.export_json(since_secs),
            };
            Some(IpcResponse::Export(out))
        }
        IpcRequest::GetLogs { lines } => {
            let logs = tokio::task::spawn_blocking(move || tunnel::tail_log(lines))
                .await
                .unwrap_or_default();
            Some(IpcResponse::Logs(logs))
        }
        IpcRequest::GetRouting => {
            let cfg = tokio::task::spawn_blocking(tunnel::load_routing)
                .await
                .unwrap_or_default();
            Some(IpcResponse::Routing(cfg))
        }
        IpcRequest::SetRouting(cfg) => {
            let cfg_clone = cfg.clone();
            match run_blocking(move || tunnel::save_routing(&cfg_clone)).await {
                Ok(_) => Some(IpcResponse::Routing(cfg)),
                Err(e) => Some(IpcResponse::Error(format!("Save routing failed: {e}"))),
            }
        }
        IpcRequest::GetRulesConfig => {
            let cfg = tokio::task::spawn_blocking(vortex_core::routing::RulesConfig::load)
                .await
                .unwrap_or_default();
            Some(IpcResponse::RulesConfig(cfg))
        }
        IpcRequest::SetRulesConfig(cfg) => {
            let cfg_clone = cfg.clone();
            match run_blocking(move || cfg_clone.save()).await {
                Ok(_) => {
                    let st = state.lock().await;
                    let _ = st.subscribers.send(DaemonEvent::RoutingReloaded);
                    Some(IpcResponse::RulesConfig(cfg))
                }
                Err(e) => Some(IpcResponse::Error(format!("Save rules failed: {e}"))),
            }
        }
        IpcRequest::ExplainRoute {
            target,
            protocol,
            port,
            process,
        } => {
            let target_fallback = target.clone();
            let res = tokio::task::spawn_blocking(move || {
                let cfg = vortex_core::routing::RulesConfig::load();
                cfg.explain(&target, protocol.as_deref(), port, process.as_deref())
            })
            .await
            .unwrap_or_else(|_| vortex_core::routing::ExplainResult {
                target: target_fallback,
                matched: false,
                rule_id: "fallback".into(),
                rule_index: 0,
                action: vortex_core::routing::RuleAction::Proxy,
                reason: "evaluation failed".into(),
            });
            Some(IpcResponse::ExplainRoute(res))
        }
        IpcRequest::ReloadRouting => {
            let st = state.lock().await;
            let _ = st.subscribers.send(DaemonEvent::RoutingReloaded);
            Some(IpcResponse::Ok)
        }
        IpcRequest::SetSelectionMode { mode } => {
            let mut st = state.lock().await;
            st.selection_mode = mode;
            Some(IpcResponse::SelectionMode(mode))
        }
        IpcRequest::GetSelectionMode => {
            let st = state.lock().await;
            Some(IpcResponse::SelectionMode(st.selection_mode))
        }
        IpcRequest::GetNodeMetrics => {
            let st = state.lock().await;
            Some(IpcResponse::NodeMetrics(st.metrics.clone()))
        }
        IpcRequest::SubscribeEvents => None,
        IpcRequest::XrayInstall => {
            match run_blocking(|| vortex_core::xray::install_xray(None)).await {
                Ok(version) => Some(IpcResponse::XrayInstalled { version }),
                Err(e) => Some(IpcResponse::Error(format!("Xray installation failed: {e}"))),
            }
        }
        IpcRequest::XrayUpdate => {
            match run_blocking(|| {
                vortex_core::xray::install_xray(None).inspect(|_| {
                    let _ = vortex_core::xray::refresh_geo_databases();
                })
            })
            .await
            {
                Ok(version) => Some(IpcResponse::XrayUpdated { version }),
                Err(e) => Some(IpcResponse::Error(format!("Xray update failed: {e}"))),
            }
        }
        IpcRequest::XrayVersion => {
            let resp = tokio::task::spawn_blocking(|| {
                let path_opt = vortex_core::xray::resolve_xray_binary().ok();
                let ver = path_opt
                    .as_ref()
                    .and_then(|p| vortex_core::xray::get_binary_version(p))
                    .or_else(vortex_core::xray::resolve_installed_version);
                let is_managed = path_opt
                    .as_ref()
                    .map(|p| p.starts_with(vortex_core::xray::xray_data_dir()))
                    .unwrap_or(false);
                IpcResponse::XrayVersion {
                    version: ver,
                    path: path_opt.map(|p| p.to_string_lossy().to_string()),
                    is_managed,
                }
            })
            .await
            .unwrap_or(IpcResponse::XrayVersion {
                version: None,
                path: None,
                is_managed: false,
            });
            Some(resp)
        }
        IpcRequest::XrayDoctor => {
            let resp = tokio::task::spawn_blocking(|| {
                let doc = vortex_core::xray::run_xray_doctor();
                IpcResponse::XrayDoctor {
                    healthy: doc.is_healthy(),
                    binary: doc.binary_path.map(|p| p.to_string_lossy().to_string()),
                    version: doc.binary_version,
                    issues: doc.issues,
                }
            })
            .await
            .unwrap_or_else(|e| IpcResponse::Error(format!("Doctor failed: {e}")));
            Some(resp)
        }
        IpcRequest::GetMode => {
            let mode = tokio::task::spawn_blocking(vortex_core::storage::get_mode_preference)
                .await
                .unwrap_or_default();
            Some(IpcResponse::Mode(mode))
        }
        IpcRequest::SetMode { mode } => {
            match run_blocking(move || Ok(vortex_core::storage::set_mode_preference(mode)?)).await {
                Ok(_) => {
                    let mut st = state.lock().await;
                    st.refresh_status();
                    let _ = st
                        .subscribers
                        .send(DaemonEvent::StatusChanged(st.status.clone()));
                    Some(IpcResponse::Mode(mode))
                }
                Err(e) => Some(IpcResponse::Error(format!("Failed to persist mode: {e}"))),
            }
        }
    }
}

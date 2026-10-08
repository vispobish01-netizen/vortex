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
        let current_sess = tunnel::load_session();
        let shield_armed = shield::is_armed();
        let xray_version = vortex_core::xray::active_xray_version();
        let backend = current_sess.as_ref().map(|s| {
            if s.kind == Kind::Xray || s.conf.contains("xray") {
                "xray".to_string()
            } else if s.kind == Kind::Wg {
                "wireguard".to_string()
            } else if s.kind == Kind::Awg {
                "amneziawg".to_string()
            } else if s.kind == Kind::Ovpn {
                "openvpn".to_string()
            } else {
                "sing-box".to_string()
            }
        });

        let status = DaemonStatus {
            connected: current_sess.is_some(),
            active_profile: current_sess.as_ref().map(|s| {
                store::load_all()
                    .into_iter()
                    .find(|p| p.id == s.id)
                    .unwrap_or_else(|| Profile::new(&s.id, &s.name, s.kind, &s.server, ""))
            }),
            uptime_secs: current_sess
                .as_ref()
                .map(|s| tunnel::now().saturating_sub(s.since))
                .unwrap_or(0),
            iface: current_sess.as_ref().map(|s| s.iface.clone()),
            server_endpoint: current_sess.as_ref().map(|s| s.server.clone()),
            exit_ip: None,
            shield_armed,
            pid: current_sess.as_ref().and_then(|s| s.pid),
            xray_version,
            backend,
        };

        DaemonState {
            status,
            subscribers: tx,
            selection_mode: SelectionMode::Manual,
            scoring_weights: ScoringWeights::default(),
            metrics: std::collections::HashMap::new(),
            consecutive_probe_failures: 0,
            last_failover_ts: None,
            failover_attempt: 0,
            history: TrafficHistory::load(),
        }
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
        self.status.backend = current_sess.as_ref().map(|s| {
            if s.kind == Kind::Xray || s.conf.contains("xray") {
                "xray".to_string()
            } else if s.kind == Kind::Wg {
                "wireguard".to_string()
            } else if s.kind == Kind::Awg {
                "amneziawg".to_string()
            } else if s.kind == Kind::Ovpn {
                "openvpn".to_string()
            } else {
                "sing-box".to_string()
            }
        });
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

    // Set socket permissions to 0600 (owner only)
    if let Err(e) = std::fs::set_permissions(&sock_path, std::fs::Permissions::from_mode(0o600)) {
        warn!("Could not set socket permissions to 0600: {e}");
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
        loop {
            interval.tick().await;
            tick_counter += 1;
            let (iface, is_connected) = {
                let mut st = bg_state.lock().await;
                st.refresh_status();
                (st.status.iface.clone(), st.status.connected)
            };

            if is_connected {
                if let Some(ifc) = iface {
                    if let Some((rx, tx)) = tunnel::bytes(&ifc) {
                        let (rx_sec, tx_sec) = if let Some((prev_rx, prev_tx)) = last_bytes {
                            (rx.saturating_sub(prev_rx), tx.saturating_sub(prev_tx))
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
                        let mut st = bg_state.lock().await;
                        if probe_ok {
                            st.consecutive_probe_failures = 0;
                            st.failover_attempt = 0;
                        } else {
                            st.consecutive_probe_failures += 1;
                            warn!(
                                "Health probe failed through active tunnel (failures: {})",
                                st.consecutive_probe_failures
                            );
                            if st.consecutive_probe_failures >= 3 {
                                let now = std::time::Instant::now();
                                let cooldown_passed = st
                                    .last_failover_ts
                                    .map(|t| now.duration_since(t) > Duration::from_secs(15))
                                    .unwrap_or(true);

                                if cooldown_passed && st.failover_attempt < 5 {
                                    st.failover_attempt += 1;
                                    st.last_failover_ts = Some(now);
                                    let active_id = active_opt
                                        .as_ref()
                                        .map(|p| p.id.clone())
                                        .unwrap_or_default();
                                    let all_profiles = store::load_all();
                                    let candidates: Vec<Profile> = all_profiles
                                        .into_iter()
                                        .filter(|p| p.id != active_id)
                                        .collect();

                                    if let Some(target) = probe::select_best_node(
                                        &candidates,
                                        &st.metrics,
                                        st.selection_mode,
                                        &st.scoring_weights,
                                    ) {
                                        let to_id = target.id.clone();
                                        let target_clone = target.clone();
                                        let reason = format!(
                                            "Health check failed {} consecutive times",
                                            st.consecutive_probe_failures
                                        );
                                        warn!("Auto-failover triggered: switching from {active_id} to {to_id} ({reason})");
                                        let _ = bg_tx.send(DaemonEvent::FailoverTriggered {
                                            from_id: active_id,
                                            to_id: to_id.clone(),
                                            reason,
                                        });

                                        let creds = if tunnel::ovpn_needs_auth(&target_clone) {
                                            target_clone
                                                .auth
                                                .as_ref()
                                                .map(|a| (a.username.clone(), a.password.clone()))
                                        } else {
                                            None
                                        };

                                        if let Ok(_sess) = tunnel::connect_with_credentials(
                                            &target_clone,
                                            creds.as_ref().map(|(u, pw)| (u.as_str(), pw.as_str())),
                                        ) {
                                            st.refresh_status();
                                            st.consecutive_probe_failures = 0;
                                            let _ = bg_tx.send(DaemonEvent::StatusChanged(
                                                st.status.clone(),
                                            ));
                                        }
                                    }
                                }
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
            let profiles = store::load_all();
            Some(IpcResponse::Profiles(profiles))
        }
        IpcRequest::Connect { profile_id } => {
            let p_opt = store::load_all().into_iter().find(|p| p.id == profile_id);
            let Some(p) = p_opt else {
                return Some(IpcResponse::Error(format!("Node '{profile_id}' not found")));
            };

            let creds = if tunnel::ovpn_needs_auth(&p) {
                p.auth
                    .as_ref()
                    .map(|a| (a.username.clone(), a.password.clone()))
            } else {
                None
            };

            match tunnel::connect_with_credentials(
                &p,
                creds.as_ref().map(|(u, pw)| (u.as_str(), pw.as_str())),
            ) {
                Ok(_sess) => {
                    let mut st = state.lock().await;
                    st.refresh_status();
                    let _ = st
                        .subscribers
                        .send(DaemonEvent::StatusChanged(st.status.clone()));
                    Some(IpcResponse::Status(st.status.clone()))
                }
                Err(e) => Some(IpcResponse::Error(format!("Connection failed: {e:#}"))),
            }
        }
        IpcRequest::Disconnect => match tunnel::disconnect() {
            Ok(_) => {
                let mut st = state.lock().await;
                st.refresh_status();
                let _ = st
                    .subscribers
                    .send(DaemonEvent::StatusChanged(st.status.clone()));
                Some(IpcResponse::Status(st.status.clone()))
            }
            Err(e) => Some(IpcResponse::Error(format!("Disconnect failed: {e:#}"))),
        },
        IpcRequest::ToggleShield { enable } => {
            let cur = shield::is_armed();
            let target = enable.unwrap_or(!cur);
            let res = if target {
                shield::set_enabled_preference(true);
                let sess = tunnel::load_session();
                let iface = sess.as_ref().map(|s| s.iface.as_str());
                let srv = sess.as_ref().map(|s| s.server.as_str());
                shield::arm(iface, srv)
            } else {
                shield::set_enabled_preference(false);
                shield::disarm()
            };

            match res {
                Ok(_) => {
                    let mut st = state.lock().await;
                    st.refresh_status();
                    let armed = st.status.shield_armed;
                    let _ = st.subscribers.send(DaemonEvent::ShieldChanged { armed });
                    Some(IpcResponse::Status(st.status.clone()))
                }
                Err(e) => Some(IpcResponse::Error(format!("Shield toggle failed: {e:#}"))),
            }
        }
        IpcRequest::AddProfile { raw } => match store::import(&raw) {
            Ok(count) => Some(IpcResponse::ProfileAdded { count }),
            Err(e) => Some(IpcResponse::Error(format!("Import failed: {e:#}"))),
        },
        IpcRequest::RemoveProfile { id } => match store::remove(&id) {
            Ok(_) => Some(IpcResponse::Ok),
            Err(e) => Some(IpcResponse::Error(format!("Remove failed: {e:#}"))),
        },
        IpcRequest::RenameProfile { id, new_name } => match store::rename(&id, &new_name) {
            Ok(_) => Some(IpcResponse::Ok),
            Err(e) => Some(IpcResponse::Error(format!("Rename failed: {e:#}"))),
        },
        IpcRequest::UpdateSubscriptions { target } => {
            let res = if let Some(t) = target {
                if t == "all" {
                    store::update_all_subs().map(|v| v.len())
                } else {
                    store::update_sub(&t).map(|(_, c)| c)
                }
            } else {
                store::update_all_subs().map(|v| v.len())
            };

            match res {
                Ok(count) => Some(IpcResponse::ProfileAdded { count }),
                Err(e) => Some(IpcResponse::Error(format!(
                    "Subscription update failed: {e:#}"
                ))),
            }
        }
        IpcRequest::RunProbe { profile_id } => {
            let prober = probe::MultiLayerProber::new(16, Duration::from_millis(2000), None);
            let profiles = store::load_all();
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
                }
                let _ = state
                    .lock()
                    .await
                    .subscribers
                    .send(DaemonEvent::ProbeCompleted {
                        profile_id: p.id.clone(),
                        rtt_ms: latency,
                    });
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
            match benchmark::run_speed_test(benchmark::DEFAULT_TEST_DURATION_SECS) {
                Ok(res) => Some(IpcResponse::Speed(res)),
                Err(e) => Some(IpcResponse::Error(format!("Speed test failed: {e:#}"))),
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
        IpcRequest::GetFlows => {
            let flows = tunnel::active_flows();
            Some(IpcResponse::Flows(flows))
        }
        IpcRequest::KillFlow { id } => match tunnel::kill_flow(&id) {
            Ok(_) => Some(IpcResponse::Ok),
            Err(e) => Some(IpcResponse::Error(format!("Kill flow failed: {e:#}"))),
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
            let logs = tunnel::tail_log(lines);
            Some(IpcResponse::Logs(logs))
        }
        IpcRequest::GetRouting => {
            let cfg = tunnel::load_routing();
            Some(IpcResponse::Routing(cfg))
        }
        IpcRequest::SetRouting(cfg) => match tunnel::save_routing(&cfg) {
            Ok(_) => Some(IpcResponse::Routing(cfg)),
            Err(e) => Some(IpcResponse::Error(format!("Save routing failed: {e:#}"))),
        },
        IpcRequest::GetRulesConfig => {
            let cfg = vortex_core::routing::RulesConfig::load();
            Some(IpcResponse::RulesConfig(cfg))
        }
        IpcRequest::SetRulesConfig(cfg) => match cfg.save() {
            Ok(_) => {
                let st = state.lock().await;
                let _ = st.subscribers.send(DaemonEvent::RoutingReloaded);
                Some(IpcResponse::RulesConfig(cfg))
            }
            Err(e) => Some(IpcResponse::Error(format!("Save rules failed: {e:#}"))),
        },
        IpcRequest::ExplainRoute {
            target,
            protocol,
            port,
            process,
        } => {
            let cfg = vortex_core::routing::RulesConfig::load();
            let res = cfg.explain(&target, protocol.as_deref(), port, process.as_deref());
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
        IpcRequest::SubscribeEvents => {
            // No direct response needed; incoming events will stream via the select block
            None
        }
        IpcRequest::XrayInstall => match vortex_core::xray::install_xray(None) {
            Ok(version) => Some(IpcResponse::XrayInstalled { version }),
            Err(e) => Some(IpcResponse::Error(format!(
                "Xray installation failed: {e:#}"
            ))),
        },
        IpcRequest::XrayUpdate => {
            let res = vortex_core::xray::install_xray(None).inspect(|_| {
                let _ = vortex_core::xray::refresh_geo_databases();
            });
            match res {
                Ok(version) => Some(IpcResponse::XrayUpdated { version }),
                Err(e) => Some(IpcResponse::Error(format!("Xray update failed: {e:#}"))),
            }
        }
        IpcRequest::XrayVersion => {
            let path_opt = vortex_core::xray::resolve_xray_binary().ok();
            let ver = path_opt
                .as_ref()
                .and_then(|p| vortex_core::xray::get_binary_version(p))
                .or_else(vortex_core::xray::resolve_installed_version);
            let is_managed = path_opt
                .as_ref()
                .map(|p| p.starts_with(vortex_core::xray::xray_data_dir()))
                .unwrap_or(false);
            Some(IpcResponse::XrayVersion {
                version: ver,
                path: path_opt.map(|p| p.to_string_lossy().to_string()),
                is_managed,
            })
        }
        IpcRequest::XrayDoctor => {
            let doc = vortex_core::xray::run_xray_doctor();
            Some(IpcResponse::XrayDoctor {
                healthy: doc.is_healthy(),
                binary: doc.binary_path.map(|p| p.to_string_lossy().to_string()),
                version: doc.binary_version,
                issues: doc.issues,
            })
        }
    }
}

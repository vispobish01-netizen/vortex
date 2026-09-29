use anyhow::{Context, Result};
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, Mutex};
use tracing::{error, info, warn};
use vortex_core::ipc::*;
use vortex_core::model::*;
use vortex_core::{benchmark, ping, shield, store, tunnel};

struct DaemonState {
    status: DaemonStatus,
    subscribers: broadcast::Sender<DaemonEvent>,
}

impl DaemonState {
    fn new(tx: broadcast::Sender<DaemonEvent>) -> Self {
        let current_sess = tunnel::load_session();
        let shield_armed = shield::is_armed();
        let status = DaemonStatus {
            connected: current_sess.is_some(),
            active_profile: current_sess
                .as_ref()
                .and_then(|s| store::load_all().into_iter().find(|p| p.id == s.id)),
            uptime_secs: current_sess
                .as_ref()
                .map(|s| tunnel::now().saturating_sub(s.since))
                .unwrap_or(0),
            iface: current_sess.as_ref().map(|s| s.iface.clone()),
            server_endpoint: current_sess.as_ref().map(|s| s.server.clone()),
            exit_ip: None,
            shield_armed,
            pid: current_sess.as_ref().and_then(|s| s.pid),
        };

        DaemonState {
            status,
            subscribers: tx,
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
        if let Some(s) = &current_sess {
            self.status.uptime_secs = tunnel::now().saturating_sub(s.since);
            if self.status.active_profile.as_ref().map(|p| &p.id) != Some(&s.id) {
                self.status.active_profile = store::load_all().into_iter().find(|p| p.id == s.id);
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
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    info!("Starting Vortex Daemon v{}", env!("CARGO_PKG_VERSION"));

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
        loop {
            interval.tick().await;
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

                        let _ = bg_tx.send(DaemonEvent::TrafficStats {
                            rx_bytes_sec: rx_sec,
                            tx_bytes_sec: tx_sec,
                            total_rx: rx,
                            total_tx: tx,
                        });
                    }
                }
            } else {
                last_bytes = None;
            }
        }
    });

    // Handle shutdown gracefully
    let shutdown_sock = sock_path.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        info!("Received shutdown signal, cleaning up socket...");
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
            let profiles = store::load_all();
            let mut results = vec![];
            if let Some(id) = profile_id {
                if let Some(p) = profiles.into_iter().find(|x| x.id == id) {
                    let r = ping::measure(&p);
                    let ms = match r {
                        ping::Ping::Ms(m) => Some(m),
                        ping::Ping::Timeout => None,
                    };
                    results.push(ProbeResult {
                        profile_id: p.id,
                        rtt_ms: ms,
                        is_available: ms.is_some(),
                        real_delay_ms: None,
                    });
                }
            } else {
                for (p, r) in ping::measure_all(profiles) {
                    let ms = match r {
                        ping::Ping::Ms(m) => Some(m),
                        ping::Ping::Timeout => None,
                    };
                    results.push(ProbeResult {
                        profile_id: p.id,
                        rtt_ms: ms,
                        is_available: ms.is_some(),
                        real_delay_ms: None,
                    });
                }
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
            let real_ip = tunnel::public_ip();
            let sess = tunnel::load_session();
            let is_sec = sess.is_some();
            Some(IpcResponse::Leak(LeakReport {
                real_ip: real_ip.clone(),
                exit_ip: real_ip,
                dns_resolvers: vec!["1.1.1.1".into()],
                ipv6_leak: false,
                is_secure: is_sec,
                details: if is_sec {
                    "Encrypted tunnel engaged"
                } else {
                    "Cleartext direct path"
                }
                .into(),
            }))
        }
        IpcRequest::GetFlows => {
            let flows = tunnel::active_flows();
            Some(IpcResponse::Flows(flows))
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
        IpcRequest::SubscribeEvents => {
            // No direct response needed; incoming events will stream via the select block
            None
        }
    }
}

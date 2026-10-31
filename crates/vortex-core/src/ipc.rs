use crate::error::VortexError;
use crate::model::{ActiveFlow, LeakReport, ProbeResult, Profile, RoutingConfig, SpeedResult};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024; // 16 MB

pub const SYSTEM_SOCKET_PATH: &str = "/run/vortex/vortex.sock";

pub fn default_socket_path() -> PathBuf {
    if let Ok(path) = std::env::var("VORTEX_SOCK") {
        if !path.is_empty() {
            return PathBuf::from(path);
        }
    }
    if unsafe { libc::geteuid() == 0 } {
        return PathBuf::from(SYSTEM_SOCKET_PATH);
    }
    if let Ok(dir) = std::env::var("XDG_RUNTIME_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir).join("vortex.sock");
        }
    }
    let uid = unsafe { libc::getuid() };
    PathBuf::from(format!("/tmp/vortex-{uid}.sock"))
}

pub fn active_socket_path() -> PathBuf {
    if let Ok(path) = std::env::var("VORTEX_SOCK") {
        if !path.is_empty() {
            return PathBuf::from(path);
        }
    }
    if unsafe { libc::geteuid() == 0 } {
        let sys = PathBuf::from(SYSTEM_SOCKET_PATH);
        if sys.exists() {
            return sys;
        }
        let root_tmp = PathBuf::from("/tmp/vortex-0.sock");
        if root_tmp.exists() {
            return root_tmp;
        }
        return default_socket_path();
    }
    if let Ok(dir) = std::env::var("XDG_RUNTIME_DIR") {
        if !dir.is_empty() {
            let p = PathBuf::from(&dir).join("vortex.sock");
            if p.exists() {
                return p;
            }
        }
    }
    let sys = PathBuf::from("/run/vortex/vortex.sock");
    if sys.exists() {
        return sys;
    }
    let uid = unsafe { libc::getuid() };
    let user_tmp = PathBuf::from(format!("/tmp/vortex-{uid}.sock"));
    if user_tmp.exists() {
        return user_tmp;
    }
    let root_tmp = PathBuf::from("/tmp/vortex-0.sock");
    if root_tmp.exists() {
        return root_tmp;
    }
    default_socket_path()
}

use crate::history::TrafficHistory;
use crate::probe::{NodeMetrics, SelectionMode};
use crate::routing::{ExplainResult, RulesConfig};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "action", content = "payload")]
pub enum IpcRequest {
    Ping,
    Version,
    GetStatus,
    GetProfiles,
    Connect {
        profile_id: String,
    },
    Disconnect,
    ToggleShield {
        enable: Option<bool>,
    },
    AddProfile {
        raw: String,
    },
    RemoveProfile {
        id: String,
    },
    RenameProfile {
        id: String,
        new_name: String,
    },
    UpdateSubscriptions {
        target: Option<String>,
    },
    RunProbe {
        profile_id: Option<String>,
    },
    RunSpeedTest,
    RunLeakTest,
    GetFlows,
    KillFlow {
        id: String,
    },
    GetLogs {
        lines: usize,
    },
    GetRouting,
    SetRouting(RoutingConfig),
    GetRulesConfig,
    SetRulesConfig(RulesConfig),
    ExplainRoute {
        target: String,
        protocol: Option<String>,
        port: Option<u16>,
        process: Option<String>,
    },
    ReloadRouting,
    GetHistory,
    ExportHistory {
        format: String,
        since_secs: Option<u64>,
    },
    SetSelectionMode {
        mode: SelectionMode,
    },
    GetSelectionMode,
    GetNodeMetrics,
    SubscribeEvents,
    XrayInstall,
    XrayUpdate,
    XrayVersion,
    XrayDoctor,
    GetMode,
    SetMode {
        mode: crate::model::OperationalMode,
    },
}

#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "status", content = "payload")]
pub enum IpcResponse {
    Ok,
    Error(String),
    Mode(crate::model::OperationalMode),
    Version {
        version: u32,
        app_version: String,
    },
    Status(DaemonStatus),
    Profiles(Vec<Profile>),
    ProfileAdded {
        count: usize,
    },
    Flows(Vec<ActiveFlow>),
    Logs(Vec<String>),
    Speed(SpeedResult),
    Probe(Vec<ProbeResult>),
    Leak(LeakReport),
    Routing(RoutingConfig),
    RulesConfig(RulesConfig),
    ExplainRoute(ExplainResult),
    SelectionMode(SelectionMode),
    NodeMetrics(std::collections::HashMap<String, NodeMetrics>),
    History(TrafficHistory),
    Export(String),
    XrayInstalled {
        version: String,
    },
    XrayUpdated {
        version: String,
    },
    XrayVersion {
        version: Option<String>,
        path: Option<String>,
        is_managed: bool,
    },
    XrayDoctor {
        healthy: bool,
        binary: Option<String>,
        version: Option<String>,
        issues: Vec<String>,
    },
}

#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "event", content = "data")]
pub enum DaemonEvent {
    StatusChanged(DaemonStatus),
    TrafficStats {
        rx_bytes_sec: u64,
        tx_bytes_sec: u64,
        total_rx: u64,
        total_tx: u64,
    },
    ProbeCompleted {
        profile_id: String,
        rtt_ms: Option<u32>,
    },
    LogLine(String),
    ShieldChanged {
        armed: bool,
    },
    FailoverTriggered {
        from_id: String,
        to_id: String,
        reason: String,
    },
    RoutingReloaded,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct DaemonStatus {
    pub connected: bool,
    pub active_profile: Option<Profile>,
    pub uptime_secs: u64,
    pub iface: Option<String>,
    pub server_endpoint: Option<String>,
    pub exit_ip: Option<String>,
    pub shield_armed: bool,
    pub pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xray_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    #[serde(default)]
    pub mode: crate::model::OperationalMode,
}

// ───────────────────────── Async Frame I/O ─────────────────────────

pub async fn write_frame_async<W: AsyncWrite + Unpin, T: Serialize>(
    writer: &mut W,
    msg: &T,
) -> Result<(), VortexError> {
    let bytes = serde_json::to_vec(msg)?;
    let len = bytes.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_frame_async<R: AsyncRead + Unpin, T: DeserializeOwned>(
    reader: &mut R,
) -> Result<T, VortexError> {
    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len > MAX_FRAME_SIZE {
        return Err(VortexError::Ipc(format!(
            "frame size {len} exceeds limit of {MAX_FRAME_SIZE} bytes"
        )));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    let msg: T = serde_json::from_slice(&buf)?;
    Ok(msg)
}

// ───────────────────────── Sync Frame I/O ─────────────────────────

pub fn write_frame_sync<W: Write, T: Serialize>(
    writer: &mut W,
    msg: &T,
) -> Result<(), VortexError> {
    let bytes = serde_json::to_vec(msg)?;
    let len = bytes.len() as u32;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(&bytes)?;
    writer.flush()?;
    Ok(())
}

pub fn read_frame_sync<R: Read, T: DeserializeOwned>(reader: &mut R) -> Result<T, VortexError> {
    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes)?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len > MAX_FRAME_SIZE {
        return Err(VortexError::Ipc(format!(
            "frame size {len} exceeds limit of {MAX_FRAME_SIZE} bytes"
        )));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    let msg: T = serde_json::from_slice(&buf)?;
    Ok(msg)
}

/// Set socket file permissions to 0600 (owner read/write only)
pub fn secure_socket_file(path: &std::path::Path) -> Result<(), VortexError> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[derive(Clone, Debug)]
pub struct IpcClient {
    pub sock_path: PathBuf,
}

impl Default for IpcClient {
    fn default() -> Self {
        Self::new()
    }
}

impl IpcClient {
    pub fn new() -> Self {
        Self {
            sock_path: active_socket_path(),
        }
    }

    pub fn with_path(path: PathBuf) -> Self {
        Self { sock_path: path }
    }

    pub fn is_daemon_running(&self) -> bool {
        if !self.sock_path.exists() {
            return false;
        }
        std::os::unix::net::UnixStream::connect(&self.sock_path).is_ok()
    }

    pub fn request_sync(&self, req: &IpcRequest) -> Result<IpcResponse, VortexError> {
        let mut stream = std::os::unix::net::UnixStream::connect(&self.sock_path).map_err(|e| {
            VortexError::Ipc(format!(
                "Cannot connect to vortexd at {:?}: {e}",
                self.sock_path
            ))
        })?;
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(15)))
            .ok();
        stream
            .set_write_timeout(Some(std::time::Duration::from_secs(15)))
            .ok();
        write_frame_sync(&mut stream, req)?;
        read_frame_sync::<_, IpcResponse>(&mut stream)
    }

    pub async fn request(&self, req: &IpcRequest) -> Result<IpcResponse, VortexError> {
        let mut stream = tokio::net::UnixStream::connect(&self.sock_path)
            .await
            .map_err(|e| {
                VortexError::Ipc(format!(
                    "Cannot connect to vortexd at {:?}: {e}",
                    self.sock_path
                ))
            })?;
        write_frame_async(&mut stream, req).await?;
        read_frame_async::<_, IpcResponse>(&mut stream).await
    }

    pub async fn subscribe_events(&self) -> Result<tokio::net::UnixStream, VortexError> {
        let mut stream = tokio::net::UnixStream::connect(&self.sock_path)
            .await
            .map_err(|e| {
                VortexError::Ipc(format!(
                    "Cannot connect to vortexd at {:?}: {e}",
                    self.sock_path
                ))
            })?;
        write_frame_async(&mut stream, &IpcRequest::SubscribeEvents).await?;
        Ok(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_async_frame_roundtrip() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let req = IpcRequest::Connect {
            profile_id: "test-node".into(),
        };

        let handle = tokio::spawn(async move {
            let received: IpcRequest = read_frame_async(&mut server).await.unwrap();
            assert_eq!(
                received,
                IpcRequest::Connect {
                    profile_id: "test-node".into()
                }
            );
            write_frame_async(
                &mut server,
                &IpcResponse::Status(DaemonStatus {
                    connected: true,
                    ..Default::default()
                }),
            )
            .await
            .unwrap();
        });

        write_frame_async(&mut client, &req).await.unwrap();
        let resp: IpcResponse = read_frame_async(&mut client).await.unwrap();
        match resp {
            IpcResponse::Status(st) => assert!(st.connected),
            _ => panic!("unexpected response"),
        }
        handle.await.unwrap();
    }

    #[test]
    fn test_sync_frame_roundtrip() {
        let mut buffer = Vec::new();
        let req = IpcRequest::Ping;
        write_frame_sync(&mut buffer, &req).unwrap();

        let mut slice = &buffer[..];
        let decoded: IpcRequest = read_frame_sync(&mut slice).unwrap();
        assert_eq!(decoded, IpcRequest::Ping);
    }
}

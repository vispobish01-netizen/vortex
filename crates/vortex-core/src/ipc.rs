use crate::error::VortexError;
use crate::model::{ActiveFlow, LeakReport, ProbeResult, Profile, RoutingConfig, SpeedResult};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024; // 16 MB

pub fn default_socket_path() -> PathBuf {
    if let Ok(dir) = std::env::var("XDG_RUNTIME_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir).join("vortex.sock");
        }
    }
    let uid = unsafe { libc::getuid() };
    PathBuf::from(format!("/tmp/vortex-{uid}.sock"))
}

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
    SetSelectionMode {
        mode: SelectionMode,
    },
    GetSelectionMode,
    GetNodeMetrics,
    SubscribeEvents,
}

#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "status", content = "payload")]
pub enum IpcResponse {
    Ok,
    Error(String),
    Version { version: u32, app_version: String },
    Status(DaemonStatus),
    Profiles(Vec<Profile>),
    ProfileAdded { count: usize },
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
            sock_path: default_socket_path(),
        }
    }

    pub fn with_path(path: PathBuf) -> Self {
        Self { sock_path: path }
    }

    pub fn is_daemon_running(&self) -> bool {
        self.sock_path.exists()
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

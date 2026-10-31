use anyhow::{Context, Result};
use tracing::{info, warn};
use vortex_core::ipc::{IpcClient, IpcRequest, IpcResponse};

/// State of the TUI client connected to vortexd.
pub struct TuiApp {
    pub client: IpcClient,
    pub is_running: bool,
}

impl Default for TuiApp {
    fn default() -> Self {
        Self::new()
    }
}

impl TuiApp {
    pub fn new() -> Self {
        Self {
            client: IpcClient::new(),
            is_running: true,
        }
    }

    /// Check if vortexd is currently reachable via IPC.
    pub fn is_daemon_online(&self) -> bool {
        self.client.is_daemon_running()
    }

    /// Query the daemon for active status.
    pub fn fetch_status(&self) -> Result<vortex_core::ipc::DaemonStatus> {
        let resp = self
            .client
            .request_sync(&IpcRequest::GetStatus)
            .context("Failed to query daemon status via IPC")?;
        match resp {
            IpcResponse::Status(status) => Ok(status),
            IpcResponse::Error(err) => anyhow::bail!("Daemon reported error: {err}"),
            other => anyhow::bail!("Unexpected response from daemon: {other:?}"),
        }
    }
}

/// Entrypoint to launch the Vortex TUI.
pub async fn run() -> Result<()> {
    let app = TuiApp::new();
    if !app.is_daemon_online() {
        warn!(
            "vortexd does not appear to be running at {:?}. Some features may require starting the daemon.",
            vortex_core::ipc::active_socket_path()
        );
    } else {
        info!("Successfully connected to vortexd via IPC.");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tui_app_init() {
        let app = TuiApp::new();
        assert!(app.is_running);
    }
}

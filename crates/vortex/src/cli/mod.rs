pub mod completion;
pub mod connect;
pub mod diagnostics;
pub mod notify;
pub mod profiles;
pub mod route;
pub mod shield;
pub mod status;
pub mod xray;

pub use completion::*;
pub use connect::*;
pub use diagnostics::*;
pub use profiles::*;
pub use route::*;
pub use shield::*;
pub use status::*;
pub use xray::*;

use vortex_core::ipc::IpcClient;

pub fn get_ipc() -> Option<IpcClient> {
    let client = IpcClient::new();
    if client.is_daemon_running() {
        Some(client)
    } else {
        None
    }
}

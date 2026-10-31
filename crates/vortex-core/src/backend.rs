use crate::model::Profile;
use crate::tunnel::Session;
use anyhow::Result;
use std::path::Path;

/// Common abstraction for tunnel backends (Xray, sing-box, WireGuard, OpenVPN).
pub trait Backend: Send + Sync {
    /// Human-readable backend name (e.g. "xray", "sing-box", "wireguard", "openvpn")
    fn name(&self) -> &'static str;

    /// Checks if this backend's binary and dependencies are installed and available
    fn is_available(&self) -> bool;

    /// Returns the active backend version if available
    fn version(&self) -> Option<String>;

    /// Validates a raw or generated configuration before activation
    fn validate_config(&self, config_content: &str) -> Result<()>;

    /// Starts a session using the given profile
    fn start(&self, profile: &Profile, runtime_dir: &Path) -> Result<Session>;

    /// Stops an active session
    fn stop(&self, session: &Session) -> Result<()>;

    /// Queries live traffic metrics (total_rx, total_tx) in bytes
    fn query_traffic(&self, session: &Session) -> Result<(u64, u64)>;
}

/// Resolves the appropriate backend implementation for a profile.
pub fn resolve_backend(profile: &Profile) -> Box<dyn Backend> {
    use crate::backends::{AmneziaBackend, Hysteria2Backend, OpenVpnBackend, WireGuardBackend};
    use crate::model::Kind;
    use crate::xray::XrayBackend;

    if profile.kind == Kind::Wg {
        Box::new(WireGuardBackend::new())
    } else if profile.kind == Kind::Awg {
        Box::new(AmneziaBackend::new())
    } else if profile.kind == Kind::Ovpn {
        Box::new(OpenVpnBackend::new())
    } else if profile.kind == Kind::Hy2 {
        Box::new(Hysteria2Backend::new())
    } else {
        Box::new(XrayBackend::new())
    }
}

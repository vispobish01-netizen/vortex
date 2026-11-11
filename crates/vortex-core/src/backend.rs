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

/// Resolves the appropriate backend implementation for a profile using its effective CoreEngine.
/// For Xray-backed profiles, prefers `ThroneBridgeBackend` (sing-box Master Router + Xray SOCKS5 bridge)
/// whenever both binaries are installed unless `VORTEX_XRAY_STANDALONE=1` is set.
pub fn resolve_backend(profile: &Profile) -> Box<dyn Backend> {
    use crate::backends::{
        AmneziaBackend, Hysteria2Backend, OpenVpnBackend, SingBoxBackend, ThroneBridgeBackend,
        WireGuardBackend,
    };
    use crate::model::{CoreEngine, Kind};
    use crate::xray::XrayBackend;

    match profile.kind {
        Kind::Wg => return Box::new(WireGuardBackend::new()),
        Kind::Awg => return Box::new(AmneziaBackend::new()),
        Kind::Ovpn => return Box::new(OpenVpnBackend::new()),
        Kind::Hy2 => return Box::new(Hysteria2Backend::new()),
        _ => {}
    }

    match profile.effective_engine() {
        CoreEngine::WireGuard => Box::new(WireGuardBackend::new()),
        CoreEngine::AmneziaWg => Box::new(AmneziaBackend::new()),
        CoreEngine::OpenVpn => Box::new(OpenVpnBackend::new()),
        CoreEngine::SingBox | CoreEngine::Auto => Box::new(SingBoxBackend::new()),
        CoreEngine::Xray => {
            let force_standalone = std::env::var("VORTEX_XRAY_STANDALONE")
                .ok()
                .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
            if !force_standalone && ThroneBridgeBackend::new().is_available() {
                Box::new(ThroneBridgeBackend::new())
            } else {
                Box::new(XrayBackend::new())
            }
        }
    }
}

/// Resolves the backend that owns an active `Session` (for clean stop / traffic polling).
pub fn resolve_backend_for_session(session: &Session) -> Box<dyn Backend> {
    use crate::backends::{
        AmneziaBackend, Hysteria2Backend, OpenVpnBackend, SingBoxBackend, ThroneBridgeBackend,
        WireGuardBackend,
    };
    use crate::model::Kind;
    use crate::xray::XrayBackend;

    if let Some(b) = session.backend.as_deref() {
        match b {
            "sing-box+xray" => return Box::new(ThroneBridgeBackend::new()),
            "sing-box" => return Box::new(SingBoxBackend::new()),
            "xray" | "xray-bridge" => return Box::new(XrayBackend::new()),
            "wireguard" => return Box::new(WireGuardBackend::new()),
            "amnezia" => return Box::new(AmneziaBackend::new()),
            "openvpn" => return Box::new(OpenVpnBackend::new()),
            "hysteria2" => return Box::new(Hysteria2Backend::new()),
            _ => {}
        }
    }

    if session.conf.ends_with("singbox.json") {
        if session.sidecar_pid.is_some() {
            return Box::new(ThroneBridgeBackend::new());
        }
        return Box::new(SingBoxBackend::new());
    }
    if session.conf.contains("xray") {
        return Box::new(XrayBackend::new());
    }

    match session.kind {
        Kind::Wg => Box::new(WireGuardBackend::new()),
        Kind::Awg => Box::new(AmneziaBackend::new()),
        Kind::Ovpn => Box::new(OpenVpnBackend::new()),
        Kind::Hy2 => Box::new(Hysteria2Backend::new()),
        Kind::Xray => Box::new(XrayBackend::new()),
        _ => Box::new(SingBoxBackend::new()),
    }
}

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Hash, Default)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    #[default]
    Vless,
    Vmess,
    Trojan,
    Ss,
    Hy2,
    Tuic,
    Wg,
    Awg,
    Ovpn,
    Xray,
}

impl Kind {
    pub fn tag(self) -> &'static str {
        match self {
            Kind::Vless => "VLESS",
            Kind::Vmess => "VMESS",
            Kind::Trojan => "TROJAN",
            Kind::Ss => "SS",
            Kind::Hy2 => "HY2",
            Kind::Tuic => "TUIC",
            Kind::Wg => "WG",
            Kind::Awg => "AWG",
            Kind::Ovpn => "OVPN",
            Kind::Xray => "XRAY",
        }
    }

    pub fn padded_tag(self) -> &'static str {
        match self {
            Kind::Vless => "VLESS ",
            Kind::Vmess => "VMESS ",
            Kind::Trojan => "TROJAN",
            Kind::Ss => "SS    ",
            Kind::Hy2 => "HY2   ",
            Kind::Tuic => "TUIC  ",
            Kind::Wg => "WG    ",
            Kind::Awg => "AWG   ",
            Kind::Ovpn => "OVPN  ",
            Kind::Xray => "XRAY  ",
        }
    }

    pub fn is_singbox(self) -> bool {
        !matches!(self, Kind::Wg | Kind::Awg | Kind::Ovpn | Kind::Xray)
    }

    pub fn is_xray_capable(self) -> bool {
        matches!(
            self,
            Kind::Vless | Kind::Vmess | Kind::Trojan | Kind::Ss | Kind::Hy2 | Kind::Xray
        )
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Hash, Default)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Tcp,
    Udp,
    Quic,
    Ws,
    Grpc,
    H2,
    HttpUpgrade,
    Xhttp,
    #[default]
    Unknown,
}

impl Transport {
    pub fn is_tcp(&self) -> bool {
        matches!(
            self,
            Transport::Tcp
                | Transport::Ws
                | Transport::Grpc
                | Transport::H2
                | Transport::HttpUpgrade
                | Transport::Xhttp
        )
    }

    pub fn is_udp(&self) -> bool {
        matches!(self, Transport::Udp | Transport::Quic)
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            Transport::Tcp => "TCP",
            Transport::Udp => "UDP",
            Transport::Quic => "UDP/QUIC",
            Transport::Ws => "TCP+WS",
            Transport::Grpc => "TCP+gRPC",
            Transport::H2 => "TCP+H2",
            Transport::HttpUpgrade => "TCP+Upgrade",
            Transport::Xhttp => "TCP+XHTTP",
            Transport::Unknown => "--",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Hash, Default)]
#[serde(rename_all = "lowercase")]
pub enum Security {
    None,
    Tls,
    Reality,
    #[default]
    Unknown,
}

impl Security {
    pub fn display_name(&self) -> &'static str {
        match self {
            Security::None => "none",
            Security::Tls => "TLS",
            Security::Reality => "Reality",
            Security::Unknown => "--",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Auth {
    pub username: String,
    pub password: String,
    #[serde(default = "default_true")]
    pub save: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Subscription {
    pub id: String,
    pub name: String,
    pub url: String,
    pub count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Subscription {
    pub fn new(id: impl Into<String>, name: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            url: url.into(),
            count: 0,
            updated: None,
            error: None,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub kind: Kind,
    pub server: String,
    pub data: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<Auth>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub_id: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<u64>,
    #[serde(default)]
    pub transport: Transport,
    #[serde(default)]
    pub security: Security,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alpn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfs: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reality_public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reality_short_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reality_spider_x: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ech: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned_peer_cert: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_quantum: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_type: Option<String>,
}

impl Profile {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        kind: Kind,
        server: impl Into<String>,
        data: impl Into<String>,
    ) -> Self {
        let server_str = server.into();
        let port = server_str
            .rsplit_once(':')
            .and_then(|(_, p)| p.split('/').next().unwrap_or("").parse::<u16>().ok());
        Self {
            id: id.into(),
            name: name.into(),
            kind,
            server: server_str,
            data: data.into(),
            auth: None,
            sub_id: None,
            tags: Vec::new(),
            group: None,
            created_at: None,
            updated_at: None,
            transport: Transport::Unknown,
            security: Security::Unknown,
            tls_version: None,
            sni: None,
            alpn: None,
            obfs: None,
            port,
            flow: None,
            fingerprint: None,
            reality_public_key: None,
            reality_short_id: None,
            reality_spider_x: None,
            ech: None,
            pinned_peer_cert: None,
            post_quantum: None,
            backend_type: None,
        }
    }

    pub fn display_transport(&self) -> String {
        match self.transport {
            Transport::Unknown => "--".to_string(),
            Transport::Quic => "UDP/QUIC".to_string(),
            Transport::Udp => "UDP".to_string(),
            Transport::Ws => "TCP+WS".to_string(),
            Transport::Grpc => "TCP+gRPC".to_string(),
            Transport::H2 => "TCP+H2".to_string(),
            Transport::HttpUpgrade => "TCP+Upgrade".to_string(),
            Transport::Xhttp => "TCP+XHTTP".to_string(),
            Transport::Tcp => {
                if self.security == Security::Reality {
                    "TCP+Reality".to_string()
                } else {
                    "TCP".to_string()
                }
            }
        }
    }

    pub fn display_security(&self) -> String {
        match self.security {
            Security::Reality => "Reality".to_string(),
            Security::Tls => {
                if let Some(v) = &self.tls_version {
                    if v.to_ascii_uppercase().starts_with("TLS") {
                        v.clone()
                    } else {
                        format!("TLS {v}")
                    }
                } else {
                    "TLS".to_string()
                }
            }
            Security::None => {
                if self.kind == Kind::Wg || self.kind == Kind::Awg {
                    "none".to_string()
                } else {
                    "none (warn)".to_string()
                }
            }
            Security::Unknown => "--".to_string(),
        }
    }

    pub fn populate_metadata(&mut self) {
        crate::parser::derive_metadata_for_profile(self);
    }
}

impl Default for Profile {
    fn default() -> Self {
        Self::new("", "", Kind::default(), "", "")
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ActiveFlow {
    pub id: String,
    pub network: String,
    pub host: String,
    pub destination: String,
    pub source: String,
    pub process: String,
    pub upload: u64,
    pub download: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RoutingConfig {
    #[serde(default = "default_true")]
    pub bypass_lan: bool,
    #[serde(default)]
    pub direct_domains: Vec<String>,
    #[serde(default)]
    pub blocked_domains: Vec<String>,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        RoutingConfig {
            bypass_lan: true,
            direct_domains: vec!["local".into(), "lan".into(), "home.arpa".into()],
            blocked_domains: vec![],
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SpeedResult {
    pub bytes: u64,
    pub duration_secs: f64,
    pub mbps: f64,
    pub mbs: f64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ReconReport {
    pub node_name: String,
    pub kind: String,
    pub target_endpoint: String,
    pub host: String,
    pub port: u16,
    pub resolved_ips: Vec<String>,
    pub reverse_dns: Option<String>,
    pub asn: Option<String>,
    pub org: Option<String>,
    pub city: Option<String>,
    pub country: Option<String>,
    pub loc: Option<String>,
    pub rtt_min: u32,
    pub rtt_avg: u32,
    pub rtt_max: u32,
    pub jitter: u32,
    pub tls_version: Option<String>,
    pub tls_cipher: Option<String>,
    pub tls_cert_subject: Option<String>,
    pub tls_cert_issuer: Option<String>,
    pub exit_ip: Option<String>,
    pub exit_colo: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ProbeResult {
    pub profile_id: String,
    pub rtt_ms: Option<u32>,
    pub is_available: bool,
    pub real_delay_ms: Option<u32>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct LeakCheckItem {
    pub name: String,
    pub passed: bool,
    pub details: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct LeakReport {
    pub real_ip: String,
    pub exit_ip: String,
    pub dns_resolvers: Vec<String>,
    pub ipv6_leak: bool,
    pub is_secure: bool,
    pub details: String,
    #[serde(default)]
    pub checks: Vec<LeakCheckItem>,
}

/// Helper function to redact secrets from URLs, configs, or auth credentials for safe logging.
pub fn redact_secret(s: &str) -> String {
    if s.len() <= 6 {
        return "***".to_string();
    }
    format!("{}***{}", &s[..2], &s[s.len() - 2..])
}

/// Helper function to redact sensitive query params or passwords from a full VPN URI.
pub fn redact_link(uri: &str) -> String {
    if let Some((proto, rest)) = uri.split_once("://") {
        if let Some((user_info, host_part)) = rest.split_once('@') {
            let redacted_user = redact_secret(user_info);
            return format!("{proto}://{redacted_user}@{host_part}");
        }
    }
    redact_secret(uri)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_link() {
        let uri = "vless://b6a03649-61f4-41aa-a51b-402c3cc6c547@example.com:443?type=ws";
        let red = redact_link(uri);
        assert!(!red.contains("b6a03649-61f4-41aa-a51b-402c3cc6c547"));
        assert!(red.contains("@example.com:443"));
    }
}

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
        }
    }

    pub fn is_singbox(self) -> bool {
        !matches!(self, Kind::Wg | Kind::Awg | Kind::Ovpn)
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
}

impl Profile {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        kind: Kind,
        server: impl Into<String>,
        data: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            kind,
            server: server.into(),
            data: data.into(),
            auth: None,
            sub_id: None,
            tags: Vec::new(),
            group: None,
            created_at: None,
            updated_at: None,
        }
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
pub struct LeakReport {
    pub real_ip: String,
    pub exit_ip: String,
    pub dns_resolvers: Vec<String>,
    pub ipv6_leak: bool,
    pub is_secure: bool,
    pub details: String,
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

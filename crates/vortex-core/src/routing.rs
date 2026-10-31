use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    net::IpAddr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

pub const DEFAULT_RULES_VERSION: u32 = 1;

fn default_true() -> bool {
    true
}

pub fn rules_file_path() -> PathBuf {
    if let Ok(dir) = std::env::var("VORTEX_CONFIG_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir).join("rules.toml");
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".config/vortex/rules.toml")
    } else {
        PathBuf::from("/etc/vortex/rules.toml")
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    #[default]
    Proxy,
    Direct,
    Block,
    ProxyGroup,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum DomainMatcher {
    Exact(String),
    Suffix(String),
    Keyword(String),
    Regex(String),
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RuleItem {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub action: RuleAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_group: Option<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domains: Vec<DomainMatcher>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ip_cidrs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub geoip: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub geosite: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protocols: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub process_names: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub uids: Vec<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cgroups: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fwmark: Option<u32>,
}

impl Default for RuleItem {
    fn default() -> Self {
        Self {
            id: "rule_default".into(),
            description: None,
            enabled: true,
            action: RuleAction::Proxy,
            target_group: None,
            domains: Vec::new(),
            ip_cidrs: Vec::new(),
            geoip: Vec::new(),
            geosite: Vec::new(),
            ports: Vec::new(),
            protocols: Vec::new(),
            process_names: Vec::new(),
            uids: Vec::new(),
            cgroups: Vec::new(),
            fwmark: None,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RulePresets {
    #[serde(default = "default_true")]
    pub bypass_lan: bool,
    #[serde(default = "default_true")]
    pub block_ads: bool,
    #[serde(default)]
    pub direct_domestic: bool,
    #[serde(default = "default_true")]
    pub proxy_all: bool,
}

impl Default for RulePresets {
    fn default() -> Self {
        Self {
            bypass_lan: true,
            block_ads: true,
            direct_domestic: false,
            proxy_all: true,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RulesConfig {
    #[serde(default = "default_rules_version")]
    pub version: u32,
    #[serde(default)]
    pub presets: RulePresets,
    #[serde(default)]
    pub custom_rules: Vec<RuleItem>,
}

fn default_rules_version() -> u32 {
    DEFAULT_RULES_VERSION
}

impl Default for RulesConfig {
    fn default() -> Self {
        Self {
            version: DEFAULT_RULES_VERSION,
            presets: RulePresets::default(),
            custom_rules: vec![
                RuleItem {
                    id: "bypass_local".into(),
                    description: Some("Direct route for local network services".into()),
                    enabled: true,
                    action: RuleAction::Direct,
                    target_group: None,
                    domains: vec![
                        DomainMatcher::Suffix("local".into()),
                        DomainMatcher::Suffix("lan".into()),
                        DomainMatcher::Suffix("home.arpa".into()),
                        DomainMatcher::Exact("localhost".into()),
                    ],
                    ip_cidrs: vec![
                        "127.0.0.0/8".into(),
                        "10.0.0.0/8".into(),
                        "172.16.0.0/12".into(),
                        "192.168.0.0/16".into(),
                        "::1/128".into(),
                        "fe80::/10".into(),
                    ],
                    geoip: Vec::new(),
                    geosite: Vec::new(),
                    ports: Vec::new(),
                    protocols: Vec::new(),
                    process_names: Vec::new(),
                    uids: Vec::new(),
                    cgroups: Vec::new(),
                    fwmark: None,
                },
                RuleItem {
                    id: "block_telemetry".into(),
                    description: Some("Block known tracker and malware domains".into()),
                    enabled: true,
                    action: RuleAction::Block,
                    target_group: None,
                    domains: vec![
                        DomainMatcher::Keyword("telemetry".into()),
                        DomainMatcher::Keyword("analytics".into()),
                        DomainMatcher::Suffix("doubleclick.net".into()),
                    ],
                    ip_cidrs: Vec::new(),
                    geoip: Vec::new(),
                    geosite: Vec::new(),
                    ports: Vec::new(),
                    protocols: Vec::new(),
                    process_names: Vec::new(),
                    uids: Vec::new(),
                    cgroups: Vec::new(),
                    fwmark: None,
                },
            ],
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ExplainResult {
    pub target: String,
    pub matched: bool,
    pub rule_id: String,
    pub rule_index: usize,
    pub action: RuleAction,
    pub reason: String,
}

impl RulesConfig {
    /// Loads rules from the given path or defaults to `~/.config/vortex/rules.toml`.
    pub fn load_from(path: &Path) -> Result<Self> {
        if !path.exists() {
            let default_cfg = Self::default();
            default_cfg.save_to(path)?;
            return Ok(default_cfg);
        }

        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read rules config from {path:?}"))?;
        let mut cfg: RulesConfig = toml::from_str(&content)
            .with_context(|| format!("Failed to parse TOML from {path:?}"))?;
        for r in &mut cfg.custom_rules {
            if r.id == "block_telemetry" {
                r.geosite.retain(|g| g != "category-ads-all");
            }
        }
        Ok(cfg)
    }

    pub fn load() -> Self {
        let p = rules_file_path();
        Self::load_from(&p).unwrap_or_default()
    }

    /// Saves rules atomically using temp file and rename with mode 0600.
    pub fn save_to(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let serialized =
            toml::to_string_pretty(self).context("Failed to serialize RulesConfig to TOML")?;

        let tmp_path = path.with_extension(format!("tmp.{}", std::process::id()));
        fs::write(&tmp_path, serialized)
            .with_context(|| format!("Failed to write temporary rules file at {tmp_path:?}"))?;
        let _ = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600));

        fs::rename(&tmp_path, path)
            .with_context(|| format!("Failed to atomically rename {tmp_path:?} to {path:?}"))?;
        Ok(())
    }

    pub fn save(&self) -> Result<()> {
        let p = rules_file_path();
        self.save_to(&p)
    }

    /// Converts routing configuration into sing-box routing rules JSON.
    pub fn to_singbox_rules(&self) -> Vec<serde_json::Value> {
        let mut rules = vec![
            serde_json::json!({"action": "sniff"}),
            serde_json::json!({"protocol": "dns", "action": "hijack-dns"}),
        ];

        // 1. Preset: Bypass LAN
        if self.presets.bypass_lan {
            rules.push(serde_json::json!({
                "ip_is_private": true,
                "outbound": "direct"
            }));
            rules.push(serde_json::json!({
                "domain_suffix": ["local", "lan", "home.arpa", "localdomain"],
                "outbound": "direct"
            }));
        }

        // 2. Preset: Block Ads
        if self.presets.block_ads {
            rules.push(serde_json::json!({
                "domain_suffix": [
                    "doubleclick.net",
                    "googleadservices.com",
                    "adservice.google.com",
                    "googlesyndication.com",
                    "adnxs.com"
                ],
                "domain_keyword": [
                    "adservice",
                    "telemetry",
                    "analytics"
                ],
                "action": "reject"
            }));
        }

        // 3. Preset: Direct Domestic
        if self.presets.direct_domestic {
            rules.push(serde_json::json!({
                "rule_set": ["geoip-cn", "geoip-ir"],
                "outbound": "direct"
            }));
        }

        // 4. Custom User Rules
        for r in &self.custom_rules {
            if !r.enabled {
                continue;
            }

            let mut obj = serde_json::Map::new();

            match r.action {
                RuleAction::Proxy => {
                    obj.insert("outbound".into(), serde_json::Value::String("proxy".into()));
                }
                RuleAction::Direct => {
                    obj.insert(
                        "outbound".into(),
                        serde_json::Value::String("direct".into()),
                    );
                }
                RuleAction::Block => {
                    obj.insert("action".into(), serde_json::Value::String("reject".into()));
                }
                RuleAction::ProxyGroup => {
                    let group = r.target_group.as_deref().unwrap_or("proxy");
                    obj.insert("outbound".into(), serde_json::Value::String(group.into()));
                }
            }

            let mut exact_domains = Vec::new();
            let mut suffix_domains = Vec::new();
            let mut keyword_domains = Vec::new();
            let mut regex_domains = Vec::new();

            for d in &r.domains {
                match d {
                    DomainMatcher::Exact(v) => exact_domains.push(v.clone()),
                    DomainMatcher::Suffix(v) => suffix_domains.push(v.clone()),
                    DomainMatcher::Keyword(v) => keyword_domains.push(v.clone()),
                    DomainMatcher::Regex(v) => regex_domains.push(v.clone()),
                }
            }

            if !exact_domains.is_empty() {
                obj.insert("domain".into(), serde_json::json!(exact_domains));
            }
            if !suffix_domains.is_empty() {
                obj.insert("domain_suffix".into(), serde_json::json!(suffix_domains));
            }
            if !keyword_domains.is_empty() {
                obj.insert("domain_keyword".into(), serde_json::json!(keyword_domains));
            }
            if !regex_domains.is_empty() {
                obj.insert("domain_regex".into(), serde_json::json!(regex_domains));
            }

            if !r.ip_cidrs.is_empty() {
                obj.insert("ip_cidr".into(), serde_json::json!(r.ip_cidrs));
            }
            let mut rule_set_tags = Vec::new();
            for g in &r.geoip {
                let tag = if g.starts_with("geoip-") {
                    g.clone()
                } else {
                    format!("geoip-{g}")
                };
                rule_set_tags.push(tag);
            }
            for g in &r.geosite {
                let tag = if g.starts_with("geosite-") {
                    g.clone()
                } else {
                    format!("geosite-{g}")
                };
                rule_set_tags.push(tag);
            }
            if !rule_set_tags.is_empty() {
                obj.insert("rule_set".into(), serde_json::json!(rule_set_tags));
            }
            if !r.ports.is_empty() {
                obj.insert("port".into(), serde_json::json!(r.ports));
            }
            if !r.protocols.is_empty() {
                obj.insert("network".into(), serde_json::json!(r.protocols));
            }
            if !r.process_names.is_empty() {
                obj.insert("process_name".into(), serde_json::json!(r.process_names));
            }
            if !r.uids.is_empty() {
                obj.insert("user_id".into(), serde_json::json!(r.uids));
            }
            if !r.cgroups.is_empty() {
                obj.insert("cgroup_path".into(), serde_json::json!(r.cgroups));
            }
            if let Some(mark) = r.fwmark {
                obj.insert("wifi_ssid".into(), serde_json::json!(mark));
            }

            rules.push(serde_json::Value::Object(obj));
        }

        rules
    }

    /// Evaluates target destination and explains rule matching result.
    pub fn explain(
        &self,
        target: &str,
        protocol: Option<&str>,
        port: Option<u16>,
        process: Option<&str>,
    ) -> ExplainResult {
        let t = target.trim().to_lowercase();
        let port_str = port.map(|p| p.to_string());

        // 1. Evaluate Presets first
        if self.presets.bypass_lan {
            let is_lan_domain = ["local", "lan", "home.arpa", "localdomain", "localhost"]
                .iter()
                .any(|d| t == *d || t.ends_with(&format!(".{d}")));

            let is_private_ip = if let Ok(ip) = t.parse::<IpAddr>() {
                match ip {
                    IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
                    IpAddr::V6(v6) => v6.is_loopback(),
                }
            } else {
                false
            };

            if is_lan_domain || is_private_ip {
                return ExplainResult {
                    target: target.to_string(),
                    matched: true,
                    rule_id: "preset_bypass_lan".into(),
                    rule_index: 0,
                    action: RuleAction::Direct,
                    reason: "Matched system preset: bypass_lan (RFC1918 / local domain)".into(),
                };
            }
        }

        if self.presets.block_ads {
            let is_ad = ["doubleclick.net", "ads.", "analytics.", "telemetry."]
                .iter()
                .any(|pat| t.contains(pat));
            if is_ad {
                return ExplainResult {
                    target: target.to_string(),
                    matched: true,
                    rule_id: "preset_block_ads".into(),
                    rule_index: 0,
                    action: RuleAction::Block,
                    reason: "Matched system preset: block_ads (ad/tracker domain pattern)".into(),
                };
            }
        }

        // 2. Evaluate Custom Rules sequentially
        for (idx, r) in self.custom_rules.iter().enumerate() {
            if !r.enabled {
                continue;
            }

            let mut matched = false;
            let mut reason = String::new();

            // Match domains
            for d in &r.domains {
                match d {
                    DomainMatcher::Exact(e) if t == e.to_lowercase() => {
                        matched = true;
                        reason = format!("exact domain match '{e}'");
                        break;
                    }
                    DomainMatcher::Suffix(s)
                        if t == s.to_lowercase()
                            || t.ends_with(&format!(".{}", s.to_lowercase())) =>
                    {
                        matched = true;
                        reason = format!("domain suffix match '.{s}'");
                        break;
                    }
                    DomainMatcher::Keyword(k) if t.contains(&k.to_lowercase()) => {
                        matched = true;
                        reason = format!("domain keyword match '{k}'");
                        break;
                    }
                    DomainMatcher::Regex(rx) => {
                        if let Ok(re) = Regex::new(rx) {
                            if re.is_match(&t) {
                                matched = true;
                                reason = format!("domain regex match '{rx}'");
                                break;
                            }
                        }
                    }
                    _ => {}
                }
            }

            // Match IP CIDR prefix or exact IP
            if !matched && !r.ip_cidrs.is_empty() {
                for cidr in &r.ip_cidrs {
                    if t == *cidr
                        || (cidr.contains('/')
                            && t.starts_with(cidr.split('/').next().unwrap_or("")))
                    {
                        matched = true;
                        reason = format!("IP/CIDR match '{cidr}'");
                        break;
                    }
                }
            }

            // Match port
            if !matched && !r.ports.is_empty() {
                if let Some(ref p_str) = port_str {
                    if r.ports.contains(p_str) {
                        matched = true;
                        reason = format!("destination port match '{p_str}'");
                    }
                }
            }

            // Match protocol
            if !matched && !r.protocols.is_empty() {
                if let Some(proto) = protocol {
                    if r.protocols.iter().any(|x| x.eq_ignore_ascii_case(proto)) {
                        matched = true;
                        reason = format!("protocol match '{proto}'");
                    }
                }
            }

            // Match process name
            if !matched && !r.process_names.is_empty() {
                if let Some(proc_name) = process {
                    if r.process_names
                        .iter()
                        .any(|x| x.eq_ignore_ascii_case(proc_name))
                    {
                        matched = true;
                        reason = format!("process name match '{proc_name}'");
                    }
                }
            }

            if matched {
                return ExplainResult {
                    target: target.to_string(),
                    matched: true,
                    rule_id: r.id.clone(),
                    rule_index: idx + 1,
                    action: r.action,
                    reason,
                };
            }
        }

        // 3. Fallback default
        let default_action = if self.presets.proxy_all {
            RuleAction::Proxy
        } else {
            RuleAction::Direct
        };

        ExplainResult {
            target: target.to_string(),
            matched: false,
            rule_id: "default_fallback".into(),
            rule_index: self.custom_rules.len() + 1,
            action: default_action,
            reason: "No explicit rule matched; applying global proxy_all default".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rules_config_default_roundtrip() {
        let cfg = RulesConfig::default();
        let toml_str = toml::to_string_pretty(&cfg).unwrap();
        let parsed: RulesConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(cfg, parsed);
    }

    #[test]
    fn test_singbox_rules_conversion() {
        let cfg = RulesConfig::default();
        let sb_rules = cfg.to_singbox_rules();
        assert!(!sb_rules.is_empty());
        let has_sniff = sb_rules.iter().any(|r| r["action"] == "sniff");
        assert!(has_sniff);
    }

    #[test]
    fn test_explain_bypass_lan() {
        let cfg = RulesConfig::default();
        let res = cfg.explain("192.168.1.1", None, None, None);
        assert!(res.matched);
        assert_eq!(res.action, RuleAction::Direct);

        let res_lan = cfg.explain("router.lan", None, None, None);
        assert!(res_lan.matched);
        assert_eq!(res_lan.action, RuleAction::Direct);
    }

    #[test]
    fn test_explain_block_ads() {
        let cfg = RulesConfig::default();
        let res = cfg.explain("ads.doubleclick.net", None, None, None);
        assert!(res.matched);
        assert_eq!(res.action, RuleAction::Block);
    }

    #[test]
    fn test_explain_fallback_proxy() {
        let cfg = RulesConfig::default();
        let res = cfg.explain("github.com", None, None, None);
        assert_eq!(res.action, RuleAction::Proxy);
    }

    #[test]
    fn test_app_and_cgroup_split_tunneling_rule_generation() {
        let mut cfg = RulesConfig::default();
        cfg.custom_rules.push(RuleItem {
            id: "per_app_bypass".into(),
            description: Some("Per-app bypass for steam and torrents".into()),
            enabled: true,
            action: RuleAction::Direct,
            target_group: None,
            domains: Vec::new(),
            ip_cidrs: Vec::new(),
            geoip: Vec::new(),
            geosite: Vec::new(),
            ports: vec!["8080".into()],
            protocols: vec!["tcp".into()],
            process_names: vec!["steam".into(), "qbittorrent".into()],
            uids: vec![1000],
            cgroups: vec!["/sys/fs/cgroup/bypass".into()],
            fwmark: Some(0x100),
        });
        let sb_rules = cfg.to_singbox_rules();
        let custom_rule = sb_rules
            .iter()
            .find(|r| r.get("process_name").is_some())
            .expect("Rule with process_name should exist");
        assert_eq!(custom_rule["outbound"], "direct");
        assert_eq!(
            custom_rule["process_name"],
            serde_json::json!(["steam", "qbittorrent"])
        );
        assert_eq!(custom_rule["user_id"], serde_json::json!([1000]));
        assert_eq!(
            custom_rule["cgroup_path"],
            serde_json::json!(["/sys/fs/cgroup/bypass"])
        );
    }
}

use crate::backend::Backend;
use crate::model::{Profile, ProfilePayloadKind};
use crate::privilege::{
    check_sudo_passwordless, resolve_singbox_binary, run_preflight_check, PrivilegeStrategy,
};
use crate::routing::RulesConfig;
use crate::shield::{parse_endpoint, resolve_server_ips};
use crate::tunnel::{
    active_run_dir, bytes, default_egress_interface, iface_exists, is_proxy_only_mode, kill_pid,
    now, proc_alive, spawn_detached_with_log, tail_log, write_secret_path, Session,
};
use crate::xray::config::extract_xray_outbound_hosts;
use crate::xray::XrayBackend;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::process::Command;
use std::thread::sleep;
use std::time::Duration;

pub const SINGBOX_TUN_IFACE: &str = "vx0";
pub const SINGBOX_MIXED_PORT: u16 = 1080;

/// Sing-box tunnel backend acting as Master Router (TUN + Clash API + unified routing rules).
pub struct SingBoxBackend;

impl SingBoxBackend {
    pub fn new() -> Self {
        Self
    }

    fn resolve_exclude_cidrs(profile: &Profile) -> (Vec<String>, Vec<String>) {
        let mut raw_ips = Vec::new();
        let mut cidrs = Vec::new();

        let mut push_ip = |ip: IpAddr| {
            let ip_s = ip.to_string();
            if !raw_ips.contains(&ip_s) {
                raw_ips.push(ip_s);
            }
            let cidr = match ip {
                IpAddr::V4(v4) => format!("{v4}/32"),
                IpAddr::V6(v6) => format!("{v6}/128"),
            };
            if !cidrs.contains(&cidr) {
                cidrs.push(cidr);
            }
        };

        let mut resolve_host = |host: &str, port: u16| {
            let trimmed = host.trim();
            if trimmed.is_empty() || trimmed == "custom" {
                return;
            }
            if let Ok(ip) = trimmed.parse::<IpAddr>() {
                push_ip(ip);
            }
            for ip in resolve_server_ips(trimmed, port) {
                push_ip(ip);
            }
        };

        let (host, port_opt) = parse_endpoint(&profile.server);
        let port = profile.port.or(port_opt).unwrap_or(443);
        resolve_host(&host, port);

        if profile.data.trim().starts_with('{') {
            if let Ok(val) = serde_json::from_str::<Value>(profile.data.trim()) {
                for extra_host in extract_xray_outbound_hosts(&val) {
                    resolve_host(&extra_host, port);
                }
            }
        }

        (raw_ips, cidrs)
    }

    fn build_inbounds(is_proxy_only: bool, exclude_cidrs: &[String]) -> Vec<Value> {
        if is_proxy_only {
            vec![json!({
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": SINGBOX_MIXED_PORT
            })]
        } else {
            let mut tun = json!({
                "type": "tun",
                "tag": "tun-in",
                "interface_name": SINGBOX_TUN_IFACE,
                "address": ["172.19.0.1/30"],
                "mtu": 9000,
                "auto_route": true,
                "auto_redirect": true,
                "strict_route": true,
                "stack": "mixed",
                "endpoint_independent_nat": true
            });
            if !exclude_cidrs.is_empty() {
                tun["route_exclude_address"] = json!(exclude_cidrs);
            }
            vec![
                tun,
                json!({
                    "type": "mixed",
                    "tag": "mixed-in",
                    "listen": "127.0.0.1",
                    "listen_port": SINGBOX_MIXED_PORT
                }),
            ]
        }
    }

    /// Builds a complete sing-box JSON configuration around an already constructed outbound.
    pub fn build_config_with_outbound(
        outbound: Value,
        raw_server_ips: &[String],
        exclude_cidrs: &[String],
        log_path: &Path,
        is_proxy_only: bool,
    ) -> Value {
        let rules_cfg = RulesConfig::load();
        let mut rules = Vec::new();
        if !raw_server_ips.is_empty() {
            rules.push(json!({
                "ip_cidr": raw_server_ips.iter().map(|ip| {
                    if ip.contains('/') {
                        ip.clone()
                    } else if ip.contains(':') {
                        format!("{ip}/128")
                    } else {
                        format!("{ip}/32")
                    }
                }).collect::<Vec<_>>(),
                "outbound": "direct"
            }));
        }
        rules.extend(rules_cfg.to_singbox_rules());

        let mut rule_sets = vec![];
        if rules_cfg.presets.direct_domestic {
            rule_sets.push(json!({
                "tag": "geoip-cn",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs"
            }));
            rule_sets.push(json!({
                "tag": "geoip-ir",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-ir.srs"
            }));
        }

        crate::tunnel::sanitize_singbox_rules(&mut rules, &rule_sets);

        json!({
            "log": {
                "level": "warn",
                "timestamp": true,
                "output": log_path.to_string_lossy()
            },
            "dns": {
                "servers": [
                    {"type": "udp", "tag": "bootstrap", "server": "1.1.1.1"},
                    {"type": "udp", "tag": "bootstrap-backup", "server": "8.8.8.8"},
                    {"type": "https", "tag": "remote", "server": "1.1.1.1", "detour": "proxy"}
                ],
                "final": "remote",
                "strategy": "ipv4_only",
                "cache_capacity": 4096
            },
            "inbounds": Self::build_inbounds(is_proxy_only, exclude_cidrs),
            "outbounds": [outbound, {"type": "direct", "tag": "direct"}],
            "route": {
                "auto_detect_interface": !is_proxy_only,
                "default_domain_resolver": "bootstrap",
                "final": "proxy",
                "rules": rules,
                "rule_set": rule_sets
            },
            "experimental": {
                "clash_api": {
                    "external_controller": "127.0.0.1:9090",
                    "secret": ""
                }
            }
        })
    }

    /// Patches a lossless full sing-box JSON config so Vortex owns its inbounds,
    /// log output path, and Clash API telemetry endpoint.
    pub fn patch_custom_config(
        mut cfg: Value,
        log_path: &Path,
        is_proxy_only: bool,
    ) -> Result<Value> {
        let obj = cfg
            .as_object_mut()
            .context("Custom sing-box config must be a JSON object")?;

        let log_val = obj
            .entry("log")
            .or_insert_with(|| json!({"level": "warn", "timestamp": true}));
        if !log_val.is_object() {
            *log_val = json!({"level": "warn", "timestamp": true});
        }
        if let Some(log_obj) = log_val.as_object_mut() {
            log_obj.insert("output".to_string(), json!(log_path.to_string_lossy()));
        }

        obj.insert(
            "inbounds".to_string(),
            Value::Array(Self::build_inbounds(is_proxy_only, &[])),
        );

        let exp = obj
            .entry("experimental")
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
        if let Some(exp_obj) = exp.as_object_mut() {
            let clash = exp_obj
                .entry("clash_api")
                .or_insert_with(|| Value::Object(serde_json::Map::new()));
            if let Some(clash_obj) = clash.as_object_mut() {
                clash_obj
                    .entry("external_controller")
                    .or_insert_with(|| json!("127.0.0.1:9090"));
                clash_obj.entry("secret").or_insert_with(|| json!(""));
            }
        }

        Ok(cfg)
    }

    fn generate_config(
        &self,
        profile: &Profile,
        log_path: &Path,
        is_proxy_only: bool,
    ) -> Result<Value> {
        if profile.payload_kind == ProfilePayloadKind::CustomConfig {
            let cfg: Value = serde_json::from_str(profile.data.trim())
                .context("Failed to parse custom sing-box JSON config")?;
            return Self::patch_custom_config(cfg, log_path, is_proxy_only);
        }

        let (_, outbound, _, _) = crate::parser::singbox_outbound_from_str(&profile.data)?;
        let (raw_ips, cidrs) = Self::resolve_exclude_cidrs(profile);
        Ok(Self::build_config_with_outbound(
            outbound,
            &raw_ips,
            &cidrs,
            log_path,
            is_proxy_only,
        ))
    }

    fn launch_config(
        &self,
        profile: &Profile,
        cfg: &Value,
        runtime_dir: &Path,
        is_proxy_only: bool,
        sidecar_pid: Option<u32>,
        backend_label: &str,
    ) -> Result<Session> {
        let singbox_bin = resolve_singbox_binary().ok_or_else(|| {
            anyhow::anyhow!("sing-box binary not found (install via `pacman -S sing-box`)")
        })?;

        let conf_path = runtime_dir.join("singbox.json");
        let log_path = runtime_dir.join("core.log");
        let cfg_str = serde_json::to_string_pretty(cfg)?;
        write_secret_path(&conf_path, &cfg_str)?;

        let chk = Command::new(&singbox_bin)
            .args(["check", "-c", &conf_path.to_string_lossy()])
            .output()?;
        if !chk.status.success() {
            let e = String::from_utf8_lossy(&chk.stderr);
            bail!(
                "sing-box rejected the config: {}",
                e.trim().lines().last().unwrap_or("unknown error")
            );
        }

        let mut cmd = if is_proxy_only {
            Command::new(&singbox_bin)
        } else {
            let preflight = run_preflight_check();
            if !preflight.tun_device_exists {
                bail!("Linux TUN device /dev/net/tun is missing (run `sudo modprobe tun` to enable the kernel TUN driver)");
            }

            match preflight.strategy {
                PrivilegeStrategy::DirectRoot | PrivilegeStrategy::FileCapabilities => {
                    Command::new(&singbox_bin)
                }
                PrivilegeStrategy::SudoPasswordless => {
                    let mut c = Command::new("sudo");
                    c.args(["-n", &singbox_bin.to_string_lossy()]);
                    c
                }
                _ => {
                    if check_sudo_passwordless() {
                        let mut c = Command::new("sudo");
                        c.args(["-n", &singbox_bin.to_string_lossy()]);
                        c
                    } else {
                        bail!(
                            "sing-box requires CAP_NET_ADMIN or root to configure TUN interface. Run `vortex setup` to grant passwordless capabilities, authenticate via sudo, or switch to proxy mode using `vortex mode proxy`."
                        );
                    }
                }
            }
        };
        cmd.args(["run", "-c", &conf_path.to_string_lossy()]);

        let log = fs::File::create(&log_path)?;
        let pid = spawn_detached_with_log(&mut cmd, log)?;

        if is_proxy_only {
            for _ in 0..40 {
                if !proc_alive(pid) {
                    let err_str = tail_log(3).join("\n");
                    bail!("sing-box proxy exited: {}", err_str.trim());
                }
                if std::net::TcpStream::connect(format!("127.0.0.1:{SINGBOX_MIXED_PORT}")).is_ok() {
                    return Ok(Session {
                        id: profile.id.clone(),
                        name: profile.name.clone(),
                        kind: profile.kind,
                        server: profile.server.clone(),
                        iface: format!("127.0.0.1:{SINGBOX_MIXED_PORT}"),
                        pid: Some(pid),
                        sidecar_pid,
                        backend: Some(backend_label.to_string()),
                        since: now(),
                        conf: conf_path.to_string_lossy().to_string(),
                    });
                }
                sleep(Duration::from_millis(50));
            }
            return Ok(Session {
                id: profile.id.clone(),
                name: profile.name.clone(),
                kind: profile.kind,
                server: profile.server.clone(),
                iface: format!("127.0.0.1:{SINGBOX_MIXED_PORT}"),
                pid: Some(pid),
                sidecar_pid,
                backend: Some(backend_label.to_string()),
                since: now(),
                conf: conf_path.to_string_lossy().to_string(),
            });
        }

        for count in 0..100 {
            if !proc_alive(pid) {
                let err_log = tail_log(5).join("\n");
                let meaningful = err_log
                    .lines()
                    .rev()
                    .find(|l| !l.trim().is_empty())
                    .unwrap_or("sing-box terminated unexpectedly")
                    .trim();
                if err_log.contains("TUNSETIFF: operation not permitted")
                    || err_log.contains("permission denied")
                {
                    bail!(
                        "PRIVILEGE ERROR: sing-box lacks CAP_NET_ADMIN for TUN interface. Run `vortex setup` or authenticate via sudo. (Details: {})",
                        meaningful
                    );
                } else {
                    bail!("sing-box exited: {}", meaningful);
                }
            }
            if iface_exists(SINGBOX_TUN_IFACE) {
                let route_ok = Command::new("ip")
                    .args(["route", "show", "table", "all", "dev", SINGBOX_TUN_IFACE])
                    .output()
                    .map(|o| {
                        o.status.success() && !String::from_utf8_lossy(&o.stdout).trim().is_empty()
                    })
                    .unwrap_or(false);
                if route_ok || count >= 20 {
                    return Ok(Session {
                        id: profile.id.clone(),
                        name: profile.name.clone(),
                        kind: profile.kind,
                        server: profile.server.clone(),
                        iface: SINGBOX_TUN_IFACE.to_string(),
                        pid: Some(pid),
                        sidecar_pid,
                        backend: Some(backend_label.to_string()),
                        since: now(),
                        conf: conf_path.to_string_lossy().to_string(),
                    });
                }
            }
            sleep(Duration::from_millis(50));
        }

        kill_pid(pid);
        bail!("timed out waiting for the tunnel interface")
    }

    /// Starts sing-box as Master Router owning TUN/Clash API, forwarding proxy traffic
    /// to an Xray-core SOCKS5 sidecar listening on `127.0.0.1:<bridge_socks_port>`.
    pub fn start_bridged(
        &self,
        profile: &Profile,
        bridge_socks_port: u16,
        xray_session: &Session,
        runtime_dir: &Path,
    ) -> Result<Session> {
        let is_proxy_only = is_proxy_only_mode(profile);
        let log_path = runtime_dir.join("core.log");
        let (raw_ips, cidrs) = Self::resolve_exclude_cidrs(profile);
        let bridge_outbound = json!({
            "type": "socks",
            "tag": "proxy",
            "server": "127.0.0.1",
            "server_port": bridge_socks_port
        });
        let cfg = Self::build_config_with_outbound(
            bridge_outbound,
            &raw_ips,
            &cidrs,
            &log_path,
            is_proxy_only,
        );
        self.launch_config(
            profile,
            &cfg,
            runtime_dir,
            is_proxy_only,
            xray_session.pid,
            "sing-box+xray",
        )
    }
}

impl Default for SingBoxBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl Backend for SingBoxBackend {
    fn name(&self) -> &'static str {
        "sing-box"
    }

    fn is_available(&self) -> bool {
        resolve_singbox_binary().is_some()
    }

    fn version(&self) -> Option<String> {
        let bin = resolve_singbox_binary()?;
        let out = Command::new(bin).arg("version").output().ok()?;
        if !out.status.success() {
            return None;
        }
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .next()
            .map(|l| l.trim().to_string())
    }

    fn validate_config(&self, config_content: &str) -> Result<()> {
        let singbox_bin = resolve_singbox_binary().ok_or_else(|| {
            anyhow::anyhow!("sing-box binary not found (install via `pacman -S sing-box`)")
        })?;
        let tmp = std::env::temp_dir().join(format!("vortex_sb_check_{}.json", std::process::id()));
        write_secret_path(&tmp, config_content)?;
        let out = Command::new(singbox_bin)
            .args(["check", "-c", &tmp.to_string_lossy()])
            .output()?;
        let _ = fs::remove_file(&tmp);
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            bail!(
                "sing-box rejected config: {}",
                err.trim().lines().last().unwrap_or("unknown error")
            );
        }
        Ok(())
    }

    fn start(&self, profile: &Profile, runtime_dir: &Path) -> Result<Session> {
        let is_proxy_only = is_proxy_only_mode(profile);
        let log_path = runtime_dir.join("core.log");
        let cfg = self.generate_config(profile, &log_path, is_proxy_only)?;
        self.launch_config(profile, &cfg, runtime_dir, is_proxy_only, None, "sing-box")
    }

    fn stop(&self, session: &Session) -> Result<()> {
        if let Some(pid) = session.pid {
            kill_pid(pid);
        }
        if let Some(spid) = session.sidecar_pid {
            kill_pid(spid);
        }
        let _ = fs::remove_file(&session.conf);
        let r_dir = active_run_dir();
        let _ = fs::remove_file(r_dir.join("xray.json"));
        let _ = fs::remove_file(r_dir.join("xray_api_port"));

        if iface_exists(SINGBOX_TUN_IFACE) {
            let _ = Command::new("ip")
                .args(["link", "delete", "dev", SINGBOX_TUN_IFACE])
                .output();
            if iface_exists(SINGBOX_TUN_IFACE) && unsafe { libc::geteuid() != 0 } {
                let _ = Command::new("sudo")
                    .args(["-n", "ip", "link", "delete", "dev", SINGBOX_TUN_IFACE])
                    .output();
            }
        }
        Ok(())
    }

    fn query_traffic(&self, session: &Session) -> Result<(u64, u64)> {
        if let Some((rx, tx)) = bytes(&session.iface) {
            return Ok((rx, tx));
        }
        Ok((0, 0))
    }
}

/// Throne-style dual-core bridge backend:
/// `sing-box` owns TUN `vx0` + Clash API `:9090` + routing rules, while
/// `Xray-core` runs behind a local SOCKS5 bridge (`127.0.0.1:<port>`) for
/// XHTTP, XDrive, PQ VLESS encryption, fragment, dialerProxy, and custom Xray JSON.
pub struct ThroneBridgeBackend;

impl ThroneBridgeBackend {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ThroneBridgeBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl Backend for ThroneBridgeBackend {
    fn name(&self) -> &'static str {
        "sing-box+xray"
    }

    fn is_available(&self) -> bool {
        SingBoxBackend::new().is_available() && XrayBackend::new().is_available()
    }

    fn version(&self) -> Option<String> {
        match (
            SingBoxBackend::new().version(),
            XrayBackend::new().version(),
        ) {
            (Some(sb), Some(xr)) => Some(format!("{sb} + {xr}")),
            (Some(sb), None) => Some(sb),
            (None, Some(xr)) => Some(xr),
            (None, None) => None,
        }
    }

    fn validate_config(&self, config_content: &str) -> Result<()> {
        XrayBackend::new().validate_config(config_content)
    }

    fn start(&self, profile: &Profile, runtime_dir: &Path) -> Result<Session> {
        let egress_iface = default_egress_interface();
        let xray = XrayBackend::new();
        let (socks_port, x_sess) =
            xray.start_bridge(profile, runtime_dir, egress_iface.as_deref())?;

        match SingBoxBackend::new().start_bridged(profile, socks_port, &x_sess, runtime_dir) {
            Ok(session) => Ok(session),
            Err(err) => {
                let _ = xray.stop(&x_sess);
                Err(err)
            }
        }
    }

    fn stop(&self, session: &Session) -> Result<()> {
        SingBoxBackend::new().stop(session)
    }

    fn query_traffic(&self, session: &Session) -> Result<(u64, u64)> {
        if let Some((rx, tx)) = bytes(&session.iface) {
            return Ok((rx, tx));
        }
        XrayBackend::new().query_traffic(session)
    }
}

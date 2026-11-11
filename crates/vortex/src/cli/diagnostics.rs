use anyhow::{bail, Result};
use std::process::Command;
use vortex_core::ipc::{IpcRequest, IpcResponse};
use vortex_core::model::OperationalMode;
use vortex_core::{benchmark, ping, recon, storage, tunnel};

use super::get_ipc;
use super::notify::send_notification;
use super::profiles::{find, load_profiles};
use super::status::{detect_country_flag, fmt_ping, trunc_str};

pub fn handle_proxy(args: &[String]) -> Result<()> {
    let sub = args.get(1).map(String::as_str).unwrap_or("status");
    match sub {
        "env" => {
            println!("export http_proxy=http://127.0.0.1:1080");
            println!("export https_proxy=http://127.0.0.1:1080");
            println!("export all_proxy=socks5://127.0.0.1:1080");
            println!("export HTTP_PROXY=http://127.0.0.1:1080");
            println!("export HTTPS_PROXY=http://127.0.0.1:1080");
            println!("export ALL_PROXY=socks5://127.0.0.1:1080");
        }
        "set" | "system" | "on" => {
            let _ = Command::new("gsettings")
                .args(["set", "org.gnome.system.proxy", "mode", "'manual'"])
                .output();
            let _ = Command::new("gsettings")
                .args(["set", "org.gnome.system.proxy.socks", "host", "'127.0.0.1'"])
                .output();
            let _ = Command::new("gsettings")
                .args(["set", "org.gnome.system.proxy.socks", "port", "1080"])
                .output();
            println!(
                "\x1b[1;32m✔ Desktop system proxy set to 127.0.0.1:1080 (if supported)\x1b[0m"
            );
            println!("  Terminal environment export:");
            println!("    export http_proxy=http://127.0.0.1:1080");
            println!("    export https_proxy=http://127.0.0.1:1080");
            println!("    export all_proxy=socks5://127.0.0.1:1080");
        }
        "unset" | "off" => {
            let _ = Command::new("gsettings")
                .args(["set", "org.gnome.system.proxy", "mode", "'none'"])
                .output();
            println!("unset http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY");
        }
        "test" => {
            let out = Command::new("curl")
                .args([
                    "-s",
                    "--max-time",
                    "5",
                    "-x",
                    "socks5://127.0.0.1:1080",
                    "https://cloudflare.com/cdn-cgi/trace",
                ])
                .output();
            match out {
                Ok(o) if o.status.success() => {
                    let s = String::from_utf8_lossy(&o.stdout);
                    println!("\x1b[1;32m✔ Proxy bridge operational on 127.0.0.1:1080\x1b[0m");
                    for l in s.lines().take(4) {
                        println!("  {l}");
                    }
                }
                _ => {
                    println!("\x1b[1;31m✕ Proxy bridge not responding on 127.0.0.1:1080 (is tunnel active?)\x1b[0m");
                }
            }
        }
        _ => {
            let sess = tunnel::load_session();
            println!("\x1b[1;36m◈ 0xPROXY // LOCAL PROXY BRIDGE & TOOL INGRESS\x1b[0m");
            println!("  SOCKS5 Bridge : \x1b[1;32msocks5://127.0.0.1:1080\x1b[0m");
            println!("  HTTP Bridge   : \x1b[1;32mhttp://127.0.0.1:1080\x1b[0m");
            match sess {
                Some(s) => println!(
                    "  Tunnel Link   : \x1b[1;32m● ACTIVE\x1b[0m -> {} ({})",
                    s.name,
                    s.kind.tag()
                ),
                None => println!("  Tunnel Link   : \x1b[2m○ INACTIVE (run `vortex up`)\x1b[0m"),
            }
            println!("\n\x1b[1mTerminal Environment Export:\x1b[0m");
            println!("  export http_proxy=http://127.0.0.1:1080");
            println!("  export https_proxy=http://127.0.0.1:1080");
            println!("  export all_proxy=socks5://127.0.0.1:1080");
            println!("\n\x1b[2mOne-line shell evaluation: eval $(vortex proxy env)\x1b[0m");
        }
    }
    Ok(())
}

pub fn set_mode_internal(mode: OperationalMode) -> Result<()> {
    storage::set_mode_preference(mode)?;
    if let Some(client) = get_ipc() {
        let _ = client.request_sync(&IpcRequest::SetMode { mode });
    }
    match mode {
        OperationalMode::Tunnel => {
            println!("\x1b[1;32m✔ Switched to TUNNEL MODE\x1b[0m (Whole-system VPN via vx0)");
            println!("  All system traffic routed through the encrypted virtual tunnel.");
        }
        OperationalMode::Proxy => {
            println!("\x1b[1;33m✔ Switched to PROXY MODE\x1b[0m (Local unprivileged SOCKS5/HTTP on 127.0.0.1:1080)");
            println!(
                "  No root privileges required. Set your browser or terminal to 127.0.0.1:1080."
            );
            println!("  Shell setup: eval $(vortex proxy env)");
        }
    }
    send_notification(
        "Vortex Mode Changed",
        match mode {
            OperationalMode::Tunnel => "Operational Mode: TUNNEL (Whole-system VPN)",
            OperationalMode::Proxy => "Operational Mode: PROXY (127.0.0.1:1080)",
        },
        Some("network-vpn"),
    );
    Ok(())
}

pub fn handle_mode(args: &[String]) -> Result<()> {
    let sub = args.get(1).map(String::as_str);
    let cur = storage::get_mode_preference();

    match sub {
        None | Some("status") | Some("get") => {
            let ipc_mode = if let Some(client) = get_ipc() {
                match client.request_sync(&IpcRequest::GetMode) {
                    Ok(IpcResponse::Mode(m)) => Some(m),
                    _ => None,
                }
            } else {
                None
            };
            let effective = ipc_mode.unwrap_or(cur);
            match effective {
                OperationalMode::Tunnel => {
                    println!("\x1b[1;36m◈ 0xMODE // TUNNEL MODE (FULL VPN)\x1b[0m");
                    println!("  Interface   : \x1b[1;32mvx0\x1b[0m (virtual TUN device)");
                    println!(
                        "  Scope       : Whole-system network routing & anti-leak kill-switch"
                    );
                    println!("  Permissions : Requires CAP_NET_ADMIN / root (managed via vortexd or sudo)");
                    println!("  Proxy Bridge: SOCKS5 & HTTP also available on 127.0.0.1:1080");
                }
                OperationalMode::Proxy => {
                    println!("\x1b[1;33m◈ 0xMODE // PROXY MODE (LOCAL SOCKS5/HTTP)\x1b[0m");
                    println!(
                        "  Interface   : \x1b[1;32m127.0.0.1:1080\x1b[0m (SOCKS5 & HTTP inbound)"
                    );
                    println!(
                        "  Scope       : Local user applications, browser, curl, git, telegram"
                    );
                    println!("  Permissions : \x1b[1;32m100% UNPRIVILEGED\x1b[0m (no root, no sudo, no TUN device)");
                    println!("  Tunnel (TUN): Disabled");
                }
            }
            println!("\nSwitch mode with:");
            println!("  vortex mode tunnel   (enable full system VPN)");
            println!("  vortex mode proxy    (enable local user-space proxy)");
            println!("  vortex mode toggle   (switch between tunnel and proxy)");
        }
        Some("toggle") => {
            let next = match cur {
                OperationalMode::Tunnel => OperationalMode::Proxy,
                OperationalMode::Proxy => OperationalMode::Tunnel,
            };
            set_mode_internal(next)?;
        }
        Some("tunnel") | Some("tun") | Some("vpn") => {
            set_mode_internal(OperationalMode::Tunnel)?;
        }
        Some("proxy") | Some("socks") | Some("http") => {
            set_mode_internal(OperationalMode::Proxy)?;
        }
        Some(other) => {
            bail!(
                "unknown mode '{other}' — valid modes are 'tunnel', 'proxy', 'toggle', or 'status'"
            );
        }
    }
    Ok(())
}

pub fn handle_speed() -> Result<()> {
    let sess = tunnel::load_session();
    match sess {
        Some(s) => println!("\x1b[1;36m⚡ VORTEX // RUNNING LIVE THROUGHPUT BENCHMARK (TUNNEL: {})\x1b[0m...", s.name),
        None => println!("\x1b[1;33m⚡ VORTEX // RUNNING DIRECT THROUGHPUT BENCHMARK (NO TUNNEL ENGAGED)\x1b[0m..."),
    }
    let res = if let Some(client) = get_ipc() {
        match client.request_sync(&IpcRequest::RunSpeedTest)? {
            IpcResponse::Speed(r) => r,
            IpcResponse::Error(e) => bail!("Speed test failed: {e}"),
            _ => benchmark::run_speed_test(4)?,
        }
    } else {
        benchmark::run_speed_test(4)?
    };
    println!("\x1b[1;32m✔ Benchmark Complete\x1b[0m");
    println!(
        "  Throughput  : \x1b[1;32m{:.2} Mbps\x1b[0m ({:.2} MB/s)",
        res.mbps, res.mbs
    );
    println!(
        "  Transferred : {:.2} MB in {:.2}s",
        res.bytes as f64 / 1_048_576.0,
        res.duration_secs
    );
    let rating = if res.mbps > 50.0 {
        "ULTRA-FAST // OPTIMAL FOR STREAMING & ENCRYPTED WARFARE"
    } else if res.mbps > 15.0 {
        "STABLE HIGH-SPEED // NORMAL OPERATION"
    } else {
        "DEGRADED // HIGH CONGESTION OR RESTRICTED ROUTE"
    };
    println!("  Rating      : \x1b[1;36m{rating}\x1b[0m");
    Ok(())
}

pub fn handle_flows() -> Result<()> {
    let flows = if let Some(client) = get_ipc() {
        match client.request_sync(&IpcRequest::GetFlows) {
            Ok(IpcResponse::Flows(f)) => f,
            _ => tunnel::active_flows(),
        }
    } else {
        tunnel::active_flows()
    };
    println!(
        "\x1b[1;36m◈ 0xNET // ACTIVE FLOWS & SOCKET MATRIX ({} ESTABLISHED)\x1b[0m",
        flows.len()
    );
    if flows.is_empty() {
        println!("  No active flows captured.");
        return Ok(());
    }
    println!(
        "{:<5} {:<18} {:<32} {:<24}",
        "PROTO", "PROCESS", "TARGET DESTINATION", "LOCAL SOURCE"
    );
    for f in flows.iter().take(25) {
        let target = if !f.host.is_empty() {
            format!("{} ({})", f.destination, f.host)
        } else {
            f.destination.clone()
        };
        println!(
            "{:<5} {:<18} {:<32} {:<24}",
            f.network.to_uppercase(),
            trunc_str(&f.process, 18),
            trunc_str(&target, 32),
            f.source
        );
    }
    Ok(())
}

pub fn handle_history(args: &[String]) -> Result<()> {
    let json_mode = args.iter().any(|a| a == "--json" || a == "-j");
    let hist = if let Some(client) = get_ipc() {
        match client.request_sync(&IpcRequest::GetHistory) {
            Ok(IpcResponse::History(h)) => h,
            _ => vortex_core::history::TrafficHistory::load(),
        }
    } else {
        vortex_core::history::TrafficHistory::load()
    };

    if json_mode {
        println!("{}", serde_json::to_string_pretty(&hist)?);
        return Ok(());
    }

    println!("\x1b[1;36m◈ 0xHIST // PERSISTENT TRAFFIC & USAGE ACCOUNTING\x1b[0m");
    println!("  Lifetime Egress Metrics:");
    println!(
        "    Total Inbound  (Rx) : \x1b[1;32m{:.2} MB\x1b[0m ({:.3} GB)",
        hist.total_rx as f64 / 1_048_576.0,
        hist.total_rx as f64 / 1_073_741_824.0
    );
    println!(
        "    Total Outbound (Tx) : \x1b[1;34m{:.2} MB\x1b[0m ({:.3} GB)",
        hist.total_tx as f64 / 1_048_576.0,
        hist.total_tx as f64 / 1_073_741_824.0
    );
    println!(
        "    Aggregated Volume   : \x1b[1;36m{:.2} MB\x1b[0m ({:.3} GB)",
        (hist.total_rx + hist.total_tx) as f64 / 1_048_576.0,
        (hist.total_rx + hist.total_tx) as f64 / 1_073_741_824.0
    );

    if !hist.daily.is_empty() {
        println!("\n  Recent Daily Volume (Last 7 Days):");
        for rec in hist.daily.iter().rev().take(7) {
            let diff = tunnel::now().saturating_sub(rec.timestamp);
            let time_str = if diff < 86400 {
                "Today".to_string()
            } else {
                format!("{}d ago", diff / 86400)
            };
            let mb = (rec.rx_bytes + rec.tx_bytes) as f64 / 1_048_576.0;
            println!(
                "    {:<12} : {:>8.2} MB  (↓ {:>7.2} MB  ↑ {:>7.2} MB)",
                time_str,
                mb,
                rec.rx_bytes as f64 / 1_048_576.0,
                rec.tx_bytes as f64 / 1_048_576.0
            );
        }
    }

    if !hist.hourly.is_empty() {
        println!("\n  Last 5 Hours Activity:");
        for rec in hist.hourly.iter().rev().take(5) {
            let diff = tunnel::now().saturating_sub(rec.timestamp);
            let time_str = if diff < 3600 {
                format!("{}m ago", diff / 60)
            } else {
                format!("{}h ago", diff / 3600)
            };
            let mb = (rec.rx_bytes + rec.tx_bytes) as f64 / 1_048_576.0;
            println!(
                "    {:<16} : {:>7.2} MB  [Node: {}]",
                time_str,
                mb,
                rec.node_name.as_deref().unwrap_or("none")
            );
        }
    }
    println!("\n\x1b[2mRun `vortex history --json` for full machine-readable accounting.\x1b[0m");
    Ok(())
}

pub fn handle_ping() -> Result<()> {
    if tunnel::load_session().is_some() {
        eprintln!("note: a tunnel is active — numbers are measured through it. `vortex down` first for real ones.");
    }
    for (p, r) in ping::measure_all(load_profiles()) {
        let flag = detect_country_flag(&p.name);
        println!(
            "{}  {flag} [{:<5}] {:<28} {}",
            fmt_ping(r),
            p.kind.tag(),
            p.name,
            p.server
        );
    }
    Ok(())
}

pub fn handle_recon(args: &[String]) -> Result<()> {
    let q = args.get(1).map(String::as_str).unwrap_or("");
    let p = find(q)?;
    println!("\x1b[1;36m⚡ VORTEX // EXECUTING DEEP NODE RECONNAISSANCE...\x1b[0m");
    println!("  Target: {} ({})\n", p.name, p.server);
    let rep = if let Some(client) = get_ipc() {
        match client.request_sync(&IpcRequest::RunRecon {
            profile_id: p.id.clone(),
        })? {
            IpcResponse::Recon(r) => r,
            IpcResponse::Error(e) => bail!("Recon failed: {e}"),
            _ => recon::probe_recon(&p)?,
        }
    } else {
        recon::probe_recon(&p)?
    };
    println!("\x1b[1;32m[+] ENDPOINT INTELLIGENCE\x1b[0m");
    println!("    Host / Target : {}:{}", rep.host, rep.port);
    println!("    Resolved IPv4 : {}", rep.resolved_ips.join(", "));
    if let Some(r) = rep.reverse_dns {
        println!("    Reverse DNS   : {r}");
    }
    if let Some(asn) = rep.asn {
        println!(
            "    ASN & Carrier : {} ({})",
            asn,
            rep.org.unwrap_or_default()
        );
    }
    if let Some(c) = rep.country {
        println!(
            "    Location      : {}, {}",
            rep.city.unwrap_or_default(),
            c
        );
    }
    if let Some(loc) = rep.loc {
        println!("    Coordinates   : {loc}");
    }
    println!("\n\x1b[1;32m[+] LATENCY & JITTER TELEMETRY\x1b[0m");
    println!("    Min Latency   : {} ms", rep.rtt_min);
    println!("    Avg Latency   : {} ms", rep.rtt_avg);
    println!("    Max Latency   : {} ms", rep.rtt_max);
    println!("    Jitter        : {} ms", rep.jitter);
    if let Some(v) = rep.tls_version {
        println!("\n\x1b[1;32m[+] CRYPTOGRAPHIC FINGERPRINT\x1b[0m");
        println!("    TLS Protocol  : {v}");
        if let Some(c) = rep.tls_cipher {
            println!("    Cipher Suite  : {c}");
        }
        if let Some(s) = rep.tls_cert_subject {
            println!("    Subject       : {s}");
        }
        if let Some(i) = rep.tls_cert_issuer {
            println!("    Issuer        : {i}");
        }
    }
    if let Some(ip) = rep.exit_ip {
        println!("\n\x1b[1;32m[+] ROUTE EXIT STATUS\x1b[0m");
        println!(
            "    Live Exit IP  : {} (Cloudflare Datacenter: {})",
            ip,
            rep.exit_colo.unwrap_or_default()
        );
    }
    Ok(())
}

pub fn handle_leaks() -> Result<()> {
    println!("\x1b[1;36m🛡 VORTEX // EXECUTING LEAK INTEGRITY SUITE...\x1b[0m\n");
    let rep = if let Some(client) = get_ipc() {
        match client.request_sync(&IpcRequest::RunLeakTest)? {
            IpcResponse::Leak(r) => r,
            IpcResponse::Error(e) => bail!("Leak check failed: {e}"),
            _ => {
                let sess = tunnel::load_session();
                let is_sec = sess.is_some();
                let srv = sess.as_ref().map(|s| s.server.as_str());
                let exit_ip = sess.as_ref().map(|_| tunnel::public_ip());
                tokio::runtime::Runtime::new()?.block_on(vortex_core::leak::run_leak_suite(
                    is_sec,
                    srv,
                    exit_ip.as_deref(),
                ))
            }
        }
    } else {
        let sess = tunnel::load_session();
        let is_sec = sess.is_some();
        let srv = sess.as_ref().map(|s| s.server.as_str());
        let exit_ip = sess.as_ref().map(|_| tunnel::public_ip());
        tokio::runtime::Runtime::new()?.block_on(vortex_core::leak::run_leak_suite(
            is_sec,
            srv,
            exit_ip.as_deref(),
        ))
    };

    println!(
        "  \x1b[1mStatus:\x1b[0m       {}",
        if rep.is_secure {
            "\x1b[1;32m[PASS] SECURE\x1b[0m"
        } else {
            "\x1b[1;31m[FAIL] LEAK DETECTED\x1b[0m"
        }
    );
    println!("  \x1b[1mOrigin IP:\x1b[0m    {}", rep.real_ip);
    println!("  \x1b[1mExit IP:\x1b[0m      {}", rep.exit_ip);
    println!(
        "  \x1b[1mResolvers:\x1b[0m    {}",
        rep.dns_resolvers.join(", ")
    );
    println!("\n\x1b[1;32m[+] PERIMETER AUDIT\x1b[0m");
    for chk in &rep.checks {
        let badge = if chk.passed {
            "\x1b[1;32m[PASS]\x1b[0m"
        } else {
            "\x1b[1;31m[FAIL]\x1b[0m"
        };
        println!("    {badge} {:<24} : {}", chk.name, chk.details);
    }
    println!("\n  \x1b[2mSummary: {}\x1b[0m\n", rep.details);
    Ok(())
}

pub fn handle_check() -> Result<()> {
    let rep = vortex_core::privilege::run_preflight_check();
    println!("\x1b[1;36m◈ VORTEX // PREFLIGHT PRIVILEGE & CAPABILITY AUDIT\x1b[0m");
    println!("──────────────────────────────────────────────────────────");
    println!(
        "  Root Privilege       : {}",
        if rep.is_root {
            "\x1b[1;32mYES (UID 0)\x1b[0m"
        } else {
            "\x1b[2mNO (Unprivileged user)\x1b[0m"
        }
    );
    println!(
        "  Process Capabilities : {}",
        if rep.has_process_caps {
            "\x1b[1;32mCAP_NET_ADMIN present in process\x1b[0m"
        } else {
            "\x1b[2mNo ambient CAP_NET_ADMIN\x1b[0m"
        }
    );
    println!(
        "  Linux TUN Device     : {} {}",
        if rep.tun_device_exists {
            "\x1b[1;32m/dev/net/tun present\x1b[0m"
        } else {
            "\x1b[1;31m/dev/net/tun MISSING\x1b[0m"
        },
        if rep.tun_accessible {
            "(read/write accessible)"
        } else {
            "(access restricted)"
        }
    );
    println!(
        "  Sing-Box Binary      : {}",
        rep.singbox_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "\x1b[1;31mNOT FOUND\x1b[0m".into())
    );
    println!(
        "  Managed Sing-Box     : {}",
        if rep.is_managed_binary {
            "\x1b[1;32mYES (~/.local/share/vortex/bin/sing-box)\x1b[0m"
        } else {
            "\x1b[2mNO (using system binary)\x1b[0m"
        }
    );
    println!(
        "  Sing-Box Caps        : {}",
        if rep.singbox_has_caps {
            "\x1b[1;32mVALID (cap_net_admin enabled)\x1b[0m"
        } else {
            "\x1b[1;33mNONE (missing cap_net_admin)\x1b[0m"
        }
    );
    println!(
        "  Xray-Core Binary     : {}",
        rep.xray_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "\x1b[1;33mNOT FOUND (`vortex xray install`)\x1b[0m".into())
    );
    println!(
        "  Xray-Core Caps       : {}",
        if rep.xray_has_caps {
            "\x1b[1;32mVALID (cap_net_admin,cap_net_raw enabled)\x1b[0m"
        } else if rep.xray_found {
            "\x1b[2mNONE (runs bridged via Sing-Box; standalone TUN needs caps)\x1b[0m"
        } else {
            "\x1b[2mN/A\x1b[0m"
        }
    );
    println!(
        "  Dual-Core Bridge     : {}",
        if rep.singbox_found && rep.xray_found {
            "\x1b[1;32mREADY (Sing-Box Master Router + Xray Bridge)\x1b[0m"
        } else {
            "\x1b[1;33mPARTIAL (single-core mode active)\x1b[0m"
        }
    );
    println!(
        "  Sudo Elevation       : {}",
        if rep.can_sudo_passwordless {
            "\x1b[1;32mPASSWORDLESS (sudo -n active)\x1b[0m"
        } else {
            "\x1b[2mPassword prompt required\x1b[0m"
        }
    );
    println!(
        "  Polkit Elevation     : {}",
        if rep.has_pkexec {
            "\x1b[1;32mAVAILABLE (pkexec found)\x1b[0m"
        } else {
            "\x1b[2mNOT FOUND\x1b[0m"
        }
    );
    println!(
        "  Privilege Strategy   : \x1b[1;35m{:?}\x1b[0m",
        rep.strategy
    );
    println!("──────────────────────────────────────────────────────────");
    println!(
        "  TUN Tunnel Readiness : {}",
        if rep.ready_for_tun {
            "\x1b[1;32m[PASS] OPERATIONAL FOR TUNNELING\x1b[0m"
        } else {
            "\x1b[1;31m[WARN] ELEVATION / CAPABILITIES NEEDED\x1b[0m"
        }
    );
    if let Some(rec) = rep.recommendation {
        println!("\n  \x1b[1mActionable Solution:\x1b[0m\n  👉 {rec}");
    }
    println!();
    Ok(())
}

pub fn handle_doctor() -> Result<()> {
    println!("\x1b[1;36m◈ VORTEX // SYSTEM & ENVIRONMENT DOCTOR\x1b[0m");
    println!("──────────────────────────────────────────────────────────");

    // 1. Core binaries
    let xray_rep = vortex_core::xray::run_xray_doctor();
    println!("  [CORES & BINARIES]");
    println!(
        "  • Xray-Core Binary   : {}",
        xray_rep
            .binary_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "\x1b[1;31mNOT FOUND (run `vortex xray install`)\x1b[0m".into())
    );
    if let Some(v) = &xray_rep.binary_version {
        println!("  • Xray-Core Version  : \x1b[1;32m{v}\x1b[0m");
    }
    let singbox = vortex_core::privilege::resolve_singbox_binary();
    println!(
        "  • Sing-Box Binary    : {}",
        singbox
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "\x1b[2mNot installed (optional)\x1b[0m".into())
    );

    // 2. Network device & Firewall
    println!("\n  [NETWORK STACK & FIREWALL]");
    let tun_ok = std::path::Path::new("/dev/net/tun").exists();
    println!(
        "  • Linux TUN Device   : {}",
        if tun_ok {
            "\x1b[1;32mAVAILABLE (/dev/net/tun)\x1b[0m"
        } else {
            "\x1b[1;31mMISSING (run `sudo modprobe tun`)\x1b[0m"
        }
    );
    let nft_ok = vortex_core::shield::is_nftables_active()
        || std::process::Command::new("nft")
            .arg("--version")
            .output()
            .is_ok();
    println!(
        "  • NFTables Firewall  : {}",
        if nft_ok {
            "\x1b[1;32mREADY (table inet vortex supported)\x1b[0m"
        } else {
            "\x1b[1;33mNFT not found (iptables fallback active)\x1b[0m"
        }
    );
    let iptables_ok = std::process::Command::new("iptables")
        .arg("--version")
        .output()
        .is_ok();
    println!(
        "  • Legacy IPtables    : {}",
        if iptables_ok {
            "\x1b[1;32mAVAILABLE\x1b[0m"
        } else {
            "\x1b[2mNOT FOUND\x1b[0m"
        }
    );

    // 3. DNS Configuration
    println!("\n  [DNS RESOLUTION & PRIVILEGES]");
    let resolvers = vortex_core::leak::get_system_dns_resolvers();
    println!("  • System Resolvers   : {}", resolvers.join(", "));
    let preflight = vortex_core::privilege::run_preflight_check();
    println!(
        "  • Tunnel Readiness   : {}",
        if preflight.ready_for_tun {
            "\x1b[1;32m[PASS] OPERATIONAL FOR WHOLE-SYSTEM TUNNEL\x1b[0m"
        } else {
            "\x1b[1;33m[WARN] CAPABILITIES OR ROOT NEEDED (run `vortex setup`)\x1b[0m"
        }
    );

    // 4. Daemon IPC Socket
    let sock_path = vortex_core::ipc::active_socket_path();
    let sock_active = sock_path.exists();
    println!(
        "  • Vortex Daemon IPC  : {}",
        if sock_active {
            format!("\x1b[1;32mONLINE ({})\x1b[0m", sock_path.display())
        } else {
            format!("\x1b[2mOFFLINE ({})\x1b[0m", sock_path.display())
        }
    );

    println!("──────────────────────────────────────────────────────────\n");
    Ok(())
}

pub fn handle_setup(_args: &[String]) -> Result<()> {
    println!("\x1b[1;36m◈ VORTEX // MANAGED CORE CAPABILITY SETUP\x1b[0m");
    println!("  Assigning network capabilities to sing-box and Xray binaries...\n");

    let paths = vortex_core::privilege::setup_managed_caps()?;
    for path in &paths {
        println!(
            "\x1b[1;32m✔ SUCCESS // Binary endowed with capabilities:\x1b[0m\n  {}",
            path.display()
        );
    }
    println!("\n  Cap spec: cap_net_admin,cap_net_bind_service,cap_net_raw+ep");
    println!("  Future whole-system TUN tunnel connections will run without root or sudo prompts!");
    Ok(())
}

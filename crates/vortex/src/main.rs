use anyhow::{bail, Context, Result};
use std::{os::unix::process::CommandExt, process::Command};
use vortex_core::ipc::{IpcClient, IpcRequest, IpcResponse};
use vortex_core::{benchmark, ping, recon, shield, store, tunnel};
mod keymap;
mod ui;

const HELP: &str = "\
vortex — elite cyber warfare VPN & proxy manager for Omarchy

  vortex                         open the cyber warfare TUI
  vortex add <x>                 import share link, sub URL, QR image (.png), or .conf/.ovpn
  vortex list                    list profiles
  vortex up [n|name]             connect (number from `list`, or part of name; no arg = last used)
  vortex down                    disconnect active tunnel
  vortex toggle                  toggle connection (disconnect if up, connect best/last if down)
  vortex best                    test every server, connect to the fastest
  vortex ping                    test latency of every profile
  vortex pick [query]            interactive fuzzy node picker (rofi / fuzzel / zenity / menu)
  vortex qr [n|name]             render compact terminal QR code for mobile scanning
  vortex conf [n|name]           show full config text (--copy to clipboard, --export to file)
  vortex proxy [env|unset|test]  manage local SOCKS5/HTTP proxy bridge (:1080) for tools
  vortex shield [on|off]         stealth kill switch & anti-leak shield (alias: killswitch)
  vortex leaks                   comprehensive leak audit (IP, DNS, IPv6, WebRTC/STUN)
  vortex recon [n|name]          deep node reconnaissance (ASN, GeoIP, TLS cert, jitter)
  vortex speed                   measure live throughput & bandwidth under load
  vortex flows                   live socket & traffic sniffer (active connections)
  vortex route                   manage split tunneling, LAN bypass, and domain rules
  vortex history [--json]        inspect cumulative traffic accounting & usage metrics
  vortex sub list                list tracked subscriptions
  vortex sub add <url>           add subscription and import nodes
  vortex sub update              update subscriptions from remote endpoints
  vortex sub rm <id>             remove a tracked subscription
  vortex update                  sync all subscriptions
  vortex auth <n|name> [--clear] manage OpenVPN username & password (with save mode)
  vortex rename <n|name> <new>   rename a profile
  vortex rm <n|name>             delete a profile
  vortex status [--json|--waybar] show active tunnel, daemon, and shield status
  vortex xray [cmd]              manage Xray-core backend (install|update|version|doctor|rollback|test)
  vortex completion <shell>      generate shell autocompletions (bash, zsh, fish)

protocols: VLESS · VMess · Trojan · Shadowsocks · Hysteria2 · REALITY · XHTTP (via Xray & sing-box)
           WireGuard · AmneziaWG · OpenVPN · Amnezia vpn:// links
";

fn find(q: &str) -> Result<store::Profile> {
    let all = load_profiles();
    let q = q.trim().to_lowercase();
    if q.is_empty() {
        let id = store::last()
            .ok_or_else(|| anyhow::anyhow!("no profile given and none used before"))?;
        return all
            .into_iter()
            .find(|p| p.id == id)
            .ok_or_else(|| anyhow::anyhow!("last used profile no longer exists"));
    }
    if let Ok(n) = q.parse::<usize>() {
        if n >= 1 && n <= all.len() {
            return Ok(all[n - 1].clone());
        }
    }
    let hits: Vec<&store::Profile> = all
        .iter()
        .filter(|p| p.id == q || p.name.to_lowercase().contains(&q))
        .collect();
    match hits.as_slice() {
        [p] => Ok((*p).clone()),
        [] => bail!("no such profile — see `vortex list`"),
        many => match many
            .iter()
            .find(|p| p.id == q || p.name.to_lowercase() == q)
        {
            Some(p) => Ok((**p).clone()),
            None => bail!(
                "'{q}' matches {} profiles — be more specific or use its number",
                many.len()
            ),
        },
    }
}

fn connect_cli(p: &store::Profile) -> Result<()> {
    let mut p = p.clone();
    let creds = if tunnel::ovpn_needs_auth(&p) {
        if let Some(ref a) = p.auth {
            Some((a.username.clone(), a.password.clone()))
        } else {
            let cred = tunnel::prompt_ovpn_credentials(None)?;
            if cred.save {
                p.auth = Some(store::Auth {
                    username: cred.username.clone(),
                    password: cred.password.clone(),
                    save: true,
                });
                store::save(&p)?;
                println!("credentials saved for '{}'", p.name);
            }
            Some((cred.username, cred.password))
        }
    } else {
        None
    };
    let s = tunnel::connect_with_credentials(
        &p,
        creds.as_ref().map(|(u, pw)| (u.as_str(), pw.as_str())),
    )?;
    println!("connected: {} ({})", s.name, s.kind.tag());
    Ok(())
}

fn fmt_ping(r: ping::Ping) -> String {
    match r {
        ping::Ping::Ms(m) => format!("{m:>5} ms"),
        ping::Ping::Timeout => "  timeout".into(),
    }
}

fn trunc_str(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

fn handle_proxy(args: &[String]) -> Result<()> {
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
        "unset" | "off" => {
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

fn handle_speed() -> Result<()> {
    let sess = tunnel::load_session();
    match sess {
        Some(s) => println!("\x1b[1;36m⚡ VORTEX // RUNNING LIVE THROUGHPUT BENCHMARK (TUNNEL: {})\x1b[0m...", s.name),
        None => println!("\x1b[1;33m⚡ VORTEX // RUNNING DIRECT THROUGHPUT BENCHMARK (NO TUNNEL ENGAGED)\x1b[0m..."),
    }
    let res = benchmark::run_speed_test(4)?;
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

fn handle_flows() -> Result<()> {
    let flows = tunnel::active_flows();
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

fn handle_xray(args: &[String]) -> Result<()> {
    let sub = args.get(1).map(String::as_str).unwrap_or("help");
    match sub {
        "install" => {
            println!("\x1b[1;36m⚡ VORTEX // XRAY-CORE AUTOMATED LIFECYCLE INSTALLER\x1b[0m");
            println!("  Querying GitHub releases API for latest stable Xray-core...");
            let tag = vortex_core::xray::install_xray(None)?;
            println!("\x1b[1;32m✔ Xray-core {tag} installed successfully!\x1b[0m");
            let data_dir = vortex_core::xray::xray_data_dir();
            println!("  Install directory: {}", data_dir.join(&tag).display());
            println!(
                "  Current symlink  : {}",
                vortex_core::xray::current_symlink_path().display()
            );
            println!(
                "  Binary path      : {}",
                vortex_core::xray::managed_xray_binary().display()
            );
        }
        "update" => {
            println!("\x1b[1;36m⚡ VORTEX // XRAY-CORE UPDATER & ASSET SYNCHRONIZATION\x1b[0m");
            println!("  Checking upstream releases...");
            let tag = vortex_core::xray::install_xray(None)?;
            println!("\x1b[1;32m✔ Xray-core is up to date: {tag}\x1b[0m");
            println!("  Refreshing GeoIP and GeoSite routing databases...");
            vortex_core::xray::refresh_geo_databases()?;
            println!("\x1b[1;32m✔ geoip.dat and geosite.dat databases updated successfully\x1b[0m");
        }
        "version" => {
            let installed_ver = vortex_core::xray::resolve_installed_version();
            let bin_path_res = vortex_core::xray::resolve_xray_binary();
            println!("\x1b[1;36m⚡ VORTEX // XRAY-CORE ENGINE STATUS\x1b[0m");
            match bin_path_res {
                Ok(path) => {
                    let bin_ver = vortex_core::xray::get_binary_version(&path);
                    let is_managed = path.starts_with(vortex_core::xray::xray_data_dir());
                    println!("  Active Binary : {}", path.display());
                    println!(
                        "  Source        : {}",
                        if is_managed {
                            "Managed (~/.local/share/vortex/xray)"
                        } else {
                            "System PATH / Arch package"
                        }
                    );
                    println!(
                        "  Version       : \x1b[1;32m{}\x1b[0m",
                        bin_ver.unwrap_or_else(|| "unknown".into())
                    );
                }
                Err(_) => {
                    println!("  Active Binary : \x1b[1;31mNone found\x1b[0m");
                    println!("  Status        : Not installed. Run `vortex xray install`");
                }
            }
            if let Some(m_ver) = installed_ver {
                println!("  Managed Copy  : {}", m_ver);
            }
        }
        "rollback" => {
            println!("\x1b[1;36m⚡ VORTEX // XRAY-CORE ATOMIC ROLLBACK\x1b[0m");
            let prev = vortex_core::xray::rollback_xray()?;
            println!("\x1b[1;32m✔ Rolled back active Xray version to {prev}\x1b[0m");
        }
        "doctor" => {
            println!("\x1b[1;36m⚡ VORTEX // XRAY SUBSYSTEM HEALTH DIAGNOSTICS\x1b[0m");
            println!("--------------------------------------------------");
            let report = vortex_core::xray::run_xray_doctor();
            if let Some(ref p) = report.binary_path {
                let ver_str = report.binary_version.as_deref().unwrap_or("unknown");
                let src_str = if report.is_system_binary {
                    "System PATH"
                } else {
                    "Managed"
                };
                println!(
                    "  [\x1b[1;32m✓\x1b[0m] Binary Resolved  : {} ({ver_str}, {src_str})",
                    p.display()
                );
            } else {
                println!("  [\x1b[1;31m✗\x1b[0m] Binary Resolved  : None found (run `vortex xray install`)");
            }

            if report.binary_executable {
                println!("  [\x1b[1;32m✓\x1b[0m] Binary Perms     : Executable (0755)");
            } else if report.binary_path.is_some() {
                println!("  [\x1b[1;31m✗\x1b[0m] Binary Perms     : Not executable");
            }

            if report.geoip_found {
                println!("  [\x1b[1;32m✓\x1b[0m] GeoIP Routing    : geoip.dat present");
            } else {
                println!("  [\x1b[1;33m!\x1b[0m] GeoIP Routing    : geoip.dat missing (run `vortex xray update`)");
            }

            if report.geosite_found {
                println!("  [\x1b[1;32m✓\x1b[0m] GeoSite Routing  : geosite.dat present");
            } else {
                println!("  [\x1b[1;33m!\x1b[0m] GeoSite Routing  : geosite.dat missing (run `vortex xray update`)");
            }

            if report.tun_device_available {
                println!("  [\x1b[1;32m✓\x1b[0m] Kernel Device    : /dev/net/tun accessible");
            } else {
                println!("  [\x1b[1;31m✗\x1b[0m] Kernel Device    : /dev/net/tun not found");
            }

            if report.nftables_available {
                println!("  [\x1b[1;32m✓\x1b[0m] Stealth Shield   : nftables available");
            } else {
                println!("  [\x1b[1;33m!\x1b[0m] Stealth Shield   : nftables not found (legacy fallback)");
            }

            println!("--------------------------------------------------");
            if report.is_healthy() {
                println!(
                    "  Overall Status    : \x1b[1;32mALL CHECKS PASSED (OPERATIONAL)\x1b[0m\n"
                );
            } else {
                println!("  Overall Status    : \x1b[1;31mISSUES DETECTED\x1b[0m");
                for issue in &report.issues {
                    println!("   • {issue}");
                }
                println!();
            }
        }
        "test" => {
            let path_str = args
                .get(2)
                .ok_or_else(|| anyhow::anyhow!("Usage: vortex xray test <config.json>"))?;
            let path = std::path::Path::new(path_str);
            if !path.exists() {
                bail!("Config file {:?} does not exist", path);
            }
            let xray_bin = vortex_core::xray::resolve_xray_binary()?;
            vortex_core::xray::validate_xray_config_file(&xray_bin, path)?;
            println!(
                "\x1b[1;32m✔ Configuration {:?} is valid and accepted by Xray-core\x1b[0m",
                path
            );
        }
        _ => {
            println!("\x1b[1;36mvortex xray — Xray-core engine management\x1b[0m");
            println!(
                "  vortex xray install        download & install latest verified Xray-core release"
            );
            println!(
                "  vortex xray update         update binary & refresh geoip.dat / geosite.dat"
            );
            println!(
                "  vortex xray version        show active Xray binary version & install location"
            );
            println!("  vortex xray rollback       roll back to previously installed Xray release");
            println!("  vortex xray doctor         perform comprehensive diagnostics check");
            println!("  vortex xray test <cfg>     validate raw Xray JSON configuration");
        }
    }
    Ok(())
}

fn get_ipc() -> Option<IpcClient> {
    let client = IpcClient::new();
    if client.is_daemon_running() {
        Some(client)
    } else {
        None
    }
}

fn load_profiles() -> Vec<store::Profile> {
    if let Some(client) = get_ipc() {
        if let Ok(IpcResponse::Profiles(profiles)) = client.request_sync(&IpcRequest::GetProfiles) {
            if !profiles.is_empty() {
                return profiles;
            }
        }
    }
    store::load_all()
}

fn which_exists(binary: &str) -> bool {
    Command::new("which")
        .arg(binary)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn send_notification(summary: &str, body: &str, icon: Option<&str>) {
    let mut cmd = Command::new("notify-send");
    cmd.arg("-a").arg("Vortex");
    cmd.arg("-t").arg("3000");
    if let Some(i) = icon {
        cmd.arg("-i").arg(i);
    }
    cmd.arg(summary).arg(body);
    let _ = cmd.spawn();
}

fn detect_country_flag(name: &str) -> String {
    let trimmed = name.trim();
    let mut chars = trimmed.chars();
    if let (Some(c1), Some(c2)) = (chars.next(), chars.next()) {
        if ('\u{1F1E6}'..='\u{1F1FF}').contains(&c1) && ('\u{1F1E6}'..='\u{1F1FF}').contains(&c2) {
            let mut flag_str = String::new();
            flag_str.push(c1);
            flag_str.push(c2);
            return flag_str;
        }
    }

    let lower = trimmed.to_lowercase();
    let flag = if lower.contains("germany")
        || lower.contains("frankfurt")
        || lower.contains("berlin")
        || lower.starts_with("de")
        || lower.contains("-de-")
        || lower.ends_with("-de")
    {
        "🇩🇪"
    } else if lower.contains("united states")
        || lower.contains("america")
        || lower.contains("ashburn")
        || lower.contains("los angeles")
        || lower.contains("new york")
        || lower.contains("chicago")
        || lower.contains("miami")
        || lower.starts_with("us")
        || lower.contains("-us-")
        || lower.ends_with("-us")
    {
        "🇺🇸"
    } else if lower.contains("netherlands")
        || lower.contains("amsterdam")
        || lower.starts_with("nl")
        || lower.contains("-nl-")
        || lower.ends_with("-nl")
    {
        "🇳🇱"
    } else if lower.contains("france")
        || lower.contains("paris")
        || lower.starts_with("fr")
        || lower.contains("-fr-")
        || lower.ends_with("-fr")
    {
        "🇫🇷"
    } else if lower.contains("united kingdom")
        || lower.contains("london")
        || lower.contains("england")
        || lower.starts_with("gb")
        || lower.starts_with("uk")
        || lower.contains("-gb-")
        || lower.ends_with("-gb")
    {
        "🇬🇧"
    } else if lower.contains("turkey")
        || lower.contains("istanbul")
        || lower.starts_with("tr")
        || lower.contains("-tr-")
        || lower.ends_with("-tr")
    {
        "🇹🇷"
    } else if lower.contains("singapore")
        || lower.starts_with("sg")
        || lower.contains("-sg-")
        || lower.ends_with("-sg")
    {
        "🇸🇬"
    } else if lower.contains("japan")
        || lower.contains("tokyo")
        || lower.contains("osaka")
        || lower.starts_with("jp")
        || lower.contains("-jp-")
        || lower.ends_with("-jp")
    {
        "🇯🇵"
    } else if lower.contains("canada")
        || lower.contains("toronto")
        || lower.contains("montreal")
        || lower.starts_with("ca")
        || lower.contains("-ca-")
        || lower.ends_with("-ca")
    {
        "🇨🇦"
    } else if lower.contains("finland")
        || lower.contains("helsinki")
        || lower.starts_with("fi")
        || lower.contains("-fi-")
        || lower.ends_with("-fi")
    {
        "🇫🇮"
    } else if lower.contains("sweden")
        || lower.contains("stockholm")
        || lower.starts_with("se")
        || lower.contains("-se-")
        || lower.ends_with("-se")
    {
        "🇸🇪"
    } else if lower.contains("switzerland")
        || lower.contains("zurich")
        || lower.starts_with("ch")
        || lower.contains("-ch-")
        || lower.ends_with("-ch")
    {
        "🇨🇭"
    } else if lower.contains("iran")
        || lower.contains("tehran")
        || lower.starts_with("ir")
        || lower.contains("-ir-")
        || lower.ends_with("-ir")
    {
        "🇮🇷"
    } else if lower.contains("uae")
        || lower.contains("dubai")
        || lower.starts_with("ae")
        || lower.contains("-ae-")
        || lower.ends_with("-ae")
    {
        "🇦🇪"
    } else if lower.contains("poland")
        || lower.contains("warsaw")
        || lower.starts_with("pl")
        || lower.contains("-pl-")
        || lower.ends_with("-pl")
    {
        "🇵🇱"
    } else if lower.contains("spain")
        || lower.contains("madrid")
        || lower.starts_with("es")
        || lower.contains("-es-")
        || lower.ends_with("-es")
    {
        "🇪🇸"
    } else if lower.contains("italy")
        || lower.contains("milan")
        || lower.contains("rome")
        || lower.starts_with("it")
        || lower.contains("-it-")
        || lower.ends_with("-it")
    {
        "🇮🇹"
    } else if lower.contains("russia")
        || lower.contains("moscow")
        || lower.starts_with("ru")
        || lower.contains("-ru-")
        || lower.ends_with("-ru")
    {
        "🇷🇺"
    } else if lower.contains("ukraine")
        || lower.contains("kyiv")
        || lower.starts_with("ua")
        || lower.contains("-ua-")
        || lower.ends_with("-ua")
    {
        "🇺🇦"
    } else if lower.contains("hong kong")
        || lower.starts_with("hk")
        || lower.contains("-hk-")
        || lower.ends_with("-hk")
    {
        "🇭🇰"
    } else if lower.contains("taiwan")
        || lower.contains("taipei")
        || lower.starts_with("tw")
        || lower.contains("-tw-")
        || lower.ends_with("-tw")
    {
        "🇹🇼"
    } else if lower.contains("korea")
        || lower.contains("seoul")
        || lower.starts_with("kr")
        || lower.contains("-kr-")
        || lower.ends_with("-kr")
    {
        "🇰🇷"
    } else if lower.contains("india")
        || lower.contains("mumbai")
        || lower.starts_with("in")
        || lower.contains("-in-")
        || lower.ends_with("-in")
    {
        "🇮🇳"
    } else if lower.contains("australia")
        || lower.contains("sydney")
        || lower.starts_with("au")
        || lower.contains("-au-")
        || lower.ends_with("-au")
    {
        "🇦🇺"
    } else if lower.contains("brazil")
        || lower.contains("sao paulo")
        || lower.starts_with("br")
        || lower.contains("-br-")
        || lower.ends_with("-br")
    {
        "🇧🇷"
    } else if lower.contains("austria")
        || lower.contains("vienna")
        || lower.starts_with("at")
        || lower.contains("-at-")
        || lower.ends_with("-at")
    {
        "🇦🇹"
    } else if lower.contains("norway")
        || lower.contains("oslo")
        || lower.starts_with("no")
        || lower.contains("-no-")
        || lower.ends_with("-no")
    {
        "🇳🇴"
    } else if lower.contains("denmark")
        || lower.contains("copenhagen")
        || lower.starts_with("dk")
        || lower.contains("-dk-")
        || lower.ends_with("-dk")
    {
        "🇩🇰"
    } else if lower.contains("belgium")
        || lower.contains("brussels")
        || lower.starts_with("be")
        || lower.contains("-be-")
        || lower.ends_with("-be")
    {
        "🇧🇪"
    } else {
        "🌐"
    };
    flag.to_string()
}

fn format_node_with_flag(name: &str, max_len: usize) -> String {
    let flag = detect_country_flag(name);
    let trimmed = name.trim();
    if trimmed.starts_with(&flag) {
        trunc_str(trimmed, max_len)
    } else {
        format!("{flag} {}", trunc_str(trimmed, max_len.saturating_sub(3)))
    }
}

fn reexec_sudo(args: &[String]) -> Result<()> {
    let exe = std::env::current_exe()?;
    let err = Command::new("sudo")
        .arg("--preserve-env=WAYLAND_DISPLAY,XDG_RUNTIME_DIR,TERM,COLORTERM,LANG")
        .arg(exe)
        .args(args)
        .exec();
    bail!("could not run sudo: {err}");
}

fn connect_profile(p: &store::Profile) -> Result<()> {
    if let Some(client) = get_ipc() {
        match client.request_sync(&IpcRequest::Connect {
            profile_id: p.id.clone(),
        })? {
            IpcResponse::Status(_) | IpcResponse::Ok => {
                let flag = detect_country_flag(&p.name);
                send_notification(
                    "Vortex Connected",
                    &format!("{flag} {} ({})", p.name, p.server),
                    Some("network-vpn"),
                );
                println!("connected: {} ({})", p.name, p.kind.tag());
                return Ok(());
            }
            IpcResponse::Error(e) => {
                bail!("Daemon connection error: {e}");
            }
            _ => {}
        }
    }

    if unsafe { libc::geteuid() } != 0 {
        return reexec_sudo(&["up".into(), p.id.clone()]);
    }

    connect_cli(p)?;
    let flag = detect_country_flag(&p.name);
    send_notification(
        "Vortex Connected",
        &format!("{flag} {} ({})", p.name, p.server),
        Some("network-vpn"),
    );
    Ok(())
}

fn handle_status(args: &[String]) -> Result<()> {
    let json_mode = args
        .iter()
        .any(|a| a == "--json" || a == "--waybar" || a == "-j");

    let daemon_status = if let Some(client) = get_ipc() {
        match client.request_sync(&IpcRequest::GetStatus) {
            Ok(IpcResponse::Status(st)) => Some(st),
            _ => None,
        }
    } else {
        None
    };

    let (connected, name, kind_tag, server, uptime_secs, armed, is_daemon) =
        if let Some(st) = &daemon_status {
            let (name, kind_tag) = if let Some(p) = &st.active_profile {
                (p.name.clone(), p.kind.tag().to_string())
            } else if let Some(s) = tunnel::load_session() {
                (s.name, s.kind.tag().to_string())
            } else {
                ("Connected".to_string(), "".to_string())
            };
            let srv = st.server_endpoint.clone().unwrap_or_default();
            (
                st.connected,
                name,
                kind_tag,
                srv,
                st.uptime_secs,
                st.shield_armed,
                true,
            )
        } else {
            let sess = tunnel::load_session();
            let armed = shield::is_armed();
            match sess {
                Some(s) => {
                    let up = tunnel::now().saturating_sub(s.since);
                    (
                        true,
                        s.name,
                        s.kind.tag().to_string(),
                        s.server,
                        up,
                        armed,
                        false,
                    )
                }
                None => (
                    false,
                    String::new(),
                    String::new(),
                    String::new(),
                    0,
                    armed,
                    false,
                ),
            }
        };

    if json_mode {
        let shield_class = if armed { "shield-armed" } else { "shield-off" };
        if connected {
            let uptime_fmt = if uptime_secs < 60 {
                format!("{uptime_secs}s")
            } else if uptime_secs < 3600 {
                format!("{}m {}s", uptime_secs / 60, uptime_secs % 60)
            } else {
                format!("{}h {}m", uptime_secs / 3600, (uptime_secs % 3600) / 60)
            };

            let class = format!("connected {shield_class}");
            let text = format_node_with_flag(&name, 16);
            let tooltip = format!(
                "<b>Vortex VPN & Proxy</b>\n<b>Status:</b> Connected\n<b>Node:</b> {} ({})\n<b>Endpoint:</b> {}\n<b>Shield:</b> {}\n<b>Uptime:</b> {}\n<i>Left-click: toggle · Right-click: menu</i>",
                name,
                kind_tag,
                server,
                if armed { "ARMED 🛡️" } else { "OFF" },
                uptime_fmt
            );

            let json = serde_json::json!({
                "text": text,
                "alt": "connected",
                "tooltip": tooltip,
                "class": class,
                "connected": true,
                "node": name,
                "protocol": kind_tag,
                "server": server,
                "shield": armed,
                "uptime_secs": uptime_secs,
            });
            println!("{}", serde_json::to_string(&json)?);
        } else {
            let class = format!("disconnected {shield_class}");
            let text = if armed {
                "󰌙 Off 🛡️"
            } else {
                "󰌙 Off"
            };
            let tooltip = format!(
                "<b>Vortex VPN & Proxy</b>\n<b>Status:</b> Disconnected\n<b>Shield:</b> {}\n<i>Left-click: connect · Right-click: menu</i>",
                if armed { "ARMED 🛡️" } else { "OFF" }
            );

            let json = serde_json::json!({
                "text": text,
                "alt": "disconnected",
                "tooltip": tooltip,
                "class": class,
                "connected": false,
                "shield": armed,
            });
            println!("{}", serde_json::to_string(&json)?);
        }
        return Ok(());
    }

    let daemon_str = if is_daemon {
        "\x1b[1;32mvortexd active\x1b[0m"
    } else {
        "\x1b[2mvortexd inactive (direct mode)\x1b[0m"
    };

    let shield_str = if armed {
        "\x1b[1;32m[SHIELD: ARMED]\x1b[0m"
    } else {
        "\x1b[2m[SHIELD: OFF]\x1b[0m"
    };

    if connected {
        println!(
            "● {} ({}) via {}  {}  [{daemon_str}]",
            name, kind_tag, server, shield_str
        );
        println!("  uptime {}s · exit {}", uptime_secs, tunnel::public_ip());
        println!("  proxy bridge: socks5://127.0.0.1:1080 · http://127.0.0.1:1080");
    } else {
        println!("○ disconnected  {}  [{daemon_str}]", shield_str);
    }
    Ok(())
}

fn handle_down() -> Result<()> {
    if let Some(client) = get_ipc() {
        match client.request_sync(&IpcRequest::Disconnect)? {
            IpcResponse::Status(_) | IpcResponse::Ok => {
                send_notification(
                    "Vortex Disconnected",
                    "Whole-system tunnel closed",
                    Some("network-vpn-disconnected"),
                );
                println!("disconnected");
                return Ok(());
            }
            IpcResponse::Error(e) => {
                bail!("Daemon disconnect error: {e}");
            }
            _ => {}
        }
    }

    if tunnel::load_session().is_none() {
        println!("disconnected");
        return Ok(());
    }

    if unsafe { libc::geteuid() } != 0 {
        return reexec_sudo(&["down".into()]);
    }

    tunnel::disconnect()?;
    send_notification(
        "Vortex Disconnected",
        "Whole-system tunnel closed",
        Some("network-vpn-disconnected"),
    );
    println!("disconnected");
    Ok(())
}

fn handle_toggle() -> Result<()> {
    let is_connected = if let Some(client) = get_ipc() {
        match client.request_sync(&IpcRequest::GetStatus) {
            Ok(IpcResponse::Status(st)) => st.connected,
            _ => tunnel::load_session().is_some(),
        }
    } else {
        tunnel::load_session().is_some()
    };

    if is_connected {
        handle_down()
    } else {
        let all = load_profiles();
        if all.is_empty() {
            bail!("no profiles imported yet — use `vortex add <link>`");
        }
        let target_profile =
            match store::last().and_then(|id| all.iter().find(|p| p.id == id).cloned()) {
                Some(p) => p,
                None => {
                    let ranked = ping::measure_all(all);
                    match ranked
                        .into_iter()
                        .find(|(_, r)| matches!(r, ping::Ping::Ms(_)))
                    {
                        Some((p, _)) => p,
                        None => bail!("no reachable profile available to connect"),
                    }
                }
            };

        connect_profile(&target_profile)
    }
}

fn handle_pick(args: &[String]) -> Result<()> {
    if let Some(q) = args.get(1) {
        let p = find(q)?;
        return connect_profile(&p);
    }

    let all = load_profiles();
    if all.is_empty() {
        bail!("no profiles imported yet — use `vortex add <link>`");
    }

    // 1. Native Omarchy desktop menu integration
    if which_exists("omarchy-menu-select") {
        let child = Command::new("omarchy-menu-select")
            .arg("Vortex Egress ❯")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn();
        if let Ok(mut child) = child {
            if let Some(mut stdin) = child.stdin.take() {
                use std::io::Write;
                for p in &all {
                    let flag = detect_country_flag(&p.name);
                    let line = format!("{flag}\t{}\t[{}] {}\n", p.name, p.kind.tag(), p.server);
                    let _ = stdin.write_all(line.as_bytes());
                }
            }
            if let Ok(out) = child.wait_with_output() {
                if out.status.success() {
                    let selected = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    if !selected.is_empty() {
                        let name = selected
                            .split('\t')
                            .nth(1)
                            .unwrap_or_else(|| selected.split('\t').next().unwrap_or(&selected))
                            .trim();
                        if let Ok(p) = find(name) {
                            return connect_profile(&p);
                        }
                    }
                }
                return Ok(());
            }
        }
    }

    let mut menu_cmd: Option<(&str, Vec<&str>)> = None;
    if which_exists("fuzzel") {
        menu_cmd = Some(("fuzzel", vec!["--dmenu", "-p", "Vortex ❯ "]));
    } else if which_exists("rofi") {
        menu_cmd = Some(("rofi", vec!["-dmenu", "-p", "Vortex ❯ "]));
    } else if which_exists("wofi") {
        menu_cmd = Some(("wofi", vec!["--dmenu", "-p", "Vortex ❯ "]));
    } else if which_exists("tofi") {
        menu_cmd = Some(("tofi", vec!["--prompt-text", "Vortex ❯ "]));
    } else if which_exists("zenity") {
        menu_cmd = Some((
            "zenity",
            vec![
                "--list",
                "--title=Vortex Egress Selector",
                "--column=Profile",
            ],
        ));
    }

    if let Some((bin, menu_args)) = menu_cmd {
        let mut lines = Vec::new();
        for (i, p) in all.iter().enumerate() {
            let flag = detect_country_flag(&p.name);
            lines.push(format!(
                "{:>2}. {flag} [{:<5}] {:<28} ({})",
                i + 1,
                p.kind.tag(),
                p.name,
                p.server
            ));
        }

        let input_text = lines.join("\n");
        let mut child = Command::new(bin)
            .args(&menu_args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .with_context(|| format!("Failed to run menu launcher {bin}"))?;

        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            let _ = stdin.write_all(input_text.as_bytes());
        }

        let out = child.wait_with_output()?;
        if out.status.success() {
            let selected = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if selected.is_empty() {
                return Ok(());
            }
            if let Some(num_str) = selected.split('.').next() {
                if let Ok(idx) = num_str.trim().parse::<usize>() {
                    if idx >= 1 && idx <= all.len() {
                        return connect_profile(&all[idx - 1]);
                    }
                }
            }
            let p = find(&selected)?;
            return connect_profile(&p);
        }
        return Ok(());
    }

    println!("\x1b[1;36m◈ 0xSELECT // PICK EGRESS NODE\x1b[0m");
    for (i, p) in all.iter().enumerate() {
        let flag = detect_country_flag(&p.name);
        println!(
            "  {:>2}) {flag} [{:<5}] {:<28} {}",
            i + 1,
            p.kind.tag(),
            p.name,
            p.server
        );
    }
    print!("\nSelect node [1-{}]: ", all.len());
    use std::io::Write;
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).ok();
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(());
    }
    let p = find(trimmed)?;
    connect_profile(&p)
}

fn handle_history(args: &[String]) -> Result<()> {
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

const BASH_COMPLETION: &str = r#"# Bash completion for vortex
_vortex_completions() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    opts="add list ls up down toggle best ping pick qr conf proxy shield leaks recon speed flows route history sub update auth rename rm status completion"

    if [[ ${COMP_CWORD} -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
        return 0
    fi

    case "${prev}" in
        up|recon|qr|conf|auth|rename|rm|pick)
            local profiles=$(vortex list 2>/dev/null | awk '{print $3}')
            COMPREPLY=( $(compgen -W "${profiles}" -- ${cur}) )
            return 0
            ;;
        status)
            COMPREPLY=( $(compgen -W "--json --waybar" -- ${cur}) )
            return 0
            ;;
        shield)
            COMPREPLY=( $(compgen -W "on off status" -- ${cur}) )
            return 0
            ;;
        route)
            COMPREPLY=( $(compgen -W "list explain bypass block clear" -- ${cur}) )
            return 0
            ;;
        completion)
            COMPREPLY=( $(compgen -W "bash zsh fish" -- ${cur}) )
            return 0
            ;;
    esac
}
complete -F _vortex_completions vortex
"#;

const ZSH_COMPLETION: &str = r#"#compdef vortex
_vortex() {
    local -a commands
    commands=(
        'add:import share link, sub URL, QR image, or .conf/.ovpn'
        'list:list all imported profiles'
        'up:connect to profile by name or number'
        'down:disconnect active tunnel'
        'toggle:connect fastest if down, disconnect if up'
        'best:test latency and connect to fastest node'
        'ping:measure RTT of all profiles'
        'pick:interactive fuzzy node selector (rofi/fuzzel/zenity)'
        'qr:display terminal QR code for mobile import'
        'conf:show raw configuration text'
        'proxy:manage local SOCKS5/HTTP proxy bridge (:1080)'
        'shield:toggle nftables stealth kill switch'
        'leaks:run comprehensive DNS, IPv6, and STUN leak audit'
        'recon:perform deep node reconnaissance'
        'speed:measure live bandwidth throughput under load'
        'flows:live socket and packet traffic sniffer'
        'route:manage split tunneling, LAN bypass, and domain rules'
        'history:inspect traffic accounting and metrics'
        'sub:manage remote subscriptions'
        'update:sync all subscriptions'
        'status:display active tunnel & shield status'
        'completion:generate shell autocompletions'
    )
    _describe -t commands 'vortex commands' commands
}
_vortex "$@"
"#;

const FISH_COMPLETION: &str = r#"# Fish completion for vortex
complete -c vortex -f
complete -c vortex -n "__fish_use_subcommand" -a "add" -d "Import share link or config"
complete -c vortex -n "__fish_use_subcommand" -a "list" -d "List profiles"
complete -c vortex -n "__fish_use_subcommand" -a "up" -d "Connect to profile"
complete -c vortex -n "__fish_use_subcommand" -a "down" -d "Disconnect tunnel"
complete -c vortex -n "__fish_use_subcommand" -a "toggle" -d "Toggle tunnel connection"
complete -c vortex -n "__fish_use_subcommand" -a "best" -d "Connect to fastest node"
complete -c vortex -n "__fish_use_subcommand" -a "ping" -d "Test latency of all nodes"
complete -c vortex -n "__fish_use_subcommand" -a "pick" -d "Interactive node selector"
complete -c vortex -n "__fish_use_subcommand" -a "shield" -d "Toggle kill switch shield"
complete -c vortex -n "__fish_use_subcommand" -a "leaks" -d "Run leak audit"
complete -c vortex -n "__fish_use_subcommand" -a "route" -d "Split tunneling rules"
complete -c vortex -n "__fish_use_subcommand" -a "history" -d "Traffic history"
complete -c vortex -n "__fish_use_subcommand" -a "status" -d "Show tunnel status"
complete -c vortex -n "__fish_seen_subcommand_from status" -l json -d "Output Waybar/JSON status"
complete -c vortex -n "__fish_seen_subcommand_from status" -l waybar -d "Output Waybar/JSON status"
"#;

fn handle_completion(args: &[String]) -> Result<()> {
    let shell = args.get(1).map(String::as_str).unwrap_or("bash");
    match shell {
        "bash" => print!("{BASH_COMPLETION}"),
        "zsh" => print!("{ZSH_COMPLETION}"),
        "fish" => print!("{FISH_COMPLETION}"),
        other => bail!("unsupported shell '{other}' — try bash, zsh, fish"),
    }
    Ok(())
}

fn handle_list() -> Result<()> {
    let active = tunnel::load_session().map(|s| s.id);
    let all = load_profiles();
    if all.is_empty() {
        println!("no profiles found — use `vortex add <link|file>`");
        return Ok(());
    }
    for (i, p) in all.iter().enumerate() {
        let mark = if active.as_deref() == Some(p.id.as_str()) {
            "●"
        } else {
            " "
        };
        let flag = detect_country_flag(&p.name);
        println!(
            "{mark} {:>2}  {flag} [{:<5}] {:<28} {}",
            i + 1,
            p.kind.tag(),
            p.name,
            p.server
        );
    }
    Ok(())
}

fn handle_ping() -> Result<()> {
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

fn handle_qr(args: &[String]) -> Result<()> {
    let q = args.get(1).map(String::as_str).unwrap_or("");
    let p = find(q)?;
    match store::generate_qr(&p.data) {
        Ok(code) => {
            let flag = detect_country_flag(&p.name);
            println!(
                "\x1b[1;36m◈ 0xQR // {flag} {} ({})\x1b[0m",
                p.name,
                p.kind.tag()
            );
            println!("{code}");
            println!("\x1b[1;32mEndpoint:\x1b[0m {}", p.server);
            if p.kind.is_singbox() {
                println!("\x1b[1;32mPayload:\x1b[0m  {}", p.data);
            }
            println!("\x1b[2mScan with your mobile VPN client (v2rayNG, Streisand, Sing-box, WireGuard, Shadowrocket)\x1b[0m");
        }
        Err(e) => bail!("could not generate QR code: {e}"),
    }
    Ok(())
}

fn handle_conf(args: &[String]) -> Result<()> {
    let mut copy = false;
    let mut export = false;
    let mut query = vec![];
    for a in &args[1..] {
        if a == "--copy" || a == "-c" {
            copy = true;
        } else if a == "--export" || a == "-e" {
            export = true;
        } else {
            query.push(a.as_str());
        }
    }
    let p = find(&query.join(" "))?;
    if copy {
        store::copy_to_clipboard(&p.data)?;
        println!("copied configuration for '{}' to clipboard", p.name);
        return Ok(());
    }
    if export {
        let path = store::export_to_file(&p)?;
        println!("exported configuration to {}", path.display());
        return Ok(());
    }
    println!(
        "\x1b[1;36m# Configuration for {} ({})\x1b[0m",
        p.name,
        p.kind.tag()
    );
    println!("{}", p.data);
    if p.kind.is_singbox() {
        if let Ok((_, ob, _, _)) = store::outbound(&p.data) {
            println!("\n\x1b[1;36m# Sing-box Outbound JSON:\x1b[0m");
            println!("{}", serde_json::to_string_pretty(&ob)?);
        }
    }
    Ok(())
}

fn handle_recon(args: &[String]) -> Result<()> {
    let q = args.get(1).map(String::as_str).unwrap_or("");
    let p = find(q)?;
    println!("\x1b[1;36m⚡ VORTEX // EXECUTING DEEP NODE RECONNAISSANCE...\x1b[0m");
    println!("  Target: {} ({})\n", p.name, p.server);
    let rep = recon::probe_recon(&p)?;
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

fn handle_leaks() -> Result<()> {
    println!("\x1b[1;36m🛡 VORTEX // EXECUTING LEAK INTEGRITY SUITE...\x1b[0m\n");
    let sess = tunnel::load_session();
    let is_sec = sess.is_some();
    let srv = sess.as_ref().map(|s| s.server.as_str());
    let exit_ip = sess.as_ref().map(|_| tunnel::public_ip());

    let rep = tokio::runtime::Runtime::new()?.block_on(vortex_core::leak::run_leak_suite(
        is_sec,
        srv,
        exit_ip.as_deref(),
    ));

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

fn handle_sub(args: &[String]) -> Result<()> {
    let subcmd = args.get(1).map(String::as_str).unwrap_or("list");
    match subcmd {
        "list" | "ls" => {
            let subs = store::load_subs();
            if subs.is_empty() {
                println!("no subscriptions configured — use `vortex sub add <url>`");
                return Ok(());
            }
            println!(
                "{:<3} {:<16} {:<24} {:<8} {:<12} URL",
                "#", "ID", "NAME", "NODES", "UPDATED"
            );
            for (i, s) in subs.iter().enumerate() {
                let updated = s
                    .updated
                    .map(|ts| {
                        let diff = tunnel::now().saturating_sub(ts);
                        if diff < 60 {
                            format!("{diff}s ago")
                        } else if diff < 3600 {
                            format!("{}m ago", diff / 60)
                        } else if diff < 86400 {
                            format!("{}h ago", diff / 3600)
                        } else {
                            format!("{}d ago", diff / 86400)
                        }
                    })
                    .unwrap_or_else(|| "never".into());
                println!(
                    "{:>2}  {:<16} {:<24} {:<8} {:<12} {}",
                    i + 1,
                    s.id,
                    trunc_str(&s.name, 24),
                    s.count,
                    updated,
                    s.url
                );
            }
            Ok(())
        }
        "add" => {
            let url = args
                .get(2)
                .ok_or_else(|| anyhow::anyhow!("usage: vortex sub add <url> [name]"))?;
            let name = args.get(3).map(String::as_str);
            let (sub, count) = store::add_sub(url, name)?;
            println!(
                "added subscription '{}' ({}) with {} node(s)",
                sub.name, sub.id, count
            );
            Ok(())
        }
        "update" | "up" | "sync" => {
            let target = args.get(2).map(String::as_str).unwrap_or("all");
            if target == "all" {
                let results = store::update_all_subs()?;
                for (name, r) in results {
                    match r {
                        Ok(n) => println!("✔ {name}: updated ({n} nodes)"),
                        Err(e) => println!("✕ {name}: failed ({e})"),
                    }
                }
            } else {
                let (sub, count) = store::update_sub(target)?;
                println!("✔ {}: updated ({count} nodes)", sub.name);
            }
            Ok(())
        }
        "rm" | "remove" | "del" => {
            let target = args
                .get(2)
                .ok_or_else(|| anyhow::anyhow!("usage: vortex sub rm <id>"))?;
            let removed = store::remove_sub(target, true)?;
            println!("removed subscription and cleaned up {removed} profile(s)");
            Ok(())
        }
        other => {
            bail!("unknown subscription command '{other}' — try list, add, update, rm")
        }
    }
}

fn handle_route(args: &[String]) -> Result<()> {
    let sub = args.get(1).map(String::as_str).unwrap_or("list");
    let mut cfg = tunnel::load_routing();
    match sub {
        "list" => {
            let rcfg = vortex_core::routing::RulesConfig::load();
            println!("\x1b[1;36m◈ 0xROUTE // SPLIT TUNNELING & ROUTING RULES MATRIX\x1b[0m");
            println!("  \x1b[1mPreset Filters:\x1b[0m");
            println!(
                "    Bypass LAN (RFC1918)    : {}",
                if rcfg.presets.bypass_lan {
                    "\x1b[1;32mENABLED\x1b[0m"
                } else {
                    "\x1b[2mDISABLED\x1b[0m"
                }
            );
            println!(
                "    Block Trackers & Ads    : {}",
                if rcfg.presets.block_ads {
                    "\x1b[1;32mENABLED\x1b[0m"
                } else {
                    "\x1b[2mDISABLED\x1b[0m"
                }
            );
            println!(
                "    Direct Domestic GeoIP   : {}",
                if rcfg.presets.direct_domestic {
                    "\x1b[1;32mENABLED\x1b[0m"
                } else {
                    "\x1b[2mDISABLED\x1b[0m"
                }
            );
            println!(
                "    Global Proxy Fallback   : {}",
                if rcfg.presets.proxy_all {
                    "\x1b[1;32mENABLED\x1b[0m"
                } else {
                    "\x1b[2mDISABLED\x1b[0m"
                }
            );
            println!(
                "\n  \x1b[1mCustom Rules ({} active):\x1b[0m",
                rcfg.custom_rules.len()
            );
            for (i, r) in rcfg.custom_rules.iter().enumerate() {
                let act = match r.action {
                    vortex_core::routing::RuleAction::Proxy => "\x1b[1;36mPROXY\x1b[0m",
                    vortex_core::routing::RuleAction::Direct => "\x1b[1;32mDIRECT\x1b[0m",
                    vortex_core::routing::RuleAction::Block => "\x1b[1;31mBLOCK\x1b[0m",
                    vortex_core::routing::RuleAction::ProxyGroup => "\x1b[1;35mGROUP\x1b[0m",
                };
                println!(
                    "    [{:02}] {:<18} -> {act} ({})",
                    i + 1,
                    r.id,
                    r.description.as_deref().unwrap_or("custom rule")
                );
            }
            println!("\n\x1b[2mExplain resolution with `vortex route explain <target>`\x1b[0m");
        }
        "explain" => {
            let target = args
                .get(2)
                .ok_or_else(|| anyhow::anyhow!("usage: vortex route explain <target>"))?;
            let rcfg = vortex_core::routing::RulesConfig::load();
            let res = rcfg.explain(target, None, None, None);
            println!("\x1b[1;36m◈ ROUTE POLICY RESOLUTION FOR:\x1b[0m {target}\n");
            println!(
                "  Matched Rule : \x1b[1m{}\x1b[0m (Rule #{})",
                res.rule_id, res.rule_index
            );
            let (act_str, act_col) = match res.action {
                vortex_core::routing::RuleAction::Proxy => ("PROXY (TUNNEL)", "\x1b[1;36m"),
                vortex_core::routing::RuleAction::Direct => ("DIRECT (BYPASS)", "\x1b[1;32m"),
                vortex_core::routing::RuleAction::Block => ("BLOCK (REJECT)", "\x1b[1;31m"),
                vortex_core::routing::RuleAction::ProxyGroup => ("PROXY GROUP", "\x1b[1;35m"),
            };
            println!("  Final Action : {act_col}{act_str}\x1b[0m");
            println!("  Match Reason : {}", res.reason);
        }
        "bypass" => {
            let domain = args
                .get(2)
                .ok_or_else(|| anyhow::anyhow!("usage: vortex route bypass <domain>"))?;
            if !cfg.direct_domains.contains(&domain.to_string()) {
                cfg.direct_domains.push(domain.to_string());
                tunnel::save_routing(&cfg)?;
                println!("added direct bypass domain: {domain}");
            }
        }
        "block" => {
            let domain = args
                .get(2)
                .ok_or_else(|| anyhow::anyhow!("usage: vortex route block <domain>"))?;
            if !cfg.blocked_domains.contains(&domain.to_string()) {
                cfg.blocked_domains.push(domain.to_string());
                tunnel::save_routing(&cfg)?;
                println!("added blocked domain: {domain}");
            }
        }
        "clear" => {
            cfg.direct_domains.clear();
            cfg.blocked_domains.clear();
            tunnel::save_routing(&cfg)?;
            println!("cleared custom domain rules");
        }
        other => bail!("unknown route command '{other}' — try list, explain, bypass, block, clear"),
    }
    Ok(())
}

fn handle_add(args: &[String]) -> Result<()> {
    let input = args[1..].join(" ");
    if input.trim().is_empty() {
        bail!("usage: vortex add <link|file|url>");
    }
    if let Some(client) = get_ipc() {
        match client.request_sync(&IpcRequest::AddProfile { raw: input.clone() })? {
            IpcResponse::ProfileAdded { count } => {
                println!("added {count} profile(s)");
                return Ok(());
            }
            IpcResponse::Error(e) => bail!("Add profile error: {e}"),
            _ => {}
        }
    }
    store::ensure_dirs()?;
    let n = store::import(&input)?;
    println!("added {n} profile(s)");
    Ok(())
}

fn handle_rm(args: &[String]) -> Result<()> {
    if args.len() < 2 {
        bail!("usage: vortex rm <profile>");
    }
    let p = find(&args[1..].join(" "))?;
    if let Some(client) = get_ipc() {
        match client.request_sync(&IpcRequest::RemoveProfile { id: p.id.clone() })? {
            IpcResponse::Ok => {
                println!("deleted {}", p.name);
                return Ok(());
            }
            IpcResponse::Error(e) => bail!("Delete error: {e}"),
            _ => {}
        }
    }
    store::remove(&p.id)?;
    println!("deleted {}", p.name);
    Ok(())
}

fn handle_rename(args: &[String]) -> Result<()> {
    if args.len() < 3 {
        bail!("usage: vortex rename <profile> <new-name>");
    }
    let p = find(args.get(1).map(String::as_str).unwrap_or(""))?;
    let new_name = args[2.min(args.len())..].join(" ");
    if let Some(client) = get_ipc() {
        match client.request_sync(&IpcRequest::RenameProfile {
            id: p.id.clone(),
            new_name: new_name.clone(),
        })? {
            IpcResponse::Ok => {
                println!("renamed");
                return Ok(());
            }
            IpcResponse::Error(e) => bail!("Rename error: {e}"),
            _ => {}
        }
    }
    let mut p2 = p.clone();
    p2.name = new_name;
    store::save(&p2)?;
    println!("renamed");
    Ok(())
}

fn handle_update() -> Result<()> {
    if let Some(client) = get_ipc() {
        match client.request_sync(&IpcRequest::UpdateSubscriptions { target: None })? {
            IpcResponse::ProfileAdded { count } => {
                println!("✔ updated ({count} nodes synchronized)");
                return Ok(());
            }
            IpcResponse::Error(e) => bail!("Update error: {e}"),
            _ => {}
        }
    }
    let results = store::update_all_subs()?;
    for (name, r) in results {
        match r {
            Ok(n) => println!("✔ {name}: {n} profiles"),
            Err(e) => eprintln!("✗ {name}: {e}"),
        }
    }
    Ok(())
}

fn handle_shield(args: &[String]) -> Result<()> {
    let sub = args.get(1).map(String::as_str).unwrap_or("status");
    match sub {
        "on" | "enable" | "arm" => {
            if let Some(client) = get_ipc() {
                match client.request_sync(&IpcRequest::ToggleShield { enable: Some(true) })? {
                    IpcResponse::Status(st) => {
                        let armed = st.shield_armed;
                        println!(
                            "shield: {}",
                            if armed {
                                "\x1b[1;32m[ARMED]\x1b[0m stealth kill-switch active"
                            } else {
                                "\x1b[1;33m[OFF]\x1b[0m stealth kill-switch disarmed"
                            }
                        );
                        send_notification(
                            "Vortex Shield",
                            if armed {
                                "Kill-switch armed"
                            } else {
                                "Kill-switch disarmed"
                            },
                            Some(if armed {
                                "security-high"
                            } else {
                                "security-medium"
                            }),
                        );
                        return Ok(());
                    }
                    IpcResponse::Error(e) => bail!("Shield toggle error: {e}"),
                    _ => {}
                }
            }
            if unsafe { libc::geteuid() } != 0 {
                return reexec_sudo(args);
            }
            let sess = tunnel::load_session();
            let iface = sess.as_ref().map(|s| s.iface.as_str());
            let srv = sess.as_ref().map(|s| s.server.as_str());
            shield::set_enabled_preference(true);
            shield::arm(iface, srv)?;
            println!("\x1b[1;32m✔ Stealth Shield ARMED // Zero-leak killswitch engaged\x1b[0m");
            if let Some(s) = sess {
                println!(
                    "  Secured on interface {} via endpoint {}",
                    s.iface, s.server
                );
            }
            Ok(())
        }
        "off" | "disable" | "disarm" => {
            if let Some(client) = get_ipc() {
                match client.request_sync(&IpcRequest::ToggleShield { enable: Some(false) })? {
                    IpcResponse::Status(st) => {
                        let armed = st.shield_armed;
                        println!(
                            "shield: {}",
                            if armed {
                                "\x1b[1;32m[ARMED]\x1b[0m stealth kill-switch active"
                            } else {
                                "\x1b[1;33m[OFF]\x1b[0m stealth kill-switch disarmed"
                            }
                        );
                        send_notification(
                            "Vortex Shield",
                            "Kill-switch disarmed",
                            Some("security-medium"),
                        );
                        return Ok(());
                    }
                    IpcResponse::Error(e) => bail!("Shield toggle error: {e}"),
                    _ => {}
                }
            }
            if unsafe { libc::geteuid() } != 0 {
                return reexec_sudo(args);
            }
            shield::set_enabled_preference(false);
            shield::disarm()?;
            println!("\x1b[1;33m○ Stealth Shield DISARMED // Firewall rules cleared\x1b[0m");
            Ok(())
        }
        _ => {
            let (armed, iface, srv) = if let Some(client) = get_ipc() {
                if let Ok(IpcResponse::Status(st)) = client.request_sync(&IpcRequest::GetStatus) {
                    (st.shield_armed, st.iface, st.server_endpoint)
                } else {
                    let st = shield::status();
                    (st.armed, st.iface, st.server)
                }
            } else {
                let st = shield::status();
                (st.armed, st.iface, st.server)
            };
            let pref = shield::is_enabled_preference();
            println!("\x1b[1;36m◈ 0xSHIELD // STEALTH KILL SWITCH & ANTI-LEAK FIREWALL\x1b[0m");
            let armed_str = if armed {
                "\x1b[1;32mARMED (ACTIVE ENFORCEMENT)\x1b[0m"
            } else {
                "\x1b[2mDISARMED (OFF)\x1b[0m"
            };
            println!("  Firewall Status : {armed_str}");
            println!(
                "  Auto-Arm On Up  : {}",
                if pref {
                    "\x1b[1;32mENABLED\x1b[0m"
                } else {
                    "\x1b[2mDISABLED\x1b[0m"
                }
            );
            if let Some(ifc) = iface {
                println!("  Tunnel Interface: {ifc}");
            }
            if let Some(s) = srv {
                println!("  Exempt Server   : {s}");
            }
            println!("\n\x1b[2mToggle with `vortex shield on` or `vortex shield off`\x1b[0m");
            Ok(())
        }
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if matches!(
        args.first().map(String::as_str),
        Some("-h" | "--help" | "help")
    ) {
        print!("{HELP}");
        return Ok(());
    }
    if matches!(
        args.first().map(String::as_str),
        Some("-V" | "-v" | "--version" | "version")
    ) {
        println!("vortex {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    // Diagnostic, proxy, status, inspection, and desktop commands that do not require root:
    match args.first().map(String::as_str) {
        Some("proxy") => return handle_proxy(&args),
        Some("speed") | Some("benchmark") => return handle_speed(),
        Some("flows") | Some("net") | Some("connections") => return handle_flows(),
        Some("status") => return handle_status(&args),
        Some("toggle") => return handle_toggle(),
        Some("down") => return handle_down(),
        Some("pick") => return handle_pick(&args),
        Some("shield") | Some("killswitch") => return handle_shield(&args),
        Some("history") | Some("hist") => return handle_history(&args),
        Some("completion") => return handle_completion(&args),
        Some("list") | Some("ls") => return handle_list(),
        Some("ping") => return handle_ping(),
        Some("qr") => return handle_qr(&args),
        Some("conf") | Some("config") => return handle_conf(&args),
        Some("recon") | Some("inspect") => return handle_recon(&args),
        Some("leaks") | Some("leak") => return handle_leaks(),
        Some("route") | Some("routing") => return handle_route(&args),
        Some("sub") | Some("subs") => return handle_sub(&args),
        Some("add") => return handle_add(&args),
        Some("rm") | Some("remove") => return handle_rm(&args),
        Some("rename") => return handle_rename(&args),
        Some("update") | Some("sync") => return handle_update(),
        Some("xray") => return handle_xray(&args),
        _ => {}
    }

    // If IPC daemon is active, route commands through daemon without requiring sudo in client:
    if let Some(client) = get_ipc() {
        match args.first().map(String::as_str) {
            Some("up") => {
                let p = find(&args[1..].join(" "))?;
                return connect_profile(&p);
            }
            Some("best") => {
                let ranked = ping::measure_all(store::load_all());
                for (p, r) in ranked.iter().take(5) {
                    println!("{}  {:<7} {}", fmt_ping(*r), p.kind.tag(), p.name);
                }
                match ranked
                    .into_iter()
                    .find(|(_, r)| matches!(r, ping::Ping::Ms(_)))
                {
                    Some((p, _)) => return connect_profile(&p),
                    None => bail!("no reachable profile"),
                }
            }
            Some("shield") | Some("killswitch") => {
                let sub = args.get(1).map(String::as_str).unwrap_or("status");
                let enable = match sub {
                    "on" | "enable" | "arm" => Some(true),
                    "off" | "disable" | "disarm" => Some(false),
                    _ => None,
                };
                if let Some(en) = enable {
                    match client.request_sync(&IpcRequest::ToggleShield { enable: Some(en) })? {
                        IpcResponse::Status(st) => {
                            let armed = st.shield_armed;
                            println!(
                                "shield: {}",
                                if armed {
                                    "\x1b[1;32m[ARMED]\x1b[0m stealth kill-switch active"
                                } else {
                                    "\x1b[1;33m[OFF]\x1b[0m stealth kill-switch disarmed"
                                }
                            );
                            send_notification(
                                "Vortex Shield",
                                if armed {
                                    "Kill-switch armed"
                                } else {
                                    "Kill-switch disarmed"
                                },
                                Some(if armed {
                                    "security-high"
                                } else {
                                    "security-medium"
                                }),
                            );
                            return Ok(());
                        }
                        IpcResponse::Error(e) => bail!("Shield toggle error: {e}"),
                        _ => {}
                    }
                }
            }
            Some("add") => {
                let input = args[1..].join(" ");
                match client.request_sync(&IpcRequest::AddProfile { raw: input })? {
                    IpcResponse::ProfileAdded { count } => {
                        println!("added {count} profile(s)");
                        return Ok(());
                    }
                    IpcResponse::Error(e) => bail!("Add profile error: {e}"),
                    _ => {}
                }
            }
            Some("rm") | Some("remove") => {
                let p = find(&args[1..].join(" "))?;
                match client.request_sync(&IpcRequest::RemoveProfile { id: p.id.clone() })? {
                    IpcResponse::Ok => {
                        println!("deleted {}", p.name);
                        return Ok(());
                    }
                    IpcResponse::Error(e) => bail!("Delete error: {e}"),
                    _ => {}
                }
            }
            Some("rename") => {
                let p = find(args.get(1).map(String::as_str).unwrap_or(""))?;
                let new_name = args[2.min(args.len())..].join(" ");
                match client.request_sync(&IpcRequest::RenameProfile {
                    id: p.id.clone(),
                    new_name,
                })? {
                    IpcResponse::Ok => {
                        println!("renamed");
                        return Ok(());
                    }
                    IpcResponse::Error(e) => bail!("Rename error: {e}"),
                    _ => {}
                }
            }
            Some("update") | Some("sync") => {
                match client.request_sync(&IpcRequest::UpdateSubscriptions { target: None })? {
                    IpcResponse::ProfileAdded { count } => {
                        println!("✔ updated ({count} nodes synchronized)");
                        return Ok(());
                    }
                    IpcResponse::Error(e) => bail!("Update error: {e}"),
                    _ => {}
                }
            }
            None => {
                // TUI can run connected to vortexd
                return ui::run();
            }
            _ => {}
        }
    }

    // Direct mode fallback: requires root for modifying tunnels/firewall
    if unsafe { libc::geteuid() } != 0 {
        match args.first().map(String::as_str) {
            None | Some("up") | Some("best") | Some("auth") => {
                let exe = std::env::current_exe()?;
                let err = Command::new("sudo")
                    .arg("--preserve-env=WAYLAND_DISPLAY,XDG_RUNTIME_DIR,TERM,COLORTERM,LANG")
                    .arg(exe)
                    .args(&args)
                    .exec();
                bail!("could not run sudo: {err}");
            }
            Some(x) => bail!("unknown command '{x}' — try `vortex --help`"),
        }
    }
    store::ensure_dirs()?;
    match args.first().map(String::as_str) {
        None => ui::run(),
        Some("add") => {
            let input = args[1..].join(" ");
            let n = store::import(&input)?;
            println!("added {n} profile(s)");
            Ok(())
        }
        Some("list") | Some("ls") => {
            let active = tunnel::load_session().map(|s| s.id);
            for (i, p) in store::load_all().iter().enumerate() {
                let mark = if active.as_deref() == Some(p.id.as_str()) {
                    "●"
                } else {
                    " "
                };
                println!(
                    "{mark} {:>2}  {:<7} {:<32} {}",
                    i + 1,
                    p.kind.tag(),
                    p.name,
                    p.server
                );
            }
            Ok(())
        }
        Some("up") => connect_profile(&find(&args[1..].join(" "))?),
        Some("ping") => {
            if tunnel::load_session().is_some() {
                eprintln!("note: a tunnel is active — numbers are measured through it. `vortex down` first for real ones.");
            }
            for (p, r) in ping::measure_all(store::load_all()) {
                println!(
                    "{}  {:<7} {:<32} {}",
                    fmt_ping(r),
                    p.kind.tag(),
                    p.name,
                    p.server
                );
            }
            Ok(())
        }
        Some("best") => {
            tunnel::disconnect()?;
            let ranked = ping::measure_all(store::load_all());
            for (p, r) in ranked.iter().take(5) {
                println!("{}  {:<7} {}", fmt_ping(*r), p.kind.tag(), p.name);
            }
            match ranked
                .into_iter()
                .find(|(_, r)| matches!(r, ping::Ping::Ms(_)))
            {
                Some((p, _)) => connect_profile(&p),
                None => bail!("no reachable profile"),
            }
        }
        Some("qr") => {
            let q = args[1..].join(" ");
            let p = find(&q)?;
            match store::generate_qr(&p.data) {
                Ok(code) => {
                    println!("\x1b[1;36m◈ 0xQR // {} ({})\x1b[0m", p.name, p.kind.tag());
                    println!("{code}");
                    println!("\x1b[1;32mEndpoint:\x1b[0m {}", p.server);
                    if p.kind.is_singbox() {
                        println!("\x1b[1;32mPayload:\x1b[0m  {}", p.data);
                    }
                    println!("\x1b[2mScan with your mobile VPN client (v2rayNG, Streisand, Sing-box, WireGuard, Shadowrocket)\x1b[0m");
                }
                Err(e) => bail!("could not generate QR code: {e}"),
            }
            Ok(())
        }
        Some("conf") | Some("config") => {
            let mut copy = false;
            let mut export = false;
            let mut query = vec![];
            for a in &args[1..] {
                if a == "--copy" || a == "-c" {
                    copy = true;
                } else if a == "--export" || a == "-e" {
                    export = true;
                } else {
                    query.push(a.as_str());
                }
            }
            let p = find(&query.join(" "))?;
            if copy {
                store::copy_to_clipboard(&p.data)?;
                println!("copied configuration for '{}' to clipboard", p.name);
                return Ok(());
            }
            if export {
                let path = store::export_to_file(&p)?;
                println!("exported configuration to {}", path.display());
                return Ok(());
            }
            println!(
                "\x1b[1;36m# Configuration for {} ({})\x1b[0m",
                p.name,
                p.kind.tag()
            );
            println!("{}", p.data);
            if p.kind.is_singbox() {
                if let Ok((_, ob, _, _)) = store::outbound(&p.data) {
                    println!("\n\x1b[1;36m# Sing-box Outbound JSON:\x1b[0m");
                    println!("{}", serde_json::to_string_pretty(&ob)?);
                }
            }
            Ok(())
        }
        Some("sub") | Some("subs") => {
            let subcmd = args.get(1).map(String::as_str).unwrap_or("list");
            match subcmd {
                "list" | "ls" => {
                    let subs = store::load_subs();
                    if subs.is_empty() {
                        println!("no subscriptions configured — use `vortex sub add <url>`");
                        return Ok(());
                    }
                    println!(
                        "{:<3} {:<16} {:<24} {:<8} {:<12} URL",
                        "#", "ID", "NAME", "NODES", "UPDATED"
                    );
                    for (i, s) in subs.iter().enumerate() {
                        let updated = s
                            .updated
                            .map(|ts| {
                                let diff = tunnel::now().saturating_sub(ts);
                                if diff < 60 {
                                    format!("{diff}s ago")
                                } else if diff < 3600 {
                                    format!("{}m ago", diff / 60)
                                } else if diff < 86400 {
                                    format!("{}h ago", diff / 3600)
                                } else {
                                    format!("{}d ago", diff / 86400)
                                }
                            })
                            .unwrap_or_else(|| "never".into());
                        println!(
                            "{:>2}  {:<16} {:<24} {:<8} {:<12} {}",
                            i + 1,
                            s.id,
                            trunc_str(&s.name, 24),
                            s.count,
                            updated,
                            s.url
                        );
                    }
                    Ok(())
                }
                "add" => {
                    let url = args
                        .get(2)
                        .ok_or_else(|| anyhow::anyhow!("usage: vortex sub add <url> [name]"))?;
                    let name = args.get(3).map(String::as_str);
                    let (sub, count) = store::add_sub(url, name)?;
                    println!(
                        "added subscription '{}' ({}) with {} node(s)",
                        sub.name, sub.id, count
                    );
                    Ok(())
                }
                "update" | "up" | "sync" => {
                    let target = args.get(2).map(String::as_str).unwrap_or("all");
                    if target == "all" {
                        let results = store::update_all_subs()?;
                        for (name, r) in results {
                            match r {
                                Ok(n) => println!("✔ {name}: updated ({n} nodes)"),
                                Err(e) => println!("✕ {name}: failed ({e})"),
                            }
                        }
                    } else {
                        let (sub, count) = store::update_sub(target)?;
                        println!("✔ {}: updated ({count} nodes)", sub.name);
                    }
                    Ok(())
                }
                "rm" | "remove" | "del" => {
                    let target = args
                        .get(2)
                        .ok_or_else(|| anyhow::anyhow!("usage: vortex sub rm <id>"))?;
                    let removed = store::remove_sub(target, true)?;
                    println!("removed subscription and cleaned up {removed} profile(s)");
                    Ok(())
                }
                other => {
                    bail!("unknown subscription command '{other}' — try list, add, update, rm")
                }
            }
        }
        Some("update") | Some("sync") => {
            let results = store::update_all_subs()?;
            for (name, r) in results {
                match r {
                    Ok(n) => println!("✔ {name}: updated ({n} nodes)"),
                    Err(e) => println!("✕ {name}: failed ({e})"),
                }
            }
            Ok(())
        }
        Some("auth") => {
            let q = args.get(1).map(String::as_str).unwrap_or("");
            let p = find(q)?;
            if p.kind != store::Kind::Ovpn {
                bail!("credentials are only applicable to OpenVPN profiles");
            }
            if args.iter().any(|a| a == "--clear" || a == "-c") {
                store::clear_auth(&p.id)?;
                println!("cleared saved credentials for '{}'", p.name);
                return Ok(());
            }
            if let Some(ref a) = p.auth {
                println!("current saved username for '{}': {}", p.name, a.username);
            }
            let cred =
                tunnel::prompt_ovpn_credentials(p.auth.as_ref().map(|a| a.username.as_str()))?;
            if cred.save {
                store::set_auth(&p.id, cred.username, cred.password)?;
                println!("credentials saved for '{}'", p.name);
            } else {
                store::clear_auth(&p.id)?;
                println!("credentials entered (not saved)");
            }
            Ok(())
        }
        Some("rename") => {
            let p = find(args.get(1).map(String::as_str).unwrap_or(""))?;
            store::rename(&p.id, &args[2.min(args.len())..].join(" "))?;
            println!("renamed");
            Ok(())
        }
        Some("rm") | Some("remove") => {
            let p = find(&args[1..].join(" "))?;
            if tunnel::load_session()
                .map(|s| s.id == p.id)
                .unwrap_or(false)
            {
                bail!("{} is connected — `vortex down` first", p.name);
            }
            store::remove(&p.id)?;
            println!("deleted {}", p.name);
            Ok(())
        }
        Some("proxy") => handle_proxy(&args),
        Some("shield") | Some("killswitch") => {
            let sub = args.get(1).map(String::as_str).unwrap_or("status");
            match sub {
                "on" | "enable" | "arm" => {
                    let sess = tunnel::load_session();
                    let iface = sess.as_ref().map(|s| s.iface.as_str());
                    let srv = sess.as_ref().map(|s| s.server.as_str());
                    shield::set_enabled_preference(true);
                    shield::arm(iface, srv)?;
                    println!(
                        "\x1b[1;32m✔ Stealth Shield ARMED // Zero-leak killswitch engaged\x1b[0m"
                    );
                    if let Some(s) = sess {
                        println!(
                            "  Secured on interface {} via endpoint {}",
                            s.iface, s.server
                        );
                    }
                }
                "off" | "disable" | "disarm" => {
                    shield::set_enabled_preference(false);
                    shield::disarm()?;
                    println!(
                        "\x1b[1;33m○ Stealth Shield DISARMED // Firewall rules cleared\x1b[0m"
                    );
                }
                _ => {
                    let st = shield::status();
                    let pref = shield::is_enabled_preference();
                    println!(
                        "\x1b[1;36m◈ 0xSHIELD // STEALTH KILL SWITCH & ANTI-LEAK FIREWALL\x1b[0m"
                    );
                    let armed_str = if st.armed {
                        "\x1b[1;32mARMED (ACTIVE ENFORCEMENT)\x1b[0m"
                    } else {
                        "\x1b[2mDISARMED (OFF)\x1b[0m"
                    };
                    println!("  Firewall Status : {armed_str}");
                    println!(
                        "  Auto-Arm On Up  : {}",
                        if pref {
                            "\x1b[1;32mENABLED\x1b[0m"
                        } else {
                            "\x1b[2mDISABLED\x1b[0m"
                        }
                    );
                    if let Some(ifc) = &st.iface {
                        println!("  Tunnel Interface: {ifc}");
                    }
                    if let Some(srv) = &st.server {
                        println!("  Exempt Server   : {srv}");
                    }
                    println!(
                        "\n\x1b[2mToggle with `vortex shield on` or `vortex shield off`\x1b[0m"
                    );
                }
            }
            Ok(())
        }
        Some("recon") | Some("inspect") => {
            let q = args[1..].join(" ");
            let p = find(&q)?;
            println!("\x1b[1;36m⚡ VORTEX // EXECUTING DEEP NODE RECONNAISSANCE...\x1b[0m");
            println!("  Target: {} ({})\n", p.name, p.server);
            let rep = recon::probe_recon(&p)?;
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
        Some("leaks") | Some("leak") => {
            println!("\x1b[1;36m🛡 VORTEX // EXECUTING LEAK INTEGRITY SUITE...\x1b[0m\n");
            let sess = tunnel::load_session();
            let is_sec = sess.is_some();
            let srv = sess.as_ref().map(|s| s.server.as_str());
            let exit_ip = sess.as_ref().map(|_| tunnel::public_ip());

            let rep = tokio::runtime::Runtime::new()?.block_on(vortex_core::leak::run_leak_suite(
                is_sec,
                srv,
                exit_ip.as_deref(),
            ));

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
        Some("speed") | Some("benchmark") => handle_speed(),
        Some("flows") | Some("net") | Some("connections") => handle_flows(),
        Some("route") | Some("routing") => {
            let sub = args.get(1).map(String::as_str).unwrap_or("list");
            let mut cfg = tunnel::load_routing();
            match sub {
                "list" => {
                    let rcfg = vortex_core::routing::RulesConfig::load();
                    println!(
                        "\x1b[1;36m◈ 0xROUTE // SPLIT TUNNELING & ROUTING RULES MATRIX\x1b[0m"
                    );
                    println!("  \x1b[1mPreset Filters:\x1b[0m");
                    println!(
                        "    Bypass LAN (RFC1918)    : {}",
                        if rcfg.presets.bypass_lan {
                            "\x1b[1;32mENABLED\x1b[0m"
                        } else {
                            "\x1b[2mDISABLED\x1b[0m"
                        }
                    );
                    println!(
                        "    Block Trackers & Ads    : {}",
                        if rcfg.presets.block_ads {
                            "\x1b[1;32mENABLED\x1b[0m"
                        } else {
                            "\x1b[2mDISABLED\x1b[0m"
                        }
                    );
                    println!(
                        "    Direct Domestic GeoIP   : {}",
                        if rcfg.presets.direct_domestic {
                            "\x1b[1;32mENABLED\x1b[0m"
                        } else {
                            "\x1b[2mDISABLED\x1b[0m"
                        }
                    );
                    println!(
                        "    Global Proxy Fallback   : {}",
                        if rcfg.presets.proxy_all {
                            "\x1b[1;32mENABLED\x1b[0m"
                        } else {
                            "\x1b[2mDISABLED\x1b[0m"
                        }
                    );
                    println!(
                        "\n  \x1b[1mCustom Rules ({} active):\x1b[0m",
                        rcfg.custom_rules.len()
                    );
                    for (i, r) in rcfg.custom_rules.iter().enumerate() {
                        let act = match r.action {
                            vortex_core::routing::RuleAction::Proxy => "\x1b[1;36mPROXY\x1b[0m",
                            vortex_core::routing::RuleAction::Direct => "\x1b[1;32mDIRECT\x1b[0m",
                            vortex_core::routing::RuleAction::Block => "\x1b[1;31mBLOCK\x1b[0m",
                            vortex_core::routing::RuleAction::ProxyGroup => {
                                "\x1b[1;35mGROUP\x1b[0m"
                            }
                        };
                        println!(
                            "    [{:02}] {:<18} -> {act} ({})",
                            i + 1,
                            r.id,
                            r.description.as_deref().unwrap_or("custom rule")
                        );
                    }
                    println!(
                        "\n\x1b[2mExplain resolution with `vortex route explain <target>`\x1b[0m"
                    );
                }
                "explain" => {
                    let target = args
                        .get(2)
                        .ok_or_else(|| anyhow::anyhow!("usage: vortex route explain <target>"))?;
                    let rcfg = vortex_core::routing::RulesConfig::load();
                    let res = rcfg.explain(target, None, None, None);
                    println!("\x1b[1;36m◈ ROUTE POLICY RESOLUTION FOR:\x1b[0m {target}\n");
                    println!(
                        "  Matched Rule : \x1b[1m{}\x1b[0m (Rule #{})",
                        res.rule_id, res.rule_index
                    );
                    let (act_str, act_col) = match res.action {
                        vortex_core::routing::RuleAction::Proxy => ("PROXY (TUNNEL)", "\x1b[1;36m"),
                        vortex_core::routing::RuleAction::Direct => {
                            ("DIRECT (BYPASS)", "\x1b[1;32m")
                        }
                        vortex_core::routing::RuleAction::Block => ("BLOCK (REJECT)", "\x1b[1;31m"),
                        vortex_core::routing::RuleAction::ProxyGroup => {
                            ("PROXY GROUP", "\x1b[1;35m")
                        }
                    };
                    println!("  Final Action : {act_col}{act_str}\x1b[0m");
                    println!("  Match Reason : {}", res.reason);
                }
                "bypass" => {
                    let domain = args
                        .get(2)
                        .ok_or_else(|| anyhow::anyhow!("usage: vortex route bypass <domain>"))?;
                    if !cfg.direct_domains.contains(&domain.to_string()) {
                        cfg.direct_domains.push(domain.to_string());
                        tunnel::save_routing(&cfg)?;
                        println!("added direct bypass domain: {domain}");
                    }
                }
                "block" => {
                    let domain = args
                        .get(2)
                        .ok_or_else(|| anyhow::anyhow!("usage: vortex route block <domain>"))?;
                    if !cfg.blocked_domains.contains(&domain.to_string()) {
                        cfg.blocked_domains.push(domain.to_string());
                        tunnel::save_routing(&cfg)?;
                        println!("added blocked domain: {domain}");
                    }
                }
                "clear" => {
                    cfg.direct_domains.clear();
                    cfg.blocked_domains.clear();
                    tunnel::save_routing(&cfg)?;
                    println!("cleared custom domain rules");
                }
                other => bail!(
                    "unknown route command '{other}' — try list, explain, bypass, block, clear"
                ),
            }
            Ok(())
        }
        Some("down") => handle_down(),
        Some("status") => handle_status(&args),
        Some(x) => bail!("unknown command '{x}' — try `vortex --help`"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_country_flag_existing_emoji() {
        assert_eq!(detect_country_flag("🇩🇪 Frankfurt"), "🇩🇪");
        assert_eq!(detect_country_flag("🇺🇸 US-Ashburn"), "🇺🇸");
        assert_eq!(detect_country_flag("🇯🇵 Tokyo 01"), "🇯🇵");
    }

    #[test]
    fn test_detect_country_flag_keywords() {
        assert_eq!(detect_country_flag("Frankfurt Fast-01"), "🇩🇪");
        assert_eq!(detect_country_flag("Amsterdam-1"), "🇳🇱");
        assert_eq!(detect_country_flag("Tokyo VIP"), "🇯🇵");
        assert_eq!(detect_country_flag("Custom Unknown"), "🌐");
    }

    #[test]
    fn test_format_node_with_flag_no_duplicates() {
        assert_eq!(format_node_with_flag("🇩🇪 Frankfurt", 20), "🇩🇪 Frankfurt");
        assert_eq!(
            format_node_with_flag("Frankfurt Fast", 20),
            "🇩🇪 Frankfurt Fast"
        );
    }
}

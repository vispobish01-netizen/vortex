mod benchmark;
mod keymap;
mod ping;
mod recon;
mod shield;
mod store;
mod tunnel;
mod ui;

use anyhow::{bail, Result};
use std::{os::unix::process::CommandExt, process::Command};

const HELP: &str = "\
vortex — elite cyber warfare VPN & proxy manager for Omarchy

  vortex               open the cyber warfare TUI
  vortex add <x>       import share link, sub URL, QR image (.png), or .conf/.ovpn
  vortex list          list profiles
  vortex up [n|name]   connect (number from `list`, or part of the name; no arg = last used)
  vortex best          test every server, connect to the fastest
  vortex ping          test latency of every profile
  vortex qr [n|name]   render compact terminal QR code for mobile scanning
  vortex conf [n|name] show full config text (--copy to clipboard, --export to file)
  vortex proxy [env]   manage local SOCKS5/HTTP proxy bridge (:1080) for tools
  vortex shield [on|off] stealth kill switch & anti-leak shield (alias: killswitch)
  vortex recon [n|name] deep node reconnaissance (ASN, GeoIP, TLS cert, jitter)
  vortex speed         measure live throughput & bandwidth under load
  vortex flows         live socket & traffic sniffer (active connections)
  vortex route         manage split tunneling, LAN bypass, and domain rules
  vortex sub list      list tracked subscriptions
  vortex sub add <url> add subscription and import nodes
  vortex sub update    update subscriptions from remote endpoints
  vortex sub rm <id>   remove a tracked subscription
  vortex update        sync all subscriptions
  vortex auth <n|name> [--clear]  manage OpenVPN username & password (with save mode)
  vortex rename <n|name> <new name>
  vortex rm <n|name>   delete a profile
  vortex down          disconnect
  vortex status        show active tunnel & shield status

protocols: VLESS · VMess · Trojan · Shadowsocks · Hysteria2 · TUIC (via sing-box)
           WireGuard · AmneziaWG · OpenVPN · Amnezia vpn:// links
";


fn find(q: &str) -> Result<store::Profile> {
    let all = store::load_all();
    let q = q.trim().to_lowercase();
    if q.is_empty() {
        let id = store::last().ok_or_else(|| anyhow::anyhow!("no profile given and none used before"))?;
        return all.into_iter().find(|p| p.id == id).ok_or_else(|| anyhow::anyhow!("last used profile no longer exists"));
    }
    if let Ok(n) = q.parse::<usize>() {
        if n >= 1 && n <= all.len() {
            return Ok(all[n - 1].clone());
        }
    }
    let hits: Vec<&store::Profile> = all.iter().filter(|p| p.id == q || p.name.to_lowercase().contains(&q)).collect();
    match hits.as_slice() {
        [p] => Ok((*p).clone()),
        [] => bail!("no such profile — see `vortex list`"),
        many => match many.iter().find(|p| p.id == q || p.name.to_lowercase() == q) {
            Some(p) => Ok((**p).clone()),
            None => bail!("'{q}' matches {} profiles — be more specific or use its number", many.len()),
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
    let s = tunnel::connect_with_credentials(&p, creds.as_ref().map(|(u, pw)| (u.as_str(), pw.as_str())))?;
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
                .args(["-s", "--max-time", "5", "-x", "socks5://127.0.0.1:1080", "https://cloudflare.com/cdn-cgi/trace"])
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
                Some(s) => println!("  Tunnel Link   : \x1b[1;32m● ACTIVE\x1b[0m -> {} ({})", s.name, s.kind.tag()),
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
    println!("  Throughput  : \x1b[1;32m{:.2} Mbps\x1b[0m ({:.2} MB/s)", res.mbps, res.mbs);
    println!("  Transferred : {:.2} MB in {:.2}s", res.bytes as f64 / 1_048_576.0, res.duration_secs);
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
    println!("\x1b[1;36m◈ 0xNET // ACTIVE FLOWS & SOCKET MATRIX ({} ESTABLISHED)\x1b[0m", flows.len());
    if flows.is_empty() {
        println!("  No active flows captured.");
        return Ok(());
    }
    println!("{:<5} {:<18} {:<32} {:<24}", "PROTO", "PROCESS", "TARGET DESTINATION", "LOCAL SOURCE");
    for f in flows.iter().take(25) {
        let target = if !f.host.is_empty() { format!("{} ({})", f.destination, f.host) } else { f.destination.clone() };
        println!("{:<5} {:<18} {:<32} {:<24}", f.network.to_uppercase(), trunc_str(&f.process, 18), trunc_str(&target, 32), f.source);
    }
    Ok(())
}

fn handle_status() -> Result<()> {
    match tunnel::load_session() {
        Some(s) => {
            let shield_str = if shield::is_armed() { "\x1b[1;32m[SHIELD: ARMED]\x1b[0m" } else { "\x1b[2m[SHIELD: OFF]\x1b[0m" };
            println!("● {} ({}) via {}  {}", s.name, s.kind.tag(), s.server, shield_str);
            println!("  uptime {}s · exit {}", tunnel::now().saturating_sub(s.since), tunnel::public_ip());
            println!("  proxy bridge: socks5://127.0.0.1:1080 · http://127.0.0.1:1080");
        }
        None => {
            let shield_str = if shield::is_armed() { "\x1b[1;32m[SHIELD: ARMED]\x1b[0m" } else { "\x1b[2m[SHIELD: OFF]\x1b[0m" };
            println!("○ disconnected  {}", shield_str);
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if matches!(args.first().map(String::as_str), Some("-h" | "--help" | "help")) {
        print!("{HELP}");
        return Ok(());
    }

    // Diagnostic and proxy commands that do not require root:
    match args.first().map(String::as_str) {
        Some("proxy") => return handle_proxy(&args),
        Some("speed") | Some("benchmark") => return handle_speed(),
        Some("flows") | Some("net") | Some("connections") => return handle_flows(),
        Some("status") => return handle_status(),
        _ => {}
    }

    // tunnels need root: re-exec through sudo (prompts in the normal terminal)
    if unsafe { libc::geteuid() } != 0 {
        let exe = std::env::current_exe()?;
        let err = Command::new("sudo")
            .arg("--preserve-env=WAYLAND_DISPLAY,XDG_RUNTIME_DIR,TERM,COLORTERM,LANG")
            .arg(exe)
            .args(&args)
            .exec();
        bail!("could not run sudo: {err}");
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
                let mark = if active.as_deref() == Some(p.id.as_str()) { "●" } else { " " };
                println!("{mark} {:>2}  {:<7} {:<32} {}", i + 1, p.kind.tag(), p.name, p.server);
            }
            Ok(())
        }
        Some("up") => connect_cli(&find(&args[1..].join(" "))?),
        Some("ping") => {
            if tunnel::load_session().is_some() {
                eprintln!("note: a tunnel is active — numbers are measured through it. `vortex down` first for real ones.");
            }
            for (p, r) in ping::measure_all(store::load_all()) {
                println!("{}  {:<7} {:<32} {}", fmt_ping(r), p.kind.tag(), p.name, p.server);
            }
            Ok(())
        }
        Some("best") => {
            tunnel::disconnect()?;
            let ranked = ping::measure_all(store::load_all());
            for (p, r) in ranked.iter().take(5) {
                println!("{}  {:<7} {}", fmt_ping(*r), p.kind.tag(), p.name);
            }
            match ranked.into_iter().find(|(_, r)| matches!(r, ping::Ping::Ms(_))) {
                Some((p, _)) => connect_cli(&p),
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
            println!("\x1b[1;36m# Configuration for {} ({})\x1b[0m", p.name, p.kind.tag());
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
                    println!("{:<3} {:<16} {:<24} {:<8} {:<12} URL", "#", "ID", "NAME", "NODES", "UPDATED");
                    for (i, s) in subs.iter().enumerate() {
                        let updated = s.updated.map(|ts| {
                            let diff = tunnel::now().saturating_sub(ts);
                            if diff < 60 { format!("{diff}s ago") }
                            else if diff < 3600 { format!("{}m ago", diff / 60) }
                            else if diff < 86400 { format!("{}h ago", diff / 3600) }
                            else { format!("{}d ago", diff / 86400) }
                        }).unwrap_or_else(|| "never".into());
                        println!("{:>2}  {:<16} {:<24} {:<8} {:<12} {}", i + 1, s.id, trunc_str(&s.name, 24), s.count, updated, s.url);
                    }
                    Ok(())
                }
                "add" => {
                    let url = args.get(2).ok_or_else(|| anyhow::anyhow!("usage: vortex sub add <url> [name]"))?;
                    let name = args.get(3).map(String::as_str);
                    let (sub, count) = store::add_sub(url, name)?;
                    println!("added subscription '{}' ({}) with {} node(s)", sub.name, sub.id, count);
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
                    let target = args.get(2).ok_or_else(|| anyhow::anyhow!("usage: vortex sub rm <id>"))?;
                    let removed = store::remove_sub(target, true)?;
                    println!("removed subscription and cleaned up {removed} profile(s)");
                    Ok(())
                }
                other => bail!("unknown subscription command '{other}' — try list, add, update, rm"),
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
            let cred = tunnel::prompt_ovpn_credentials(p.auth.as_ref().map(|a| a.username.as_str()))?;
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
            if tunnel::load_session().map(|s| s.id == p.id).unwrap_or(false) {
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
                    println!("\x1b[1;32m✔ Stealth Shield ARMED // Zero-leak killswitch engaged\x1b[0m");
                    if let Some(s) = sess {
                        println!("  Secured on interface {} via endpoint {}", s.iface, s.server);
                    }
                }
                "off" | "disable" | "disarm" => {
                    shield::set_enabled_preference(false);
                    shield::disarm()?;
                    println!("\x1b[1;33m○ Stealth Shield DISARMED // Firewall rules cleared\x1b[0m");
                }
                _ => {
                    let st = shield::status();
                    let pref = shield::is_enabled_preference();
                    println!("\x1b[1;36m◈ 0xSHIELD // STEALTH KILL SWITCH & ANTI-LEAK FIREWALL\x1b[0m");
                    let armed_str = if st.armed { "\x1b[1;32mARMED (ACTIVE ENFORCEMENT)\x1b[0m" } else { "\x1b[2mDISARMED (OFF)\x1b[0m" };
                    println!("  Firewall Status : {armed_str}");
                    println!("  Auto-Arm On Up  : {}", if pref { "\x1b[1;32mENABLED\x1b[0m" } else { "\x1b[2mDISABLED\x1b[0m" });
                    if let Some(ifc) = &st.iface {
                        println!("  Tunnel Interface: {ifc}");
                    }
                    if let Some(srv) = &st.server {
                        println!("  Exempt Server   : {srv}");
                    }
                    println!("\n\x1b[2mToggle with `vortex shield on` or `vortex shield off`\x1b[0m");
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
                println!("    ASN & Carrier : {} ({})", asn, rep.org.unwrap_or_default());
            }
            if let Some(c) = rep.country {
                println!("    Location      : {}, {}", rep.city.unwrap_or_default(), c);
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
                println!("    Live Exit IP  : {} (Cloudflare Datacenter: {})", ip, rep.exit_colo.unwrap_or_default());
            }
            Ok(())
        }
        Some("speed") | Some("benchmark") => handle_speed(),
        Some("flows") | Some("net") | Some("connections") => handle_flows(),
        Some("route") | Some("routing") => {
            let sub = args.get(1).map(String::as_str).unwrap_or("list");
            let mut cfg = tunnel::load_routing();
            match sub {
                "list" => {
                    println!("\x1b[1;36m◈ 0xROUTE // SPLIT TUNNELING & ROUTING RULES MATRIX\x1b[0m");
                    println!("  Bypass LAN (RFC1918) : {}", if cfg.bypass_lan { "\x1b[1;32mENABLED\x1b[0m" } else { "\x1b[2mDISABLED\x1b[0m" });
                    println!("  Direct Domains (LAN) : {}", if cfg.direct_domains.is_empty() { "none".into() } else { cfg.direct_domains.join(", ") });
                    println!("  Blocked Domains (Ad) : {}", if cfg.blocked_domains.is_empty() { "none".into() } else { cfg.blocked_domains.join(", ") });
                }
                "bypass" => {
                    let domain = args.get(2).ok_or_else(|| anyhow::anyhow!("usage: vortex route bypass <domain>"))?;
                    if !cfg.direct_domains.contains(&domain.to_string()) {
                        cfg.direct_domains.push(domain.to_string());
                        tunnel::save_routing(&cfg)?;
                        println!("added direct bypass domain: {domain}");
                    }
                }
                "block" => {
                    let domain = args.get(2).ok_or_else(|| anyhow::anyhow!("usage: vortex route block <domain>"))?;
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
                other => bail!("unknown route command '{other}' — try list, bypass, block, clear"),
            }
            Ok(())
        }
        Some("down") => {
            tunnel::disconnect()?;
            println!("disconnected");
            Ok(())
        }
        Some("status") => handle_status(),
        Some(x) => bail!("unknown command '{x}' — try `vortex --help`"),
    }
}

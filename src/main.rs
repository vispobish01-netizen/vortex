mod ping;
mod store;
mod tunnel;
mod ui;

use anyhow::{bail, Result};
use std::{os::unix::process::CommandExt, process::Command};

const HELP: &str = "\
vortex — minimal VPN/proxy manager for Omarchy

  vortex               open the TUI
  vortex add <x>       import share link, sub URL, QR image (.png), or .conf/.ovpn
  vortex list          list profiles
  vortex up [n|name]   connect (number from `list`, or part of the name; no arg = last used)
  vortex best          test every server, connect to the fastest
  vortex ping          test latency of every profile
  vortex qr [n|name]   render compact terminal QR code for mobile scanning
  vortex conf [n|name] show full config text (--copy to clipboard, --export to file)
  vortex sub list      list tracked subscriptions
  vortex sub add <url> add subscription and import nodes
  vortex sub update    update subscriptions from remote endpoints
  vortex sub rm <id>   remove a tracked subscription
  vortex update        sync all subscriptions
  vortex auth <n|name> [--clear]  manage OpenVPN username & password (with save mode)
  vortex rename <n|name> <new name>
  vortex rm <n|name>   delete a profile
  vortex down          disconnect
  vortex status        show the active tunnel

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

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if matches!(args.first().map(String::as_str), Some("-h" | "--help" | "help")) {
        print!("{HELP}");
        return Ok(());
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
                    println!("{:<3} {:<16} {:<24} {:<8} {:<12} {}", "#", "ID", "NAME", "NODES", "UPDATED", "URL");
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
        Some("down") => {
            tunnel::disconnect()?;
            println!("disconnected");
            Ok(())
        }
        Some("status") => {
            match tunnel::load_session() {
                Some(s) => {
                    println!("● {} ({}) via {}", s.name, s.kind.tag(), s.server);
                    println!("  uptime {}s · exit {}", tunnel::now().saturating_sub(s.since), tunnel::public_ip());
                }
                None => println!("○ disconnected"),
            }
            Ok(())
        }
        Some(x) => bail!("unknown command '{x}' — try `vortex --help`"),
    }
}

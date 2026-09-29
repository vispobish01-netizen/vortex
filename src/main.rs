mod ping;
mod store;
mod tunnel;
mod ui;

use anyhow::{bail, Result};
use std::{os::unix::process::CommandExt, process::Command};

const HELP: &str = "\
vortex — minimal VPN/proxy manager for Omarchy

  vortex               open the TUI
  vortex add <x>       import a share link, subscription URL, or .conf/.ovpn file
  vortex list          list profiles
  vortex up [n|name]   connect (number from `list`, or part of the name; no arg = last used)
  vortex best          test every server, connect to the fastest
  vortex ping          test latency of every profile
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

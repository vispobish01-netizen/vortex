use anyhow::{bail, Result};
use vortex_core::ipc::{IpcRequest, IpcResponse};
use vortex_core::{store, tunnel};

use super::get_ipc;
use super::status::{detect_country_flag, trunc_str};

pub fn load_profiles() -> Vec<store::Profile> {
    if let Some(client) = get_ipc() {
        if let Ok(IpcResponse::Profiles(profiles)) = client.request_sync(&IpcRequest::GetProfiles) {
            if !profiles.is_empty() {
                return profiles;
            }
        }
    }
    store::load_all()
}

pub fn find(q: &str) -> Result<store::Profile> {
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

pub fn handle_list() -> Result<()> {
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

pub fn handle_qr(args: &[String]) -> Result<()> {
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

pub fn handle_conf(args: &[String]) -> Result<()> {
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

pub fn handle_sub(args: &[String]) -> Result<()> {
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

pub fn handle_add(args: &[String]) -> Result<()> {
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

pub fn handle_rm(args: &[String]) -> Result<()> {
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

pub fn handle_rename(args: &[String]) -> Result<()> {
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

pub fn handle_update() -> Result<()> {
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

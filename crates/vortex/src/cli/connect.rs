use anyhow::{bail, Context, Result};
use std::{os::unix::process::CommandExt, process::Command};
use vortex_core::ipc::{IpcRequest, IpcResponse};
use vortex_core::{ping, storage, store, tunnel};

use super::get_ipc;
use super::notify::{send_notification, which_exists};
use super::profiles::{find, load_profiles};
use super::status::{detect_country_flag, fmt_ping};

pub fn handle_auth(args: &[String]) -> Result<()> {
    let q = args.get(1).map(String::as_str).unwrap_or("");
    let p = find(q)?;
    if p.kind != store::Kind::Ovpn {
        bail!("credentials are only applicable to OpenVPN profiles");
    }
    if args.iter().any(|a| a == "--clear" || a == "-c") {
        if let Some(client) = get_ipc() {
            match client.request_sync(&IpcRequest::ClearAuth {
                profile_id: p.id.clone(),
            })? {
                IpcResponse::Ok => {
                    println!("cleared saved credentials for '{}'", p.name);
                    return Ok(());
                }
                IpcResponse::Error(e) => bail!("ClearAuth failed: {e}"),
                _ => {}
            }
        }
        store::clear_auth(&p.id)?;
        println!("cleared saved credentials for '{}'", p.name);
        return Ok(());
    }
    if let Some(ref a) = p.auth {
        println!("current saved username for '{}': {}", p.name, a.username);
    }
    let cred = tunnel::prompt_ovpn_credentials(p.auth.as_ref().map(|a| a.username.as_str()))?;
    if cred.save {
        if let Some(client) = get_ipc() {
            match client.request_sync(&IpcRequest::SetAuth {
                profile_id: p.id.clone(),
                username: cred.username.clone(),
                password: cred.password.clone(),
            })? {
                IpcResponse::Ok => {
                    println!("credentials saved for '{}'", p.name);
                    return Ok(());
                }
                IpcResponse::Error(e) => bail!("SetAuth failed: {e}"),
                _ => {}
            }
        }
        store::set_auth(&p.id, cred.username, cred.password)?;
        println!("credentials saved for '{}'", p.name);
    } else {
        if let Some(client) = get_ipc() {
            let _ = client.request_sync(&IpcRequest::ClearAuth {
                profile_id: p.id.clone(),
            });
        } else {
            store::clear_auth(&p.id)?;
        }
        println!("credentials entered (not saved)");
    }
    Ok(())
}

pub fn handle_best() -> Result<()> {
    if get_ipc().is_none() {
        let _ = tunnel::disconnect();
    }
    let ranked = ping::measure_all(load_profiles());
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

pub fn reexec_sudo(args: &[String]) -> Result<()> {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        if get_ipc().is_none() {
            send_notification(
                "Vortex",
                "start vortexd: systemctl --user enable --now vortexd",
                Some("dialog-error"),
            );
            bail!("start vortexd: systemctl --user enable --now vortexd");
        }
        bail!("sudo re-exec is not supported when stdin is not a TTY");
    }
    let exe = std::env::current_exe()?;
    let err = Command::new("sudo")
        .arg("--preserve-env=WAYLAND_DISPLAY,XDG_RUNTIME_DIR,TERM,COLORTERM,LANG,VORTEX_SOCK,VORTEX_BACKEND,VORTEX_MODE,VORTEX_RUN_DIR")
        .arg(exe)
        .args(args)
        .exec();
    bail!("could not run sudo: {err}");
}

pub fn connect_cli(p: &store::Profile) -> Result<()> {
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

pub fn connect_profile(p: &store::Profile) -> Result<()> {
    if let Some(client) = get_ipc() {
        let req = if tunnel::ovpn_needs_auth(p) && p.auth.is_none() {
            let cred = tunnel::prompt_ovpn_credentials(None)?;
            if cred.save {
                let _ = client.request_sync(&IpcRequest::SetAuth {
                    profile_id: p.id.clone(),
                    username: cred.username.clone(),
                    password: cred.password.clone(),
                });
            }
            IpcRequest::ConnectWithCredentials {
                profile_id: p.id.clone(),
                username: cred.username,
                password: cred.password,
            }
        } else {
            IpcRequest::Connect {
                profile_id: p.id.clone(),
            }
        };

        match client.request_sync(&req)? {
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
                let e_lower = e.to_lowercase();
                if (e_lower.contains("cap_net_admin")
                    || e_lower.contains("tunsetiff")
                    || e_lower.contains("privilege")
                    || e_lower.contains("root")
                    || e_lower.contains("operation not permitted")
                    || e_lower.contains("permission denied"))
                    && unsafe { libc::geteuid() != 0 }
                    && !storage::get_mode_preference().is_proxy()
                {
                    return reexec_sudo(&["up".into(), p.id.clone()]);
                }
                bail!("Daemon connection error: {e}");
            }
            _ => {}
        }
    }

    if unsafe { libc::geteuid() } != 0 && !storage::get_mode_preference().is_proxy() {
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

pub fn handle_down() -> Result<()> {
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

pub fn handle_toggle() -> Result<()> {
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

pub fn handle_pick(args: &[String]) -> Result<()> {
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

    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        if get_ipc().is_none() {
            send_notification(
                "Vortex",
                "start vortexd: systemctl --user enable --now vortexd",
                Some("dialog-error"),
            );
            bail!("start vortexd: systemctl --user enable --now vortexd");
        }
        bail!("no desktop menu launcher found and stdin is not a TTY");
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

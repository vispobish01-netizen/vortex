use anyhow::{bail, Result};
use vortex_core::{storage, store};

mod cli;
mod keymap;
mod ui;

use cli::*;

const HELP: &str = "\
vortex — elite cyber warfare VPN & proxy manager for Omarchy

  vortex                         open the cyber warfare TUI
  vortex mode [tunnel|proxy|toggle] inspect or set operational mode (VPN vs SOCKS5/HTTP)
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
  vortex check                   preflight audit of root, capabilities, and TUN device
  vortex setup                   grant network capabilities to Vortex sing-box binary
  vortex xray [cmd]              manage Xray-core backend (install|update|version|doctor|rollback|test)
  vortex completion <shell>      generate shell autocompletions (bash, zsh, fish)

protocols: VLESS · VMess · Trojan · Shadowsocks · Hysteria2 · REALITY · XHTTP (via Xray & sing-box)
           WireGuard · AmneziaWG · OpenVPN · Amnezia vpn:// links
";

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
        Some("doctor") => return handle_doctor(),
        Some("check") | Some("--check") => return handle_check(),
        Some("setup") => return handle_setup(&args),
        Some("proxy") => return handle_proxy(&args),
        Some("mode") => return handle_mode(&args),
        Some("speed") | Some("benchmark") => return handle_speed(),
        Some("flows") | Some("net") | Some("connections") => return handle_flows(),
        Some("status") => return handle_status(&args),
        Some("toggle") => return handle_toggle(),
        Some("down") | Some("disconnect") => return handle_down(),
        Some("pick") => return handle_pick(&args),
        Some("shield") | Some("killswitch") | Some("kill-switch") => return handle_shield(&args),
        Some("history") | Some("hist") => return handle_history(&args),
        Some("completion") => return handle_completion(&args),
        Some("list") | Some("ls") => return handle_list(),
        Some("ping") | Some("test") => return handle_ping(),
        Some("qr") => return handle_qr(&args),
        Some("conf") | Some("config") | Some("export") => return handle_conf(&args),
        Some("recon") | Some("inspect") => return handle_recon(&args),
        Some("leaks") | Some("leak") => return handle_leaks(),
        Some("route") | Some("routing") | Some("routes") => return handle_route(&args),
        Some("sub") | Some("subs") => return handle_sub(&args),
        Some("add") | Some("import") => return handle_add(&args),
        Some("rm") | Some("remove") => return handle_rm(&args),
        Some("rename") => return handle_rename(&args),
        Some("update") | Some("sync") => return handle_update(),
        Some("xray") => return handle_xray(&args),
        Some("best") => return handle_best(),
        Some("up") => {
            let p = find(&args[1..].join(" "))?;
            return connect_profile(&p);
        }
        Some("auth") => return handle_auth(&args),
        _ => {}
    }

    match args.first().map(String::as_str) {
        None => {
            if unsafe { libc::geteuid() } != 0
                && !storage::get_mode_preference().is_proxy()
                && cli::get_ipc().is_none()
            {
                let preflight = vortex_core::privilege::run_preflight_check();
                if !preflight.singbox_has_caps && !preflight.xray_has_caps {
                    return reexec_sudo(&args);
                }
            }
            store::ensure_dirs()?;
            ui::run()
        }
        Some(x) => bail!("unknown command '{x}' — try `vortex --help`"),
    }
}

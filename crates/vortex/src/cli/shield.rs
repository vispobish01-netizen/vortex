use anyhow::{bail, Result};
use vortex_core::ipc::{IpcRequest, IpcResponse};
use vortex_core::{shield, tunnel};

use super::connect::reexec_sudo;
use super::get_ipc;
use super::notify::send_notification;

pub fn handle_shield(args: &[String]) -> Result<()> {
    use std::io::IsTerminal;
    let sub = args.get(1).map(String::as_str).unwrap_or_else(|| {
        if !std::io::stdin().is_terminal() {
            "toggle"
        } else {
            "status"
        }
    });
    match sub {
        "toggle" => {
            if let Some(client) = get_ipc() {
                match client.request_sync(&IpcRequest::ToggleShield { enable: None })? {
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
            let is_armed = shield::is_armed();
            if is_armed {
                shield::set_enabled_preference(false);
                shield::disarm()?;
                println!("\x1b[1;33m○ Stealth Shield DISARMED // Firewall rules cleared\x1b[0m");
            } else {
                let sess = tunnel::load_session();
                let iface = sess.as_ref().map(|s| s.iface.as_str());
                let srv = sess.as_ref().map(|s| s.server.as_str());
                shield::set_enabled_preference(true);
                shield::arm(iface, srv)?;
                println!("\x1b[1;32m✔ Stealth Shield ARMED // Zero-leak killswitch engaged\x1b[0m");
            }
            Ok(())
        }
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
                match client.request_sync(&IpcRequest::ToggleShield {
                    enable: Some(false),
                })? {
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

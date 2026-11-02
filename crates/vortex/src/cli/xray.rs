use anyhow::{bail, Result};

pub fn handle_xray(args: &[String]) -> Result<()> {
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

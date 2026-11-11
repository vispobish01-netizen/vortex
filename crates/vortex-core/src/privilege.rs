use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

pub const MANAGED_SINGBOX_DIR: &str = ".local/share/vortex/bin";
pub const MANAGED_SINGBOX_BIN: &str = "sing-box";

/// Linux capability constants
#[allow(dead_code)]
const CAP_NET_BIND_SERVICE: u64 = 10;
const CAP_NET_ADMIN: u64 = 12;
#[allow(dead_code)]
const CAP_NET_RAW: u64 = 13;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrivilegeStrategy {
    /// Already running as effective UID 0 (root)
    DirectRoot,
    /// Binary has ambient/file capabilities (cap_net_admin, etc.)
    FileCapabilities,
    /// Cached or passwordless sudo available (sudo -n)
    SudoPasswordless,
    /// Sudo available but requires interactive password prompt
    SudoInteractive,
    /// Polkit pkexec available
    Pkexec,
    /// Unprivileged user-space mode (Proxy only on 127.0.0.1:1080, no TUN)
    UnprivilegedProxyOnly,
    /// No privilege escalation mechanism found
    Unavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightReport {
    pub is_root: bool,
    pub has_process_caps: bool,
    pub tun_device_exists: bool,
    pub tun_accessible: bool,
    pub singbox_found: bool,
    pub singbox_path: Option<PathBuf>,
    pub is_managed_binary: bool,
    pub singbox_has_caps: bool,
    pub singbox_missing_caps: Vec<String>,
    #[serde(default)]
    pub xray_found: bool,
    #[serde(default)]
    pub xray_path: Option<PathBuf>,
    #[serde(default)]
    pub xray_has_caps: bool,
    #[serde(default)]
    pub xray_missing_caps: Vec<String>,
    pub can_sudo_passwordless: bool,
    pub has_pkexec: bool,
    pub strategy: PrivilegeStrategy,
    pub ready_for_tun: bool,
    pub issues: Vec<String>,
    pub recommendation: Option<String>,
}

/// Returns the path to the Vortex-managed sing-box binary (~/.local/share/vortex/bin/sing-box).
pub fn managed_singbox_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    PathBuf::from(home)
        .join(MANAGED_SINGBOX_DIR)
        .join(MANAGED_SINGBOX_BIN)
}

/// Resolves the preferred sing-box binary:
/// 1. First, check if the managed binary (~/.local/share/vortex/bin/sing-box) exists and has capabilities.
/// 2. Second, check system sing-box in PATH.
/// 3. Third, fallback to managed binary if it exists.
pub fn resolve_singbox_binary() -> Option<PathBuf> {
    let managed = managed_singbox_path();
    if managed.exists() && check_file_caps(&managed).0 {
        return Some(managed);
    }

    if let Some(path) = crate::xray::install::which_in_path("sing-box") {
        return Some(path);
    }

    if managed.exists() {
        return Some(managed);
    }

    None
}

/// Checks effective process capabilities via /proc/self/status.
pub fn check_process_caps() -> bool {
    if unsafe { libc::geteuid() == 0 } {
        return true;
    }

    let status = match fs::read_to_string("/proc/self/status") {
        Ok(s) => s,
        Err(_) => return false,
    };

    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("CapEff:") {
            let hex = rest.trim();
            if let Ok(mask) = u64::from_str_radix(hex, 16) {
                let has_admin = (mask & (1 << CAP_NET_ADMIN)) != 0;
                return has_admin;
            }
        }
    }

    false
}

/// Checks whether a binary has the necessary file capabilities:
/// `cap_net_admin`, `cap_net_raw`, `cap_net_bind_service`.
/// Returns (has_all_required, missing_caps).
pub fn check_file_caps(binary: &Path) -> (bool, Vec<String>) {
    let mut missing = Vec::new();
    let canonical = binary
        .canonicalize()
        .unwrap_or_else(|_| binary.to_path_buf());
    if !canonical.exists() {
        return (false, vec!["file not found".into()]);
    }

    let out = match Command::new("getcap").arg(&canonical).output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_lowercase(),
        _ => return (false, vec!["unable to run getcap".into()]),
    };

    let has_admin = out.contains("cap_net_admin");
    let has_raw = out.contains("cap_net_raw");
    let has_bind = out.contains("cap_net_bind_service");

    if !has_admin {
        missing.push("cap_net_admin".into());
    }
    if !has_raw {
        missing.push("cap_net_raw".into());
    }
    if !has_bind {
        missing.push("cap_net_bind_service".into());
    }

    let ok = has_admin; // cap_net_admin is the strict essential for TUN
    (ok, missing)
}

/// Returns true if the process runs as root or `binary` holds `cap_net_raw`
/// (required for `SO_BINDTODEVICE` / Xray `sockopt.interface` loop protection).
pub fn check_file_cap_raw(binary: &Path) -> bool {
    if unsafe { libc::geteuid() == 0 } {
        return true;
    }
    let canonical = binary
        .canonicalize()
        .unwrap_or_else(|_| binary.to_path_buf());
    if !canonical.exists() {
        return false;
    }
    Command::new("getcap")
        .arg(&canonical)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .to_lowercase()
                .contains("cap_net_raw")
        })
        .unwrap_or(false)
}

/// Checks whether /dev/net/tun exists and is accessible.
pub fn check_tun_device() -> (bool, bool) {
    let path = Path::new("/dev/net/tun");
    let exists = path.exists();
    if !exists {
        return (false, false);
    }

    let accessible = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .is_ok();

    (exists, accessible)
}

/// Checks if passwordless sudo (`sudo -n true`) succeeds.
pub fn check_sudo_passwordless() -> bool {
    Command::new("sudo")
        .args(["-n", "true"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Checks if pkexec is available.
pub fn check_pkexec() -> bool {
    crate::xray::install::which_in_path("pkexec").is_some()
}

/// Runs a comprehensive preflight privilege audit for system-wide TUN tunneling.
pub fn run_preflight_check() -> PreflightReport {
    let is_root = unsafe { libc::geteuid() == 0 };
    let has_process_caps = check_process_caps();
    let (tun_device_exists, tun_accessible) = check_tun_device();

    let singbox_path = resolve_singbox_binary();
    let singbox_found = singbox_path.is_some();
    let managed_path = managed_singbox_path();
    let is_managed = singbox_path.as_deref() == Some(&managed_path);

    let (singbox_has_caps, singbox_missing_caps) = if let Some(ref p) = singbox_path {
        check_file_caps(p)
    } else {
        (false, vec!["sing-box not found".into()])
    };

    let xray_path = crate::xray::install::resolve_xray_binary().ok();
    let xray_found = xray_path.is_some();
    let (xray_has_caps, xray_missing_caps) = if let Some(ref p) = xray_path {
        check_file_caps(p)
    } else {
        (false, vec!["xray not found".into()])
    };

    let can_sudo_passwordless = check_sudo_passwordless();
    let has_pkexec = check_pkexec();

    let mut issues = Vec::new();

    if !singbox_found && !xray_found {
        issues.push("neither sing-box nor Xray-core binary is installed".into());
    }

    if !tun_device_exists {
        issues.push("/dev/net/tun device node does not exist (module 'tun' not loaded)".into());
    } else if !tun_accessible && !is_root {
        issues.push("/dev/net/tun cannot be opened with read/write permissions".into());
    }

    // Determine privilege strategy
    let strategy = if is_root {
        PrivilegeStrategy::DirectRoot
    } else if singbox_has_caps || xray_has_caps {
        PrivilegeStrategy::FileCapabilities
    } else if can_sudo_passwordless {
        PrivilegeStrategy::SudoPasswordless
    } else if has_pkexec
        && (std::env::var("DISPLAY").is_ok() || std::env::var("WAYLAND_DISPLAY").is_ok())
    {
        PrivilegeStrategy::Pkexec
    } else if crate::xray::install::which_in_path("sudo").is_some() {
        PrivilegeStrategy::SudoInteractive
    } else {
        PrivilegeStrategy::Unavailable
    };

    let ready_for_tun = is_root
        || singbox_has_caps
        || xray_has_caps
        || can_sudo_passwordless
        || strategy == PrivilegeStrategy::SudoInteractive
        || strategy == PrivilegeStrategy::Pkexec;

    let recommendation = if !tun_device_exists {
        Some("Run `sudo modprobe tun` to load the Linux virtual network TUN driver.".into())
    } else if !singbox_found && !xray_found {
        Some("Install sing-box (`sudo pacman -S sing-box`) or Xray (`vortex xray install`).".into())
    } else if is_root || singbox_has_caps || xray_has_caps || can_sudo_passwordless {
        None
    } else {
        Some("Run `vortex setup` to grant network capabilities to sing-box / Xray binaries for passwordless tunneling, or authenticate via sudo.".into())
    };

    PreflightReport {
        is_root,
        has_process_caps,
        tun_device_exists,
        tun_accessible,
        singbox_found,
        singbox_path,
        is_managed_binary: is_managed,
        singbox_has_caps,
        singbox_missing_caps,
        xray_found,
        xray_path,
        xray_has_caps,
        xray_missing_caps,
        can_sudo_passwordless,
        has_pkexec,
        strategy,
        ready_for_tun: ready_for_tun && tun_device_exists,
        issues,
        recommendation,
    }
}

/// Applies required network capabilities to a binary via direct root, sudo, or pkexec.
pub fn apply_caps_to_binary(binary: &Path) -> Result<()> {
    let canonical = binary
        .canonicalize()
        .unwrap_or_else(|_| binary.to_path_buf());
    let cap_spec = "cap_net_admin,cap_net_bind_service,cap_net_raw+ep";
    let target_str = canonical.to_string_lossy().to_string();

    let status = if unsafe { libc::geteuid() == 0 } {
        Command::new("setcap")
            .args([cap_spec, &target_str])
            .status()?
    } else if check_sudo_passwordless() {
        Command::new("sudo")
            .args(["-n", "setcap", cap_spec, &target_str])
            .status()?
    } else if crate::xray::install::which_in_path("sudo").is_some() {
        println!(
            "Prompting for sudo to assign capabilities to {:?}...",
            canonical
        );
        Command::new("sudo")
            .args(["setcap", cap_spec, &target_str])
            .status()?
    } else if check_pkexec() {
        Command::new("pkexec")
            .args(["setcap", cap_spec, &target_str])
            .status()?
    } else {
        bail!("Neither sudo nor pkexec found to run setcap");
    };

    if !status.success() {
        bail!(
            "setcap command failed to set capabilities on {:?}",
            canonical
        );
    }

    let (ok, missing) = check_file_caps(&canonical);
    if !ok {
        bail!(
            "Verification failed: missing capabilities on {:?}: {:?}",
            canonical,
            missing
        );
    }

    Ok(())
}

/// Sets up dedicated copies of the sing-box and/or Xray binaries owned by Vortex and sets capabilities on them.
/// `setcap cap_net_admin,cap_net_bind_service,cap_net_raw+ep ...`
pub fn setup_managed_caps() -> Result<Vec<PathBuf>> {
    let mut configured = Vec::new();

    // 1. sing-box setup
    if let Some(system_bin) = crate::xray::install::which_in_path("sing-box") {
        let target_path = managed_singbox_path();
        if let Some(parent) = target_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if fs::copy(&system_bin, &target_path).is_ok() {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&target_path, fs::Permissions::from_mode(0o755));
            if apply_caps_to_binary(&target_path).is_ok() {
                configured.push(target_path);
            }
        }
    } else if managed_singbox_path().exists() {
        let target_path = managed_singbox_path();
        if apply_caps_to_binary(&target_path).is_ok() {
            configured.push(target_path);
        }
    }

    // 2. Xray setup
    if let Ok(xray_path) = crate::xray::install::resolve_xray_binary() {
        let canonical_xray = xray_path.canonicalize().unwrap_or(xray_path);
        if apply_caps_to_binary(&canonical_xray).is_ok() {
            configured.push(canonical_xray);
        }
    }

    if configured.is_empty() {
        bail!("Could not configure capabilities: neither sing-box nor Xray binaries found. Install sing-box or run `vortex xray install`.");
    }

    Ok(configured)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_managed_singbox_path_structure() {
        let path = managed_singbox_path();
        assert!(path
            .to_string_lossy()
            .contains(".local/share/vortex/bin/sing-box"));
    }

    #[test]
    fn test_preflight_check_runs_without_panic() {
        let rep = run_preflight_check();
        assert!(rep.strategy != PrivilegeStrategy::Unavailable || !rep.ready_for_tun);
    }
}

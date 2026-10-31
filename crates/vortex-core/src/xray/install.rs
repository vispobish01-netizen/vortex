use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256, Sha512};
use std::cmp::Ordering;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{info, warn};

pub const PINNED_XRAY_VERSION: &str = "v26.9.30";
pub const XRAY_RELEASES_API: &str = "https://api.github.com/repos/XTLS/Xray-core/releases";
pub const GEOIP_URL: &str = "https://github.com/v2fly/geoip/releases/latest/download/geoip.dat";
pub const GEOSITE_URL: &str =
    "https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat";

/// Parsed semantic version representation for comparison
#[derive(Debug, Clone)]
pub struct SemVer {
    pub raw: String,
    pub numbers: Vec<u64>,
    pub is_pre: bool,
}

impl PartialEq for SemVer {
    fn eq(&self, other: &Self) -> bool {
        self.numbers == other.numbers && self.is_pre == other.is_pre
    }
}

impl Eq for SemVer {}

impl SemVer {
    pub fn parse(tag: &str) -> Option<Self> {
        let clean = tag.trim().strip_prefix('v').unwrap_or(tag.trim());
        let (num_part, pre_part) = clean.split_once('-').unwrap_or((clean, ""));
        let numbers: Result<Vec<u64>, _> = num_part.split('.').map(|s| s.parse::<u64>()).collect();
        let nums = numbers.ok()?;
        if nums.is_empty() {
            return None;
        }
        Some(Self {
            raw: tag.to_string(),
            numbers: nums,
            is_pre: !pre_part.is_empty(),
        })
    }
}

impl PartialOrd for SemVer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SemVer {
    fn cmp(&self, other: &Self) -> Ordering {
        let max_len = self.numbers.len().max(other.numbers.len());
        for i in 0..max_len {
            let a = self.numbers.get(i).copied().unwrap_or(0);
            let b = other.numbers.get(i).copied().unwrap_or(0);
            match a.cmp(&b) {
                Ordering::Equal => continue,
                non_eq => return non_eq,
            }
        }
        // If numbers are equal, non-prerelease is greater than prerelease
        match (self.is_pre, other.is_pre) {
            (false, true) => Ordering::Greater,
            (true, false) => Ordering::Less,
            _ => Ordering::Equal,
        }
    }
}

/// Information about an Xray release asset
#[derive(Debug, Clone)]
pub struct XrayReleaseInfo {
    pub tag: String,
    pub semver: SemVer,
    pub zip_name: String,
    pub zip_url: String,
    pub dgst_url: String,
}

/// Target architecture asset names
pub fn target_asset_names() -> (&'static str, &'static str) {
    let arch = std::env::consts::ARCH;
    match arch {
        "aarch64" => ("Xray-linux-arm64-v8a.zip", "Xray-linux-arm64-v8a.zip.dgst"),
        _ => ("Xray-linux-64.zip", "Xray-linux-64.zip.dgst"),
    }
}

/// Root data directory for managed Xray installations (~/.local/share/vortex/xray)
pub fn xray_data_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("VORTEX_DATA_DIR") {
        if !dir.is_empty() {
            let p = PathBuf::from(dir).join("xray");
            if p.exists() {
                return p;
            }
        }
    }
    if unsafe { libc::geteuid() == 0 } {
        let sys_path = PathBuf::from("/var/lib/vortex/cores/xray");
        if sys_path.exists() {
            return sys_path;
        }
        if let Ok(sudo_user) = std::env::var("SUDO_USER") {
            if !sudo_user.is_empty() {
                let candidate =
                    PathBuf::from(format!("/home/{sudo_user}/.local/share/vortex/xray"));
                if candidate.exists() {
                    return candidate;
                }
            }
        }
    }
    if let Ok(data_home) = std::env::var("XDG_DATA_HOME") {
        if !data_home.is_empty() {
            let p = PathBuf::from(data_home).join("vortex").join("xray");
            if p.exists() {
                return p;
            }
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    let default_path = PathBuf::from(home).join(".local/share/vortex/xray");
    if default_path.exists() {
        return default_path;
    }
    if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        if !sudo_user.is_empty() {
            let candidate = PathBuf::from(format!("/home/{sudo_user}/.local/share/vortex/xray"));
            if candidate.exists() {
                return candidate;
            }
        }
    }
    default_path
}

/// Symlink path to active managed Xray
pub fn current_symlink_path() -> PathBuf {
    xray_data_dir().join("current")
}

/// Path to the managed xray binary (~/.local/share/vortex/xray/current/xray)
pub fn managed_xray_binary() -> PathBuf {
    current_symlink_path().join("xray")
}

/// Resolves directory containing geoip.dat and geosite.dat databases
pub fn geo_assets_dir() -> Option<PathBuf> {
    let search_dirs = [
        current_symlink_path(),
        xray_data_dir(),
        PathBuf::from("/var/lib/vortex/cores/xray"),
        PathBuf::from("/usr/share/xray"),
        PathBuf::from("/usr/local/share/xray"),
        PathBuf::from("/var/lib/xray"),
        PathBuf::from("/usr/share/v2ray"),
    ];
    search_dirs
        .into_iter()
        .find(|d| d.join("geoip.dat").exists())
}

/// Queries all releases from XTLS/Xray-core and determines the highest version release
pub fn fetch_latest_release_info(api_url: Option<&str>) -> Result<XrayReleaseInfo> {
    let url = api_url.unwrap_or(XRAY_RELEASES_API);
    let output = Command::new("curl")
        .args([
            "-sL",
            "--max-time",
            "15",
            "-H",
            "User-Agent: vortex-proxy-manager",
            "-H",
            "Accept: application/vnd.github.v3+json",
            url,
        ])
        .output()
        .context("Failed to query GitHub API via curl")?;

    if !output.status.success() {
        bail!(
            "Failed to fetch Xray releases: HTTP error (curl exit code {})",
            output.status
        );
    }

    let releases: serde_json::Value = serde_json::from_slice(&output.stdout)
        .context("Failed to parse GitHub releases response as JSON")?;

    let array = releases
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("GitHub API did not return an array of releases"))?;

    let (target_zip, target_dgst) = target_asset_names();

    let mut parsed_releases = Vec::new();
    for rel in array {
        let tag = match rel["tag_name"].as_str() {
            Some(t) => t,
            None => continue,
        };
        let semver = match SemVer::parse(tag) {
            Some(v) => v,
            None => continue,
        };
        let assets = match rel["assets"].as_array() {
            Some(a) => a,
            None => continue,
        };

        let mut zip_url = None;
        let mut dgst_url = None;

        for asset in assets {
            let name = asset["name"].as_str().unwrap_or("");
            let download_url = asset["browser_download_url"].as_str().unwrap_or("");
            if name == target_zip {
                zip_url = Some(download_url.to_string());
            } else if name == target_dgst {
                dgst_url = Some(download_url.to_string());
            }
        }

        if let (Some(zu), Some(du)) = (zip_url, dgst_url) {
            parsed_releases.push(XrayReleaseInfo {
                tag: tag.to_string(),
                semver,
                zip_name: target_zip.to_string(),
                zip_url: zu,
                dgst_url: du,
            });
        }
    }

    if parsed_releases.is_empty() {
        bail!("No matching Xray-core releases found with required assets");
    }

    // Sort by semver descending
    parsed_releases.sort_by(|a, b| b.semver.cmp(&a.semver));

    Ok(parsed_releases.remove(0))
}

/// Parses expected checksums from a .dgst file content
pub fn parse_dgst(content: &str) -> (Option<String>, Option<String>) {
    let mut sha256 = None;
    let mut sha512 = None;

    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("SHA2-256=") {
            sha256 = Some(rest.trim().to_ascii_lowercase());
        } else if let Some(rest) = trimmed.strip_prefix("SHA256=") {
            sha256 = Some(rest.trim().to_ascii_lowercase());
        } else if let Some(rest) = trimmed.strip_prefix("SHA2-512=") {
            sha512 = Some(rest.trim().to_ascii_lowercase());
        } else if let Some(rest) = trimmed.strip_prefix("SHA512=") {
            sha512 = Some(rest.trim().to_ascii_lowercase());
        }
    }

    (sha256, sha512)
}

/// Verifies bytes against SHA256 and/or SHA512 digests from the dgst file
pub fn verify_checksum(bytes: &[u8], dgst_content: &str) -> Result<()> {
    let (exp_sha256, exp_sha512) = parse_dgst(dgst_content);

    if exp_sha256.is_none() && exp_sha512.is_none() {
        bail!("No SHA256 or SHA512 hash found in .dgst checksum file");
    }

    if let Some(expected_256) = exp_sha256 {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let actual_256 = format!("{:x}", hasher.finalize());
        if actual_256.to_ascii_lowercase() != expected_256 {
            bail!("SHA256 checksum mismatch! Expected {expected_256}, got {actual_256}");
        }
        info!("SHA256 checksum verified successfully: {actual_256}");
    }

    if let Some(expected_512) = exp_sha512 {
        let mut hasher = Sha512::new();
        hasher.update(bytes);
        let actual_512 = format!("{:x}", hasher.finalize());
        if actual_512.to_ascii_lowercase() != expected_512 {
            bail!("SHA512 checksum mismatch! Expected {expected_512}, got {actual_512}");
        }
        info!("SHA512 checksum verified successfully");
    }

    Ok(())
}

/// Downloads and installs Xray-core to ~/.local/share/vortex/xray/<version>/ with atomic symlink update
pub fn install_xray(target_release: Option<XrayReleaseInfo>) -> Result<String> {
    // If running as root (e.g. systemd or daemon setup), installs into /var/lib/vortex/cores/xray
    let rel = match target_release {
        Some(r) => r,
        None => fetch_latest_release_info(None)?,
    };

    let base_dir = xray_data_dir();
    fs::create_dir_all(&base_dir).context("Failed to create Xray data directory")?;

    let version_dir = base_dir.join(&rel.tag);
    if version_dir.exists() {
        info!("Version {} already installed at {:?}", rel.tag, version_dir);
        switch_current_symlink(&rel.tag)?;
        return Ok(rel.tag);
    }

    info!("Downloading Xray-core {} from {}", rel.tag, rel.zip_url);

    // Download zip payload into memory / temp file
    let zip_output = Command::new("curl")
        .args(["-sL", "--max-time", "60", &rel.zip_url])
        .output()
        .context("Failed to download Xray zip asset via curl")?;

    if !zip_output.status.success() {
        bail!(
            "Failed to download Xray-core zip: curl exited with status {}",
            zip_output.status
        );
    }
    let zip_bytes = zip_output.stdout;

    // Download .dgst file
    let dgst_output = Command::new("curl")
        .args(["-sL", "--max-time", "30", &rel.dgst_url])
        .output()
        .context("Failed to download Xray .dgst asset via curl")?;

    if !dgst_output.status.success() {
        bail!(
            "Failed to download Xray-core .dgst: curl exited with status {}",
            dgst_output.status
        );
    }
    let dgst_content = String::from_utf8_lossy(&dgst_output.stdout);

    // Checksum verification
    verify_checksum(&zip_bytes, &dgst_content)
        .context("Aborting installation due to checksum verification failure")?;

    // Create temporary extract dir
    let tmp_extract_dir = base_dir.join(format!(".tmp_extract_{}_{}", rel.tag, std::process::id()));
    if tmp_extract_dir.exists() {
        let _ = fs::remove_dir_all(&tmp_extract_dir);
    }
    fs::create_dir_all(&tmp_extract_dir)?;

    let tmp_zip_path = tmp_extract_dir.join("xray.zip");
    fs::write(&tmp_zip_path, &zip_bytes)?;

    // Unpack using unzip
    let unzip_status = Command::new("unzip")
        .args([
            "-q",
            "-o",
            tmp_zip_path.to_str().unwrap(),
            "-d",
            tmp_extract_dir.to_str().unwrap(),
        ])
        .status()
        .context("Failed to execute `unzip`")?;

    let _ = fs::remove_file(&tmp_zip_path);

    if !unzip_status.success() {
        let _ = fs::remove_dir_all(&tmp_extract_dir);
        bail!("`unzip` failed to unpack Xray archive (status: {unzip_status})");
    }

    // Ensure xray binary is marked executable
    let xray_bin = tmp_extract_dir.join("xray");
    if !xray_bin.exists() {
        let _ = fs::remove_dir_all(&tmp_extract_dir);
        bail!("Extracted archive does not contain 'xray' binary");
    }
    let mut perms = fs::metadata(&xray_bin)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&xray_bin, perms)?;

    // Rename temp extract to permanent version directory
    fs::rename(&tmp_extract_dir, &version_dir)
        .context("Failed to move extracted Xray to target version directory")?;

    // Atomic symlink switch
    switch_current_symlink(&rel.tag)?;

    info!(
        "Successfully installed Xray-core {} to {:?}",
        rel.tag, version_dir
    );
    Ok(rel.tag)
}

/// Atomically points the `current` symlink to the specified version folder
pub fn switch_current_symlink(version_tag: &str) -> Result<()> {
    let base_dir = xray_data_dir();
    let target_dir = base_dir.join(version_tag);
    if !target_dir.exists() {
        bail!(
            "Cannot switch symlink: version directory {:?} does not exist",
            target_dir
        );
    }

    let current_link = current_symlink_path();
    let tmp_link = base_dir.join(format!(".current_tmp_{}", std::process::id()));

    let _ = fs::remove_file(&tmp_link);
    std::os::unix::fs::symlink(&target_dir, &tmp_link)
        .context("Failed to create temporary symlink for atomic swap")?;

    fs::rename(&tmp_link, &current_link)
        .context("Failed to atomically update 'current' symlink")?;

    Ok(())
}

/// Refreshes geoip.dat and geosite.dat databases
pub fn refresh_geo_databases() -> Result<()> {
    if unsafe { libc::geteuid() } == 0 {
        bail!("Never run vortex xray update as root!");
    }

    let target_dir = if current_symlink_path().exists() {
        current_symlink_path()
    } else {
        xray_data_dir()
    };

    if !target_dir.exists() {
        fs::create_dir_all(&target_dir)?;
    }

    info!("Refreshing geoip.dat and geosite.dat in {:?}", target_dir);

    // Fetch geoip.dat
    let geoip_dest = target_dir.join("geoip.dat");
    let out = Command::new("curl")
        .args([
            "-sL",
            "--max-time",
            "30",
            "-o",
            geoip_dest.to_str().unwrap(),
            GEOIP_URL,
        ])
        .status()?;
    if !out.success() {
        warn!("Failed to refresh geoip.dat");
    }

    // Fetch geosite.dat
    let geosite_dest = target_dir.join("geosite.dat");
    let out = Command::new("curl")
        .args([
            "-sL",
            "--max-time",
            "30",
            "-o",
            geosite_dest.to_str().unwrap(),
            GEOSITE_URL,
        ])
        .status()?;
    if !out.success() {
        warn!("Failed to refresh geosite.dat");
    }

    Ok(())
}

/// Rolls back to the previously installed version
pub fn rollback_xray() -> Result<String> {
    let base_dir = xray_data_dir();
    if !base_dir.exists() {
        bail!("No Xray installations found in {:?}", base_dir);
    }

    let mut versions = Vec::new();
    for entry in fs::read_dir(&base_dir)?.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name == "current" || name.starts_with('.') {
            continue;
        }
        if entry.path().is_dir() {
            if let Some(v) = SemVer::parse(&name) {
                versions.push(v);
            }
        }
    }

    if versions.len() < 2 {
        bail!(
            "Cannot rollback: fewer than two versions are installed in {:?}",
            base_dir
        );
    }

    versions.sort_by(|a, b| b.cmp(a));

    let current_version = resolve_installed_version().unwrap_or_default();
    let previous = versions
        .iter()
        .find(|v| v.raw != current_version)
        .ok_or_else(|| anyhow::anyhow!("No older version found to roll back to"))?;

    switch_current_symlink(&previous.raw)?;
    info!("Rolled back active Xray version to {}", previous.raw);
    Ok(previous.raw.clone())
}

/// Resolves version from an xray binary by running `xray version`
pub fn get_binary_version(bin_path: &Path) -> Option<String> {
    let out = Command::new(bin_path).args(["version"]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Usually formatted: "Xray 26.9.30 (Xray, Penetrates Everything.) ..."
    for line in stdout.lines() {
        if line.starts_with("Xray ") {
            let part = line.split_whitespace().nth(1)?;
            return Some(format!("v{}", part.trim_start_matches('v')));
        }
    }
    None
}

/// Resolves active installed version tag from the current symlink
pub fn resolve_installed_version() -> Option<String> {
    let link = current_symlink_path();
    if let Ok(target) = fs::read_link(&link) {
        if let Some(name) = target.file_name() {
            return Some(name.to_string_lossy().to_string());
        }
    }
    let bin = managed_xray_binary();
    if bin.exists() {
        return get_binary_version(&bin);
    }
    None
}

/// Helper to search for a binary on PATH and standard locations without shelling out to `which`
pub fn which_in_path(bin: &str) -> Option<PathBuf> {
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            let candidate = dir.join(bin);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    for standard in ["/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"] {
        let candidate = Path::new(standard).join(bin);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Resolves which Xray binary to use:
/// 1. Prefer system binary on PATH if installed and version is >= managed version
/// 2. Otherwise use managed binary (~/.local/share/vortex/xray/current/xray)
pub fn resolve_xray_binary() -> Result<PathBuf> {
    let managed = managed_xray_binary();
    let managed_exists = managed.exists();

    let sys_path = which_in_path("xray");

    match (sys_path, managed_exists) {
        (Some(sys), true) => {
            let sys_ver = get_binary_version(&sys).and_then(|v| SemVer::parse(&v));
            let man_ver = resolve_installed_version().and_then(|v| SemVer::parse(&v));
            match (sys_ver, man_ver) {
                (Some(sv), Some(mv)) if sv >= mv => Ok(sys),
                (Some(_), Some(_)) => Ok(managed),
                (Some(_), None) => Ok(sys),
                (None, Some(_)) => Ok(managed),
                (None, None) => Ok(managed),
            }
        }
        (Some(sys), false) => Ok(sys),
        (None, true) => Ok(managed),
        (None, false) => {
            if let Ok(sudo_user) = std::env::var("SUDO_USER") {
                if !sudo_user.is_empty() {
                    let fallback = PathBuf::from(format!(
                        "/home/{sudo_user}/.local/share/vortex/xray/current/xray"
                    ));
                    if fallback.exists() {
                        return Ok(fallback);
                    }
                }
            }
            bail!("Xray-core binary not found. Run `vortex xray install` to install it.")
        }
    }
}

/// Returns the version string of the active Xray binary (checking both binary and managed symlink)
pub fn active_xray_version() -> Option<String> {
    if let Ok(bin) = resolve_xray_binary() {
        if let Some(ver) = get_binary_version(&bin) {
            return Some(ver);
        }
    }
    resolve_installed_version()
}

/// Health report returned by `vortex xray doctor`
#[derive(Debug, Clone)]
pub struct DoctorReport {
    pub binary_path: Option<PathBuf>,
    pub binary_version: Option<String>,
    pub is_system_binary: bool,
    pub binary_executable: bool,
    pub geoip_found: bool,
    pub geosite_found: bool,
    pub tun_device_available: bool,
    pub nftables_available: bool,
    pub issues: Vec<String>,
}

impl DoctorReport {
    pub fn is_healthy(&self) -> bool {
        self.issues.is_empty()
    }
}

/// Diagnostic health check for the Xray subsystem
pub fn run_xray_doctor() -> DoctorReport {
    let mut issues = Vec::new();
    let mut bin_path = None;
    let mut bin_ver = None;
    let mut is_system = false;
    let mut is_exec = false;

    match resolve_xray_binary() {
        Ok(path) => {
            bin_ver = get_binary_version(&path);
            is_system = !path.starts_with(xray_data_dir());
            is_exec = fs::metadata(&path)
                .map(|m| m.permissions().mode() & 0o111 != 0)
                .unwrap_or(false);
            if !is_exec {
                issues.push(format!("Binary {:?} is not executable", path));
            }
            bin_path = Some(path);
        }
        Err(e) => {
            issues.push(format!("Xray binary missing: {e}"));
        }
    }

    // Check geo databases
    let search_dirs = [
        current_symlink_path(),
        xray_data_dir(),
        PathBuf::from("/var/lib/vortex/cores/xray"),
        PathBuf::from("/usr/share/xray"),
        PathBuf::from("/usr/local/share/xray"),
        PathBuf::from("/var/lib/xray"),
        PathBuf::from("/usr/share/v2ray"),
    ];

    let geoip_found = search_dirs.iter().any(|d| d.join("geoip.dat").exists());
    let geosite_found = search_dirs.iter().any(|d| d.join("geosite.dat").exists());

    if !geoip_found {
        issues.push("geoip.dat not found (run `vortex xray update` to fetch)".into());
    }
    if !geosite_found {
        issues.push("geosite.dat not found (run `vortex xray update` to fetch)".into());
    }

    // Check TUN device
    let tun_device_available = Path::new("/dev/net/tun").exists();
    if !tun_device_available {
        issues.push("Linux TUN device /dev/net/tun is not present".into());
    }

    // Check nftables
    let nftables_available = crate::shield::is_nftables_active()
        || Command::new("nft").arg("--version").output().is_ok();
    if !nftables_available {
        issues.push("nftables binary (`nft`) not found in PATH".into());
    }

    DoctorReport {
        binary_path: bin_path,
        binary_version: bin_ver,
        is_system_binary: is_system,
        binary_executable: is_exec,
        geoip_found,
        geosite_found,
        tun_device_available,
        nftables_available,
        issues,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_semver_parsing_and_ordering() {
        let v1 = SemVer::parse("v26.7.28").unwrap();
        let v2 = SemVer::parse("v26.9.30").unwrap();
        let v3 = SemVer::parse("26.9.30").unwrap();
        let v4 = SemVer::parse("v27.0.0-beta1").unwrap();

        assert_eq!(v2.numbers, vec![26, 9, 30]);
        assert_eq!(v3.numbers, vec![26, 9, 30]);
        assert!(v2 > v1);
        assert_eq!(v2, v3);
        assert!(v4 > v2);
    }

    #[test]
    fn test_dgst_parsing() {
        let sample = "\
MD5= 32de8b213cf5e6a80b3b09e8da26005b
SHA1= 16b59f3317bc4d7757c4d50fd390b7d1b396ab0c
SHA2-256= f851110beaff16e78d643f0ccfd9524b4a44dfd59bae3e34bb52bba378f7690e
SHA2-512= 459cbb3644eb706488a6244f7c228c625868e01c2fef9d37a0ab49bc6112b6c4e582377a00a4c23f384314a8f2d2d717180d1ec71a18dac55bb46a83bfc2a9da
";
        let (sha256, sha512) = parse_dgst(sample);
        assert_eq!(
            sha256.as_deref(),
            Some("f851110beaff16e78d643f0ccfd9524b4a44dfd59bae3e34bb52bba378f7690e")
        );
        assert_eq!(
            sha512.as_deref(),
            Some("459cbb3644eb706488a6244f7c228c625868e01c2fef9d37a0ab49bc6112b6c4e582377a00a4c23f384314a8f2d2d717180d1ec71a18dac55bb46a83bfc2a9da")
        );
    }

    #[test]
    fn test_verify_checksum_success_and_failure() {
        let payload = b"hello vortex xray test payload";
        let mut hasher = Sha256::new();
        hasher.update(payload);
        let actual_hash = format!("{:x}", hasher.finalize());

        let good_dgst = format!("SHA2-256= {actual_hash}\n");
        assert!(verify_checksum(payload, &good_dgst).is_ok());

        let bad_dgst =
            "SHA2-256= 0000000000000000000000000000000000000000000000000000000000000000\n";
        assert!(verify_checksum(payload, bad_dgst).is_err());
    }
}

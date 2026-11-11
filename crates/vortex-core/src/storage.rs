use crate::crypto::{decrypt_secret, encrypt_secret, get_or_create_master_key, user_config_dir};
use crate::error::VortexError;
use crate::model::{Auth, Kind, OperationalMode, Profile, Subscription};
use crate::parser::parse_any;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn config_dir() -> PathBuf {
    user_config_dir()
}

pub fn profiles_dir() -> PathBuf {
    config_dir().join("profiles")
}

pub fn subs_file() -> PathBuf {
    config_dir().join("subscriptions.json")
}

pub fn last_file() -> PathBuf {
    config_dir().join("last")
}

pub fn mode_file() -> PathBuf {
    config_dir().join("mode")
}

pub fn get_mode_preference() -> OperationalMode {
    if let Ok(m) = std::env::var("VORTEX_MODE") {
        let m = m.trim().to_ascii_lowercase();
        if m == "proxy" || m == "socks" || m == "http" {
            return OperationalMode::Proxy;
        }
        if m == "tunnel" || m == "tun" || m == "vpn" {
            return OperationalMode::Tunnel;
        }
    }
    let user_path = mode_file();
    if let Ok(content) = fs::read_to_string(&user_path) {
        let m = content.trim().to_ascii_lowercase();
        if m == "proxy" || m == "socks" || m == "http" {
            return OperationalMode::Proxy;
        }
        if m == "tunnel" || m == "tun" || m == "vpn" {
            return OperationalMode::Tunnel;
        }
    }
    let sys_path = Path::new("/etc/vortex/mode");
    if let Ok(content) = fs::read_to_string(sys_path) {
        let m = content.trim().to_ascii_lowercase();
        if m == "proxy" || m == "socks" || m == "http" {
            return OperationalMode::Proxy;
        }
    }
    OperationalMode::Tunnel
}

pub fn set_mode_preference(mode: OperationalMode) -> Result<(), VortexError> {
    let _ = ensure_dirs();
    let path = mode_file();
    atomic_write(&path, mode.as_str().as_bytes())?;
    if unsafe { libc::geteuid() == 0 } {
        let _ = fs::write("/etc/vortex/mode", mode.as_str());
    }
    Ok(())
}

pub fn ensure_dirs() -> Result<(), VortexError> {
    let cfg = config_dir();
    fs::create_dir_all(&cfg)?;
    let _ = fs::set_permissions(&cfg, fs::Permissions::from_mode(0o700));

    let prof = profiles_dir();
    fs::create_dir_all(&prof)?;
    let _ = fs::set_permissions(&prof, fs::Permissions::from_mode(0o700));

    Ok(())
}

/// Performs an atomic file write with strict 0600 permissions.
pub fn atomic_write(path: &Path, content: &[u8]) -> Result<(), VortexError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
    }

    let nonce = now_secs() ^ (std::process::id() as u64);
    let tmp_path = path.with_extension(format!("tmp.{nonce}"));

    fs::write(&tmp_path, content)?;
    fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))?;
    fs::rename(&tmp_path, path)?;
    Ok(())
}

/// Stored representation of a Profile on disk (sensitive data encrypted).
#[derive(Serialize, Deserialize, Clone, Debug)]
struct StoredProfile {
    pub id: String,
    pub name: String,
    pub kind: Kind,
    pub server: String,
    pub encrypted_data: Option<String>,
    pub plaintext_data: Option<String>,
    pub auth: Option<Auth>,
    pub sub_id: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub group: Option<String>,
    pub created_at: Option<u64>,
    pub updated_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_type: Option<String>,
    #[serde(default)]
    pub engine: crate::model::CoreEngine,
    #[serde(default)]
    pub payload_kind: crate::model::ProfilePayloadKind,
}

pub fn save_profile(p: &Profile) -> Result<(), VortexError> {
    ensure_dirs()?;
    let key = get_or_create_master_key()?;

    // Encrypt sensitive config data
    let enc_bytes = encrypt_secret(&p.data, &key)?;
    let enc_b64 = base64::engine::general_purpose::STANDARD.encode(enc_bytes);

    let stored = StoredProfile {
        id: p.id.clone(),
        name: p.name.clone(),
        kind: p.kind,
        server: p.server.clone(),
        encrypted_data: Some(enc_b64),
        plaintext_data: None, // sensitive data kept encrypted at rest
        auth: p.auth.clone(),
        sub_id: p.sub_id.clone(),
        tags: p.tags.clone(),
        group: p.group.clone(),
        created_at: p.created_at.or(Some(now_secs())),
        updated_at: Some(now_secs()),
        backend_type: p.backend_type.clone(),
        engine: p.engine,
        payload_kind: p.payload_kind,
    };

    let json = serde_json::to_string_pretty(&stored)?;
    let path = profiles_dir().join(format!("{}.json", p.id));
    atomic_write(&path, json.as_bytes())?;
    Ok(())
}

pub fn load_profile_from_path(path: &Path) -> Result<Profile, VortexError> {
    let content = fs::read_to_string(path)?;

    // 1. Prefer encrypted StoredProfile format
    if let Ok(stored) = serde_json::from_str::<StoredProfile>(&content) {
        let data_opt = if let Some(enc_b64) = stored.encrypted_data {
            let key = get_or_create_master_key()?;
            let enc_bytes = base64::engine::general_purpose::STANDARD
                .decode(enc_b64)
                .map_err(|e| {
                    VortexError::Crypto(format!("Invalid base64 in encrypted data: {e}"))
                })?;
            Some(decrypt_secret(&enc_bytes, &key)?)
        } else {
            stored.plaintext_data
        };

        if let Some(data) = data_opt {
            let mut p = Profile {
                id: stored.id,
                name: stored.name,
                kind: stored.kind,
                server: stored.server,
                data,
                auth: stored.auth,
                sub_id: stored.sub_id,
                tags: stored.tags,
                group: stored.group,
                created_at: stored.created_at,
                updated_at: stored.updated_at,
                backend_type: stored.backend_type,
                engine: stored.engine,
                payload_kind: stored.payload_kind,
                ..Default::default()
            };
            p.populate_metadata();
            return Ok(p);
        }
    }

    // 2. Fallback: legacy plaintext Profile JSON (e.g. older /etc/vortex/profiles/*.json)
    let mut legacy: Profile = serde_json::from_str(&content)?;
    legacy.populate_metadata();
    Ok(legacy)
}

pub fn load_all() -> Vec<Profile> {
    let _ = ensure_dirs();
    let mut profiles = vec![];
    let mut seen_ids = HashSet::new();

    let user_dir = profiles_dir();
    if let Ok(entries) = fs::read_dir(&user_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|x| x.to_str()) == Some("json") {
                if let Ok(p) = load_profile_from_path(&path) {
                    if seen_ids.insert(p.id.clone()) {
                        profiles.push(p);
                    }
                }
            }
        }
    }

    // Read-only backward compatibility with legacy /etc/vortex/profiles (when VORTEX_CONFIG_DIR isn't isolated)
    if std::env::var("VORTEX_CONFIG_DIR")
        .ok()
        .filter(|s| !s.is_empty())
        .is_none()
    {
        let sys_dir = Path::new("/etc/vortex/profiles");
        if sys_dir != user_dir.as_path() {
            if let Ok(entries) = fs::read_dir(sys_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|x| x.to_str()) == Some("json") {
                        if let Ok(p) = load_profile_from_path(&path) {
                            if seen_ids.insert(p.id.clone()) {
                                profiles.push(p);
                            }
                        }
                    }
                }
            }
        }
    }

    profiles.sort_by(|a, b| {
        a.name
            .bytes()
            .map(|c| c.to_ascii_lowercase())
            .cmp(b.name.bytes().map(|c| c.to_ascii_lowercase()))
    });
    profiles
}

pub fn remove(id: &str) -> Result<(), VortexError> {
    let path = profiles_dir().join(format!("{id}.json"));
    if path.exists() {
        fs::remove_file(path)?;
    }
    if std::env::var("VORTEX_CONFIG_DIR")
        .ok()
        .filter(|s| !s.is_empty())
        .is_none()
    {
        let sys_path = Path::new("/etc/vortex/profiles").join(format!("{id}.json"));
        if sys_path.exists() {
            let _ = fs::remove_file(sys_path);
        }
    }
    Ok(())
}

pub fn rename(id: &str, new_name: &str) -> Result<(), VortexError> {
    let new_name = new_name.trim();
    if new_name.is_empty() {
        return Err(VortexError::Config("Profile name cannot be empty".into()));
    }
    let mut p = load_all()
        .into_iter()
        .find(|p| p.id == id)
        .ok_or_else(|| VortexError::NotFound(format!("Profile '{id}' not found")))?;
    p.name = new_name.to_string();
    p.updated_at = Some(now_secs());
    save_profile(&p)?;
    Ok(())
}

pub fn set_auth(id: &str, username: String, password: String) -> Result<(), VortexError> {
    let mut p = load_all()
        .into_iter()
        .find(|p| p.id == id)
        .ok_or_else(|| VortexError::NotFound(format!("Profile '{id}' not found")))?;
    p.auth = Some(Auth {
        username,
        password,
        save: true,
    });
    save_profile(&p)
}

pub fn clear_auth(id: &str) -> Result<(), VortexError> {
    let mut p = load_all()
        .into_iter()
        .find(|p| p.id == id)
        .ok_or_else(|| VortexError::NotFound(format!("Profile '{id}' not found")))?;
    p.auth = None;
    save_profile(&p)
}

pub fn set_last(id: &str) {
    let _ = atomic_write(&last_file(), id.as_bytes());
}

pub fn last() -> Option<String> {
    if let Ok(s) = fs::read_to_string(last_file()) {
        let t = s.trim().to_string();
        if !t.is_empty() {
            return Some(t);
        }
    }
    if std::env::var("VORTEX_CONFIG_DIR")
        .ok()
        .filter(|s| !s.is_empty())
        .is_none()
    {
        if let Ok(s) = fs::read_to_string("/etc/vortex/last") {
            let t = s.trim().to_string();
            if !t.is_empty() {
                return Some(t);
            }
        }
    }
    None
}

// ───────────────────────── Subscriptions ─────────────────────────

pub fn load_subs() -> Vec<Subscription> {
    let mut subs: Vec<Subscription> = fs::read_to_string(subs_file())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    if std::env::var("VORTEX_CONFIG_DIR")
        .ok()
        .filter(|s| !s.is_empty())
        .is_none()
    {
        if let Ok(sys_raw) = fs::read_to_string("/etc/vortex/subscriptions.json") {
            if let Ok(sys_subs) = serde_json::from_str::<Vec<Subscription>>(&sys_raw) {
                for s in sys_subs {
                    if !subs.iter().any(|existing| existing.id == s.id) {
                        subs.push(s);
                    }
                }
            }
        }
    }
    subs
}

pub fn save_subs(subs: &[Subscription]) -> Result<(), VortexError> {
    let path = subs_file();
    let json = serde_json::to_string_pretty(subs)?;
    atomic_write(&path, json.as_bytes())?;
    Ok(())
}

pub fn slug(name: &str) -> String {
    let s: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    let mut out = s
        .split('-')
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    if out.is_empty() {
        out = "node".into();
    }
    out.truncate(32);
    out
}

pub fn sub_name_from_url(url_str: &str) -> (String, String) {
    let parsed = url::Url::parse(url_str).ok();
    let fragment = parsed
        .as_ref()
        .and_then(|u| u.fragment())
        .map(|s| {
            percent_encoding::percent_decode_str(s)
                .decode_utf8_lossy()
                .to_string()
        })
        .filter(|s| !s.trim().is_empty());
    let host = parsed
        .as_ref()
        .and_then(|u| u.host_str())
        .map(String::from)
        .unwrap_or_else(|| "subscription".into());
    let name = fragment.unwrap_or_else(|| host.clone());
    let mut base_id = slug(&name);
    if base_id.is_empty() {
        base_id = slug(&host);
    }
    (base_id, name)
}

pub fn import(raw: &str) -> Result<usize, VortexError> {
    let trimmed = raw.trim();
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        let (_, count) = add_sub(trimmed, None)?;
        return Ok(count);
    }
    let imported = parse_any(trimmed)?;
    if imported.is_empty() {
        return Ok(0);
    }

    let existing = load_all();
    let mut ids: HashSet<String> = existing.iter().map(|p| p.id.clone()).collect();
    let mut data_set: HashSet<String> = existing.iter().map(|p| p.data.clone()).collect();
    let mut count = 0;

    for mut p in imported {
        if data_set.contains(&p.data) {
            continue;
        }
        let base_id = slug(&p.name);
        let mut id = base_id.clone();
        let mut idx = 2;
        while ids.contains(&id) || profiles_dir().join(format!("{id}.json")).exists() {
            id = format!("{base_id}-{idx}");
            idx += 1;
        }
        p.id = id.clone();
        p.created_at = Some(now_secs());
        p.updated_at = Some(now_secs());
        save_profile(&p)?;
        ids.insert(id);
        data_set.insert(p.data.clone());
        count += 1;
    }

    Ok(count)
}

fn fetch_subscription_nodes(url: &str) -> Result<Vec<Profile>, VortexError> {
    let output = std::process::Command::new("curl")
        .args(["-fsSL", "--max-time", "20", "-A", "vortex/0.3", url])
        .output()
        .map_err(|e| VortexError::Network(format!("Failed to fetch subscription: {e}")))?;

    if !output.status.success() {
        let err_msg = format!(
            "HTTP error: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        return Err(VortexError::Network(err_msg));
    }

    let body = String::from_utf8_lossy(&output.stdout).to_string();
    parse_any(&body)
}

fn replace_sub_profiles(sub_id: &str, nodes: Vec<Profile>) -> Result<usize, VortexError> {
    let existing = load_all();
    let active_id = crate::tunnel::load_session().map(|s| s.id);
    for p in &existing {
        if p.sub_id.as_deref() == Some(sub_id) && active_id.as_deref() != Some(&p.id) {
            let _ = remove(&p.id);
        }
    }

    let remaining = load_all();
    let mut ids: HashSet<String> = remaining.iter().map(|p| p.id.clone()).collect();
    let mut data_set: HashSet<String> = remaining.iter().map(|p| p.data.clone()).collect();
    let mut imported_count = 0;

    for mut p in nodes {
        if data_set.contains(&p.data) {
            continue;
        }
        p.sub_id = Some(sub_id.to_string());
        let base_id = format!("{sub_id}-{}", slug(&p.name));
        let mut id = base_id.clone();
        let mut idx = 2;
        while ids.contains(&id) || profiles_dir().join(format!("{id}.json")).exists() {
            id = format!("{base_id}-{idx}");
            idx += 1;
        }
        p.id = id.clone();
        p.created_at = Some(now_secs());
        p.updated_at = Some(now_secs());
        save_profile(&p)?;
        ids.insert(id);
        data_set.insert(p.data.clone());
        imported_count += 1;
    }
    Ok(imported_count)
}

pub fn add_sub(url: &str, name: Option<&str>) -> Result<(Subscription, usize), VortexError> {
    let mut subs = load_subs();
    let (mut id, mut sub_name) = sub_name_from_url(url);
    if let Some(h) = name.filter(|s| !s.trim().is_empty()) {
        sub_name = h.trim().to_string();
        id = slug(&sub_name);
    }

    let existing_pos = subs.iter().position(|s| s.url == url);
    let sub_id = if let Some(pos) = existing_pos {
        subs[pos].id.clone()
    } else {
        let base = id.clone();
        let mut idx = 2;
        while subs.iter().any(|s| s.id == id) {
            id = format!("{base}-{idx}");
            idx += 1;
        }
        id
    };

    let nodes = match fetch_subscription_nodes(url) {
        Ok(n) => n,
        Err(e) => {
            let failed_sub = Subscription {
                id: sub_id.clone(),
                name: sub_name,
                url: url.to_string(),
                count: 0,
                updated: Some(now_secs()),
                error: Some(e.to_string()),
            };
            if let Some(pos) = existing_pos {
                subs[pos] = failed_sub;
            } else {
                subs.push(failed_sub);
            }
            let _ = save_subs(&subs);
            return Err(e);
        }
    };

    let imported_count = replace_sub_profiles(&sub_id, nodes)?;

    let sub = Subscription {
        id: sub_id,
        name: sub_name,
        url: url.to_string(),
        count: imported_count,
        updated: Some(now_secs()),
        error: None,
    };

    if let Some(pos) = subs.iter().position(|s| s.id == sub.id) {
        subs[pos] = sub.clone();
    } else {
        subs.push(sub.clone());
    }
    save_subs(&subs)?;

    Ok((sub, imported_count))
}

pub fn update_sub(id_or_url: &str) -> Result<(Subscription, usize), VortexError> {
    let subs = load_subs();
    let sub = subs
        .iter()
        .find(|s| s.id == id_or_url || s.url == id_or_url)
        .cloned()
        .ok_or_else(|| VortexError::NotFound(format!("subscription '{id_or_url}' not found")))?;

    let nodes = fetch_subscription_nodes(&sub.url)?;
    let count = replace_sub_profiles(&sub.id, nodes)?;

    let mut subs = load_subs();
    let mut updated_sub = sub;
    updated_sub.count = count;
    updated_sub.updated = Some(now_secs());
    updated_sub.error = None;
    if let Some(pos) = subs.iter().position(|s| s.id == updated_sub.id) {
        subs[pos] = updated_sub.clone();
    }
    save_subs(&subs)?;
    Ok((updated_sub, count))
}

pub type SubUpdateResults = Vec<(String, Result<usize, VortexError>)>;

pub fn update_all_subs() -> Result<SubUpdateResults, VortexError> {
    let subs = load_subs();
    if subs.is_empty() {
        return Err(VortexError::NotFound(
            "no subscriptions configured — use `vortex sub add <url>`".into(),
        ));
    }
    let mut results = Vec::new();
    for sub in subs {
        match fetch_subscription_nodes(&sub.url)
            .and_then(|nodes| replace_sub_profiles(&sub.id, nodes))
        {
            Ok(count) => {
                let mut all_subs = load_subs();
                if let Some(pos) = all_subs.iter().position(|s| s.id == sub.id) {
                    all_subs[pos].count = count;
                    all_subs[pos].updated = Some(now_secs());
                    all_subs[pos].error = None;
                    let _ = save_subs(&all_subs);
                }
                results.push((sub.name, Ok(count)));
            }
            Err(e) => results.push((sub.name, Err(e))),
        }
    }
    Ok(results)
}

pub fn remove_sub(id_or_url: &str, cleanup_nodes: bool) -> Result<usize, VortexError> {
    let mut subs = load_subs();
    let pos = subs
        .iter()
        .position(|s| s.id == id_or_url || s.url == id_or_url)
        .ok_or_else(|| VortexError::NotFound(format!("subscription '{id_or_url}' not found")))?;
    let sub = subs.remove(pos);
    save_subs(&subs)?;

    let mut removed_count = 0;
    if cleanup_nodes {
        let active_id = crate::tunnel::load_session().map(|s| s.id);
        for p in load_all() {
            if p.sub_id.as_deref() == Some(&sub.id) {
                if active_id.as_deref() == Some(&p.id) {
                    continue;
                }
                remove(&p.id)?;
                removed_count += 1;
            }
        }
    }
    Ok(removed_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_storage_roundtrip() {
        let temp_dir =
            std::env::temp_dir().join(format!("vortex_test_storage_{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp_dir);
        std::env::set_var("VORTEX_CONFIG_DIR", temp_dir.to_str().unwrap());

        let mut p = Profile::new(
            "test-secure-node",
            "Secure Node",
            Kind::Vless,
            "1.2.3.4:443",
            "vless://secret-uuid@1.2.3.4:443?type=xhttp&security=reality",
        );
        p.populate_metadata();

        save_profile(&p).unwrap();
        let loaded = load_profile_from_path(&profiles_dir().join("test-secure-node.json")).unwrap();
        assert_eq!(loaded.id, p.id);
        assert_eq!(loaded.data, p.data);
        assert_eq!(loaded.engine, crate::model::CoreEngine::Xray);

        // Verify the file on disk does NOT contain the plaintext UUID!
        let raw_disk = fs::read_to_string(profiles_dir().join("test-secure-node.json")).unwrap();
        assert!(!raw_disk.contains("secret-uuid"));
        assert!(raw_disk.contains("encrypted_data"));

        remove("test-secure-node").unwrap();
        std::env::remove_var("VORTEX_CONFIG_DIR");
        let _ = fs::remove_dir_all(temp_dir);
    }
}

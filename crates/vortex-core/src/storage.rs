use crate::crypto::{decrypt_secret, encrypt_secret, get_or_create_master_key, user_config_dir};
use crate::error::VortexError;
use crate::model::{Auth, Kind, Profile, Subscription};
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
    };

    let json = serde_json::to_string_pretty(&stored)?;
    let path = profiles_dir().join(format!("{}.json", p.id));
    atomic_write(&path, json.as_bytes())?;
    Ok(())
}

pub fn load_profile_from_path(path: &Path) -> Result<Profile, VortexError> {
    let content = fs::read_to_string(path)?;
    let stored: StoredProfile = serde_json::from_str(&content)?;

    let data = if let Some(enc_b64) = stored.encrypted_data {
        let key = get_or_create_master_key()?;
        let enc_bytes = base64::engine::general_purpose::STANDARD
            .decode(enc_b64)
            .map_err(|e| VortexError::Crypto(format!("Invalid base64 in encrypted data: {e}")))?;
        decrypt_secret(&enc_bytes, &key)?
    } else if let Some(plain) = stored.plaintext_data {
        plain
    } else {
        return Err(VortexError::Config(
            "Missing payload data in profile".into(),
        ));
    };

    Ok(Profile {
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
    })
}

pub fn load_all() -> Vec<Profile> {
    let _ = ensure_dirs();
    let dir = profiles_dir();
    let Ok(entries) = fs::read_dir(dir) else {
        return vec![];
    };

    let mut profiles = vec![];
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|x| x.to_str()) == Some("json") {
            if let Ok(p) = load_profile_from_path(&path) {
                profiles.push(p);
            }
        }
    }

    profiles.sort_by_key(|a| a.name.to_lowercase());
    profiles
}

pub fn remove(id: &str) -> Result<(), VortexError> {
    let path = profiles_dir().join(format!("{id}.json"));
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}

pub fn rename(id: &str, new_name: &str) -> Result<(), VortexError> {
    let path = profiles_dir().join(format!("{id}.json"));
    if !path.exists() {
        return Err(VortexError::NotFound(format!("Profile '{id}' not found")));
    }
    let mut p = load_profile_from_path(&path)?;
    p.name = new_name.trim().to_string();
    p.updated_at = Some(now_secs());
    save_profile(&p)?;
    Ok(())
}

pub fn set_last(id: &str) {
    let _ = atomic_write(&last_file(), id.as_bytes());
}

pub fn last() -> Option<String> {
    fs::read_to_string(last_file())
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

// ───────────────────────── Subscriptions ─────────────────────────

pub fn load_subs() -> Vec<Subscription> {
    let path = subs_file();
    fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
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
            if c.is_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    let parts: Vec<&str> = s.split('-').filter(|p| !p.is_empty()).collect();
    if parts.is_empty() {
        "node".into()
    } else {
        parts.join("-")
    }
}

pub fn import(raw: &str) -> Result<usize, VortexError> {
    let imported = parse_any(raw)?;
    if imported.is_empty() {
        return Ok(0);
    }

    let existing = load_all();
    let mut data_set: HashSet<String> = existing.iter().map(|p| p.data.clone()).collect();
    let mut count = 0;

    for mut p in imported {
        if data_set.contains(&p.data) {
            continue;
        }
        let base_id = slug(&p.name);
        let mut id = base_id.clone();
        let mut idx = 2;
        while profiles_dir().join(format!("{id}.json")).exists() {
            id = format!("{base_id}-{idx}");
            idx += 1;
        }
        p.id = id;
        p.created_at = Some(now_secs());
        p.updated_at = Some(now_secs());
        save_profile(&p)?;
        data_set.insert(p.data.clone());
        count += 1;
    }

    Ok(count)
}

pub fn add_sub(url: &str, name: Option<&str>) -> Result<(Subscription, usize), VortexError> {
    let mut subs = load_subs();
    let sub_name = name
        .map(|s| s.to_string())
        .unwrap_or_else(|| url.split('/').nth(2).unwrap_or("Subscription").to_string());
    let sub_id = slug(&sub_name);

    // Fetch subscription content via curl
    let output = std::process::Command::new("curl")
        .args(["-fsSL", "--max-time", "15", url])
        .output()
        .map_err(|e| VortexError::Network(format!("Failed to fetch subscription: {e}")))?;

    if !output.status.success() {
        let err_msg = format!(
            "HTTP error: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        let failed_sub = Subscription {
            id: sub_id.clone(),
            name: sub_name,
            url: url.to_string(),
            count: 0,
            updated: Some(now_secs()),
            error: Some(err_msg.clone()),
        };
        subs.push(failed_sub.clone());
        save_subs(&subs)?;
        return Err(VortexError::Network(err_msg));
    }

    let body = String::from_utf8_lossy(&output.stdout).to_string();
    let nodes = parse_any(&body)?;
    let mut imported_count = 0;

    for mut p in nodes {
        p.sub_id = Some(sub_id.clone());
        p.id = format!("{sub_id}-{}", slug(&p.name));
        let mut idx = 2;
        while profiles_dir().join(format!("{}.json", p.id)).exists() {
            p.id = format!("{sub_id}-{}-{}", slug(&p.name), idx);
            idx += 1;
        }
        save_profile(&p)?;
        imported_count += 1;
    }

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

pub fn remove_sub(id: &str, cleanup_nodes: bool) -> Result<usize, VortexError> {
    let mut subs = load_subs();
    subs.retain(|s| s.id != id);
    save_subs(&subs)?;

    let mut removed_count = 0;
    if cleanup_nodes {
        for p in load_all() {
            if p.sub_id.as_deref() == Some(id) {
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
        let temp_dir = std::env::temp_dir().join("vortex_test_storage");
        std::env::set_var("VORTEX_CONFIG_DIR", temp_dir.to_str().unwrap());

        let p = Profile::new(
            "test-secure-node",
            "Secure Node",
            Kind::Vless,
            "1.2.3.4:443",
            "vless://secret-uuid@1.2.3.4:443?type=ws",
        );

        save_profile(&p).unwrap();
        let loaded = load_profile_from_path(&profiles_dir().join("test-secure-node.json")).unwrap();
        assert_eq!(loaded.id, p.id);
        assert_eq!(loaded.data, p.data);

        // Verify the file on disk does NOT contain the plaintext UUID!
        let raw_disk = fs::read_to_string(profiles_dir().join("test-secure-node.json")).unwrap();
        assert!(!raw_disk.contains("secret-uuid"));
        assert!(raw_disk.contains("encrypted_data"));

        remove("test-secure-node").unwrap();
        let _ = fs::remove_dir_all(temp_dir);
    }
}

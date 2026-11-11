use crate::error::VortexError;
use age::secrecy::SecretString;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

pub fn user_home_dir() -> PathBuf {
    if let Ok(u) = std::env::var("SUDO_USER") {
        if !u.is_empty() && u != "root" {
            return PathBuf::from("/home").join(u);
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            return PathBuf::from(home);
        }
    }
    PathBuf::from("/root")
}

pub fn user_config_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("VORTEX_CONFIG_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    let candidate = user_home_dir().join(".config").join("vortex");
    if candidate.exists() || user_home_dir().as_path() != std::path::Path::new("/root") {
        return candidate;
    }
    PathBuf::from("/etc/vortex")
}

pub fn generate_secure_token() -> String {
    let mut bytes = [0u8; 32];
    if let Ok(mut f) = fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut bytes);
    } else {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(1337);
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = ((now >> (i % 16)) ^ (i as u128)) as u8;
        }
    }
    let mut hex = String::with_capacity(64);
    for b in bytes {
        hex.push_str(&format!("{b:02x}"));
    }
    hex
}

pub fn get_or_create_master_key() -> Result<String, VortexError> {
    let service = "vortex";
    let user = "master_key";

    // 1. Try keyring first
    if let Ok(entry) = keyring::Entry::new(service, user) {
        if let Ok(password) = entry.get_password() {
            if !password.is_empty() {
                return Ok(password);
            }
        }
    }

    // 2. Check local fallback file in ~/.config/vortex/.key
    let key_file = user_config_dir().join(".key");
    if key_file.exists() {
        if let Ok(key) = std::fs::read_to_string(&key_file) {
            let key = key.trim().to_string();
            if !key.is_empty() {
                return Ok(key);
            }
        }
    }

    // 3. Generate new secure key
    let new_key = generate_secure_token();

    // 4. Attempt to save to keyring
    let mut stored_in_keyring = false;
    if let Ok(entry) = keyring::Entry::new(service, user) {
        if entry.set_password(&new_key).is_ok() {
            stored_in_keyring = true;
        }
    }

    if !stored_in_keyring {
        tracing::warn!(
            "System keyring unavailable; falling back to local master key file at {:?}",
            key_file
        );
        if let Some(parent) = key_file.parent() {
            let _ = std::fs::create_dir_all(parent);
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
        std::fs::write(&key_file, &new_key)?;
        let _ = std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600));
    }

    Ok(new_key)
}

pub fn encrypt_secret(plaintext: &str, passphrase: &str) -> Result<Vec<u8>, VortexError> {
    let encryptor =
        age::Encryptor::with_user_passphrase(SecretString::from(passphrase.to_string()));
    let mut ciphertext = vec![];
    let mut writer = encryptor
        .wrap_output(&mut ciphertext)
        .map_err(|e| VortexError::Crypto(format!("Failed to wrap age encryptor output: {e}")))?;
    writer.write_all(plaintext.as_bytes())?;
    writer
        .finish()
        .map_err(|e| VortexError::Crypto(format!("Failed to finish age encryption: {e}")))?;
    Ok(ciphertext)
}

pub fn decrypt_secret(ciphertext: &[u8], passphrase: &str) -> Result<String, VortexError> {
    let decryptor = age::Decryptor::new_buffered(ciphertext)
        .map_err(|e| VortexError::Crypto(format!("Invalid age header format: {e}")))?;
    let identity = age::scrypt::Identity::new(SecretString::from(passphrase.to_string()));
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|e| VortexError::Crypto(format!("Passphrase decryption failed: {e}")))?;
    let mut plaintext = String::new();
    reader.read_to_string(&mut plaintext)?;
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_age_encryption_roundtrip() {
        let secret = "vless://b6a03649-61f4-41aa-a51b-402c3cc6c547@example.com:443?type=grpc";
        let passphrase = "test_secure_passphrase_123!";
        let encrypted = encrypt_secret(secret, passphrase).unwrap();
        assert!(!encrypted.is_empty());
        assert_ne!(encrypted, secret.as_bytes());

        let decrypted = decrypt_secret(&encrypted, passphrase).unwrap();
        assert_eq!(decrypted, secret);
    }

    #[test]
    fn test_age_decryption_wrong_passphrase_fails() {
        let secret = "top_secret_credentials";
        let encrypted = encrypt_secret(secret, "correct_pass").unwrap();
        let res = decrypt_secret(&encrypted, "wrong_pass");
        assert!(res.is_err());
    }
}

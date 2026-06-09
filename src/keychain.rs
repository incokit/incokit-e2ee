//! Optional OS-keychain storage for the 32-byte master key.
//!
//! Enabled by the `keychain` feature. The key is base64-encoded and stored as
//! a password entry keyed by `(service, account)`:
//!
//! - **macOS** — login Keychain (gated by Touch ID / the login password)
//! - **Windows** — Credential Manager (DPAPI-protected)
//! - **Linux** — the Secret Service (GNOME Keyring / KWallet)
//!
//! Each function comes in two forms: a convenience version that uses the
//! default service name [`DEFAULT_SERVICE`], and an explicit `*_in_service`
//! version so a consumer can namespace entries under their own app id.

use keyring::Entry;

/// Default keychain service name. Override with the `*_in_service` functions.
pub const DEFAULT_SERVICE: &str = "com.incokit.encryption";

fn entry(service: &str, account: &str) -> Result<Entry, String> {
    Entry::new(service, account).map_err(|e| format!("Keychain entry error: {}", e))
}

/// Save the master key under `(service, account)`.
pub fn save_master_key_in_service(
    service: &str,
    account: &str,
    master_key: &[u8; 32],
) -> Result<(), String> {
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(master_key);
    entry(service, account)?
        .set_password(&encoded)
        .map_err(|e| format!("Keychain save error: {}", e))
}

/// Load the master key for `(service, account)`. `Ok(None)` if absent.
pub fn load_master_key_in_service(
    service: &str,
    account: &str,
) -> Result<Option<[u8; 32]>, String> {
    match entry(service, account)?.get_password() {
        Ok(encoded) => Ok(Some(decode_key(&encoded)?)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(format!("Keychain load error: {}", e)),
    }
}

/// Delete the master key for `(service, account)`. Absent entry is a no-op.
pub fn delete_master_key_in_service(service: &str, account: &str) -> Result<(), String> {
    match entry(service, account)?.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(format!("Keychain delete error: {}", e)),
    }
}

/// True if a master key exists for `(service, account)`.
pub fn has_master_key_in_service(service: &str, account: &str) -> bool {
    matches!(load_master_key_in_service(service, account), Ok(Some(_)))
}

// ── Convenience wrappers using DEFAULT_SERVICE ───────────────────────────────

/// Save the master key under [`DEFAULT_SERVICE`].
pub fn save_master_key(account: &str, master_key: &[u8; 32]) -> Result<(), String> {
    save_master_key_in_service(DEFAULT_SERVICE, account, master_key)
}

/// Load the master key under [`DEFAULT_SERVICE`]. `Ok(None)` if absent.
pub fn load_master_key(account: &str) -> Result<Option<[u8; 32]>, String> {
    load_master_key_in_service(DEFAULT_SERVICE, account)
}

/// Delete the master key under [`DEFAULT_SERVICE`].
pub fn delete_master_key(account: &str) -> Result<(), String> {
    delete_master_key_in_service(DEFAULT_SERVICE, account)
}

/// True if a master key exists under [`DEFAULT_SERVICE`].
pub fn has_master_key(account: &str) -> bool {
    has_master_key_in_service(DEFAULT_SERVICE, account)
}

/// Decode a stored base64 password back into a 32-byte key, validating length.
/// Pulled out so the encoding contract is unit-testable without touching the
/// OS keychain (which CI runners usually don't have).
fn decode_key(encoded: &str) -> Result<[u8; 32], String> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| format!("Keychain decode error: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!(
            "Invalid key length in keychain: expected 32, got {}",
            bytes.len()
        ));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    /// The encode/decode contract is the only platform-independent part of
    /// this module (the keyring calls hit the real OS). Lock it: a stored key
    /// round-trips, and the default service name is unchanged so existing
    /// entries stay findable.
    #[test]
    fn key_encoding_roundtrips() {
        let key = [9u8; 32];
        let encoded = base64::engine::general_purpose::STANDARD.encode(key);
        assert_eq!(decode_key(&encoded).unwrap(), key);
    }

    #[test]
    fn decode_rejects_wrong_length() {
        let short = base64::engine::general_purpose::STANDARD.encode([1u8; 16]);
        let err = decode_key(&short).unwrap_err();
        assert!(err.contains("expected 32"), "got: {err}");
    }

    #[test]
    fn decode_rejects_garbage_base64() {
        assert!(decode_key("!!!not base64!!!").is_err());
    }

    #[test]
    fn default_service_name_is_stable() {
        // Changing this orphans every key already saved in users' keychains.
        assert_eq!(DEFAULT_SERVICE, "com.incokit.encryption");
    }
}

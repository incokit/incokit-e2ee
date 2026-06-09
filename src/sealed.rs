//! Wire-format encryption helpers for string-shaped storage.
//!
//! Raw AES-GCM ciphertext lives in [`crate::encryption`]. This
//! module wraps it into the wire format actually stored in the database:
//! `"e2ee:" + base64(nonce || ciphertext || tag)`.
//!
//! The `"e2ee:"` prefix exists for two reasons:
//!
//! 1. **Backward compatibility.** Rows written before E2EE shipped hold
//!    plaintext. `try_unseal_*` returns such rows as-is; `unseal_*`
//!    (strict) rejects them. Callers decrypt legacy rows with
//!    `try_unseal_*` until a migration rewraps them.
//!
//! 2. **Self-describing blobs.** A human looking at a stored row can
//!    tell at a glance whether a field is encrypted, which is handy when
//!    debugging or writing migrations.
//!
//! The prefix is part of the stored wire format — changing it would make
//! every existing row unreadable. If you need to bump the algorithm or
//! format, add a NEW prefix and rewrap on read. Do NOT reuse `"e2ee:"`
//! for a different scheme.

use crate::encryption;
use crate::error::{CryptoError, CryptoResult};
use base64::Engine;
use serde::{de::DeserializeOwned, Serialize};

/// Wire-format prefix. Do not change without a data migration.
pub const E2EE_PREFIX: &str = "e2ee:";

// ─── bytes ─────────────────────────────────────────────────────────────────

/// Encrypt `plaintext` → `"e2ee:<base64>"`.
pub fn seal_bytes(entity_key: &[u8; 32], plaintext: &[u8]) -> CryptoResult<String> {
    let raw = encryption::encrypt(entity_key, plaintext)?;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&raw);
    Ok(format!("{}{}", E2EE_PREFIX, b64))
}

/// Strict: decrypt wire-format string. Input without the `"e2ee:"` prefix
/// is rejected with [`CryptoError::MissingE2eePrefix`].
pub fn unseal_bytes(entity_key: &[u8; 32], stored: &str) -> CryptoResult<Vec<u8>> {
    let b64 = stored
        .strip_prefix(E2EE_PREFIX)
        .ok_or(CryptoError::MissingE2eePrefix)?;
    let raw = base64::engine::general_purpose::STANDARD.decode(b64)?;
    encryption::decrypt(entity_key, &raw)
}

/// Lenient: decrypt if prefixed, otherwise return the bytes as-is.
/// Use for fields that may contain legacy plaintext.
pub fn try_unseal_bytes(entity_key: &[u8; 32], stored: &str) -> CryptoResult<Vec<u8>> {
    if stored.starts_with(E2EE_PREFIX) {
        unseal_bytes(entity_key, stored)
    } else {
        Ok(stored.as_bytes().to_vec())
    }
}

// ─── strings ───────────────────────────────────────────────────────────────

pub fn seal_string(entity_key: &[u8; 32], plaintext: &str) -> CryptoResult<String> {
    seal_bytes(entity_key, plaintext.as_bytes())
}

/// Strict string decrypt.
pub fn unseal_string(entity_key: &[u8; 32], stored: &str) -> CryptoResult<String> {
    let bytes = unseal_bytes(entity_key, stored)?;
    Ok(String::from_utf8(bytes)?)
}

/// Lenient string decrypt (backward-compat with plaintext rows).
pub fn try_unseal_string(entity_key: &[u8; 32], stored: &str) -> CryptoResult<String> {
    let bytes = try_unseal_bytes(entity_key, stored)?;
    Ok(String::from_utf8(bytes)?)
}

// ─── json ──────────────────────────────────────────────────────────────────

/// Serialize `value` to JSON and seal. Use this over `seal_string(..., &to_string(v))`
/// so the call site reads as "encrypt this structured value", not as string juggling.
pub fn seal_json<T: Serialize>(entity_key: &[u8; 32], value: &T) -> CryptoResult<String> {
    let s = serde_json::to_string(value)?;
    seal_string(entity_key, &s)
}

/// Strict JSON decrypt.
pub fn unseal_json<T: DeserializeOwned>(entity_key: &[u8; 32], stored: &str) -> CryptoResult<T> {
    let s = unseal_string(entity_key, stored)?;
    Ok(serde_json::from_str(&s)?)
}

/// Lenient JSON decrypt (backward-compat with plaintext JSON rows).
pub fn try_unseal_json<T: DeserializeOwned>(
    entity_key: &[u8; 32],
    stored: &str,
) -> CryptoResult<T> {
    let s = try_unseal_string(entity_key, stored)?;
    Ok(serde_json::from_str(&s)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const KEY: [u8; 32] = [7u8; 32];

    #[test]
    fn string_roundtrip() {
        let sealed = seal_string(&KEY, "hello").unwrap();
        assert!(sealed.starts_with(E2EE_PREFIX));
        assert_eq!(unseal_string(&KEY, &sealed).unwrap(), "hello");
    }

    #[test]
    fn json_roundtrip() {
        let v = json!({"a": 1, "b": "two"});
        let sealed = seal_json(&KEY, &v).unwrap();
        let back: serde_json::Value = unseal_json(&KEY, &sealed).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn strict_rejects_plaintext() {
        let result = unseal_string(&KEY, "hello plaintext");
        assert!(matches!(result, Err(CryptoError::MissingE2eePrefix)));
    }

    #[test]
    fn lenient_passes_plaintext_through() {
        let out = try_unseal_string(&KEY, "hello plaintext").unwrap();
        assert_eq!(out, "hello plaintext");
    }

    #[test]
    fn wrong_key_fails() {
        let sealed = seal_string(&KEY, "secret").unwrap();
        let wrong = [9u8; 32];
        assert!(unseal_string(&wrong, &sealed).is_err());
    }

    #[test]
    fn lenient_invalid_base64_after_prefix_still_errors() {
        // An `e2ee:` prefix with garbage base64 should fail even in
        // lenient mode — the prefix is a commitment, not a hint.
        let result = try_unseal_string(&KEY, "e2ee:!!!not-base64!!!");
        assert!(result.is_err());
    }

    /// The security-critical property of lenient mode: once a blob carries
    /// the `e2ee:` prefix, a wrong key must FAIL — it must never silently
    /// fall through to returning the raw ciphertext bytes. Otherwise a
    /// key-mismatch bug would leak ciphertext into a field expecting
    /// plaintext, masking the failure.
    #[test]
    fn lenient_sealed_blob_with_wrong_key_fails_closed() {
        let sealed = seal_string(&KEY, "top secret").unwrap();
        let wrong = [9u8; 32];

        let result = try_unseal_string(&wrong, &sealed);
        assert!(
            result.is_err(),
            "a prefixed blob under the wrong key must error, not pass ciphertext through"
        );
    }

    /// Flipping a byte inside the base64 payload must be caught by AES-GCM
    /// authentication, in both strict and lenient modes.
    #[test]
    fn tampered_wire_format_is_detected() {
        let sealed = seal_string(&KEY, "integrity matters").unwrap();

        // Corrupt one character of the base64 body (skip the "e2ee:" prefix).
        let mut bytes: Vec<u8> = sealed.into_bytes();
        let body_start = E2EE_PREFIX.len();
        // Pick a char well inside the body and bump it to a different valid
        // base64 char so it still decodes but the plaintext/tag changes.
        let idx = body_start + 4;
        bytes[idx] = if bytes[idx] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(bytes).unwrap();

        assert!(
            unseal_string(&KEY, &tampered).is_err(),
            "strict must reject tamper"
        );
        assert!(
            try_unseal_string(&KEY, &tampered).is_err(),
            "lenient must also reject tamper on a prefixed blob"
        );
    }

    /// `seal_bytes`/`unseal_bytes` (the binary path under the string/json
    /// helpers) must roundtrip non-UTF-8 payloads that the string API can't.
    #[test]
    fn bytes_roundtrip_handles_non_utf8() {
        let payload = [0x00u8, 0xFF, 0xFE, 0x80, 0x01];
        let sealed = seal_bytes(&KEY, &payload).unwrap();
        assert!(sealed.starts_with(E2EE_PREFIX));
        assert_eq!(unseal_bytes(&KEY, &sealed).unwrap(), payload);
    }
}

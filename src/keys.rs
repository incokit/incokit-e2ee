use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};

use super::encryption;
use super::error::{CryptoError, CryptoResult};

/// Generate a random 256-bit master key.
pub fn generate_master_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

/// Generate a random 32-byte salt.
pub fn generate_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// Generate a random 256-bit recovery key.
/// Returns raw bytes — caller formats as display string.
pub fn generate_recovery_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

/// Format recovery key as XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX.
/// 64 hex chars in 8 groups of 8, separated by dashes. No truncation = perfect round-trip.
pub fn format_recovery_key(key: &[u8; 32]) -> String {
    let hex: String = key.iter().map(|b| format!("{:02X}", b)).collect();

    hex.as_bytes()
        .chunks(8)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or(""))
        .collect::<Vec<&str>>()
        .join("-")
}

/// Parse a formatted recovery key back to 32 raw bytes.
pub fn parse_recovery_key(formatted: &str) -> Result<Vec<u8>, String> {
    let clean: String = formatted
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect();

    if clean.len() != 64 {
        return Err(format!(
            "Invalid recovery key: expected 64 hex chars, got {}",
            clean.len()
        ));
    }

    let bytes: Result<Vec<u8>, _> = (0..32)
        .map(|i| u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16))
        .collect();

    bytes.map_err(|e| format!("Invalid recovery key hex: {}", e))
}

/// Generate X25519 keypair for profile sharing.
/// Returns (private_key_bytes, public_key_bytes).
pub fn generate_x25519_keypair() -> ([u8; 32], [u8; 32]) {
    let secret = StaticSecret::random_from_rng(rand::thread_rng());
    let public = PublicKey::from(&secret);

    let private_bytes: [u8; 32] = secret.to_bytes();
    let public_bytes: [u8; 32] = public.to_bytes();

    (private_bytes, public_bytes)
}

/// Encrypt a profile key for sharing using X25519 + AES-256-GCM.
///
/// Performs X25519 Diffie-Hellman to derive a shared secret,
/// then encrypts the profile key with it.
///
/// sender_private: owner's X25519 private key
/// recipient_public: recipient's X25519 public key
/// profile_key: the profile key to share
pub fn encrypt_profile_key_for_sharing(
    sender_private: &[u8; 32],
    recipient_public: &[u8; 32],
    profile_key: &[u8; 32],
) -> CryptoResult<Vec<u8>> {
    encrypt_blob_for_sharing(sender_private, recipient_public, profile_key)
}

/// Decrypt a shared profile key using X25519 + AES-256-GCM.
///
/// recipient_private: recipient's X25519 private key
/// sender_public: owner's X25519 public key
/// encrypted_profile_key: the encrypted profile key blob
pub fn decrypt_shared_profile_key(
    recipient_private: &[u8; 32],
    sender_public: &[u8; 32],
    encrypted_profile_key: &[u8],
) -> CryptoResult<[u8; 32]> {
    let plaintext = decrypt_shared_blob(recipient_private, sender_public, encrypted_profile_key)?;
    if plaintext.len() != 32 {
        return Err(CryptoError::InvalidKeyLength {
            expected: 32,
            actual: plaintext.len(),
        });
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&plaintext);
    Ok(key)
}

/// Generic X25519 + AES-256-GCM envelope wrapper for arbitrary-length
/// payloads. The two share helpers above are thin wrappers over this:
/// they enforce a 32-byte length on the way out (because they wrap
/// keys), but anything that needs an opaque blob (e.g. the proxy
/// payload sealed for a shared profile recipient) calls this directly.
pub fn encrypt_blob_for_sharing(
    sender_private: &[u8; 32],
    recipient_public: &[u8; 32],
    plaintext: &[u8],
) -> CryptoResult<Vec<u8>> {
    let shared_secret = x25519_diffie_hellman(sender_private, recipient_public);
    let enc_key = derive_sharing_key(&shared_secret)?;
    encryption::encrypt(&enc_key, plaintext)
}

/// Reverse of [`encrypt_blob_for_sharing`].
pub fn decrypt_shared_blob(
    recipient_private: &[u8; 32],
    sender_public: &[u8; 32],
    ciphertext: &[u8],
) -> CryptoResult<Vec<u8>> {
    let shared_secret = x25519_diffie_hellman(recipient_private, sender_public);
    let enc_key = derive_sharing_key(&shared_secret)?;
    encryption::decrypt(&enc_key, ciphertext)
}

/// Generate a random profile key for a new profile.
pub fn generate_profile_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

/// Derive a deterministic profile key from master key + profile ID.
/// Same master_key + same profile_id → same profile_key every time.
/// No need to store the profile key — derive on-the-fly.
///
/// Thin alias over [`KeyNamespace::Profile`] for call sites that predate
/// the namespace refactor. New code for other entities should call
/// `KeyNamespace::Proxy.derive_key(...)` etc. directly.
pub fn derive_profile_key(master_key: &[u8; 32], profile_id: i64) -> CryptoResult<[u8; 32]> {
    super::namespace::KeyNamespace::Profile.derive_key(master_key, profile_id)
}

/// Encrypt private key with master key for storage on server.
pub fn encrypt_private_key(master_key: &[u8; 32], private_key: &[u8; 32]) -> CryptoResult<Vec<u8>> {
    encryption::encrypt(master_key, private_key)
}

/// Decrypt private key with master key.
pub fn decrypt_private_key(master_key: &[u8; 32], encrypted: &[u8]) -> CryptoResult<[u8; 32]> {
    let plaintext = encryption::decrypt(master_key, encrypted)?;
    if plaintext.len() != 32 {
        return Err(CryptoError::InvalidKeyLength {
            expected: 32,
            actual: plaintext.len(),
        });
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&plaintext);
    Ok(key)
}

/// Wrap a 32-byte profile key with the master key.
///
/// Phase 2b stores `profiles.encrypted_profile_key = AES-GCM(master,
/// profile_key)` so the random per-profile key survives across sessions
/// (HKDF derivation is gone). Same primitive as `encrypt_private_key`
/// — we keep separate names so the two call sites don't accidentally
/// drift apart at the type level.
pub fn wrap_profile_key_with_master(
    master_key: &[u8; 32],
    profile_key: &[u8; 32],
) -> CryptoResult<Vec<u8>> {
    encryption::encrypt(master_key, profile_key)
}

/// Reverse of [`wrap_profile_key_with_master`].
pub fn unwrap_profile_key_with_master(
    master_key: &[u8; 32],
    wrapped: &[u8],
) -> CryptoResult<[u8; 32]> {
    let plaintext = encryption::decrypt(master_key, wrapped)?;
    if plaintext.len() != 32 {
        return Err(CryptoError::InvalidKeyLength {
            expected: 32,
            actual: plaintext.len(),
        });
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&plaintext);
    Ok(key)
}

// --- Internal helpers ---

fn x25519_diffie_hellman(my_private: &[u8; 32], their_public: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*my_private);
    let public = PublicKey::from(*their_public);
    let shared = secret.diffie_hellman(&public);
    shared.to_bytes()
}

fn derive_sharing_key(shared_secret: &[u8; 32]) -> CryptoResult<[u8; 32]> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut key = [0u8; 32];
    hk.expand(b"incokit-profile-sharing-v1", &mut key)
        .map_err(|e| CryptoError::Hkdf(e.to_string()))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_master_key() {
        let k1 = generate_master_key();
        let k2 = generate_master_key();
        assert_ne!(k1, k2); // Random
        assert_eq!(k1.len(), 32);
    }

    #[test]
    fn test_x25519_keypair() {
        let (priv_a, pub_a) = generate_x25519_keypair();
        let (priv_b, pub_b) = generate_x25519_keypair();

        // DH should produce same shared secret
        let shared_ab = x25519_diffie_hellman(&priv_a, &pub_b);
        let shared_ba = x25519_diffie_hellman(&priv_b, &pub_a);
        assert_eq!(shared_ab, shared_ba);
    }

    #[test]
    fn test_profile_key_sharing_roundtrip() {
        let (priv_a, pub_a) = generate_x25519_keypair();
        let (priv_b, pub_b) = generate_x25519_keypair();
        let profile_key = generate_profile_key();

        // A encrypts for B
        let encrypted = encrypt_profile_key_for_sharing(&priv_a, &pub_b, &profile_key).unwrap();

        // B decrypts
        let decrypted = decrypt_shared_profile_key(&priv_b, &pub_a, &encrypted).unwrap();

        assert_eq!(decrypted, profile_key);
    }

    #[test]
    fn test_recovery_key_format() {
        let key = generate_recovery_key();
        let formatted = format_recovery_key(&key);

        // 64 hex chars in 8 groups of 8, separated by dashes.
        // Total length = 8*8 + 7 dashes = 71 chars.
        assert!(formatted.contains('-'));
        assert_eq!(formatted.len(), 71);
        let groups: Vec<&str> = formatted.split('-').collect();
        assert_eq!(groups.len(), 8);
        for g in &groups {
            assert_eq!(g.len(), 8);
            assert!(g.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn test_recovery_key_roundtrip() {
        let key = generate_recovery_key();
        let formatted = format_recovery_key(&key);
        let parsed = parse_recovery_key(&formatted).unwrap();
        assert_eq!(parsed, key.to_vec());
    }

    #[test]
    fn test_parse_recovery_key_tolerant() {
        let key = [0xAB_u8; 32];
        let formatted = format_recovery_key(&key);

        // Lowercase + extra whitespace should still parse
        let mangled = format!(" {} ", formatted.to_lowercase());
        let parsed = parse_recovery_key(&mangled).unwrap();
        assert_eq!(parsed, key.to_vec());
    }

    #[test]
    fn test_encrypt_decrypt_private_key() {
        let master = generate_master_key();
        let (private_key, _) = generate_x25519_keypair();

        let encrypted = encrypt_private_key(&master, &private_key).unwrap();
        let decrypted = decrypt_private_key(&master, &encrypted).unwrap();

        assert_eq!(decrypted, private_key);
    }

    // ── Sharing-envelope security properties (Phase 0 gap) ──────────────────
    //
    // The happy-path roundtrip is covered above. These cover the properties a
    // sharing scheme actually has to guarantee: only the intended recipient
    // can open it, tampering is detected, the wrong sender is rejected, and
    // length invariants hold. A regression in any of these leaks or corrupts
    // every shared profile, so they're the crown-jewel tests for this module.

    /// A share that A sealed for B must NOT be openable by a third party C,
    /// even though C holds a valid keypair. This is the core confidentiality
    /// guarantee of profile sharing.
    #[test]
    fn shared_key_not_decryptable_by_third_party() {
        let (priv_a, pub_a) = generate_x25519_keypair();
        let (_priv_b, pub_b) = generate_x25519_keypair();
        let (priv_c, _pub_c) = generate_x25519_keypair();
        let profile_key = generate_profile_key();

        // A seals for B.
        let sealed = encrypt_profile_key_for_sharing(&priv_a, &pub_b, &profile_key).unwrap();

        // C (even with A's correct public key) tries to open it — must fail:
        // C's DH secret with A differs from B's, so the AES-GCM tag won't
        // verify.
        let result = decrypt_shared_profile_key(&priv_c, &pub_a, &sealed);
        assert!(
            result.is_err(),
            "a non-recipient must not be able to decrypt the share"
        );
    }

    /// Decrypting with the wrong *sender* public key must fail: the recipient
    /// can't be tricked into accepting a key that wasn't sealed by the
    /// claimed owner.
    #[test]
    fn shared_key_rejects_wrong_sender_public_key() {
        let (priv_a, _pub_a) = generate_x25519_keypair();
        let (priv_b, pub_b) = generate_x25519_keypair();
        let (_priv_x, pub_x) = generate_x25519_keypair(); // impostor "sender"
        let profile_key = generate_profile_key();

        let sealed = encrypt_profile_key_for_sharing(&priv_a, &pub_b, &profile_key).unwrap();

        // B uses the WRONG sender pubkey (pub_x instead of A's) → DH mismatch.
        let result = decrypt_shared_profile_key(&priv_b, &pub_x, &sealed);
        assert!(
            result.is_err(),
            "decrypt must fail when the sender public key doesn't match the sealer"
        );
    }

    /// Flipping a single ciphertext byte must be detected by AES-GCM's
    /// authentication tag — no silent corruption.
    #[test]
    fn shared_key_tampering_is_detected() {
        let (priv_a, pub_a) = generate_x25519_keypair();
        let (priv_b, pub_b) = generate_x25519_keypair();
        let profile_key = generate_profile_key();

        let mut sealed = encrypt_profile_key_for_sharing(&priv_a, &pub_b, &profile_key).unwrap();
        // Tamper with the last byte (inside the GCM tag region).
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;

        let result = decrypt_shared_profile_key(&priv_b, &pub_a, &sealed);
        assert!(result.is_err(), "tampered ciphertext must be rejected");
    }

    /// The generic blob envelope (used for non-key payloads like a shared
    /// proxy config) must roundtrip arbitrary-length data, not just 32 bytes.
    #[test]
    fn blob_sharing_roundtrips_arbitrary_length() {
        let (priv_a, pub_a) = generate_x25519_keypair();
        let (priv_b, pub_b) = generate_x25519_keypair();

        for payload in [
            b"".as_slice(),
            b"socks5://user:pass@1.2.3.4:1080",
            &[0xFFu8; 500],
        ] {
            let sealed = encrypt_blob_for_sharing(&priv_a, &pub_b, payload).unwrap();
            let opened = decrypt_shared_blob(&priv_b, &pub_a, &sealed).unwrap();
            assert_eq!(
                opened,
                payload,
                "blob of len {} must roundtrip",
                payload.len()
            );
        }
    }

    /// `decrypt_shared_profile_key` enforces a 32-byte result: a blob that
    /// decrypts to a different length is a corrupt/forged key, not a valid one.
    #[test]
    fn shared_profile_key_rejects_non_32_byte_payload() {
        let (priv_a, pub_a) = generate_x25519_keypair();
        let (priv_b, pub_b) = generate_x25519_keypair();

        // Seal a 16-byte payload via the generic blob path, then try to read
        // it back through the key-typed path which demands exactly 32 bytes.
        let sealed = encrypt_blob_for_sharing(&priv_a, &pub_b, &[7u8; 16]).unwrap();
        let result = decrypt_shared_profile_key(&priv_b, &pub_a, &sealed);

        match result {
            Err(CryptoError::InvalidKeyLength { expected, actual }) => {
                assert_eq!(expected, 32);
                assert_eq!(actual, 16);
            }
            other => panic!("expected InvalidKeyLength {{ 32, 16 }}, got {other:?}"),
        }
    }

    // ── Master-key wrap/unwrap (Phase 2b profile-key-at-rest, untested) ─────

    #[test]
    fn wrap_unwrap_profile_key_with_master_roundtrips() {
        let master = generate_master_key();
        let profile_key = generate_profile_key();

        let wrapped = wrap_profile_key_with_master(&master, &profile_key).unwrap();
        // Wrapped blob is the key + AES-GCM overhead, never the bare key.
        assert!(wrapped.len() > 32);
        assert_ne!(
            &wrapped[..32],
            &profile_key[..],
            "must not store key in clear"
        );

        let unwrapped = unwrap_profile_key_with_master(&master, &wrapped).unwrap();
        assert_eq!(unwrapped, profile_key);
    }

    #[test]
    fn unwrap_profile_key_with_wrong_master_fails() {
        let master = generate_master_key();
        let other_master = generate_master_key();
        let profile_key = generate_profile_key();

        let wrapped = wrap_profile_key_with_master(&master, &profile_key).unwrap();
        let result = unwrap_profile_key_with_master(&other_master, &wrapped);
        assert!(result.is_err(), "a different master key must not unwrap");
    }

    /// Random nonce per encryption: wrapping the same key twice must yield
    /// different ciphertexts (otherwise a static-nonce bug would leak
    /// equality of plaintexts across rows).
    #[test]
    fn wrap_profile_key_is_non_deterministic() {
        let master = generate_master_key();
        let profile_key = generate_profile_key();

        let a = wrap_profile_key_with_master(&master, &profile_key).unwrap();
        let b = wrap_profile_key_with_master(&master, &profile_key).unwrap();
        assert_ne!(a, b, "AES-GCM must use a fresh nonce each call");

        // …yet both must decrypt back to the same key.
        assert_eq!(
            unwrap_profile_key_with_master(&master, &a).unwrap(),
            unwrap_profile_key_with_master(&master, &b).unwrap(),
        );
    }
}

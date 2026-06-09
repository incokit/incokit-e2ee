use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use rand::RngCore;

use super::error::{CryptoError, CryptoResult};

/// Encrypt plaintext with AES-256-GCM.
/// Returns: nonce (12 bytes) || ciphertext || tag (16 bytes)
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength {
        expected: 32,
        actual: key.len(),
    })?;

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CryptoError::Encrypt)?;

    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt data (nonce || ciphertext || tag) with AES-256-GCM.
pub fn decrypt(key: &[u8; 32], data: &[u8]) -> CryptoResult<Vec<u8>> {
    if data.len() < 12 + 16 {
        return Err(CryptoError::CiphertextTooShort {
            min: 12 + 16,
            actual: data.len(),
        });
    }

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength {
        expected: 32,
        actual: key.len(),
    })?;
    let nonce = Nonce::from_slice(&data[..12]);
    let ciphertext = &data[12..];

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::Decrypt)
}

/// Derive a 32-byte key from input using Argon2id.
/// Params: 64MB memory, 3 iterations, 4 parallelism.
pub fn derive_key(input: &[u8], salt: &[u8]) -> CryptoResult<[u8; 32]> {
    let params = argon2::Params::new(65536, 3, 4, Some(32))
        .map_err(|e| CryptoError::Argon2Params(e.to_string()))?;
    let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(input, salt, &mut key)
        .map_err(|e| CryptoError::Argon2Hash(e.to_string()))?;
    Ok(key)
}

/// Encrypt master key with a derived key (PIN path or recovery path).
pub fn wrap_master_key(derived_key: &[u8; 32], master_key: &[u8; 32]) -> CryptoResult<Vec<u8>> {
    encrypt(derived_key, master_key)
}

/// Decrypt master key with a derived key.
pub fn unwrap_master_key(derived_key: &[u8; 32], wrapped: &[u8]) -> CryptoResult<[u8; 32]> {
    let plaintext = decrypt(derived_key, wrapped)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [42u8; 32];
        let plaintext = b"hello world cookies data";

        let encrypted = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key = [42u8; 32];
        let wrong_key = [99u8; 32];
        let plaintext = b"secret data";

        let encrypted = encrypt(&key, plaintext).unwrap();
        let result = decrypt(&wrong_key, &encrypted);

        assert!(matches!(result, Err(CryptoError::Decrypt)));
    }

    #[test]
    fn test_derive_key() {
        let input = b"123456";
        let salt = b"random_salt_here_32bytes_long!!!!";

        let key1 = derive_key(input, salt).unwrap();
        let key2 = derive_key(input, salt).unwrap();

        assert_eq!(key1, key2); // Deterministic

        let key3 = derive_key(b"654321", salt).unwrap();
        assert_ne!(key1, key3); // Different input = different key
    }

    #[test]
    fn test_wrap_unwrap_master_key() {
        let derived = [42u8; 32];
        let master = [99u8; 32];

        let wrapped = wrap_master_key(&derived, &master).unwrap();
        let unwrapped = unwrap_master_key(&derived, &wrapped).unwrap();

        assert_eq!(unwrapped, master);
    }

    #[test]
    fn test_decrypt_too_short() {
        let key = [1u8; 32];
        let result = decrypt(&key, &[0u8; 5]);
        assert!(matches!(
            result,
            Err(CryptoError::CiphertextTooShort { .. })
        ));
    }
}

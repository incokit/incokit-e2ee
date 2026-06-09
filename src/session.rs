//! RAII wrapper around the in-memory session master key.
//!
//! The bare `[u8; 32]` master key has been passed around the codebase as
//! a plain array, which makes it hard to audit where it flows and leaves
//! stale copies on the stack. `SessionKey` wraps the bytes in a type that:
//!
//! - zeroizes on drop, so temporary copies don't linger in freed memory
//! - exposes key material only through `derive(...)` or `as_bytes()`
//!   (the latter is an escape hatch; avoid in new code)
//! - cannot be accidentally cloned or serialized
//!
//! Wrap the master key the moment you load it (after PIN unlock, recovery,
//! or reading it back from the OS keychain) and pass the `SessionKey` around
//! instead of the raw array. Hold it only for as long as you need it; when it
//! drops, the bytes are wiped.

use crate::error::CryptoResult;
use crate::namespace::KeyNamespace;
use zeroize::Zeroize;

pub struct SessionKey([u8; 32]);

impl SessionKey {
    /// Wrap a 32-byte master key. The caller is responsible for sourcing the
    /// key material (PIN-derived unwrap, recovery, or OS keychain).
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Derive a per-entity key. Preferred over `as_bytes()` because it
    /// keeps the master key material encapsulated.
    pub fn derive(&self, namespace: KeyNamespace, id: i64) -> CryptoResult<[u8; 32]> {
        namespace.derive_key(&self.0, id)
    }

    /// Escape hatch for code that still needs the raw master key (X25519
    /// sharing flow, `encrypt_private_key`, legacy helpers). Avoid in
    /// new code — reach for `derive(...)` instead.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for SessionKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

// Explicitly don't implement Clone, Copy, Debug, Serialize, Deserialize
// to prevent accidental leaks.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_delegates_to_namespace() {
        let key = SessionKey::new([11u8; 32]);
        let derived = key.derive(KeyNamespace::Profile, 42).unwrap();
        let expected = KeyNamespace::Profile.derive_key(&[11u8; 32], 42).unwrap();
        assert_eq!(derived, expected);
    }

    #[test]
    fn as_bytes_returns_inner() {
        let key = SessionKey::new([7u8; 32]);
        assert_eq!(key.as_bytes(), &[7u8; 32]);
    }
}

//! Single source of truth for per-entity key derivation.
//!
//! Each E2EE-aware entity (profile, proxy, session, bookmark, ...) has
//! its own HKDF namespace. A key derived for one namespace cannot decrypt
//! a blob encrypted under another, so a bug that mixes up entity ids can't
//! silently cross boundaries — the ciphertext simply fails to authenticate.
//!
//! # Wire format
//!
//! `HKDF-SHA256(master_key).expand("incokit-{namespace}:{id}", 32)`
//!
//! For the X25519 sharing flow the info string is the static
//! `"incokit-profile-sharing-v1"` (no id suffix). The `"incokit-"` prefix
//! and these info strings are part of the persisted wire format — DO NOT
//! change them without a rewrap migration, or existing encrypted rows
//! become unreadable.

use crate::error::{CryptoError, CryptoResult};
use hkdf::Hkdf;
use sha2::Sha256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyNamespace {
    Profile,
    Proxy,
    Session,
    Bookmark,
    /// Key used in the X25519 sharing flow. Unlike the per-entity
    /// variants, this one has no id suffix — the info string is
    /// the constant `"incokit-profile-sharing-v1"`.
    ProfileSharing,
}

impl KeyNamespace {
    /// The `{namespace}` segment of the info string.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Profile => "profile",
            Self::Proxy => "proxy",
            Self::Session => "session",
            Self::Bookmark => "bookmark",
            // Legacy compatibility: this namespace does not follow the
            // `"incokit-{namespace}:{id}"` template — see `derive_key` below.
            Self::ProfileSharing => "profile-sharing-v1",
        }
    }

    /// Derive a 32-byte key for a given entity id.
    ///
    /// For [`KeyNamespace::ProfileSharing`] the `id` argument is ignored
    /// (the info string has no id suffix).
    pub fn derive_key(&self, master_key: &[u8; 32], id: i64) -> CryptoResult<[u8; 32]> {
        let info = match self {
            Self::ProfileSharing => format!("incokit-{}", self.as_str()),
            _ => format!("incokit-{}:{}", self.as_str(), id),
        };
        let hk = Hkdf::<Sha256>::new(None, master_key);
        let mut key = [0u8; 32];
        hk.expand(info.as_bytes(), &mut key)
            .map_err(|e| CryptoError::Hkdf(e.to_string()))?;
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Guardrail test: if this ever fails, a refactor broke the wire
    /// format. Any profile row stored before the change would become
    /// undecryptable. Fix the refactor, do NOT change the expected value.
    #[test]
    fn profile_namespace_matches_legacy_inline_format() {
        let master = [42u8; 32];
        let id = 123_i64;

        let via_namespace = KeyNamespace::Profile.derive_key(&master, id).unwrap();

        // The exact derivation the wire format commits to. If this assertion
        // ever fails, a refactor changed the info string and every row stored
        // under the old format would become undecryptable.
        let legacy_info = format!("incokit-profile:{}", id);
        let hk = Hkdf::<Sha256>::new(None, &master);
        let mut legacy = [0u8; 32];
        hk.expand(legacy_info.as_bytes(), &mut legacy).unwrap();

        assert_eq!(via_namespace, legacy);
    }

    /// Same guardrail for the sharing namespace — the committed info string
    /// is `"incokit-profile-sharing-v1"`.
    #[test]
    fn sharing_namespace_matches_legacy_inline_format() {
        let shared = [7u8; 32];
        let via_namespace = KeyNamespace::ProfileSharing.derive_key(&shared, 0).unwrap();

        let hk = Hkdf::<Sha256>::new(None, &shared);
        let mut legacy = [0u8; 32];
        hk.expand(b"incokit-profile-sharing-v1", &mut legacy)
            .unwrap();

        assert_eq!(via_namespace, legacy);
    }

    #[test]
    fn different_namespaces_same_id_different_keys() {
        let master = [1u8; 32];
        let p = KeyNamespace::Profile.derive_key(&master, 1).unwrap();
        let x = KeyNamespace::Proxy.derive_key(&master, 1).unwrap();
        let s = KeyNamespace::Session.derive_key(&master, 1).unwrap();
        let b = KeyNamespace::Bookmark.derive_key(&master, 1).unwrap();

        assert_ne!(p, x);
        assert_ne!(p, s);
        assert_ne!(p, b);
        assert_ne!(x, s);
        assert_ne!(x, b);
        assert_ne!(s, b);
    }

    #[test]
    fn same_namespace_different_ids_different_keys() {
        let master = [1u8; 32];
        let a = KeyNamespace::Profile.derive_key(&master, 1).unwrap();
        let b = KeyNamespace::Profile.derive_key(&master, 2).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn derive_is_deterministic() {
        let master = [9u8; 32];
        let k1 = KeyNamespace::Proxy.derive_key(&master, 42).unwrap();
        let k2 = KeyNamespace::Proxy.derive_key(&master, 42).unwrap();
        assert_eq!(k1, k2);
    }
}

//! Entity-scoped encryption helpers.
//!
//! Most persisted rows follow the same shape: one numeric id, a few
//! sensitive fields that need encryption under a per-entity key. This
//! module wires the three pieces together — [`SessionKey`] for the
//! master key, [`KeyNamespace`] for scoping, [`crate::sealed`] for the wire
//! format — so that adding a new encrypted entity only requires implementing
//! [`EncryptedEntity`] and calling the `*_entity_*` helpers.
//!
//! Example:
//!
//! ```
//! use incokit_e2ee::entity::{EncryptedEntity, seal_entity_json, try_unseal_entity_json};
//! use incokit_e2ee::namespace::KeyNamespace;
//! use incokit_e2ee::session::SessionKey;
//! use serde_json::json;
//!
//! struct ProxyRow { id: i64 }
//!
//! impl EncryptedEntity for ProxyRow {
//!     const NAMESPACE: KeyNamespace = KeyNamespace::Proxy;
//!     fn entity_id(&self) -> i64 { self.id }
//! }
//!
//! let session = SessionKey::new([42u8; 32]); // sourced from PIN unlock / keychain
//! let row = ProxyRow { id: 7 };
//! let payload = json!({ "host": "1.2.3.4", "port": 1080 });
//!
//! let blob = seal_entity_json(&session, &row, &payload).unwrap();
//! let back: serde_json::Value = try_unseal_entity_json(&session, &row, &blob).unwrap();
//! assert_eq!(back, payload);
//! ```

use crate::error::CryptoResult;
use crate::namespace::KeyNamespace;
use crate::sealed::{
    seal_json, seal_string, try_unseal_json, try_unseal_string, unseal_json, unseal_string,
};
use crate::session::SessionKey;
use serde::{de::DeserializeOwned, Serialize};

/// A type whose sensitive fields are encrypted under a per-entity key
/// derived from the session master key.
///
/// Implementors declare which [`KeyNamespace`] scopes their key and how
/// to pull the id used in derivation. The trait is intentionally small
/// — everything else lives in free functions keyed on the trait, so
/// there's no blanket-impl magic to debug.
pub trait EncryptedEntity {
    /// HKDF namespace — one per entity type.
    const NAMESPACE: KeyNamespace;

    /// Numeric id fed into the key-derivation info string. Must be
    /// stable for the lifetime of the row; if you renumber ids, you
    /// must rewrap every blob.
    fn entity_id(&self) -> i64;
}

impl SessionKey {
    /// Convenience: derive the per-entity key for a specific row.
    pub fn entity_key<E: EncryptedEntity>(&self, entity: &E) -> CryptoResult<[u8; 32]> {
        self.derive(E::NAMESPACE, entity.entity_id())
    }
}

// ─── string helpers ───────────────────────────────────────────────────────

pub fn seal_entity_string<E: EncryptedEntity>(
    session: &SessionKey,
    entity: &E,
    plaintext: &str,
) -> CryptoResult<String> {
    let key = session.entity_key(entity)?;
    seal_string(&key, plaintext)
}

/// Strict: reject plaintext (missing `e2ee:` prefix).
pub fn unseal_entity_string<E: EncryptedEntity>(
    session: &SessionKey,
    entity: &E,
    stored: &str,
) -> CryptoResult<String> {
    let key = session.entity_key(entity)?;
    unseal_string(&key, stored)
}

/// Lenient: accept legacy plaintext rows.
pub fn try_unseal_entity_string<E: EncryptedEntity>(
    session: &SessionKey,
    entity: &E,
    stored: &str,
) -> CryptoResult<String> {
    let key = session.entity_key(entity)?;
    try_unseal_string(&key, stored)
}

// ─── JSON helpers ─────────────────────────────────────────────────────────

pub fn seal_entity_json<E: EncryptedEntity, T: Serialize>(
    session: &SessionKey,
    entity: &E,
    value: &T,
) -> CryptoResult<String> {
    let key = session.entity_key(entity)?;
    seal_json(&key, value)
}

/// Strict: reject plaintext JSON.
pub fn unseal_entity_json<E: EncryptedEntity, T: DeserializeOwned>(
    session: &SessionKey,
    entity: &E,
    stored: &str,
) -> CryptoResult<T> {
    let key = session.entity_key(entity)?;
    unseal_json(&key, stored)
}

/// Lenient: accept legacy plaintext JSON rows.
pub fn try_unseal_entity_json<E: EncryptedEntity, T: DeserializeOwned>(
    session: &SessionKey,
    entity: &E,
    stored: &str,
) -> CryptoResult<T> {
    let key = session.entity_key(entity)?;
    try_unseal_json(&key, stored)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Dummy {
        id: i64,
    }

    impl EncryptedEntity for Dummy {
        const NAMESPACE: KeyNamespace = KeyNamespace::Profile;
        fn entity_id(&self) -> i64 {
            self.id
        }
    }

    fn session() -> SessionKey {
        SessionKey::new([42u8; 32])
    }

    #[test]
    fn roundtrip_string() {
        let s = session();
        let e = Dummy { id: 7 };
        let sealed = seal_entity_string(&s, &e, "hello").unwrap();
        assert_eq!(try_unseal_entity_string(&s, &e, &sealed).unwrap(), "hello");
    }

    #[test]
    fn different_ids_cannot_cross_decrypt() {
        let s = session();
        let a = Dummy { id: 1 };
        let b = Dummy { id: 2 };
        let sealed = seal_entity_string(&s, &a, "secret").unwrap();
        assert!(try_unseal_entity_string(&s, &b, &sealed).is_err());
    }

    #[test]
    fn plaintext_passes_through_try_variant() {
        let s = session();
        let e = Dummy { id: 1 };
        assert_eq!(
            try_unseal_entity_string(&s, &e, "legacy-plaintext").unwrap(),
            "legacy-plaintext"
        );
    }

    #[test]
    fn plaintext_rejected_by_strict_variant() {
        let s = session();
        let e = Dummy { id: 1 };
        assert!(unseal_entity_string(&s, &e, "legacy-plaintext").is_err());
    }

    // A second entity type sharing the SAME id space but a DIFFERENT
    // namespace. This is the realistic cross-entity collision: a proxy and a
    // profile can both have id=1.
    struct OtherEntity {
        id: i64,
    }
    impl EncryptedEntity for OtherEntity {
        const NAMESPACE: KeyNamespace = KeyNamespace::Proxy;
        fn entity_id(&self) -> i64 {
            self.id
        }
    }

    /// Same id, different namespace ⇒ different derived key ⇒ no cross-decrypt.
    /// Guards against a refactor that drops the namespace from key derivation,
    /// which would let one entity type read another's sealed fields.
    #[test]
    fn same_id_different_namespace_cannot_cross_decrypt() {
        let s = session();
        let profile = Dummy { id: 1 };
        let proxy = OtherEntity { id: 1 };

        let sealed = seal_entity_string(&s, &profile, "profile-secret").unwrap();
        assert!(
            try_unseal_entity_string(&s, &proxy, &sealed).is_err(),
            "a proxy key must not decrypt a profile blob sharing the same id"
        );
    }

    /// A different session master key derives different entity keys, so a
    /// blob sealed under one session can't be opened under another.
    #[test]
    fn different_session_key_cannot_decrypt() {
        let e = Dummy { id: 7 };
        let sealed = seal_entity_string(&session(), &e, "secret").unwrap();

        let other_session = SessionKey::new([99u8; 32]);
        assert!(unseal_entity_string(&other_session, &e, &sealed).is_err());
    }

    #[test]
    fn roundtrip_json() {
        use serde_json::json;
        let s = session();
        let e = Dummy { id: 3 };
        let value = json!({ "host": "1.2.3.4", "port": 1080 });

        let sealed = seal_entity_json(&s, &e, &value).unwrap();
        let back: serde_json::Value = try_unseal_entity_json(&s, &e, &sealed).unwrap();
        assert_eq!(back, value);
    }
}

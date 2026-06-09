//! # incokit-e2ee
//!
//! The end-to-end-encryption core extracted verbatim from the
//! [Incokit](https://incokit.com) desktop app. This is the exact code that
//! seals your profiles, proxies, and cookies before they ever leave your
//! machine — published so you don't have to take our word for it.
//!
//! ## What it does
//!
//! - **Master key** — a random 256-bit key, never sent to any server. It is
//!   wrapped by a PIN-derived key and (separately) a recovery key, both via
//!   Argon2id. Only the wrapped blobs are stored remotely.
//! - **Symmetric encryption** — AES-256-GCM with a fresh random 96-bit nonce
//!   per message ([`encryption`]).
//! - **Per-entity keys** — every profile/proxy/row gets its own key via
//!   HKDF-SHA256 from the master key, scoped by [`namespace::KeyNamespace`].
//!   A key for one entity cannot decrypt another's blob.
//! - **Sharing** — profile keys are sealed for another user with X25519
//!   ECDH + HKDF + AES-256-GCM ([`keys`]). The server only ever sees
//!   ciphertext and public keys.
//! - **Wire format** — `"e2ee:" + base64(nonce || ciphertext || tag)`
//!   ([`sealed`]), self-describing and forward-compatible.
//! - **Key hygiene** — [`session::SessionKey`] zeroizes on drop and refuses
//!   to be cloned, debugged, or serialized.
//!
//! ## Threat model (read this)
//!
//! We sell antidetect software, not snake oil, so here is the honest version.
//!
//! **What this protects:** the confidentiality and integrity of profile data
//! at rest on the server and in transit. A server operator, a database leak,
//! or a network observer sees only AES-256-GCM ciphertext and public keys.
//! Tampering is detected (the GCM auth tag fails). A key derived for one
//! entity, user, or namespace cannot open another's data.
//!
//! **What it does NOT protect, and we won't pretend otherwise:**
//!
//! - **A weak PIN.** The PIN wraps the master key through Argon2id, but a
//!   6-digit PIN is a 10⁶ space. The [`oprf`] module is a hash-based blind,
//!   **not** a true OPRF — see its module docs for the exact limitation and
//!   why we rely on server-side rate limiting (and plan a ristretto255 VOPRF
//!   / OPAQUE upgrade). If your threat model includes an attacker who can
//!   brute-force the PIN offline against a stolen wrapped blob, raise the PIN
//!   entropy.
//! - **A compromised endpoint.** If malware owns the machine while the app is
//!   unlocked, the master key is in memory. E2EE is not endpoint security.
//! - **Metadata.** Row existence, sizes, and timing are not hidden.
//!
//! ## Status
//!
//! Primitives are standard and come from audited crates (RustCrypto,
//! `x25519-dalek`, `argon2`). This crate has **not** had an independent
//! third-party audit. Read the code, run `cargo test`, and judge for
//! yourself — that's the whole point of publishing it.
//!
//! ## Crate layout
//!
//! | Module | Responsibility |
//! |--------|----------------|
//! | [`encryption`] | AES-256-GCM, Argon2id key derivation, master-key wrap/unwrap |
//! | [`keys`] | X25519 sharing, profile-key wrap, recovery-key format |
//! | [`namespace`] | Per-entity HKDF key derivation |
//! | [`sealed`] | `"e2ee:"` wire format (bytes/string/JSON) |
//! | [`entity`] | [`EncryptedEntity`] trait + per-entity seal/unseal helpers |
//! | [`session`] | [`SessionKey`] — zeroizing master-key handle |
//! | [`oprf`] | PIN blind/finalize (hash-based; see limitations) |
//! | [`error`] | [`CryptoError`] / [`CryptoResult`] |
//! | [`keychain`] | Optional OS-keychain storage (feature `keychain`) |

#![forbid(unsafe_code)]

pub mod encryption;
pub mod entity;
pub mod error;
pub mod keys;
pub mod namespace;
pub mod oprf;
pub mod sealed;
pub mod session;

#[cfg(feature = "keychain")]
pub mod keychain;

pub use entity::EncryptedEntity;
pub use error::{CryptoError, CryptoResult};
pub use namespace::KeyNamespace;
pub use session::SessionKey;

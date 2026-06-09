# incokit-e2ee

[![CI](https://github.com/incokit/incokit-e2ee/actions/workflows/ci.yml/badge.svg)](https://github.com/incokit/incokit-e2ee/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

The end-to-end-encryption core from the [Incokit](https://incokit.com) desktop
app — published verbatim so you can read exactly how your profiles, proxies,
and cookies are protected before they leave your machine.

> **Why this exists.** Incokit manages many isolated browser profiles and syncs
> them across machines. "Encrypted" is easy to claim. This is the actual code
> that does it. Read it, run the tests, decrypt the golden vectors yourself. No
> trust required.

## What it gives you

| | |
|---|---|
| **Symmetric** | AES-256-GCM, fresh random 96-bit nonce per message |
| **PIN/recovery** | Argon2id (64 MiB, 3 iterations, 4 lanes) wraps a random 256-bit master key |
| **Per-entity keys** | HKDF-SHA256, namespaced so one row's key can't open another's |
| **Sharing** | X25519 ECDH + HKDF + AES-256-GCM; the server only ever sees ciphertext + public keys |
| **Wire format** | `"e2ee:" + base64(nonce ‖ ciphertext ‖ tag)` — self-describing, forward-compatible |
| **Key hygiene** | `SessionKey` zeroizes on drop; no `Clone`, `Debug`, or `Serialize` |
| **Safety** | `#![forbid(unsafe_code)]`, all primitives from audited crates |

## Install

```toml
[dependencies]
incokit-e2ee = "0.1"

# Optional: store the master key in the OS keychain
# incokit-e2ee = { version = "0.1", features = ["keychain"] }
```

## Quick start

```rust
use incokit_e2ee::{
    encryption, keys,
    entity::{seal_entity_json, try_unseal_entity_json, EncryptedEntity},
    namespace::KeyNamespace,
    session::SessionKey,
};
use serde_json::json;

// 1. Derive a wrapping key from the user's PIN (Argon2id), generate a master key,
//    and store only the WRAPPED master key remotely.
let salt = keys::generate_salt();
let pin_key = encryption::derive_key(b"314159", &salt)?;
let master_key = keys::generate_master_key();
let wrapped = encryption::wrap_master_key(&pin_key, &master_key)?; // store this

// 2. On unlock, re-derive and unwrap. Wrong PIN => AES-GCM tag fails.
let master_key = encryption::unwrap_master_key(&pin_key, &wrapped)?;

// 3. Encrypt a row. Each entity gets its own key (namespace + id).
struct Profile { id: i64 }
impl EncryptedEntity for Profile {
    const NAMESPACE: KeyNamespace = KeyNamespace::Profile;
    fn entity_id(&self) -> i64 { self.id }
}

let session = SessionKey::new(master_key);     // zeroizes on drop
let profile = Profile { id: 42 };
let blob = seal_entity_json(&session, &profile, &json!({ "cookie": "secret" }))?;
assert!(blob.starts_with("e2ee:"));

let back: serde_json::Value = try_unseal_entity_json(&session, &profile, &blob)?;
# Ok::<(), incokit_e2ee::CryptoError>(())
```

Full lifecycle (PIN unlock, per-entity encryption, X25519 sharing):

```sh
cargo run --example full_flow
```

## Modules

- [`encryption`] — AES-256-GCM, Argon2id, master-key wrap/unwrap
- [`keys`] — X25519 sharing, profile-key wrap, recovery-key format/parse
- [`namespace`] — per-entity HKDF key derivation
- [`sealed`] — the `"e2ee:"` wire format (bytes / string / JSON)
- [`entity`] — the `EncryptedEntity` trait + per-entity helpers
- [`session`] — `SessionKey`, the zeroizing master-key handle
- [`oprf`] — PIN blind/finalize (hash-based — **read the limitations**)
- [`error`] — `CryptoError` / `CryptoResult`
- [`keychain`] — optional OS-keychain storage (feature `keychain`)

[`encryption`]: https://docs.rs/incokit-e2ee/latest/incokit_e2ee/encryption/
[`keys`]: https://docs.rs/incokit-e2ee/latest/incokit_e2ee/keys/
[`namespace`]: https://docs.rs/incokit-e2ee/latest/incokit_e2ee/namespace/
[`sealed`]: https://docs.rs/incokit-e2ee/latest/incokit_e2ee/sealed/
[`entity`]: https://docs.rs/incokit-e2ee/latest/incokit_e2ee/entity/
[`session`]: https://docs.rs/incokit-e2ee/latest/incokit_e2ee/session/
[`oprf`]: https://docs.rs/incokit-e2ee/latest/incokit_e2ee/oprf/
[`error`]: https://docs.rs/incokit-e2ee/latest/incokit_e2ee/error/
[`keychain`]: https://docs.rs/incokit-e2ee/latest/incokit_e2ee/keychain/

## Threat model (the honest version)

We sell antidetect software, not snake oil. Here's what this does and doesn't do.

**Protects:** confidentiality + integrity of data at rest and in transit. A
server operator, a DB leak, or a network observer sees only AES-256-GCM
ciphertext and public keys. Tampering is detected (GCM tag). A key derived for
one entity / user / namespace cannot decrypt another's data.

**Does NOT protect:**

- **A weak PIN.** A 6-digit PIN is a 10⁶ space. The [`oprf`] module is a
  hash-based blind, **not** a true OPRF — see its docs for the exact weakness.
  We rely on server-side rate limiting and plan a ristretto255 VOPRF / OPAQUE
  upgrade. If your attacker can brute-force the PIN offline against a stolen
  wrapped blob, use a higher-entropy secret.
- **A compromised endpoint.** While the app is unlocked, the master key is in
  memory. E2EE is not endpoint security.
- **Metadata.** Row existence, sizes, and timing are not hidden.

## Audit status

The primitives are standard and come from audited crates (RustCrypto,
`x25519-dalek`, `argon2`). **This crate has not had an independent third-party
audit.** The point of publishing it is so you don't have to take that on faith.

## Tests

```sh
cargo test                      # unit + integration + doctests
cargo test --features keychain  # also the OS-keychain encode/decode contract
```

`tests/golden_vectors.rs` pins the wire format and key derivation to fixed
outputs captured from the shipping app — including decrypting a ciphertext the
app itself produced. If those ever break, the format changed and real users'
data would stop decrypting.

## License

[MIT](./LICENSE)

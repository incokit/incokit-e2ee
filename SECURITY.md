# Security Policy

## Reporting a vulnerability

If you find a security issue in `incokit-e2ee`, please **do not open a public
issue**. Email **security@incokit.com** with:

- a description of the issue and its impact,
- steps to reproduce (a failing test or PoC is ideal),
- the commit hash you found it on.

We aim to acknowledge within 72 hours and to ship a fix or mitigation before any
public disclosure. We're happy to credit you in the release notes if you'd like.

## Scope

This crate is the cryptographic core. In scope:

- key derivation, encryption, decryption, and the wire format,
- the X25519 sharing flow,
- key handling (zeroization, accidental leakage via traits/serialization),
- the optional `keychain` storage path.

Known limitations are documented in the [README threat model](./README.md#threat-model-the-honest-version)
and the [`oprf` module docs](./src/oprf.rs) — the hash-based PIN blind is a
deliberate, documented design point, not a vulnerability report we need. A
ristretto255 VOPRF / OPAQUE upgrade is the tracked path; concrete proposals are
welcome.

## What we'd love reports about

- A way to decrypt data without the correct key.
- A namespace/entity/user isolation bypass (one key opening another's blob).
- Key material leaking into logs, clones, serialized output, or freed memory.
- A wire-format ambiguity that lets ciphertext be reinterpreted.

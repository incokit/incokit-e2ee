//! Golden-vector regression tests.
//!
//! This crate was extracted verbatim from the Incokit desktop app. These
//! tests lock the WIRE FORMAT and KEY DERIVATION to fixed, known-good outputs
//! captured from the original in-app implementation. If any of these fail, the
//! extraction (or a future change) altered the bytes a real user's data was
//! encrypted with — meaning existing ciphertext would no longer decrypt. They
//! must hold byte-for-byte forever, or ship with an explicit rewrap migration.
//!
//! Reference values were generated from the original `incokit_lib::crypto`
//! module (the code shipping in the desktop app). Deterministic functions are
//! asserted against exact bytes; the randomized AES-GCM path is verified by
//! decrypting a ciphertext the original produced.

use incokit_e2ee::{encryption, keys::format_recovery_key, namespace::KeyNamespace, oprf};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

// ── Argon2id (PIN/recovery key stretching) ───────────────────────────────────
// derive_key is deterministic: same (input, salt) → same 32-byte key. If the
// Argon2 params (64 MiB / 3 iters / 4 lanes / V0x13) ever change, every wrapped
// master key in the field becomes unrecoverable.
#[test]
fn argon2_derive_key_matches_app() {
    let dk = encryption::derive_key(b"123456", b"saltsaltsaltsaltsaltsaltsaltsalt").unwrap();
    assert_eq!(
        hex(&dk),
        "53f2075f9c08e84086646d8e3082c6a996a0f4044d7a56d73ab4c5f08ea83477",
    );
}

// ── HKDF per-entity key derivation ───────────────────────────────────────────
// The info strings ("incokit-profile:123", etc.) are the wire format. These
// pin them so no refactor can silently change what key a row was sealed under.
#[test]
fn hkdf_namespace_keys_match_app() {
    let master = [42u8; 32];

    assert_eq!(
        hex(&KeyNamespace::Profile.derive_key(&master, 123).unwrap()),
        "4e8847ce72473ab3eb6d82903979b78524a1ef916128dad615e1bc77c14c794f",
        "profile namespace info string changed",
    );
    assert_eq!(
        hex(&KeyNamespace::Proxy.derive_key(&master, 7).unwrap()),
        "9262c3980c46c1255d814362d9ac2a37e2605a613fb7928e29e1e320ae04127b",
        "proxy namespace info string changed",
    );
    assert_eq!(
        hex(&KeyNamespace::ProfileSharing.derive_key(&master, 0).unwrap()),
        "d0dd030213b554a2f8726b1174ef4c40961d16b3b82d4f159cadd0340d964e70",
        "sharing namespace info string changed",
    );
}

// ── OPRF blind/finalize (PIN-bound, user-bound) ──────────────────────────────
#[test]
fn oprf_blind_and_finalize_match_app() {
    assert_eq!(
        hex(&oprf::blind("user-1", "123456")),
        "866c9830cc5de2392c629b04e23f7915dea3bc8679d1ad4bfc48572c44ecd90a",
    );
    assert_eq!(
        hex(&oprf::finalize("user-1", "123456", &[99u8; 32])),
        "5a60261cbbca0e7941944b24ae807ce3723ede839fe120ae6fffb67386e1450d",
    );
}

// ── Recovery key display format ──────────────────────────────────────────────
#[test]
fn recovery_key_format_matches_app() {
    assert_eq!(
        format_recovery_key(&[0xABu8; 32]),
        "ABABABAB-ABABABAB-ABABABAB-ABABABAB-ABABABAB-ABABABAB-ABABABAB-ABABABAB",
    );
}

// ── AES-256-GCM cross-version decrypt ────────────────────────────────────────
// encrypt() uses a fresh random nonce, so its output isn't a fixed vector. But
// the FORMAT (nonce || ciphertext || tag) must be stable: this ciphertext was
// produced by the ORIGINAL app code with key [7u8; 32]. If this crate can still
// decrypt it to the original plaintext, the wire format is byte-compatible.
#[test]
fn decrypts_ciphertext_produced_by_app() {
    let key = [7u8; 32];
    let ciphertext = hex_decode(
        "b1d408f84e85fccfc6979c9e2ec659830f23d42be3448dd948186ab2fb2da7f073e46531406837f2e0304eab",
    );
    let plaintext = encryption::decrypt(&key, &ciphertext).unwrap();
    assert_eq!(plaintext, b"golden plaintext");
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

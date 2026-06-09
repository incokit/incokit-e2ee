//! End-to-end walkthrough of the whole E2EE lifecycle, top to bottom.
//!
//! Run it: `cargo run --example full_flow`
//!
//! Everything here is deterministic except the random key/nonce generation,
//! so the printed ciphertext changes each run — but every roundtrip asserts,
//! so a successful run proves the API does what it claims.

use incokit_e2ee::{
    encryption,
    entity::{seal_entity_json, try_unseal_entity_json, EncryptedEntity},
    keys,
    namespace::KeyNamespace,
    sealed::{seal_string, unseal_string},
    session::SessionKey,
};
use serde_json::json;

// Any row you want to encrypt implements EncryptedEntity: pick a namespace
// (so a proxy key can't open a profile blob) and expose its numeric id.
struct ProfileRow {
    id: i64,
}
impl EncryptedEntity for ProfileRow {
    const NAMESPACE: KeyNamespace = KeyNamespace::Profile;
    fn entity_id(&self) -> i64 {
        self.id
    }
}

fn main() {
    println!("== 1. Set up the master key from a PIN ==");
    // In a real app the salt is random + stored server-side; the PIN comes
    // from the user. derive_key runs Argon2id (64 MiB, 3 iterations).
    let user_salt = keys::generate_salt();
    let pin = "314159";
    let pin_key = encryption::derive_key(pin.as_bytes(), &user_salt).unwrap();

    // The master key is random and never leaves the device in the clear.
    let master_key = keys::generate_master_key();

    // Wrap the master key under the PIN-derived key. Only THIS blob is stored
    // remotely — the server never sees `master_key`.
    let wrapped = encryption::wrap_master_key(&pin_key, &master_key).unwrap();
    println!(
        "   wrapped master key ({} bytes) is what the server stores",
        wrapped.len()
    );

    // On unlock: re-derive from the PIN, unwrap. Wrong PIN → AES-GCM tag fails.
    let pin_key_again = encryption::derive_key(pin.as_bytes(), &user_salt).unwrap();
    let unwrapped = encryption::unwrap_master_key(&pin_key_again, &wrapped).unwrap();
    assert_eq!(unwrapped, master_key);
    println!("   unlocked: master key recovered from PIN ✓");

    println!("\n== 2. Encrypt a profile's fields (per-entity key) ==");
    // Wrap the master key in a SessionKey: it zeroizes on drop and won't clone.
    let session = SessionKey::new(master_key);
    let profile = ProfileRow { id: 42 };

    let secrets = json!({
        "cookies": [{ "name": "sid", "value": "abc123" }],
        "proxy": "socks5://user:pass@1.2.3.4:1080",
    });

    // seal_entity_json derives a per-(namespace, id) key under the hood.
    let blob = seal_entity_json(&session, &profile, &secrets).unwrap();
    println!("   stored blob: {}…", &blob[..40.min(blob.len())]);
    assert!(blob.starts_with("e2ee:"));
    assert!(!blob.contains("abc123"), "secret must not appear in clear");

    let restored: serde_json::Value = try_unseal_entity_json(&session, &profile, &blob).unwrap();
    assert_eq!(restored, secrets);
    println!("   decrypted back to the original JSON ✓");

    // A DIFFERENT profile id cannot open this blob.
    let other = ProfileRow { id: 99 };
    assert!(try_unseal_entity_json::<_, serde_json::Value>(&session, &other, &blob).is_err());
    println!("   profile #99 cannot decrypt profile #42's blob ✓");

    println!("\n== 3. Share a profile key with another user (X25519) ==");
    // Each user has an X25519 keypair. Alice shares a profile key with Bob.
    let (alice_priv, alice_pub) = keys::generate_x25519_keypair();
    let (bob_priv, bob_pub) = keys::generate_x25519_keypair();
    let profile_key = keys::generate_profile_key();

    // Alice seals the profile key FOR Bob.
    let sealed_for_bob =
        keys::encrypt_profile_key_for_sharing(&alice_priv, &bob_pub, &profile_key).unwrap();

    // Bob opens it with his private key + Alice's public key.
    let bob_got = keys::decrypt_shared_profile_key(&bob_priv, &alice_pub, &sealed_for_bob).unwrap();
    assert_eq!(bob_got, profile_key);
    println!("   Bob recovered the shared profile key ✓");

    println!("\n== 4. Plain string seal/unseal (wire format) ==");
    let s = seal_string(session.as_bytes(), "hello").unwrap();
    println!("   seal_string -> {s}");
    assert_eq!(unseal_string(session.as_bytes(), &s).unwrap(), "hello");

    println!("\nAll steps verified. This is the same code Incokit ships.");
}

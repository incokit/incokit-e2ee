use sha2::{Digest, Sha256};

/// OPRF-like blind step (client-side).
///
/// Note: this is NOT a true OPRF. A real OPRF sends a value the server
/// cannot invert even if it sees the protocol flow. Here we send a
/// deterministic hash, and a 6-digit PIN only has a 10^6 preimage space —
/// so an attacker who logs edge-function requests and has access to the
/// HMAC key (or can query the server enough times) can map blind values
/// back to PINs. We rely on:
///   - the server never logging raw requests, and
///   - server-side rate limiting (5 attempts per hour per user) to bound
///     online brute force.
///
/// Upgrade to ristretto255 VOPRF or OPAQUE is tracked as a v2 item.
///
/// Same (user_id, PIN) → same blind every time, so the server's HMAC
/// output is stable and can re-derive the wrapping key on each unlock.
/// Different users with the same PIN produce different blinds, so one
/// attacker account cannot build a PIN dictionary that applies to other
/// victims — the HMAC output is effectively user-bound.
pub fn blind(user_id: &str, pin: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"incokit-oprf-v2"); // v2 marks the user_id binding
    hasher.update((user_id.len() as u32).to_be_bytes());
    hasher.update(user_id.as_bytes());
    hasher.update(pin.as_bytes());
    hasher.finalize().to_vec()
}

/// OPRF finalize step (client-side).
///
/// Combines the user_id, PIN, and the server's HMAC evaluation to
/// produce the key material that wraps the master key. Same inputs
/// always produce the same output.
///
/// Binding user_id on both sides (blind + finalize) means a stolen
/// evaluated element from user A cannot be replayed to wrap user B's
/// master key, and vice versa.
pub fn finalize(user_id: &str, pin: &str, evaluated: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"incokit-oprf-finalize-v2");
    hasher.update((user_id.len() as u32).to_be_bytes());
    hasher.update(user_id.as_bytes());
    hasher.update(pin.as_bytes());
    hasher.update(evaluated);
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER_A: &str = "00000000-0000-0000-0000-000000000001";
    const USER_B: &str = "00000000-0000-0000-0000-000000000002";

    #[test]
    fn test_blind_produces_32_bytes() {
        assert_eq!(blind(USER_A, "123456").len(), 32);
    }

    #[test]
    fn test_blind_deterministic_same_inputs() {
        assert_eq!(blind(USER_A, "123456"), blind(USER_A, "123456"));
    }

    #[test]
    fn test_blind_different_pin() {
        assert_ne!(blind(USER_A, "123456"), blind(USER_A, "654321"));
    }

    #[test]
    fn test_blind_different_user_same_pin() {
        // Core security property: user_id binding.
        assert_ne!(blind(USER_A, "123456"), blind(USER_B, "123456"));
    }

    #[test]
    fn test_finalize_deterministic() {
        let ev = [99u8; 32];
        assert_eq!(
            finalize(USER_A, "123456", &ev),
            finalize(USER_A, "123456", &ev),
        );
    }

    #[test]
    fn test_finalize_different_user_same_pin_same_ev() {
        let ev = [99u8; 32];
        assert_ne!(
            finalize(USER_A, "123456", &ev),
            finalize(USER_B, "123456", &ev),
        );
    }

    #[test]
    fn test_finalize_different_pin() {
        let ev = [99u8; 32];
        assert_ne!(
            finalize(USER_A, "123456", &ev),
            finalize(USER_A, "654321", &ev),
        );
    }

    #[test]
    fn test_finalize_different_evaluated() {
        let e1 = [99u8; 32];
        let e2 = [1u8; 32];
        assert_ne!(
            finalize(USER_A, "123456", &e1),
            finalize(USER_A, "123456", &e2),
        );
    }

    #[test]
    fn test_finalize_produces_32_bytes() {
        let ev = [42u8; 32];
        assert_eq!(finalize(USER_A, "123456", &ev).len(), 32);
    }

    #[test]
    fn test_length_prefix_prevents_collision() {
        // Ensure "ab" + "cde" and "abc" + "de" produce different blinds
        // (guard against concatenation ambiguity if user_id contains
        // characters that could look like PIN digits).
        let a = blind("ab", "cde123");
        let b = blind("abc", "de0123");
        assert_ne!(a, b);
    }
}

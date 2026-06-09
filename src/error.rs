//! Precise error type for the crypto layer.
//!
//! Library code uses `CryptoResult<T>` (= `Result<T, CryptoError>`). A blanket
//! `From<CryptoError> for String` impl is provided so callers that need a flat
//! string (e.g. an IPC/FFI boundary that serializes errors as text) can convert
//! with `?` without losing the original `Display` message.
//!
//! Why not just `String` everywhere? Because "Encryption failed" collapses
//! wrong-key, truncated-ciphertext, and malformed-base64 into one message,
//! which makes debugging and telemetry harder. The enum preserves shape
//! without changing the user-facing surface.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("encryption is locked — unlock before retrying")]
    NotUnlocked,

    #[error("session belongs to a different user")]
    UserIdMismatch,

    #[error("invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    #[error("AES-GCM encrypt failed")]
    Encrypt,

    #[error("AES-GCM decrypt failed (wrong key or corrupted data)")]
    Decrypt,

    #[error("ciphertext too short: need at least {min} bytes, got {actual}")]
    CiphertextTooShort { min: usize, actual: usize },

    #[error("Argon2 parameters error: {0}")]
    Argon2Params(String),

    #[error("Argon2 hash failed: {0}")]
    Argon2Hash(String),

    #[error("HKDF expand failed: {0}")]
    Hkdf(String),

    #[error("base64 decode: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("utf-8: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),

    /// Returned by strict decrypt paths when input does not start with the
    /// wire-format prefix `"e2ee:"`. Callers that want to tolerate legacy
    /// plaintext rows should use `try_unseal_*` variants instead.
    #[error("missing e2ee prefix — data is not encrypted")]
    MissingE2eePrefix,
}

impl From<CryptoError> for String {
    fn from(e: CryptoError) -> Self {
        e.to_string()
    }
}

pub type CryptoResult<T> = Result<T, CryptoError>;

// SPDX-License-Identifier: GPL-3.0-or-later

//! Error type for `vault-core`.

use thiserror::Error;

/// All fallible operations in `vault-core` return this error.
#[derive(Debug, Error)]
pub enum Error {
    /// A malformed Bitwarden `EncString` was encountered.
    #[error("malformed EncString: {0}")]
    EncString(&'static str),

    /// Base64 decoding of an `EncString` component failed.
    #[error("base64 decode failed: {0}")]
    Base64(#[from] base64::DecodeError),

    /// HMAC verification of an `EncString` failed — ciphertext is corrupt or the wrong MAC key was used.
    #[error("MAC verification failed")]
    MacMismatch,

    /// CBC unpadding of decrypted plaintext failed.
    #[error("CBC unpadding failed")]
    Unpad,

    /// A KDF parameter was outside its accepted range.
    #[error("invalid KDF parameters: {0}")]
    Kdf(&'static str),

    /// Argon2 KDF reported an internal error.
    #[error("argon2: {0}")]
    Argon2(argon2::Error),

    /// HKDF expansion failed (output length out of range).
    #[error("HKDF expand failed")]
    Hkdf,

    /// JSON parsing of an encrypted export envelope failed.
    #[error("export JSON parse failed: {0}")]
    Json(#[from] serde_json::Error),

    /// The supplied export password did not validate against `encKeyValidation_DO_NOT_EDIT`.
    #[error("export password did not validate")]
    BadExportPassword,

    /// The export envelope declared an unsupported version or KDF type.
    #[error("unsupported export format: {0}")]
    UnsupportedExport(&'static str),

    /// Password generation could not satisfy the requested options.
    #[error("generate: {0}")]
    Generate(&'static str),
}

impl From<argon2::Error> for Error {
    fn from(e: argon2::Error) -> Self {
        Self::Argon2(e)
    }
}

/// Convenience `Result` alias used throughout `vault-core`.
pub type Result<T> = core::result::Result<T, Error>;

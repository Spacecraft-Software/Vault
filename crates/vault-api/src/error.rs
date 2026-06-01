// SPDX-License-Identifier: GPL-3.0-or-later

//! Error type for `vault-api`.

use thiserror::Error;

/// All fallible operations in `vault-api` return this error.
#[derive(Debug, Error)]
pub enum Error {
    /// Underlying transport failure (DNS, TCP, TLS, HTTP framing).
    #[error("transport: {0}")]
    Transport(#[from] reqwest::Error),

    /// Server returned a non-success HTTP status with an error body.
    #[error("server returned {status}: {message}")]
    ServerStatus {
        /// HTTP status code from the server.
        status: u16,
        /// Human-readable message, drawn from the response body when present.
        message: String,
    },

    /// Server response body could not be deserialized.
    #[error("malformed response: {0}")]
    Decode(#[from] serde_json::Error),

    /// `BaseUrls::infer_from` could not split a single base URL into api/identity halves.
    #[error("invalid base URL: {0}")]
    BaseUrl(&'static str),

    /// Operation requires a two-factor token Vault doesn't yet support (M2).
    #[error("two-factor authentication required (provider {0:?}) — not yet implemented")]
    TwoFactorRequired(Vec<u32>),

    /// vault-core surfaced an error (KDF, hashing, etc.) during the API flow.
    #[error("crypto: {0}")]
    Crypto(#[from] vault_core::Error),
}

/// Convenience `Result` alias used throughout `vault-api`.
pub type Result<T> = core::result::Result<T, Error>;

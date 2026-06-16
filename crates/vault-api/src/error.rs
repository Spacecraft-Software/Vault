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

    /// A caller-supplied credential was malformed (e.g. a non-UTF-8 API-key secret).
    #[error("invalid credential: {0}")]
    Credential(&'static str),

    /// Operation requires a two-factor token Vault doesn't yet support (M2).
    #[error("two-factor authentication required (provider {0:?}) — not yet implemented")]
    TwoFactorRequired(Vec<u32>),

    /// vault-core surfaced an error (KDF, hashing, etc.) during the API flow.
    #[error("crypto: {0}")]
    Crypto(#[from] vault_core::Error),

    /// The post-quantum transport (feature `pqc`) could not build its rustls
    /// client config. Not expected in practice (safe defaults are always valid).
    #[cfg(feature = "pqc")]
    #[error("pqc tls config: {0}")]
    PqcTls(String),
}

/// Convenience `Result` alias used throughout `vault-api`.
pub type Result<T> = core::result::Result<T, Error>;

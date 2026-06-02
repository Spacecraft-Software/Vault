// SPDX-License-Identifier: GPL-3.0-or-later

//! Master-password hash for the `/identity/connect/token` flow.
//!
//! Bitwarden never sends the user's master password to the server. Instead it
//! sends a *master-password hash* derived as:
//!
//! ```text
//! master_key = KDF(password, email_lowercase, kdf_params)         // 32 bytes
//! master_password_hash = PBKDF2-SHA-256(
//!     password = master_key,
//!     salt     = password_bytes,
//!     iters    = 1,
//!     length   = 32,
//! )
//! ```
//!
//! The hash is then base64-encoded and supplied as the `password` field of
//! the OAuth password-grant request. Server-side, the same hash is computed
//! during registration and only the hash is stored.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha256;

use crate::error::{Error, Result};

/// Compute the base64-encoded master-password hash sent to `/identity/connect/token`.
///
/// # Errors
///
/// Returns [`Error::Kdf`] if the single-iteration PBKDF2 reports an invalid
/// output length (unreachable for the fixed 32-byte output here).
pub fn master_password_hash(master_key: &[u8; 32], password: &[u8]) -> Result<String> {
    let mut out = [0u8; 32];
    pbkdf2::<Hmac<Sha256>>(master_key, password, 1, &mut out)
        .map_err(|_| Error::Kdf("master-password-hash output length"))?;
    Ok(B64.encode(out))
}

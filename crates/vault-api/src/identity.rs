// SPDX-License-Identifier: GPL-3.0-or-later

//! Identity service — prelogin (KDF discovery) and OAuth2 password-grant token.

use serde::{Deserialize, Serialize};
use vault_core::kdf::{KdfParams, KdfType};

/// `POST /accounts/prelogin` response.
///
/// The server returns the KDF parameters tied to the account's email so the
/// client can derive the master key locally.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreloginResponse {
    /// KDF discriminant (0 = PBKDF2-SHA-256, 1 = Argon2id).
    pub kdf: u8,
    /// PBKDF2 iterations, or Argon2 `t_cost`.
    pub kdf_iterations: u32,
    /// Argon2 memory cost in KiB (only for Argon2id).
    #[serde(default)]
    pub kdf_memory: Option<u32>,
    /// Argon2 parallelism lanes (only for Argon2id).
    #[serde(default)]
    pub kdf_parallelism: Option<u32>,
}

impl PreloginResponse {
    /// Translate the server's prelogin response into a `KdfParams`.
    pub fn into_kdf_params(self) -> Result<KdfParams, vault_core::Error> {
        let kind = KdfType::try_from(self.kdf)?;
        Ok(KdfParams {
            kind,
            iterations: self.kdf_iterations,
            memory_kib: self.kdf_memory,
            parallelism: self.kdf_parallelism,
        })
    }
}

/// `POST /connect/token` success body — a subset; fields Vault does not yet
/// use are kept as `serde_json::Value` so unknown extensions don't fail.
#[derive(Clone, Debug, Deserialize)]
pub struct TokenResponse {
    /// OAuth2 access token, used as `Authorization: Bearer …` on API calls.
    pub access_token: String,
    /// Seconds until `access_token` expires.
    #[serde(default)]
    pub expires_in: u64,
    /// `Bearer`.
    pub token_type: String,
    /// OAuth2 refresh token for renewing the access token without re-prompt.
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// Encrypted user symmetric key (EncString form). Decrypts to a 64-byte
    /// enc+mac pair under the stretched master key.
    #[serde(default, rename = "Key")]
    pub key: Option<String>,
    /// Encrypted RSA private key (EncString form).
    #[serde(default, rename = "PrivateKey")]
    pub private_key: Option<String>,
}

/// `POST /connect/token` error body in the 2FA-required shape.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TwoFactorErrorBody {
    /// Map of provider id → provider parameters (Vault doesn't read the params yet).
    pub two_factor_providers2: Option<serde_json::Value>,
    /// Legacy form — list of provider ids only.
    pub two_factor_providers: Option<Vec<u32>>,
}

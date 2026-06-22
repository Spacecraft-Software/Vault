// SPDX-License-Identifier: GPL-3.0-or-later

//! Identity service — prelogin (KDF discovery) and `OAuth2` password-grant token.

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
    ///
    /// # Errors
    ///
    /// Returns [`vault_core::Error::Kdf`] if the `kdf` discriminant is not a
    /// KDF type Vault supports.
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
    /// `OAuth2` access token, used as `Authorization: Bearer …` on API calls.
    pub access_token: String,
    /// Seconds until `access_token` expires.
    #[serde(default)]
    pub expires_in: u64,
    /// `Bearer`.
    pub token_type: String,
    /// `OAuth2` refresh token for renewing the access token without re-prompt.
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// Encrypted user symmetric key (`EncString` form). Decrypts to a 64-byte
    /// enc+mac pair under the stretched master key.
    #[serde(default, rename = "Key")]
    pub key: Option<String>,
    /// Encrypted RSA private key (`EncString` form).
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
    #[serde(default, deserialize_with = "deserialize_provider_ids")]
    pub two_factor_providers: Option<Vec<u32>>,
}

/// Deserialize the legacy `TwoFactorProviders` list tolerantly.
///
/// Bitwarden's hosted server serializes the provider ids as **strings**
/// (`["0","7"]`), while other deployments have sent them as integers (`[0,7]`).
/// A strict `Vec<u32>` rejected the string form — and because that failed the
/// *entire* [`TwoFactorErrorBody`] parse, a real 2FA challenge was silently
/// downgraded into a generic `invalid_grant` ("bad password"). Accept either
/// representation, and never fail on an unexpected entry: 2FA detection must be
/// robust, and the ids are only used as a non-empty signal.
fn deserialize_provider_ids<'de, D>(deserializer: D) -> Result<Option<Vec<u32>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = Option::<Vec<serde_json::Value>>::deserialize(deserializer)?;
    Ok(raw.map(|values| {
        values
            .iter()
            .filter_map(|v| {
                v.as_u64()
                    .and_then(|n| u32::try_from(n).ok())
                    .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
            })
            .collect()
    }))
}

#[cfg(test)]
mod tests {
    use super::TwoFactorErrorBody;

    /// The exact shape Bitwarden's hosted server returns: provider ids as
    /// **strings** in the legacy array, plus the modern providers map. Regression
    /// guard for the bug where the string ids failed the whole parse and a 2FA
    /// challenge surfaced as "bad password".
    #[test]
    fn parses_bitwarden_cloud_two_factor_challenge() {
        let body = r#"{
            "error":"invalid_grant",
            "error_description":"Two factor required.",
            "TwoFactorProviders":["0","7"],
            "TwoFactorProviders2":{"0":null,"7":{"challenge":"abc"}},
            "MasterPasswordPolicy":{"Object":"masterPasswordPolicy"}
        }"#;
        let parsed: TwoFactorErrorBody = serde_json::from_str(body).expect("2FA body must parse");
        assert_eq!(parsed.two_factor_providers, Some(vec![0, 7]));
        assert!(parsed.two_factor_providers2.is_some());
    }

    /// Integer-id deployments must still parse.
    #[test]
    fn parses_integer_provider_ids() {
        let parsed: TwoFactorErrorBody =
            serde_json::from_str(r#"{"TwoFactorProviders":[0,7]}"#).unwrap();
        assert_eq!(parsed.two_factor_providers, Some(vec![0, 7]));
    }

    /// A genuine bad-password 400 (no 2FA fields) parses to all-None, so the
    /// caller correctly treats it as a credential failure rather than 2FA.
    #[test]
    fn genuine_bad_password_has_no_providers() {
        let body =
            r#"{"error":"invalid_grant","error_description":"username or password is incorrect"}"#;
        let parsed: TwoFactorErrorBody = serde_json::from_str(body).unwrap();
        assert!(parsed.two_factor_providers.is_none());
        assert!(parsed.two_factor_providers2.is_none());
    }
}

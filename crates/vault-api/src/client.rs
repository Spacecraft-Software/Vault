// SPDX-License-Identifier: GPL-3.0-or-later

//! Bitwarden / Vaultwarden REST client.
//!
//! The client owns the HTTP transport, the device identifier, and the most
//! recent access token. It does **not** hold the master key or the user
//! symmetric key — those live behind the agent boundary (PRD §7.3) and are
//! supplied to the client only for the brief moment they're needed to compute
//! the master-password hash.

use reqwest::Client;
use reqwest::header::{HeaderMap, HeaderValue};
use uuid::Uuid;
use zeroize::Zeroizing;

use vault_core::kdf::{KdfParams, derive_master_key};
use vault_core::login::master_password_hash;

use crate::error::{Error, Result};
use crate::identity::{PreloginResponse, TokenResponse, TwoFactorErrorBody};
use crate::sync::SyncResponse;
use crate::urls::BaseUrls;

/// Bitwarden CLI client identifier (matches the official CLI and rbw).
pub const CLIENT_ID: &str = "cli";
/// Bitwarden device-type for desktop / CLI clients.
pub const DEVICE_TYPE_CLI: u32 = 14;

/// REST client for a single Bitwarden / Vaultwarden account.
#[derive(Debug)]
pub struct BitwardenClient {
    http: Client,
    urls: BaseUrls,
    device_id: Uuid,
    device_name: String,
    user_agent: String,
    access_token: Option<Zeroizing<String>>,
}

impl BitwardenClient {
    /// Build a new client pointed at `urls`. The device identifier persists
    /// across calls and should be saved by the caller across process restarts.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Transport`] if the underlying `reqwest` client fails to build.
    pub fn new(urls: BaseUrls, device_id: Uuid, device_name: impl Into<String>) -> Result<Self> {
        let user_agent = format!("vault/{} (Spacecraft-Software)", env!("CARGO_PKG_VERSION"));
        let http = Client::builder()
            .user_agent(&user_agent)
            .https_only(urls.api.scheme() == "https")
            .build()?;
        Ok(Self {
            http,
            urls,
            device_id,
            device_name: device_name.into(),
            user_agent,
            access_token: None,
        })
    }

    /// Construct from an existing `reqwest::Client` — primarily for tests
    /// that need to point a fresh client at a wiremock origin.
    pub fn new_with_http(
        http: Client,
        urls: BaseUrls,
        device_id: Uuid,
        device_name: impl Into<String>,
    ) -> Self {
        let user_agent = format!("vault/{} (Spacecraft-Software)", env!("CARGO_PKG_VERSION"));
        Self {
            http,
            urls,
            device_id,
            device_name: device_name.into(),
            user_agent,
            access_token: None,
        }
    }

    /// Stable per-install device identifier (matches Bitwarden's `deviceIdentifier`).
    #[must_use]
    pub const fn device_id(&self) -> Uuid {
        self.device_id
    }

    /// `User-Agent` sent on every request.
    #[must_use]
    pub fn user_agent(&self) -> &str {
        &self.user_agent
    }

    /// Whether the client currently holds a valid-looking access token.
    #[must_use]
    pub const fn is_authenticated(&self) -> bool {
        self.access_token.is_some()
    }

    /// `POST /accounts/prelogin` — discover the account's KDF parameters.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Transport`] on transport failure or [`Error::ServerStatus`]
    /// if the server rejects the prelogin request.
    pub async fn prelogin(&self, email: &str) -> Result<PreloginResponse> {
        let url = self
            .urls
            .identity
            .join("accounts/prelogin")
            .map_err(|_| Error::BaseUrl("could not build prelogin URL"))?;
        let body = serde_json::json!({ "email": email });
        let resp = self.http.post(url).json(&body).send().await?;
        handle_json(resp).await
    }

    /// `POST /connect/token` — exchange `(email, master_password)` for an
    /// access token, given the prelogin KDF parameters.
    ///
    /// The supplied password is consumed to compute the master-password hash
    /// and discarded; only the resulting hash leaves this function.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TwoFactorRequired`] if the account has 2FA enabled,
    /// [`Error::ServerStatus`] on a bad password / other non-success status,
    /// or a crypto error if master-key derivation fails.
    pub async fn login_password(
        &mut self,
        email: &str,
        password: &[u8],
        params: KdfParams,
    ) -> Result<TokenResponse> {
        let email_lower = email.trim().to_lowercase();
        let master_key = derive_master_key(password, email_lower.as_bytes(), params)?;
        let hash = master_password_hash(&master_key, password)?;

        let url = self
            .urls
            .identity
            .join("connect/token")
            .map_err(|_| Error::BaseUrl("could not build token URL"))?;

        let form: [(&str, &str); 8] = [
            ("grant_type", "password"),
            ("username", email_lower.as_str()),
            ("password", hash.as_str()),
            ("scope", "api offline_access"),
            ("client_id", CLIENT_ID),
            ("deviceType", "14"),
            ("deviceIdentifier", &self.device_id.to_string()),
            ("deviceName", &self.device_name),
        ];

        let resp = self
            .http
            .post(url)
            .header("Auth-Email", base64_url_no_pad(email_lower.as_bytes()))
            .form(&form)
            .send()
            .await?;

        let status = resp.status();
        if status.is_success() {
            let token: TokenResponse = resp.json().await?;
            self.access_token = Some(Zeroizing::new(token.access_token.clone()));
            Ok(token)
        } else if status.as_u16() == 400 {
            // Could be 2FA-required or bad-password — peek at the body.
            let body = resp.text().await.unwrap_or_default();
            if let Ok(tfa) = serde_json::from_str::<TwoFactorErrorBody>(&body) {
                if let Some(legacy) = tfa.two_factor_providers
                    && !legacy.is_empty()
                {
                    return Err(Error::TwoFactorRequired(legacy));
                }
                if tfa.two_factor_providers2.is_some() {
                    return Err(Error::TwoFactorRequired(vec![]));
                }
            }
            Err(Error::ServerStatus {
                status: status.as_u16(),
                message: body,
            })
        } else {
            Err(Error::ServerStatus {
                status: status.as_u16(),
                message: resp.text().await.unwrap_or_default(),
            })
        }
    }

    /// `GET /sync` — fetch the full encrypted vault. Requires a prior `login_password`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ServerStatus`] if no access token is held or the
    /// server replies non-2xx, or [`Error::Transport`] on transport failure.
    ///
    /// # Panics
    ///
    /// Never: the `Bearer` header is built from an ASCII access token.
    #[allow(clippy::expect_used)] // access tokens are ASCII; HeaderValue construction cannot fail
    pub async fn sync(&self) -> Result<SyncResponse> {
        let token = self.access_token.as_ref().ok_or(Error::ServerStatus {
            status: 401,
            message: "no access token; call login_password() first".into(),
        })?;

        let url = self
            .urls
            .api
            .join("sync")
            .map_err(|_| Error::BaseUrl("could not build sync URL"))?;

        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            HeaderValue::try_from(format!("Bearer {}", token.as_str())).expect("token is ASCII"),
        );

        let resp = self.http.get(url).headers(headers).send().await?;
        handle_json(resp).await
    }

    /// `DELETE /api/ciphers/{id}` — soft-delete a cipher.
    ///
    /// Bitwarden's hosted API and Vaultwarden both move the cipher to the
    /// account's trash; the user can restore it from the web UI for ~30 days
    /// (hosted) or until purged (Vaultwarden). This client surfaces only the
    /// delete; restore is out of scope for Vault.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ServerStatus`] if the client lacks an access token,
    /// if the server replies with a non-2xx status (`404` if the id is
    /// unknown, `401` if the token is expired). Returns [`Error::Transport`] on
    /// transport failure.
    ///
    /// # Panics
    ///
    /// Never: the `Bearer` header is built from an ASCII access token.
    #[allow(clippy::expect_used)] // access tokens are ASCII; HeaderValue construction cannot fail
    pub async fn delete_cipher(&self, id: &str) -> Result<()> {
        let token = self.access_token.as_ref().ok_or(Error::ServerStatus {
            status: 401,
            message: "no access token; call login_password() first".into(),
        })?;

        let url = self
            .urls
            .api
            .join(&format!("ciphers/{id}"))
            .map_err(|_| Error::BaseUrl("could not build delete-cipher URL"))?;

        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            HeaderValue::try_from(format!("Bearer {}", token.as_str())).expect("token is ASCII"),
        );

        let resp = self.http.delete(url).headers(headers).send().await?;
        let status = resp.status();
        if status.is_success() {
            Ok(())
        } else {
            Err(Error::ServerStatus {
                status: status.as_u16(),
                message: resp.text().await.unwrap_or_default(),
            })
        }
    }
}

async fn handle_json<T: serde::de::DeserializeOwned>(resp: reqwest::Response) -> Result<T> {
    let status = resp.status();
    if status.is_success() {
        Ok(resp.json().await?)
    } else {
        Err(Error::ServerStatus {
            status: status.as_u16(),
            message: resp.text().await.unwrap_or_default(),
        })
    }
}

fn base64_url_no_pad(b: &[u8]) -> String {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    B64URL.encode(b)
}

// SPDX-License-Identifier: GPL-3.0-or-later

//! Bitwarden / Vaultwarden REST client.
//!
//! The client owns the HTTP transport, the device identifier, and the most
//! recent access token. It does **not** hold the master key or the user
//! symmetric key — those live behind the agent boundary (PRD §7.3) and are
//! supplied to the client only for the brief moment they're needed to compute
//! the master-password hash.

use reqwest::Client;
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
    refresh_token: Option<Zeroizing<String>>,
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
            refresh_token: None,
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
            refresh_token: None,
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

    /// The current refresh token, if any — so the caller can persist it
    /// (encrypted) for a later `refresh` without re-prompting for the password.
    #[must_use]
    pub fn refresh_token(&self) -> Option<&str> {
        self.refresh_token.as_ref().map(|z| z.as_str())
    }

    /// Seed the client with a refresh token (no access token yet) — used to
    /// rebuild an authenticated session from a persisted refresh token. Call
    /// [`refresh`](Self::refresh) afterwards to obtain an access token.
    pub fn set_refresh_token(&mut self, refresh_token: String) {
        self.refresh_token = Some(Zeroizing::new(refresh_token));
    }

    /// Build a token-less client seeded with a refresh token (for restoring a
    /// session from the cache). Call [`refresh`](Self::refresh) to go live.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Transport`] if the `reqwest` client fails to build.
    pub fn with_refresh_token(
        urls: BaseUrls,
        device_id: Uuid,
        device_name: impl Into<String>,
        refresh_token: String,
    ) -> Result<Self> {
        let mut client = Self::new(urls, device_id, device_name)?;
        client.refresh_token = Some(Zeroizing::new(refresh_token));
        Ok(client)
    }

    /// `POST /connect/token` with `grant_type=refresh_token` — mint a fresh
    /// access token from the held refresh token, updating it if the server
    /// rotates it.
    ///
    /// # Errors
    ///
    /// [`Error::ServerStatus`] if no refresh token is held or the server
    /// rejects it (e.g. expired/revoked), or [`Error::Transport`] on failure.
    pub async fn refresh(&mut self) -> Result<()> {
        let refresh = self.refresh_token.as_ref().ok_or(Error::ServerStatus {
            status: 401,
            message: "no refresh token held".into(),
        })?;
        let url = self
            .urls
            .identity
            .join("connect/token")
            .map_err(|_| Error::BaseUrl("could not build token URL"))?;
        let form: [(&str, &str); 3] = [
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh.as_str()),
            ("client_id", CLIENT_ID),
        ];
        let resp = self.http.post(url).form(&form).send().await?;
        let status = resp.status();
        if status.is_success() {
            let token: TokenResponse = resp.json().await?;
            self.access_token = Some(Zeroizing::new(token.access_token.clone()));
            if let Some(rt) = token.refresh_token {
                self.refresh_token = Some(Zeroizing::new(rt));
            }
            Ok(())
        } else {
            Err(Error::ServerStatus {
                status: status.as_u16(),
                message: resp.text().await.unwrap_or_default(),
            })
        }
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
            self.refresh_token = token.refresh_token.clone().map(Zeroizing::new);
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

    /// `POST /connect/token` with `grant_type=client_credentials` — authenticate
    /// with a Bitwarden **personal API key** (`client_id = "user.<uuid>"` +
    /// `client_secret`, from the web vault). This grant is **not** 2FA-challenged,
    /// so it's the way to obtain a token for an account with two-factor auth
    /// enabled without an interactive TOTP prompt.
    ///
    /// The API key authenticates the *session* only: the returned
    /// [`TokenResponse`] still carries the user key wrapped under the stretched
    /// master key (`key`), so the caller must still derive the master key from
    /// the master password to decrypt the vault — the API key never replaces it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Credential`] if `client_secret` is not valid UTF-8,
    /// [`Error::ServerStatus`] on a rejected API key (a plain `400` — there is
    /// no 2FA branch on this grant), or [`Error::Transport`] on transport failure.
    pub async fn login_api_key(
        &mut self,
        client_id: &str,
        client_secret: &[u8],
    ) -> Result<TokenResponse> {
        // Held in Zeroizing so the secret scrubs on drop even on early return.
        let secret = Zeroizing::new(
            std::str::from_utf8(client_secret)
                .map_err(|_| Error::Credential("api-key client_secret is not valid UTF-8"))?
                .to_owned(),
        );
        let url = self
            .urls
            .identity
            .join("connect/token")
            .map_err(|_| Error::BaseUrl("could not build token URL"))?;

        let device = self.device_id.to_string();
        let form: [(&str, &str); 7] = [
            ("grant_type", "client_credentials"),
            ("scope", "api"),
            ("client_id", client_id),
            ("client_secret", secret.as_str()),
            ("deviceType", "14"),
            ("deviceIdentifier", &device),
            ("deviceName", &self.device_name),
        ];

        let resp = self.http.post(url).form(&form).send().await?;
        let status = resp.status();
        if status.is_success() {
            let token: TokenResponse = resp.json().await?;
            self.access_token = Some(Zeroizing::new(token.access_token.clone()));
            self.refresh_token = token.refresh_token.clone().map(Zeroizing::new);
            Ok(token)
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
    pub async fn sync(&mut self) -> Result<SyncResponse> {
        let url = self
            .urls
            .api
            .join("sync")
            .map_err(|_| Error::BaseUrl("could not build sync URL"))?;
        let resp = self
            .send_with_auth(|http, bearer| http.get(url.clone()).header("Authorization", bearer))
            .await?;
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
    pub async fn delete_cipher(&mut self, id: &str) -> Result<()> {
        let url = self
            .urls
            .api
            .join(&format!("ciphers/{id}"))
            .map_err(|_| Error::BaseUrl("could not build delete-cipher URL"))?;
        let resp = self
            .send_with_auth(|http, bearer| http.delete(url.clone()).header("Authorization", bearer))
            .await?;
        expect_success(resp).await
    }

    /// `POST /api/ciphers` — create a new cipher from an already-encrypted
    /// [`vault_core::Cipher`]. Returns the server-assigned id.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ServerStatus`] if the client lacks an access token or
    /// the server replies non-2xx, [`Error::Transport`] on transport failure,
    /// or [`Error::Decode`] if the response id cannot be parsed.
    pub async fn create_cipher(&mut self, cipher: &vault_core::Cipher) -> Result<String> {
        let url = self
            .urls
            .api
            .join("ciphers")
            .map_err(|_| Error::BaseUrl("could not build create-cipher URL"))?;
        let body = CipherRequest::from_cipher(cipher);
        let resp = self
            .send_with_auth(|http, bearer| {
                http.post(url.clone())
                    .header("Authorization", bearer)
                    .json(&body)
            })
            .await?;
        let status = resp.status();
        if status.is_success() {
            let res: CipherIdResponse = resp.json().await?;
            Ok(res.id)
        } else {
            Err(Error::ServerStatus {
                status: status.as_u16(),
                message: resp.text().await.unwrap_or_default(),
            })
        }
    }

    /// `PUT /api/ciphers/{id}` — replace an existing cipher with the
    /// already-encrypted `cipher`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ServerStatus`] if the client lacks an access token or
    /// the server replies non-2xx (`404` for an unknown id), or
    /// [`Error::Transport`] on transport failure.
    pub async fn update_cipher(&mut self, id: &str, cipher: &vault_core::Cipher) -> Result<()> {
        let url = self
            .urls
            .api
            .join(&format!("ciphers/{id}"))
            .map_err(|_| Error::BaseUrl("could not build update-cipher URL"))?;
        let body = CipherRequest::from_cipher(cipher);
        let resp = self
            .send_with_auth(|http, bearer| {
                http.put(url.clone())
                    .header("Authorization", bearer)
                    .json(&body)
            })
            .await?;
        expect_success(resp).await
    }

    /// Send an authenticated request and, on a `401` with a refresh token held,
    /// `refresh` once and resend. `build` is given the HTTP client and the
    /// `Bearer …` header value, and must produce the full request each call
    /// (it may be invoked twice). Errors if no access token is held.
    async fn send_with_auth<F>(&mut self, build: F) -> Result<reqwest::Response>
    where
        F: Fn(&Client, String) -> reqwest::RequestBuilder,
    {
        let bearer = self.bearer()?;
        let resp = build(&self.http, bearer).send().await?;
        if resp.status().as_u16() == 401 && self.refresh_token.is_some() {
            self.refresh().await?;
            let bearer = self.bearer()?;
            return Ok(build(&self.http, bearer).send().await?);
        }
        Ok(resp)
    }

    /// The `Bearer …` header value for the current access token (owned, so it
    /// doesn't borrow `self` across an `await`).
    fn bearer(&self) -> Result<String> {
        let token = self.access_token.as_ref().ok_or(Error::ServerStatus {
            status: 401,
            message: "no access token; call login_password() first".into(),
        })?;
        Ok(format!("Bearer {}", token.as_str()))
    }
}

/// Map a response to `Ok(())` on 2xx or [`Error::ServerStatus`] otherwise.
async fn expect_success(resp: reqwest::Response) -> Result<()> {
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

/// Bitwarden create/update cipher request body. Note the wire shape: the
/// top level is **`camelCase`** (`type`, `folderId`, `name`, `notes`, `login`,
/// `secureNote`) while the nested `login` object reuses `vault_core`'s
/// `PascalCase` [`Login`](vault_core::cipher::Login) — the asymmetry the
/// Bitwarden API actually expects.
#[derive(serde::Serialize, Debug)]
struct CipherRequest<'a> {
    #[serde(rename = "type")]
    cipher_type: u8,
    #[serde(rename = "folderId", skip_serializing_if = "Option::is_none")]
    folder_id: Option<&'a str>,
    name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    login: Option<&'a vault_core::cipher::Login>,
    #[serde(rename = "secureNote", skip_serializing_if = "Option::is_none")]
    secure_note: Option<SecureNoteRequest>,
}

impl<'a> CipherRequest<'a> {
    fn from_cipher(c: &'a vault_core::Cipher) -> Self {
        Self {
            cipher_type: c.cipher_type,
            folder_id: c.folder_id.as_deref(),
            name: c.name.as_deref().unwrap_or_default(),
            notes: c.notes.as_deref(),
            login: c.login.as_ref(),
            // Bitwarden requires a `secureNote: { type: 0 }` marker on type-2.
            secure_note: (c.cipher_type == 2).then_some(SecureNoteRequest { note_type: 0 }),
        }
    }
}

#[derive(serde::Serialize, Debug)]
struct SecureNoteRequest {
    #[serde(rename = "type")]
    note_type: u8,
}

/// Minimal projection of a create-cipher response — we only need the new id.
#[derive(serde::Deserialize)]
struct CipherIdResponse {
    #[serde(rename = "Id", alias = "id")]
    id: String,
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

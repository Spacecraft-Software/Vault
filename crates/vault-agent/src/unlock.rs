// SPDX-License-Identifier: GPL-3.0-or-later

//! Unlock flow — drive `vault-api` end-to-end and yield a populated `Vault`.

use std::collections::HashMap;

use uuid::Uuid;
use zeroize::Zeroizing;

use vault_api::{BaseUrls, BitwardenClient, SyncResponse, TokenResponse};
use vault_core::cipher::{Cipher, decrypt_user_key};
use vault_core::kdf::{KdfParams, derive_master_key, stretch_master_key};
use vault_ipc::proto::{ApiKeyCreds, Error as IpcError};
use vault_store::VaultCache;

use crate::state::{Vault, account_dir_name};

/// Unlock the agent: try an online login, and if the network is unreachable
/// fall back to the encrypted local cache (offline session, no token).
///
/// Only a connectivity failure (`IpcError::Network`) triggers the cache
/// fallback; a bad password or 2FA requirement propagates as-is. An offline
/// session has `client = None`, so server ops return `IpcError::Offline`.
pub async fn perform_unlock(
    server: &str,
    email: &str,
    password: &[u8],
    device_id: Option<&str>,
    api_key: Option<&ApiKeyCreds>,
) -> Result<Vault, IpcError> {
    match online_unlock(server, email, password, device_id, api_key).await {
        Ok(vault) => Ok(vault),
        Err(IpcError::Network(net)) => {
            // Network down — recover from cache if we have one for this account.
            load_cache(server, email).map_or_else(
                || Err(IpcError::Network(net)),
                |cache| unlock_from_cache(&cache, server, email, password),
            )
        }
        Err(other) => Err(other),
    }
}

/// Full online unlock: prelogin → derive master key → login → decrypt user key
/// → sync → assemble, then persist the encrypted cache for offline use.
async fn online_unlock(
    server: &str,
    email: &str,
    password: &[u8],
    device_id: Option<&str>,
    api_key: Option<&ApiKeyCreds>,
) -> Result<Vault, IpcError> {
    let email_lower = email.trim().to_lowercase();
    let urls = BaseUrls::self_hosted(server).map_err(|e| IpcError::Internal(e.to_string()))?;
    // Prefer the account profile's stable device id; fall back to a fresh one
    // so an unregistered unlock still works (it just registers a new device).
    let device = device_id
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or_else(Uuid::new_v4);
    let mut client = BitwardenClient::new(urls, device, "vault-agent").map_err(api_err)?;

    let prelogin = client.prelogin(&email_lower).await.map_err(api_err)?;
    let params = prelogin.into_kdf_params().map_err(crypto_err)?;

    // Master key — buffered into Zeroizing so it scrubs on drop. Even though
    // we wipe explicitly below, the Zeroizing<_> guards against early-return
    // paths inside the borrow.
    let master = Zeroizing::new(
        derive_master_key(password, email_lower.as_bytes(), params).map_err(crypto_err)?,
    );
    let (stretch_enc, stretch_mac) = stretch_master_key(&master).map_err(crypto_err)?;
    let stretch_enc = Zeroizing::new(stretch_enc);
    let stretch_mac = Zeroizing::new(stretch_mac);

    // Authenticate. An API key (request-supplied or previously persisted) uses
    // the client_credentials grant, which skips 2FA; otherwise the password
    // grant. Either way the master key derived above is what decrypts the vault.
    let token = obtain_token(
        &mut client,
        &email_lower,
        password,
        params,
        api_key,
        server,
        email,
    )
    .await?;

    let encrypted_user_key = token
        .key
        .as_deref()
        .ok_or_else(|| IpcError::Internal("server omitted Key in token response".into()))?;
    let (user_enc_arr, user_mac_arr) =
        decrypt_user_key(encrypted_user_key, &stretch_enc, &stretch_mac).map_err(crypto_err)?;
    let user_enc = Zeroizing::new(user_enc_arr);
    let user_mac = Zeroizing::new(user_mac_arr);

    let sync = client.sync().await.map_err(api_err)?;
    let (ciphers, folders) = ciphers_and_folders(&sync, &user_enc, &user_mac);

    // Capture the refresh token before the client is moved into the vault, so
    // it can be persisted (encrypted) and reused after a cache/PIN unlock.
    let refresh_token = client.refresh_token().map(|s| Zeroizing::new(s.to_owned()));

    // `client` holds the access token internally (`login_password` stashed it).
    // Hand it to the vault so Sync / Remove / Edit / Add reuse the session.
    let vault = Vault {
        server: server.to_owned(),
        email: email_lower,
        user_enc,
        user_mac,
        ciphers,
        folders,
        client: Some(client),
        protected_user_key: encrypted_user_key.to_owned(),
        kdf: params,
        refresh_token,
        device_id: device.to_string(),
        last_sync: now_iso(),
    };
    // Persist for offline unlock; a write failure must not fail a good unlock.
    if let Err(e) = vault.persist_cache(&sync) {
        eprintln!("vault-agent: cache persist after unlock failed: {e}");
    }
    Ok(vault)
}

/// Authenticate `client` and return the token. Grant selection: request-supplied
/// API-key creds (persisted on success, so future unlocks reuse them) → a
/// previously stored API key → the password grant. The API-key grants use
/// `client_credentials`, which skips 2FA; the password grant can surface
/// [`IpcError::TwoFactorRequired`].
async fn obtain_token(
    client: &mut BitwardenClient,
    email_lower: &str,
    password: &[u8],
    params: KdfParams,
    api_key: Option<&ApiKeyCreds>,
    server: &str,
    email: &str,
) -> Result<TokenResponse, IpcError> {
    if let Some(creds) = api_key {
        let token = client
            .login_api_key(&creds.client_id, &creds.client_secret)
            .await
            .map_err(api_err)?;
        // Enrollment succeeded — persist the key so plain `unlock` reuses it.
        persist_apikey(server, email, creds)?;
        return Ok(token);
    }
    if let Some(stored) =
        cache_dir(server, email).and_then(|d| vault_store::load_apikey_from_dir(&d).ok())
    {
        return client
            .login_api_key(&stored.client_id, stored.client_secret.as_bytes())
            .await
            .map_err(api_err);
    }
    client
        .login_password(email_lower, password, params)
        .await
        .map_err(translate_login_err)
}

/// Persist a request-supplied API key (0600) for the account. The
/// `client_secret` is valid UTF-8 here — `login_api_key` already verified it
/// against the server.
fn persist_apikey(server: &str, email: &str, creds: &ApiKeyCreds) -> Result<(), IpcError> {
    let dir = cache_dir(server, email)
        .ok_or_else(|| IpcError::Internal("no data directory".to_owned()))?;
    let client_secret = String::from_utf8(creds.client_secret.clone())
        .map_err(|_| IpcError::Internal("api-key client_secret is not valid UTF-8".to_owned()))?;
    let store_creds = vault_store::ApiKeyCreds {
        client_id: creds.client_id.clone(),
        client_secret,
    };
    vault_store::save_apikey_to_dir(&dir, &store_creds)
        .map_err(|e| IpcError::Internal(format!("write api key: {e}")))?;
    Ok(())
}

/// Report whether an API key is stored for the account (never the secret).
#[must_use]
pub fn apikey_status(server: &str, email: &str) -> vault_ipc::proto::ApiKeyStatus {
    let creds = cache_dir(server, email).and_then(|d| vault_store::load_apikey_from_dir(&d).ok());
    vault_ipc::proto::ApiKeyStatus {
        configured: creds.is_some(),
        client_id: creds.map(|c| c.client_id),
    }
}

/// Forget the stored API key for the account (idempotent — no key is success).
///
/// # Errors
///
/// [`IpcError::Internal`] if the data dir can't be located or the removal fails.
pub fn apikey_forget(server: &str, email: &str) -> Result<(), IpcError> {
    let dir = cache_dir(server, email)
        .ok_or_else(|| IpcError::Internal("no data directory".to_owned()))?;
    vault_store::delete_apikey_from_dir(&dir).map_err(|e| IpcError::Internal(e.to_string()))
}

/// Offline unlock from the encrypted local cache — no network. Recovers the
/// user key from the master password via the cached protected key, then builds
/// a read-only (`client = None`) vault. A wrong password is `BadPassword`.
fn unlock_from_cache(
    cache: &VaultCache,
    server: &str,
    email: &str,
    password: &[u8],
) -> Result<Vault, IpcError> {
    let protected = cache
        .protected_user_key
        .as_deref()
        .ok_or_else(|| IpcError::Internal("cached account has no protected user key".to_owned()))?;
    let (user_enc, user_mac) = recover_user_key(cache, email, password, protected)
        .map_err(|e| e.into_ipc(|| IpcError::BadPassword))?;
    vault_from_user_key(cache, server, email, user_enc, user_mac)
}

/// The unwrapped user key: the symmetric encryption and MAC halves, each
/// zeroised on drop.
pub type UserKey = (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>);

/// What went wrong recovering the user key from a protected key + secret.
pub enum KeyRecover {
    /// The secret (master password / PIN) was wrong — MAC mismatch.
    WrongSecret,
    /// A non-recoverable error (missing KDF, malformed key).
    Internal(String),
}

impl KeyRecover {
    /// Map to an `IpcError`, using `wrong` for the wrong-secret case so each
    /// caller can choose `BadPassword` vs PIN-specific handling.
    fn into_ipc(self, wrong: impl FnOnce() -> IpcError) -> IpcError {
        match self {
            Self::WrongSecret => wrong(),
            Self::Internal(s) => IpcError::Internal(s),
        }
    }
}

/// Derive a key from `secret` + the cache's KDF/email salt and decrypt
/// `protected` (an `EncString` over the 64-byte user key). Shared by the
/// offline-master and PIN paths; the MAC check distinguishes a wrong secret.
pub fn recover_user_key(
    cache: &VaultCache,
    email: &str,
    secret: &[u8],
    protected: &str,
) -> Result<UserKey, KeyRecover> {
    let email_lower = email.trim().to_lowercase();
    let kdf: KdfParams = cache
        .kdf
        .ok_or_else(|| KeyRecover::Internal("cached account has no KDF params".to_owned()))?;
    let master = Zeroizing::new(
        derive_master_key(secret, email_lower.as_bytes(), kdf)
            .map_err(|e| KeyRecover::Internal(format!("crypto: {e}")))?,
    );
    let (stretch_enc, stretch_mac) =
        stretch_master_key(&master).map_err(|e| KeyRecover::Internal(format!("crypto: {e}")))?;
    let stretch_enc = Zeroizing::new(stretch_enc);
    let stretch_mac = Zeroizing::new(stretch_mac);
    let (user_enc_arr, user_mac_arr) = decrypt_user_key(protected, &stretch_enc, &stretch_mac)
        .map_err(|_| KeyRecover::WrongSecret)?;
    Ok((Zeroizing::new(user_enc_arr), Zeroizing::new(user_mac_arr)))
}

/// Build a read-only vault (`client = None`) from a recovered user key by
/// decrypting the cached `/sync` payload. Shared by every cache-based unlock.
pub fn vault_from_user_key(
    cache: &VaultCache,
    server: &str,
    email: &str,
    user_enc: Zeroizing<[u8; 32]>,
    user_mac: Zeroizing<[u8; 32]>,
) -> Result<Vault, IpcError> {
    let payload = cache
        .load_payload(&user_enc, &user_mac)
        .map_err(|e| IpcError::Internal(format!("decrypt cached vault: {e}")))?;
    let sync: SyncResponse = serde_json::from_slice(&payload)
        .map_err(|e| IpcError::Internal(format!("parse cached vault: {e}")))?;
    let (ciphers, folders) = ciphers_and_folders(&sync, &user_enc, &user_mac);
    let kdf = cache
        .kdf
        .ok_or_else(|| IpcError::Internal("cached account has no KDF params".to_owned()))?;
    // Recover the refresh token (encrypted under the user key) so this offline /
    // PIN session can lazily go online. A decode failure just leaves it absent.
    let refresh_token = cache.refresh_token.as_deref().and_then(|enc| {
        let parsed = vault_core::EncString::parse(enc).ok()?;
        let bytes = parsed.decrypt(&user_enc, &user_mac).ok()?;
        String::from_utf8(bytes).ok().map(Zeroizing::new)
    });
    Ok(Vault {
        server: server.to_owned(),
        email: email.trim().to_lowercase(),
        user_enc,
        user_mac,
        ciphers,
        folders,
        client: None,
        protected_user_key: cache.protected_user_key.clone().unwrap_or_default(),
        kdf,
        refresh_token,
        device_id: cache.device_id.clone(),
        last_sync: cache.last_sync.clone(),
    })
}

/// Load the account's cache, if one exists and parses.
pub fn load_cache(server: &str, email: &str) -> Option<VaultCache> {
    let dir = vault_store::default_data_dir()?.join(account_dir_name(server, email));
    vault_store::load_from_dir(&dir).ok()
}

/// Path to the account's cache directory.
pub fn cache_dir(server: &str, email: &str) -> Option<std::path::PathBuf> {
    Some(vault_store::default_data_dir()?.join(account_dir_name(server, email)))
}

/// Write `cache` back to the account's directory.
fn save_cache(server: &str, email: &str, cache: &VaultCache) -> Result<(), IpcError> {
    let dir = cache_dir(server, email)
        .ok_or_else(|| IpcError::Internal("no data directory".to_owned()))?;
    vault_store::save_to_dir(&dir, cache)
        .map_err(|e| IpcError::Internal(format!("write cache: {e}")))?;
    Ok(())
}

/// PIN unlock from the cache: recover the user key with `pin` and build a
/// read-only vault. Tracks failed attempts in the persisted cache; the
/// `MAX_PIN_ATTEMPTS`-th wrong PIN wipes the pin key and reports `PinLockedOut`.
pub fn unlock_pin(server: &str, email: &str, pin: &[u8]) -> Result<Vault, IpcError> {
    let mut cache = load_cache(server, email).ok_or(IpcError::PinNotSet)?;
    let res = pin_attempt(&mut cache, server, email, pin);
    // The attempt mutates the counter (and may wipe the key on lockout) whether
    // or not it succeeded — persist that. Best-effort: a write failure mustn't
    // mask the unlock result.
    let _ = save_cache(server, email, &cache);
    res
}

/// Pure PIN-attempt logic over an in-memory cache (no disk): on the correct PIN
/// resets `pin_failures` and returns a read-only vault; on a wrong PIN bumps
/// the counter and returns `BadPin`, wiping the pin key and returning
/// `PinLockedOut` once `MAX_PIN_ATTEMPTS` is reached.
pub fn pin_attempt(
    cache: &mut VaultCache,
    server: &str,
    email: &str,
    pin: &[u8],
) -> Result<Vault, IpcError> {
    // A wiped-by-lockout cache keeps `pin_failures` at the max — report lockout
    // (not "no PIN set") so the user knows to use the master password.
    if cache.pin_failures >= crate::state::MAX_PIN_ATTEMPTS {
        return Err(IpcError::PinLockedOut);
    }
    let protected = cache
        .pin_protected_user_key
        .clone()
        .ok_or(IpcError::PinNotSet)?;

    match recover_user_key(cache, email, pin, &protected) {
        Ok((user_enc, user_mac)) => {
            cache.pin_failures = 0;
            vault_from_user_key(cache, server, email, user_enc, user_mac)
        }
        Err(KeyRecover::Internal(s)) => Err(IpcError::Internal(s)),
        Err(KeyRecover::WrongSecret) => {
            cache.pin_failures += 1;
            let remaining = crate::state::MAX_PIN_ATTEMPTS.saturating_sub(cache.pin_failures);
            if remaining == 0 {
                // Lockout: drop the pin key so it can't be brute-forced further.
                cache.pin_protected_user_key = None;
                Err(IpcError::PinLockedOut)
            } else {
                Err(IpcError::BadPin {
                    attempts_remaining: remaining,
                })
            }
        }
    }
}

/// Encrypt the 64-byte user key under a key derived from `pin` (account KDF,
/// email salt) — the value stored as `pin_protected_user_key`. The inverse of
/// the PIN side of [`recover_user_key`].
///
/// # Errors
///
/// [`IpcError::Internal`] on a key-derivation failure.
pub fn pin_protect_user_key(
    email: &str,
    kdf: KdfParams,
    user_enc: &[u8; 32],
    user_mac: &[u8; 32],
    pin: &[u8],
) -> Result<String, IpcError> {
    let email_lower = email.trim().to_lowercase();
    let master = Zeroizing::new(
        derive_master_key(pin, email_lower.as_bytes(), kdf)
            .map_err(|e| IpcError::Internal(format!("crypto: {e}")))?,
    );
    let (stretch_enc, stretch_mac) =
        stretch_master_key(&master).map_err(|e| IpcError::Internal(format!("crypto: {e}")))?;
    let mut user_key = Zeroizing::new(Vec::with_capacity(64));
    user_key.extend_from_slice(user_enc);
    user_key.extend_from_slice(user_mac);
    Ok(vault_core::EncString::encrypt(&stretch_enc, &stretch_mac, &user_key).serialize())
}

/// Forget any enrolled PIN for the account (idempotent — no cache is success).
pub fn pin_disable(server: &str, email: &str) -> Result<(), IpcError> {
    let Some(mut cache) = load_cache(server, email) else {
        return Ok(());
    };
    cache.pin_protected_user_key = None;
    cache.pin_failures = 0;
    save_cache(server, email, &cache)
}

/// Report PIN enrollment + attempts remaining for the account.
pub fn pin_status(server: &str, email: &str) -> vault_ipc::proto::PinStatus {
    let cache = load_cache(server, email);
    let enabled = cache
        .as_ref()
        .is_some_and(|c| c.pin_protected_user_key.is_some());
    let failures = cache.as_ref().map_or(0, |c| c.pin_failures);
    vault_ipc::proto::PinStatus {
        enabled,
        attempts_remaining: crate::state::MAX_PIN_ATTEMPTS.saturating_sub(failures),
    }
}

/// Re-cast a `/sync` payload into the typed views the agent caches: a list of
/// [`Cipher`]s and an `id → decrypted-name` folder map. Shared by the initial
/// [`perform_unlock`] and the standalone `resync` so both paths interpret the
/// server response identically.
///
/// The server hands ciphers/folders to `vault-api` as `serde_json::Value`;
/// here they are decoded into [`Cipher`] (dropping any that don't fit the
/// schema) and folder names are decrypted eagerly — there are typically few.
pub fn ciphers_and_folders(
    sync: &SyncResponse,
    user_enc: &[u8; 32],
    user_mac: &[u8; 32],
) -> (Vec<Cipher>, HashMap<String, String>) {
    let ciphers: Vec<Cipher> = sync
        .ciphers
        .iter()
        .filter_map(|v| serde_json::from_value(v.clone()).ok())
        .collect();

    let mut folders = HashMap::new();
    for f in &sync.folders {
        let Some(obj) = f.as_object() else { continue };
        let Some(id) = obj.get("Id").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(name_enc) = obj.get("Name").and_then(|v| v.as_str()) else {
            continue;
        };
        if let Ok(enc) = vault_core::EncString::parse(name_enc)
            && let Ok(pt) = enc.decrypt(user_enc, user_mac)
            && let Ok(name) = String::from_utf8(pt)
        {
            folders.insert(id.to_owned(), name);
        }
    }
    (ciphers, folders)
}

fn api_err(e: vault_api::Error) -> IpcError {
    match e {
        vault_api::Error::ServerStatus { status, message } if status == 400 => {
            if message.contains("invalid_grant") || message.to_lowercase().contains("username") {
                IpcError::BadPassword
            } else {
                IpcError::Network(format!("HTTP {status}: {message}"))
            }
        }
        vault_api::Error::ServerStatus { status, message } => {
            IpcError::Network(format!("HTTP {status}: {message}"))
        }
        vault_api::Error::TwoFactorRequired(_) => IpcError::TwoFactorRequired,
        other => IpcError::Network(other.to_string()),
    }
}

fn translate_login_err(e: vault_api::Error) -> IpcError {
    api_err(e)
}

#[allow(clippy::needless_pass_by_value)] // used as a `map_err` callback, which hands ownership of `e`
fn crypto_err(e: vault_core::Error) -> IpcError {
    IpcError::Internal(format!("crypto: {e}"))
}

#[allow(clippy::many_single_char_names)] // h/m/s/y/d are the conventional date-field names
pub fn now_iso() -> Option<String> {
    use std::time::SystemTime;
    let now = SystemTime::now();
    let dur = now.duration_since(SystemTime::UNIX_EPOCH).ok()?;
    // ISO 8601 UTC formatted manually to avoid pulling chrono in just for this.
    let secs = dur.as_secs();
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, mo, d) = days_to_ymd(days);
    Some(format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z"))
}

// Casts below are inherent to the integer civil-calendar algorithm; every
// intermediate is bounded well within the target type.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]
fn days_to_ymd(days_since_epoch: u64) -> (i32, u32, u32) {
    // Civil-from-days, after Howard Hinnant. Epoch 1970-01-01 → days = 0.
    let z: i64 = i64::try_from(days_since_epoch).unwrap_or(0) + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y_minus_2000 = (yoe as i64) + era * 400 - 2000;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = y_minus_2000 + i64::from(m <= 2) + 2000;
    (i32::try_from(y).unwrap_or(0), m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc_str(enc: &[u8; 32], mac: &[u8; 32], plain: &str) -> String {
        vault_core::EncString::encrypt(enc, mac, plain.as_bytes()).serialize()
    }

    #[test]
    fn ciphers_and_folders_decodes_typed_views() {
        let enc = [1u8; 32];
        let mac = [2u8; 32];

        // Two well-formed ciphers and one folder with an encrypted name.
        let sync = SyncResponse {
            profile: serde_json::Value::Null,
            folders: vec![serde_json::json!({
                "Id": "fid-1",
                "Name": enc_str(&enc, &mac, "Work"),
            })],
            collections: vec![],
            ciphers: vec![
                serde_json::json!({
                    "Id": "c1",
                    "Type": 1,
                    "Name": enc_str(&enc, &mac, "github.com"),
                }),
                serde_json::json!({
                    "Id": "c2",
                    "Type": 2,
                    "Name": enc_str(&enc, &mac, "note"),
                }),
            ],
            domains: serde_json::Value::Null,
            sends: vec![],
        };

        let (ciphers, folders) = ciphers_and_folders(&sync, &enc, &mac);

        assert_eq!(ciphers.len(), 2);
        assert_eq!(ciphers[0].id, "c1");
        assert_eq!(
            ciphers[0].decrypt_name(&enc, &mac).unwrap().as_deref(),
            Some("github.com")
        );
        assert_eq!(folders.get("fid-1").map(String::as_str), Some("Work"));
    }

    #[test]
    fn unlock_from_cache_recovers_offline_and_rejects_wrong_password() {
        use vault_core::kdf::KdfType;

        let kdf = KdfParams {
            kind: KdfType::Pbkdf2Sha256,
            iterations: 1_000,
            memory_kib: None,
            parallelism: None,
        };
        let email = "user@example.org";
        let password = b"hunter2";
        let user_enc = [7u8; 32];
        let user_mac = [9u8; 32];

        // Protect the 64-byte user key under the master-stretched key.
        let master = derive_master_key(password, email.as_bytes(), kdf).unwrap();
        let (stretch_enc, stretch_mac) = stretch_master_key(&master).unwrap();
        let mut user_key = user_enc.to_vec();
        user_key.extend_from_slice(&user_mac);
        let protected =
            vault_core::EncString::encrypt(&stretch_enc, &stretch_mac, &user_key).serialize();

        // A one-cipher sync payload, encrypted under the user key.
        let sync = SyncResponse {
            profile: serde_json::Value::Null,
            folders: vec![],
            collections: vec![],
            ciphers: vec![serde_json::json!({
                "Id": "c1",
                "Type": 1,
                "Name": enc_str(&user_enc, &user_mac, "github.com"),
            })],
            domains: serde_json::Value::Null,
            sends: vec![],
        };
        let sync_bytes = serde_json::to_vec(&sync).unwrap();
        let mut cache = VaultCache::new("dev".into(), "https://x".into(), email);
        cache
            .set_payload(&user_enc, &user_mac, &sync_bytes)
            .unwrap();
        cache.protected_user_key = Some(protected);
        cache.kdf = Some(kdf);
        // A refresh token, encrypted under the user key, must round-trip back
        // into the recovered vault so an offline session can go online.
        cache.refresh_token = Some(
            vault_core::EncString::encrypt(&user_enc, &user_mac, b"my-refresh-token").serialize(),
        );

        let vault = unlock_from_cache(&cache, "https://x", email, password).unwrap();
        assert!(vault.client.is_none(), "offline session has no token");
        assert_eq!(
            vault.refresh_token.as_deref().map(String::as_str),
            Some("my-refresh-token"),
            "refresh token recovered from cache"
        );
        assert_eq!(vault.ciphers.len(), 1);
        assert_eq!(
            vault.ciphers[0]
                .decrypt_name(&user_enc, &user_mac)
                .unwrap()
                .as_deref(),
            Some("github.com")
        );

        assert!(
            matches!(
                unlock_from_cache(&cache, "https://x", email, b"wrong"),
                Err(IpcError::BadPassword)
            ),
            "wrong password must be rejected"
        );
    }

    /// Build a cache with a payload + master + PIN protected keys, for the
    /// in-memory PIN-attempt tests.
    fn seeded_pin_cache(
        email: &str,
        user_enc: &[u8; 32],
        user_mac: &[u8; 32],
        kdf: KdfParams,
        pin: &[u8],
    ) -> VaultCache {
        let sync = SyncResponse {
            profile: serde_json::Value::Null,
            folders: vec![],
            collections: vec![],
            ciphers: vec![serde_json::json!({
                "Id": "c1",
                "Type": 1,
                "Name": enc_str(user_enc, user_mac, "github.com"),
            })],
            domains: serde_json::Value::Null,
            sends: vec![],
        };
        let sync_bytes = serde_json::to_vec(&sync).unwrap();
        let mut cache = VaultCache::new("dev".into(), "https://x".into(), email);
        cache.set_payload(user_enc, user_mac, &sync_bytes).unwrap();
        cache.kdf = Some(kdf);
        cache.pin_protected_user_key =
            Some(pin_protect_user_key(email, kdf, user_enc, user_mac, pin).unwrap());
        cache
    }

    #[test]
    fn pin_attempt_recovers_resets_counts_and_locks_out() {
        use vault_core::kdf::KdfType;
        let kdf = KdfParams {
            kind: KdfType::Pbkdf2Sha256,
            iterations: 1_000,
            memory_kib: None,
            parallelism: None,
        };
        let email = "user@example.org";
        let user_enc = [7u8; 32];
        let user_mac = [9u8; 32];
        let mut cache = seeded_pin_cache(email, &user_enc, &user_mac, kdf, b"1234");

        // Correct PIN → read-only vault with the cached cipher.
        let vault = pin_attempt(&mut cache, "https://x", email, b"1234").unwrap();
        assert!(vault.client.is_none());
        assert_eq!(vault.ciphers.len(), 1);

        // Two wrong PINs bump the counter and report the remaining count.
        for expected in [4u32, 3] {
            assert!(matches!(
                pin_attempt(&mut cache, "https://x", email, b"0000"),
                Err(IpcError::BadPin { attempts_remaining }) if attempts_remaining == expected
            ));
        }
        assert_eq!(cache.pin_failures, 2);

        // A correct PIN resets the counter back to zero.
        pin_attempt(&mut cache, "https://x", email, b"1234").unwrap();
        assert_eq!(cache.pin_failures, 0);

        // Five wrong PINs in a row → lockout, pin key wiped.
        let mut last = Err(IpcError::PinNotSet);
        for _ in 0..crate::state::MAX_PIN_ATTEMPTS {
            last = pin_attempt(&mut cache, "https://x", email, b"0000");
        }
        assert!(matches!(last, Err(IpcError::PinLockedOut)));
        assert_eq!(
            cache.pin_protected_user_key, None,
            "pin key wiped on lockout"
        );
        // A further attempt stays locked out (not "no PIN set").
        assert!(matches!(
            pin_attempt(&mut cache, "https://x", email, b"1234"),
            Err(IpcError::PinLockedOut)
        ));
    }

    #[test]
    fn pin_attempt_without_enrolled_pin_is_pin_not_set() {
        use vault_core::kdf::KdfType;
        let kdf = KdfParams {
            kind: KdfType::Pbkdf2Sha256,
            iterations: 1_000,
            memory_kib: None,
            parallelism: None,
        };
        let mut cache = VaultCache::new("dev".into(), "https://x".into(), "u@e.org");
        cache.kdf = Some(kdf);
        assert!(matches!(
            pin_attempt(&mut cache, "https://x", "u@e.org", b"1234"),
            Err(IpcError::PinNotSet)
        ));
    }

    #[test]
    fn ciphers_and_folders_skips_malformed_folder_entries() {
        let enc = [3u8; 32];
        let mac = [4u8; 32];
        let sync = SyncResponse {
            profile: serde_json::Value::Null,
            // Missing Name, and an undecryptable Name — both dropped silently.
            folders: vec![
                serde_json::json!({ "Id": "fid-missing-name" }),
                serde_json::json!({ "Id": "fid-bad", "Name": "not-an-encstring" }),
            ],
            collections: vec![],
            ciphers: vec![],
            domains: serde_json::Value::Null,
            sends: vec![],
        };

        let (ciphers, folders) = ciphers_and_folders(&sync, &enc, &mac);
        assert!(ciphers.is_empty());
        assert!(folders.is_empty());
    }
}

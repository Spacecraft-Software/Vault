// SPDX-License-Identifier: GPL-3.0-or-later

//! Unlock flow — drive `vault-api` end-to-end and yield a populated `Vault`.

use std::collections::HashMap;

use uuid::Uuid;
use zeroize::Zeroizing;

use vault_api::{BaseUrls, BitwardenClient, SyncResponse};
use vault_core::cipher::{Cipher, decrypt_user_key};
use vault_core::kdf::{KdfParams, derive_master_key, stretch_master_key};
use vault_ipc::proto::Error as IpcError;
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
) -> Result<Vault, IpcError> {
    match online_unlock(server, email, password, device_id).await {
        Ok(vault) => Ok(vault),
        Err(IpcError::Network(net)) => {
            // Network down — recover from cache if we have one for this account.
            match load_cache(server, email) {
                Some(cache) => unlock_from_cache(&cache, server, email, password),
                None => Err(IpcError::Network(net)),
            }
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

    let token = client
        .login_password(&email_lower, password, params)
        .await
        .map_err(translate_login_err)?;

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
        device_id: device.to_string(),
        last_sync: now_iso(),
    };
    // Persist for offline unlock; a write failure must not fail a good unlock.
    if let Err(e) = vault.persist_cache(&sync) {
        eprintln!("vault-agent: cache persist after unlock failed: {e}");
    }
    Ok(vault)
}

/// Offline unlock from the encrypted local cache — no network. Derives the
/// master key from the cached KDF params, decrypts the protected user key (the
/// EncString MAC check is the wrong-password detector), then loads ciphers from
/// the cached `/sync` payload. The session has no token (`client = None`).
fn unlock_from_cache(
    cache: &VaultCache,
    server: &str,
    email: &str,
    password: &[u8],
) -> Result<Vault, IpcError> {
    let email_lower = email.trim().to_lowercase();
    let kdf: KdfParams = cache
        .kdf
        .ok_or_else(|| IpcError::Internal("cached account has no KDF params".to_owned()))?;
    let protected = cache
        .protected_user_key
        .as_deref()
        .ok_or_else(|| IpcError::Internal("cached account has no protected user key".to_owned()))?;

    let master = Zeroizing::new(
        derive_master_key(password, email_lower.as_bytes(), kdf).map_err(crypto_err)?,
    );
    let (stretch_enc, stretch_mac) = stretch_master_key(&master).map_err(crypto_err)?;
    let stretch_enc = Zeroizing::new(stretch_enc);
    let stretch_mac = Zeroizing::new(stretch_mac);

    // A decrypt failure here is overwhelmingly a wrong password (MAC mismatch);
    // surface it as such rather than a generic internal error.
    let (user_enc_arr, user_mac_arr) = decrypt_user_key(protected, &stretch_enc, &stretch_mac)
        .map_err(|_| IpcError::BadPassword)?;
    let user_enc = Zeroizing::new(user_enc_arr);
    let user_mac = Zeroizing::new(user_mac_arr);

    let payload = cache
        .load_payload(&user_enc, &user_mac)
        .map_err(|e| IpcError::Internal(format!("decrypt cached vault: {e}")))?;
    let sync: SyncResponse = serde_json::from_slice(&payload)
        .map_err(|e| IpcError::Internal(format!("parse cached vault: {e}")))?;
    let (ciphers, folders) = ciphers_and_folders(&sync, &user_enc, &user_mac);

    Ok(Vault {
        server: server.to_owned(),
        email: email_lower,
        user_enc,
        user_mac,
        ciphers,
        folders,
        client: None,
        protected_user_key: protected.to_owned(),
        kdf,
        device_id: cache.device_id.clone(),
        last_sync: cache.last_sync.clone(),
    })
}

/// Load the account's cache, if one exists and parses.
fn load_cache(server: &str, email: &str) -> Option<VaultCache> {
    let dir = vault_store::default_data_dir()?.join(account_dir_name(server, email));
    vault_store::load_from_dir(&dir).ok()
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
        let (senc, smac) = stretch_master_key(&master).unwrap();
        let mut user_key = user_enc.to_vec();
        user_key.extend_from_slice(&user_mac);
        let protected = vault_core::EncString::encrypt(&senc, &smac, &user_key).serialize();

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

        let vault = unlock_from_cache(&cache, "https://x", email, password).unwrap();
        assert!(vault.client.is_none(), "offline session has no token");
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

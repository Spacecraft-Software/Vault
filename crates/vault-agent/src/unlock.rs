// SPDX-License-Identifier: GPL-3.0-or-later

//! Unlock flow — drive `vault-api` end-to-end and yield a populated `Vault`.

use std::collections::HashMap;

use uuid::Uuid;
use zeroize::Zeroizing;

use vault_api::{BaseUrls, BitwardenClient};
use vault_core::cipher::{Cipher, decrypt_user_key};
use vault_core::kdf::{derive_master_key, stretch_master_key};
use vault_ipc::proto::Error as IpcError;

use crate::state::Vault;

/// Lock-step the unlock sequence:
/// prelogin → derive master key → login → decrypt user key → sync → assemble.
pub async fn perform_unlock(
    server: &str,
    email: &str,
    password: &[u8],
) -> Result<Vault, IpcError> {
    let email_lower = email.trim().to_lowercase();
    let urls = BaseUrls::self_hosted(server).map_err(|e| IpcError::Internal(e.to_string()))?;
    let mut client = BitwardenClient::new(urls, Uuid::new_v4(), "vault-agent")
        .map_err(api_err)?;

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

    // Server returns Profile / Folders / Ciphers / etc as serde_json::Value
    // at the vault-api layer — re-cast Ciphers and Folders into typed views.
    let ciphers: Vec<Cipher> = sync
        .ciphers
        .iter()
        .filter_map(|v| serde_json::from_value(v.clone()).ok())
        .collect();

    // Decrypt folder names eagerly — there are typically few.
    let mut folders = HashMap::new();
    for f in &sync.folders {
        let Some(obj) = f.as_object() else { continue };
        let Some(id) = obj.get("Id").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(name_enc) = obj.get("Name").and_then(|v| v.as_str()) else {
            continue;
        };
        if let Ok(enc) = vault_core::EncString::parse(name_enc) {
            if let Ok(pt) = enc.decrypt(&user_enc, &user_mac) {
                if let Ok(name) = String::from_utf8(pt) {
                    folders.insert(id.to_owned(), name);
                }
            }
        }
    }

    Ok(Vault {
        server: server.to_owned(),
        email: email_lower,
        user_enc,
        user_mac,
        ciphers,
        folders,
        access_token: Zeroizing::new(token.access_token),
        last_sync: now_iso(),
    })
}

fn api_err(e: vault_api::Error) -> IpcError {
    match e {
        vault_api::Error::ServerStatus { status, message } if status == 400 => {
            if message.contains("invalid_grant") || message.to_lowercase().contains("username")
            {
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

fn crypto_err(e: vault_core::Error) -> IpcError {
    IpcError::Internal(format!("crypto: {e}"))
}

fn now_iso() -> Option<String> {
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
    let y = y_minus_2000 + if m <= 2 { 1 } else { 0 } + 2000;
    (i32::try_from(y).unwrap_or(0), m as u32, d as u32)
}

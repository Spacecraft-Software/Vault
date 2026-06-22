// SPDX-License-Identifier: GPL-3.0-or-later

//! `/sync` response — opaque-friendly shape.
//!
//! At M2 Vault is only required to *transport and persist* the sync payload,
//! not to decrypt every field. The struct below keeps the high-level skeleton
//! (profile, ciphers, folders, collections, etc.) as `serde_json::Value` so
//! schema drift in the server doesn't break the cache round-trip. Typed
//! decoding of individual ciphers lands in M3.

use serde::{Deserialize, Serialize};

/// `GET /sync` response.
///
/// Bitwarden's hosted API and Vaultwarden both serialize this (and the nested
/// cipher objects) in **camelCase** (`ciphers`, `folderId`, `revisionDate`, …).
/// An earlier `PascalCase` assumption parsed every field to its `#[serde(default)]`
/// empty value, so a fully-populated vault silently synced as zero items.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncResponse {
    /// User profile metadata (id, email, KDF, etc.).
    #[serde(default)]
    pub profile: serde_json::Value,
    /// Folder list (each item is an EncString-encrypted name + id).
    #[serde(default)]
    pub folders: Vec<serde_json::Value>,
    /// Collection list (org-scoped folders).
    #[serde(default)]
    pub collections: Vec<serde_json::Value>,
    /// Cipher list — the actual vault items.
    #[serde(default)]
    pub ciphers: Vec<serde_json::Value>,
    /// Domains config (equivalent-domain lists).
    #[serde(default)]
    pub domains: serde_json::Value,
    /// Bitwarden Sends.
    #[serde(default)]
    pub sends: Vec<serde_json::Value>,
}

impl SyncResponse {
    /// Number of ciphers in the payload.
    #[must_use]
    pub const fn cipher_count(&self) -> usize {
        self.ciphers.len()
    }
    /// Number of folders in the payload.
    #[must_use]
    pub const fn folder_count(&self) -> usize {
        self.folders.len()
    }

    /// The account's RSA private-key envelope (`profile.privateKey`), if present
    /// — a type-2 `EncString` wrapping the PKCS#8 DER key under the user key. Used
    /// to unwrap organization keys.
    #[must_use]
    pub fn private_key(&self) -> Option<&str> {
        self.profile
            .get("privateKey")
            .and_then(serde_json::Value::as_str)
    }

    /// `(organization_id, wrapped_org_key)` for each organization the account
    /// belongs to that ships a key (`profile.organizations[]`). Each key is a
    /// type-4 (RSA-OAEP-SHA1) `EncString`; memberships without a key are skipped.
    #[must_use]
    pub fn organization_keys(&self) -> Vec<(String, String)> {
        self.profile
            .get("organizations")
            .and_then(serde_json::Value::as_array)
            .map(|orgs| {
                orgs.iter()
                    .filter_map(|o| {
                        let id = o.get("id")?.as_str()?.to_owned();
                        let key = o.get("key")?.as_str()?.to_owned();
                        Some((id, key))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

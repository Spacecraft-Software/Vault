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
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
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
    pub fn cipher_count(&self) -> usize {
        self.ciphers.len()
    }
    /// Number of folders in the payload.
    #[must_use]
    pub fn folder_count(&self) -> usize {
        self.folders.len()
    }
}

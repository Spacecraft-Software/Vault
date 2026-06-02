// SPDX-License-Identifier: GPL-3.0-or-later

//! Vault store — on-disk encrypted cache for a synced Bitwarden vault.
//!
//! The cache is a JSON file under `$XDG_DATA_HOME/vault/<account>/cache.json`.
//! Its `payload` field is a Vault [`EncString`] over the raw `/sync` response
//! bytes; everything else (sync revision, last-sync timestamp, server-side
//! profile id) is recorded in plaintext so a `vault status` invocation does
//! not need to touch the master key.
//!
//! Writes go through `write_atomic`: the new contents are flushed to a
//! sibling tempfile in the same directory and then `rename(2)`d over the
//! real file, so a crash mid-write never produces a torn cache.

#![forbid(unsafe_code)]

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use vault_core::EncString;

/// Persistent on-disk cache for one Bitwarden account.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VaultCache {
    /// Schema version — bumped when the on-disk shape changes.
    pub schema_version: u32,
    /// Stable per-install device identifier (UUID v4 string).
    pub device_id: String,
    /// Server origin this cache was pulled from (`https://vault.example.org`).
    pub server: String,
    /// Account email this cache belongs to (lowercased).
    pub email: String,
    /// Last successful sync time (ISO 8601 UTC, RFC 3339).
    pub last_sync: Option<String>,
    /// Encrypted `/sync` payload — an `EncString` over the JSON response
    /// body, encrypted under a key supplied by the agent at write time.
    pub payload: Option<String>,
}

impl VaultCache {
    /// Build a fresh cache for `(server, email)` with no payload yet.
    #[must_use]
    pub fn new(device_id: String, server: String, email: &str) -> Self {
        Self {
            schema_version: 1,
            device_id,
            server,
            email: email.to_lowercase(),
            last_sync: None,
            payload: None,
        }
    }

    /// Encrypt `sync_bytes` under `(enc_key, mac_key)` and store the
    /// resulting `EncString` as the cache payload, stamping `last_sync` with
    /// the current UTC time.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Time`] if the current time fails to format as RFC 3339.
    pub fn set_payload(
        &mut self,
        enc_key: &[u8; 32],
        mac_key: &[u8; 32],
        sync_bytes: &[u8],
    ) -> Result<(), Error> {
        let enc = EncString::encrypt(enc_key, mac_key, sync_bytes);
        self.payload = Some(enc.serialize());
        let now = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|e| Error::Time(e.to_string()))?;
        self.last_sync = Some(now);
        Ok(())
    }

    /// Decrypt and return the most recent sync payload bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoPayload`] if the cache has never been synced, or a
    /// [`Error::Crypto`] if the payload fails to parse or authenticate.
    pub fn load_payload(&self, enc_key: &[u8; 32], mac_key: &[u8; 32]) -> Result<Vec<u8>, Error> {
        let enc_str = self.payload.as_deref().ok_or(Error::NoPayload)?;
        let enc = EncString::parse(enc_str)?;
        Ok(enc.decrypt(enc_key, mac_key)?)
    }
}

/// Default cache directory: `$XDG_DATA_HOME/vault/<account>` (with the
/// account directory created lazily by `save_to_dir`).
#[must_use]
pub fn default_data_dir() -> Option<PathBuf> {
    dirs::data_dir().map(|d| d.join("vault"))
}

/// Save `cache` to `<dir>/cache.json` atomically.
///
/// # Errors
///
/// Returns [`Error::Io`] if the directory cannot be created or the atomic
/// write fails, or [`Error::Json`] if `cache` fails to serialise.
pub fn save_to_dir(dir: &Path, cache: &VaultCache) -> Result<PathBuf, Error> {
    fs::create_dir_all(dir)?;
    let path = dir.join("cache.json");
    let json = serde_json::to_vec_pretty(cache)?;
    write_atomic(&path, &json)?;
    Ok(path)
}

/// Load `<dir>/cache.json`. Returns `Err(Error::NotFound)` if missing.
///
/// # Errors
///
/// Returns [`Error::NotFound`] if the cache file is absent, [`Error::Io`] on
/// any other read failure, or [`Error::Json`] if the file fails to parse.
pub fn load_from_dir(dir: &Path) -> Result<VaultCache, Error> {
    let path = dir.join("cache.json");
    let bytes = fs::read(&path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => Error::NotFound(path.clone()),
        _ => Error::Io(e),
    })?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Atomic write: tempfile in the same dir → fsync → rename.
fn write_atomic(target: &Path, bytes: &[u8]) -> Result<(), Error> {
    let parent = target.parent().ok_or(Error::Path("no parent directory"))?;
    let tmp = tempfile::NamedTempFile::new_in(parent)?;
    {
        let mut f = tmp.as_file();
        f.write_all(bytes)?;
        f.flush()?;
        f.sync_all()?;
    }
    // persist() consumes the NamedTempFile and renames atomically. On error
    // it returns the tempfile back so it gets cleaned up.
    tmp.persist(target).map_err(|e| Error::Io(e.error))?;
    Ok(())
}

/// Errors surfaced by `vault-store`.
#[derive(Debug, Error)]
pub enum Error {
    /// Filesystem IO failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// JSON encoding / decoding failure.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    /// Cache file does not exist at the expected location.
    #[error("cache not found at {0}")]
    NotFound(PathBuf),
    /// Cache has no encrypted payload yet (never synced).
    #[error("no payload — never synced")]
    NoPayload,
    /// `EncString` or crypto error from `vault-core`.
    #[error("crypto: {0}")]
    Crypto(#[from] vault_core::Error),
    /// Filesystem path edge case (target has no parent, etc.).
    #[error("path: {0}")]
    Path(&'static str),
    /// Time formatting failure when stamping `last_sync`.
    #[error("time: {0}")]
    Time(String),
}

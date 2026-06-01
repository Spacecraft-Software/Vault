// SPDX-License-Identifier: GPL-3.0-or-later

//! Bitwarden encrypted-export envelope.
//!
//! Vault supports **password-protected** exports (the JSON file produced by
//! `Tools → Export Vault → File-format: .json (encrypted) → Account-restricted:
//! off, password: yes` in the official clients). The format:
//!
//! ```json
//! {
//!   "encrypted": true,
//!   "passwordProtected": true,
//!   "salt": "<base64 or utf-8 string>",
//!   "kdfType": 0,
//!   "kdfIterations": 600000,
//!   "kdfMemory": null,
//!   "kdfParallelism": null,
//!   "encKeyValidation_DO_NOT_EDIT": "2.iv|ct|mac",
//!   "data": "2.iv|ct|mac"
//! }
//! ```
//!
//! Validation rule (matches the official clients): the export password,
//! stretched through HKDF, must decrypt `encKeyValidation_DO_NOT_EDIT` to a
//! string equal to the un-stretched derived key. If that check passes, the
//! same `(enc, mac)` pair decrypts `data` to the cleartext vault JSON.

use serde::{Deserialize, Serialize};

use crate::enc_string::EncString;
use crate::error::{Error, Result};
use crate::kdf::{KdfParams, KdfType, derive_master_key, stretch_master_key};

/// On-disk shape of an encrypted Bitwarden export.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EncryptedExport {
    /// Always `true` for encrypted exports.
    pub encrypted: bool,
    /// `true` for password-protected exports (the form Vault supports here).
    #[serde(rename = "passwordProtected", default)]
    pub password_protected: bool,
    /// Salt string as written by the exporter. Used verbatim as the KDF salt.
    pub salt: String,
    /// KDF discriminant.
    #[serde(rename = "kdfType")]
    pub kdf_type: KdfType,
    /// PBKDF2 iterations / Argon2 `t_cost`.
    #[serde(rename = "kdfIterations")]
    pub kdf_iterations: u32,
    /// Argon2 `m_cost` in KiB (only present for Argon2id).
    #[serde(rename = "kdfMemory")]
    pub kdf_memory: Option<u32>,
    /// Argon2 `p_cost` (only present for Argon2id).
    #[serde(rename = "kdfParallelism")]
    pub kdf_parallelism: Option<u32>,
    /// Self-validation `EncString` — proves the password was correct.
    #[serde(rename = "encKeyValidation_DO_NOT_EDIT")]
    pub enc_key_validation: String,
    /// The encrypted vault payload (JSON when decrypted).
    pub data: String,
}

impl EncryptedExport {
    /// Parse the JSON envelope without performing any cryptography.
    pub fn from_json(s: &str) -> Result<Self> {
        let out: Self = serde_json::from_str(s)?;
        if !out.encrypted {
            return Err(Error::UnsupportedExport("envelope.encrypted is false"));
        }
        if !out.password_protected {
            return Err(Error::UnsupportedExport(
                "account-key-protected exports require a logged-in session",
            ));
        }
        Ok(out)
    }

    /// KDF parameters extracted from the envelope.
    #[must_use]
    pub fn kdf_params(&self) -> KdfParams {
        KdfParams {
            kind: self.kdf_type,
            iterations: self.kdf_iterations,
            memory_kib: self.kdf_memory,
            parallelism: self.kdf_parallelism,
        }
    }

    /// Decrypt the export using `password`, returning the inner plaintext JSON bytes.
    ///
    /// Fails with `Error::BadExportPassword` if the supplied password does
    /// not validate against the `encKeyValidation_DO_NOT_EDIT` field —
    /// indistinguishable in timing from a successful path up to that check.
    pub fn decrypt(&self, password: &[u8]) -> Result<Vec<u8>> {
        let derived = derive_master_key(password, self.salt.as_bytes(), self.kdf_params())?;
        let (enc_key, mac_key) = stretch_master_key(&derived)?;

        let validation = EncString::parse(&self.enc_key_validation)?;
        let validation_pt = validation
            .decrypt(&enc_key, &mac_key)
            .map_err(|_| Error::BadExportPassword)?;

        // Bitwarden writes the un-stretched 32-byte derived key as a hex string
        // (lowercase, 64 chars) into the validation slot.
        let expected_hex = hex::encode(derived);
        if validation_pt != expected_hex.as_bytes() {
            return Err(Error::BadExportPassword);
        }

        let data = EncString::parse(&self.data)?;
        data.decrypt(&enc_key, &mac_key)
    }
}

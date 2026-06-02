// SPDX-License-Identifier: GPL-3.0-or-later

//! Bitwarden cipher item — the per-vault-entry shape that `/sync` returns.
//!
//! The on-wire representation has every user-visible field wrapped in an
//! `EncString` encrypted under the *user symmetric key* — distinct from the
//! KDF-derived master key. The decryption helpers here take an `(enc, mac)`
//! pair and surface a [`PlainCipher`] view with the requested fields opened.
//!
//! Vault currently models the `Login` cipher type (`type == 1`) fully; other
//! types (`secure_note`, `card`, `identity`) decode their `name` and `notes`
//! but leave structured fields untouched. Richer typing lands in M4.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::enc_string::EncString;
use crate::error::{Error, Result};

/// `/sync` cipher object, kept generous with `serde(default)` so future
/// server-side additions don't break the cache round-trip.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Cipher {
    /// Server-assigned UUID.
    #[serde(default)]
    pub id: String,
    /// Cipher type (1 = login, 2 = secure note, 3 = card, 4 = identity).
    #[serde(rename = "Type", default)]
    pub cipher_type: u8,
    /// Folder this cipher belongs to, or `None` for unfiled.
    #[serde(default)]
    pub folder_id: Option<String>,
    /// Organization this cipher belongs to, if any.
    #[serde(default)]
    pub organization_id: Option<String>,
    /// Encrypted display name.
    #[serde(default)]
    pub name: Option<String>,
    /// Encrypted notes (any type).
    #[serde(default)]
    pub notes: Option<String>,
    /// Login-specific fields (present iff `cipher_type == 1`).
    #[serde(default)]
    pub login: Option<Login>,
    /// User-defined custom fields.
    #[serde(default)]
    pub fields: Option<Vec<CustomField>>,
}

/// Login-specific encrypted fields.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Login {
    /// Encrypted username.
    #[serde(default)]
    pub username: Option<String>,
    /// Encrypted password.
    #[serde(default)]
    pub password: Option<String>,
    /// Encrypted TOTP secret URI.
    #[serde(default)]
    pub totp: Option<String>,
    /// Encrypted URI list.
    #[serde(default)]
    pub uris: Option<Vec<LoginUri>>,
}

/// One URI on a login cipher.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct LoginUri {
    /// Encrypted URI.
    #[serde(default)]
    pub uri: Option<String>,
}

/// User-defined `Fields[]` entry.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct CustomField {
    /// Encrypted field name.
    #[serde(default)]
    pub name: Option<String>,
    /// Encrypted field value.
    #[serde(default)]
    pub value: Option<String>,
    /// Field type (0 = text, 1 = hidden, 2 = boolean, 3 = linked).
    #[serde(rename = "Type", default)]
    pub field_type: u8,
}

/// Decrypted view of a cipher — only the fields the caller asked for.
#[derive(Clone, Debug)]
pub struct PlainCipher {
    /// Server-assigned UUID.
    pub id: String,
    /// Cipher type.
    pub cipher_type: u8,
    /// Folder id (still encrypted in the source) — name resolution lives in the agent.
    pub folder_id: Option<String>,
    /// Decrypted display name.
    pub name: Option<String>,
    /// Decrypted notes, if present and asked for.
    pub notes: Option<String>,
    /// Decrypted username (login items only).
    pub username: Option<String>,
    /// Decrypted password (login items only).
    pub password: Option<String>,
    /// Decrypted TOTP URI (login items only).
    pub totp: Option<String>,
    /// First decrypted URI (login items only).
    pub primary_uri: Option<String>,
}

impl Drop for PlainCipher {
    fn drop(&mut self) {
        if let Some(s) = self.password.as_mut() {
            s.zeroize();
        }
        if let Some(s) = self.totp.as_mut() {
            s.zeroize();
        }
        if let Some(s) = self.notes.as_mut() {
            s.zeroize();
        }
    }
}

/// Which fields to materialise during decryption.
#[derive(Clone, Copy, Debug, Default)]
#[allow(clippy::struct_excessive_bools)] // one flag per decryptable field — a bitset would be less legible
pub struct DecryptOptions {
    /// Decrypt `notes` if present. Default `false`.
    pub notes: bool,
    /// Decrypt `login.username`. Default `false`.
    pub username: bool,
    /// Decrypt `login.password`. Default `false`.
    pub password: bool,
    /// Decrypt `login.totp`. Default `false`.
    pub totp: bool,
    /// Decrypt the first `login.uris[].uri`. Default `false`.
    pub primary_uri: bool,
}

impl DecryptOptions {
    /// Decrypt every login-relevant field plus notes.
    #[must_use]
    pub const fn all() -> Self {
        Self {
            notes: true,
            username: true,
            password: true,
            totp: true,
            primary_uri: true,
        }
    }
    /// Decrypt only `username` — useful for list views.
    #[must_use]
    pub const fn username_only() -> Self {
        Self {
            notes: false,
            username: true,
            password: false,
            totp: false,
            primary_uri: false,
        }
    }
}

impl Cipher {
    /// Decrypt this cipher's name under `(enc_key, mac_key)`. Returns
    /// `Ok(None)` for ciphers with no name field (rare; mostly secure notes
    /// that never had one set).
    ///
    /// # Errors
    ///
    /// Returns [`Error::MacMismatch`] or [`Error::Unpad`] if the name field is
    /// present but fails authentication or decryption under the given keys.
    pub fn decrypt_name(&self, enc_key: &[u8; 32], mac_key: &[u8; 32]) -> Result<Option<String>> {
        decrypt_optional(self.name.as_deref(), enc_key, mac_key)
    }

    /// Decrypt the requested set of fields and return a [`PlainCipher`] view.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MacMismatch`] or [`Error::Unpad`] if any requested
    /// field fails authentication or decryption under the given keys.
    pub fn decrypt(
        &self,
        enc_key: &[u8; 32],
        mac_key: &[u8; 32],
        opts: DecryptOptions,
    ) -> Result<PlainCipher> {
        let name = decrypt_optional(self.name.as_deref(), enc_key, mac_key)?;
        let notes = if opts.notes {
            decrypt_optional(self.notes.as_deref(), enc_key, mac_key)?
        } else {
            None
        };

        let mut out = PlainCipher {
            id: self.id.clone(),
            cipher_type: self.cipher_type,
            folder_id: self.folder_id.clone(),
            name,
            notes,
            username: None,
            password: None,
            totp: None,
            primary_uri: None,
        };

        if let Some(login) = self.login.as_ref() {
            if opts.username {
                out.username = decrypt_optional(login.username.as_deref(), enc_key, mac_key)?;
            }
            if opts.password {
                out.password = decrypt_optional(login.password.as_deref(), enc_key, mac_key)?;
            }
            if opts.totp {
                out.totp = decrypt_optional(login.totp.as_deref(), enc_key, mac_key)?;
            }
            if opts.primary_uri
                && let Some(first) = login.uris.as_ref().and_then(|uris| uris.first())
            {
                out.primary_uri = decrypt_optional(first.uri.as_deref(), enc_key, mac_key)?;
            }
        }

        Ok(out)
    }
}

/// Decrypt the user symmetric key (the `Key` field returned by
/// `/identity/connect/token`) using the stretched master key.
///
/// The plaintext is 64 bytes: `enc_key || mac_key`, both 32 bytes.
///
/// # Errors
///
/// Returns [`Error::MacMismatch`] / [`Error::Unpad`] if the wrapped key fails
/// authentication or decryption under the stretched master key, or
/// [`Error::EncString`] if the decrypted plaintext is not exactly 64 bytes.
pub fn decrypt_user_key(
    encrypted_user_key: &str,
    stretch_enc: &[u8; 32],
    stretch_mac: &[u8; 32],
) -> Result<([u8; 32], [u8; 32])> {
    let enc = EncString::parse(encrypted_user_key)?;
    // `Zeroizing` scrubs the 64-byte plaintext on every return path below.
    let pt = Zeroizing::new(enc.decrypt(stretch_enc, stretch_mac)?);
    if pt.len() != 64 {
        return Err(Error::EncString("user-key plaintext must be 64 bytes"));
    }
    let mut user_enc = [0u8; 32];
    let mut user_mac = [0u8; 32];
    user_enc.copy_from_slice(&pt[..32]);
    user_mac.copy_from_slice(&pt[32..]);
    Ok((user_enc, user_mac))
}

fn decrypt_optional(
    field: Option<&str>,
    enc_key: &[u8; 32],
    mac_key: &[u8; 32],
) -> Result<Option<String>> {
    let Some(s) = field else { return Ok(None) };
    if s.is_empty() {
        return Ok(None);
    }
    let enc = EncString::parse(s)?;
    let pt = enc.decrypt(enc_key, mac_key)?;
    let txt = String::from_utf8(pt).map_err(|_| Error::EncString("field is not valid UTF-8"))?;
    Ok(Some(txt))
}

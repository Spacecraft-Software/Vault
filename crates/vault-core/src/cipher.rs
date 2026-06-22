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
#[serde(rename_all = "camelCase")]
pub struct Cipher {
    /// Server-assigned UUID.
    #[serde(default)]
    pub id: String,
    /// Cipher type (1 = login, 2 = secure note, 3 = card, 4 = identity).
    #[serde(rename = "type", default)]
    pub cipher_type: u8,
    /// Folder this cipher belongs to, or `None` for unfiled.
    #[serde(default)]
    pub folder_id: Option<String>,
    /// Organization this cipher belongs to, if any.
    #[serde(default)]
    pub organization_id: Option<String>,
    /// Per-cipher symmetric key ("cipher key encryption"): an `EncString`
    /// wrapping 64 bytes (enc(32)‖mac(32)) under the user key. When present —
    /// the default for current Bitwarden vaults — every other field of this item
    /// is encrypted under *this* key, not the user key directly. See
    /// [`Cipher::decrypt`].
    #[serde(default)]
    pub key: Option<String>,
    /// Encrypted display name.
    #[serde(default)]
    pub name: Option<String>,
    /// Encrypted notes (any type).
    #[serde(default)]
    pub notes: Option<String>,
    /// Login-specific fields (present iff `cipher_type == 1`).
    #[serde(default)]
    pub login: Option<Login>,
    /// Card-specific fields (present iff `cipher_type == 3`).
    #[serde(default)]
    pub card: Option<Card>,
    /// Identity-specific fields (present iff `cipher_type == 4`).
    #[serde(default)]
    pub identity: Option<Identity>,
    /// User-defined custom fields.
    #[serde(default)]
    pub fields: Option<Vec<CustomField>>,
}

/// Login-specific encrypted fields.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
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
#[serde(rename_all = "camelCase")]
pub struct LoginUri {
    /// Encrypted URI.
    #[serde(default)]
    pub uri: Option<String>,
}

/// Card-specific encrypted fields (cipher type 3).
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Card {
    /// Encrypted cardholder name.
    #[serde(default)]
    pub cardholder_name: Option<String>,
    /// Encrypted card brand (`Visa`, `Mastercard`, …).
    #[serde(default)]
    pub brand: Option<String>,
    /// Encrypted card number.
    #[serde(default)]
    pub number: Option<String>,
    /// Encrypted expiry month (`1`–`12`, as stored).
    #[serde(default)]
    pub exp_month: Option<String>,
    /// Encrypted expiry year.
    #[serde(default)]
    pub exp_year: Option<String>,
    /// Encrypted security code (CVV/CVC).
    #[serde(default)]
    pub code: Option<String>,
}

/// Identity-specific encrypted fields (cipher type 4).
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Identity {
    /// Encrypted title (`Mr`, `Ms`, …).
    #[serde(default)]
    pub title: Option<String>,
    /// Encrypted first name.
    #[serde(default)]
    pub first_name: Option<String>,
    /// Encrypted middle name.
    #[serde(default)]
    pub middle_name: Option<String>,
    /// Encrypted last name.
    #[serde(default)]
    pub last_name: Option<String>,
    /// Encrypted username.
    #[serde(default)]
    pub username: Option<String>,
    /// Encrypted company.
    #[serde(default)]
    pub company: Option<String>,
    /// Encrypted Social Security Number (or national id).
    #[serde(default)]
    pub ssn: Option<String>,
    /// Encrypted passport number.
    #[serde(default)]
    pub passport_number: Option<String>,
    /// Encrypted driver's-license number.
    #[serde(default)]
    pub license_number: Option<String>,
    /// Encrypted email.
    #[serde(default)]
    pub email: Option<String>,
    /// Encrypted phone number.
    #[serde(default)]
    pub phone: Option<String>,
    /// Encrypted address line 1.
    #[serde(default)]
    pub address1: Option<String>,
    /// Encrypted address line 2.
    #[serde(default)]
    pub address2: Option<String>,
    /// Encrypted address line 3.
    #[serde(default)]
    pub address3: Option<String>,
    /// Encrypted city / locality.
    #[serde(default)]
    pub city: Option<String>,
    /// Encrypted state / province.
    #[serde(default)]
    pub state: Option<String>,
    /// Encrypted postal code.
    #[serde(default)]
    pub postal_code: Option<String>,
    /// Encrypted country.
    #[serde(default)]
    pub country: Option<String>,
}

/// User-defined `Fields[]` entry.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomField {
    /// Encrypted field name.
    #[serde(default)]
    pub name: Option<String>,
    /// Encrypted field value.
    #[serde(default)]
    pub value: Option<String>,
    /// Field type (0 = text, 1 = hidden, 2 = boolean, 3 = linked).
    #[serde(rename = "type", default)]
    pub field_type: u8,
}

/// Decrypted card fields (cipher type 3).
#[derive(Clone, Debug, Default)]
pub struct PlainCard {
    /// Cardholder name.
    pub cardholder_name: Option<String>,
    /// Card brand.
    pub brand: Option<String>,
    /// Card number (sensitive — zeroized on drop).
    pub number: Option<String>,
    /// Expiry month.
    pub exp_month: Option<String>,
    /// Expiry year.
    pub exp_year: Option<String>,
    /// Security code / CVV (sensitive — zeroized on drop).
    pub code: Option<String>,
}

impl Drop for PlainCard {
    fn drop(&mut self) {
        for s in [self.number.as_mut(), self.code.as_mut()]
            .into_iter()
            .flatten()
        {
            s.zeroize();
        }
    }
}

/// Decrypted identity fields (cipher type 4).
#[derive(Clone, Debug, Default)]
pub struct PlainIdentity {
    /// Title.
    pub title: Option<String>,
    /// First name.
    pub first_name: Option<String>,
    /// Middle name.
    pub middle_name: Option<String>,
    /// Last name.
    pub last_name: Option<String>,
    /// Username.
    pub username: Option<String>,
    /// Company.
    pub company: Option<String>,
    /// SSN / national id (sensitive — zeroized on drop).
    pub ssn: Option<String>,
    /// Passport number (sensitive — zeroized on drop).
    pub passport_number: Option<String>,
    /// License number (sensitive — zeroized on drop).
    pub license_number: Option<String>,
    /// Email.
    pub email: Option<String>,
    /// Phone.
    pub phone: Option<String>,
    /// Address line 1.
    pub address1: Option<String>,
    /// Address line 2.
    pub address2: Option<String>,
    /// Address line 3.
    pub address3: Option<String>,
    /// City.
    pub city: Option<String>,
    /// State / province.
    pub state: Option<String>,
    /// Postal code.
    pub postal_code: Option<String>,
    /// Country.
    pub country: Option<String>,
}

impl Drop for PlainIdentity {
    fn drop(&mut self) {
        for s in [
            self.ssn.as_mut(),
            self.passport_number.as_mut(),
            self.license_number.as_mut(),
        ]
        .into_iter()
        .flatten()
        {
            s.zeroize();
        }
    }
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
    /// Decrypted card fields (card items only, when asked for).
    pub card: Option<PlainCard>,
    /// Decrypted identity fields (identity items only, when asked for).
    pub identity: Option<PlainIdentity>,
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
    /// Decrypt the `card` sub-object (all its fields). Default `false`.
    pub card: bool,
    /// Decrypt the `identity` sub-object (all its fields). Default `false`.
    pub identity: bool,
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
            card: true,
            identity: true,
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
            card: false,
            identity: false,
        }
    }
}

/// A per-cipher field key — the (enc, mac) pair recovered from a cipher's own
/// `key` ("cipher key encryption"), each half zeroized on drop.
type ItemKey = (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>);

impl Cipher {
    /// Resolve the per-cipher field key for "cipher key encryption".
    ///
    /// When [`key`](Self::key) is present it is an `EncString` wrapping 64 bytes
    /// of key material (enc(32)‖mac(32)) under the user key; every other field of
    /// the cipher is then encrypted under *that* key. Returns `Ok(None)` for
    /// older items with no per-cipher key (their fields use the user key
    /// directly), so callers can fall back to `(enc_key, mac_key)`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MacMismatch`] when the wrapped key fails authentication
    /// under the user key — e.g. an organization item, whose key is wrapped
    /// under an org key Vault does not hold — or [`Error::EncString`] if the
    /// unwrapped key is not 64 bytes.
    fn item_field_key(&self, enc_key: &[u8; 32], mac_key: &[u8; 32]) -> Result<Option<ItemKey>> {
        let Some(raw_key) = self.key.as_deref() else {
            return Ok(None);
        };
        let material = Zeroizing::new(EncString::parse(raw_key)?.decrypt(enc_key, mac_key)?);
        if material.len() != 64 {
            return Err(Error::EncString("cipher key must unwrap to 64 bytes"));
        }
        let mut item_enc = Zeroizing::new([0u8; 32]);
        let mut item_mac = Zeroizing::new([0u8; 32]);
        item_enc.copy_from_slice(&material[..32]);
        item_mac.copy_from_slice(&material[32..]);
        Ok(Some((item_enc, item_mac)))
    }

    /// Decrypt this cipher's name. Returns `Ok(None)` for ciphers with no name
    /// field (rare; mostly secure notes that never had one set).
    ///
    /// # Errors
    ///
    /// Returns [`Error::MacMismatch`] or [`Error::Unpad`] if the name field (or
    /// the per-cipher key) is present but fails authentication or decryption.
    pub fn decrypt_name(&self, enc_key: &[u8; 32], mac_key: &[u8; 32]) -> Result<Option<String>> {
        let item_key = self.item_field_key(enc_key, mac_key)?;
        let (enc_key, mac_key): (&[u8; 32], &[u8; 32]) = match &item_key {
            Some((e, m)) => (&**e, &**m),
            None => (enc_key, mac_key),
        };
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
        // Cipher-key encryption: when this item carries its own `key`, every
        // field below is encrypted under that per-item key. Shadow the user key
        // with it so the rest of this method needs no special-casing.
        let item_key = self.item_field_key(enc_key, mac_key)?;
        let (enc_key, mac_key): (&[u8; 32], &[u8; 32]) = match &item_key {
            Some((e, m)) => (&**e, &**m),
            None => (enc_key, mac_key),
        };

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
            card: None,
            identity: None,
        };

        if opts.card
            && let Some(card) = self.card.as_ref()
        {
            let d = |s: Option<&str>| decrypt_optional(s, enc_key, mac_key);
            out.card = Some(PlainCard {
                cardholder_name: d(card.cardholder_name.as_deref())?,
                brand: d(card.brand.as_deref())?,
                number: d(card.number.as_deref())?,
                exp_month: d(card.exp_month.as_deref())?,
                exp_year: d(card.exp_year.as_deref())?,
                code: d(card.code.as_deref())?,
            });
        }

        if opts.identity
            && let Some(id) = self.identity.as_ref()
        {
            let d = |s: Option<&str>| decrypt_optional(s, enc_key, mac_key);
            out.identity = Some(PlainIdentity {
                title: d(id.title.as_deref())?,
                first_name: d(id.first_name.as_deref())?,
                middle_name: d(id.middle_name.as_deref())?,
                last_name: d(id.last_name.as_deref())?,
                username: d(id.username.as_deref())?,
                company: d(id.company.as_deref())?,
                ssn: d(id.ssn.as_deref())?,
                passport_number: d(id.passport_number.as_deref())?,
                license_number: d(id.license_number.as_deref())?,
                email: d(id.email.as_deref())?,
                phone: d(id.phone.as_deref())?,
                address1: d(id.address1.as_deref())?,
                address2: d(id.address2.as_deref())?,
                address3: d(id.address3.as_deref())?,
                city: d(id.city.as_deref())?,
                state: d(id.state.as_deref())?,
                postal_code: d(id.postal_code.as_deref())?,
                country: d(id.country.as_deref())?,
            });
        }

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

    /// Encrypt a [`PlainCipher`]'s populated fields under `(enc_key, mac_key)`,
    /// producing a `/sync`-shaped `Cipher` ready to serialize into a create or
    /// update request. The inverse of [`Cipher::decrypt`].
    ///
    /// `cipher_type`, `id`, and `folder_id` pass through from `plain`
    /// unchanged (they are plaintext metadata, not `EncString` fields). Login
    /// sub-fields are emitted only for `cipher_type == 1`, card sub-fields only
    /// for `cipher_type == 3`; identity (type 4) write isn't built yet.
    #[must_use]
    pub fn from_plain(plain: &PlainCipher, enc_key: &[u8; 32], mac_key: &[u8; 32]) -> Self {
        let enc = |s: &str| EncString::encrypt(enc_key, mac_key, s.as_bytes()).serialize();
        let login = (plain.cipher_type == 1).then(|| Login {
            username: plain.username.as_deref().map(&enc),
            password: plain.password.as_deref().map(&enc),
            totp: plain.totp.as_deref().map(&enc),
            uris: plain
                .primary_uri
                .as_deref()
                .map(|u| vec![LoginUri { uri: Some(enc(u)) }]),
        });
        let card = if plain.cipher_type == 3 {
            plain.card.as_ref().map(|c| Card {
                cardholder_name: c.cardholder_name.as_deref().map(&enc),
                brand: c.brand.as_deref().map(&enc),
                number: c.number.as_deref().map(&enc),
                exp_month: c.exp_month.as_deref().map(&enc),
                exp_year: c.exp_year.as_deref().map(&enc),
                code: c.code.as_deref().map(&enc),
            })
        } else {
            None
        };
        let identity = if plain.cipher_type == 4 {
            plain.identity.as_ref().map(|i| Identity {
                title: i.title.as_deref().map(&enc),
                first_name: i.first_name.as_deref().map(&enc),
                middle_name: i.middle_name.as_deref().map(&enc),
                last_name: i.last_name.as_deref().map(&enc),
                username: i.username.as_deref().map(&enc),
                company: i.company.as_deref().map(&enc),
                ssn: i.ssn.as_deref().map(&enc),
                passport_number: i.passport_number.as_deref().map(&enc),
                license_number: i.license_number.as_deref().map(&enc),
                email: i.email.as_deref().map(&enc),
                phone: i.phone.as_deref().map(&enc),
                address1: i.address1.as_deref().map(&enc),
                address2: i.address2.as_deref().map(&enc),
                address3: i.address3.as_deref().map(&enc),
                city: i.city.as_deref().map(&enc),
                state: i.state.as_deref().map(&enc),
                postal_code: i.postal_code.as_deref().map(&enc),
                country: i.country.as_deref().map(&enc),
            })
        } else {
            None
        };
        Self {
            id: plain.id.clone(),
            cipher_type: plain.cipher_type,
            folder_id: plain.folder_id.clone(),
            organization_id: None,
            // Vault writes fields under the user key directly (no per-cipher
            // key); the server accepts this. Round-tripping a server item's own
            // `key` would require re-wrapping it, which write paths don't do.
            key: None,
            name: plain.name.as_deref().map(&enc),
            notes: plain.notes.as_deref().map(&enc),
            login,
            card,
            identity,
            fields: None,
        }
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

#[cfg(test)]
mod tests {
    use super::{Cipher, DecryptOptions, Login};
    use crate::enc_string::EncString;

    const USER_ENC: [u8; 32] = [1u8; 32];
    const USER_MAC: [u8; 32] = [2u8; 32];
    const ITEM_ENC: [u8; 32] = [3u8; 32];
    const ITEM_MAC: [u8; 32] = [4u8; 32];

    fn under(enc: &[u8; 32], mac: &[u8; 32], plain: &str) -> String {
        EncString::encrypt(enc, mac, plain.as_bytes()).serialize()
    }

    /// "Cipher key encryption": the item's fields are encrypted under a per-item
    /// key, and that key is an `EncString` (64 bytes) wrapped under the user key.
    /// Regression guard — decrypting fields with the user key directly fails MAC.
    #[test]
    fn cipher_key_encryption_round_trips() {
        // The 64-byte item key (enc‖mac) wrapped under the user key.
        let mut material = [0u8; 64];
        material[..32].copy_from_slice(&ITEM_ENC);
        material[32..].copy_from_slice(&ITEM_MAC);
        let wrapped = EncString::encrypt(&USER_ENC, &USER_MAC, &material).serialize();

        let cipher = Cipher {
            cipher_type: 1,
            key: Some(wrapped),
            // name + password encrypted under the ITEM key, not the user key.
            name: Some(under(&ITEM_ENC, &ITEM_MAC, "github.com")),
            login: Some(Login {
                password: Some(under(&ITEM_ENC, &ITEM_MAC, "hunter2")),
                ..Login::default()
            }),
            ..Cipher::default()
        };

        assert_eq!(
            cipher
                .decrypt_name(&USER_ENC, &USER_MAC)
                .unwrap()
                .as_deref(),
            Some("github.com"),
        );
        let plain = cipher
            .decrypt(&USER_ENC, &USER_MAC, DecryptOptions::all())
            .unwrap();
        assert_eq!(plain.password.as_deref(), Some("hunter2"));
    }

    /// Items without a per-cipher `key` (older vaults) still decrypt directly
    /// under the user key.
    #[test]
    fn no_cipher_key_uses_user_key_directly() {
        let cipher = Cipher {
            cipher_type: 2,
            key: None,
            name: Some(under(&USER_ENC, &USER_MAC, "legacy note")),
            ..Cipher::default()
        };
        assert_eq!(
            cipher
                .decrypt_name(&USER_ENC, &USER_MAC)
                .unwrap()
                .as_deref(),
            Some("legacy note"),
        );
    }

    /// A `key` that can't be unwrapped under the user key (e.g. an organization
    /// item) surfaces as an error rather than silently mis-decrypting.
    #[test]
    fn unwrappable_cipher_key_errors() {
        let wrong = [9u8; 32];
        let mut material = [0u8; 64];
        material[..32].copy_from_slice(&ITEM_ENC);
        material[32..].copy_from_slice(&ITEM_MAC);
        // Key wrapped under a DIFFERENT user key than we'll decrypt with.
        let wrapped = EncString::encrypt(&wrong, &wrong, &material).serialize();
        let cipher = Cipher {
            cipher_type: 1,
            key: Some(wrapped),
            name: Some(under(&ITEM_ENC, &ITEM_MAC, "github.com")),
            ..Cipher::default()
        };
        assert!(cipher.decrypt_name(&USER_ENC, &USER_MAC).is_err());
    }
}

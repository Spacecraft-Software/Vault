// SPDX-License-Identifier: GPL-3.0-or-later

//! Bitwarden `EncString` — `<type>.<iv>|<ct>|<mac>` base64 envelope.
//!
//! Vault currently implements **type 2** only: AES-256-CBC with PKCS#7 padding,
//! authenticated by an Encrypt-then-MAC HMAC-SHA-256 over `iv || ct`. Legacy
//! type 0 (CBC without MAC) is intentionally rejected.

use aes::Aes256;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::error::{Error, Result};

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;
type HmacSha256 = Hmac<Sha256>;

/// AES-256 key (32 bytes).
pub const KEY_LEN: usize = 32;
/// AES block / IV length (16 bytes).
pub const IV_LEN: usize = 16;
/// HMAC-SHA-256 tag length (32 bytes).
pub const MAC_LEN: usize = 32;

/// Bitwarden type 2: AES-256-CBC + HMAC-SHA-256 (Encrypt-then-MAC).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncString {
    iv: [u8; IV_LEN],
    ct: Vec<u8>,
    mac: [u8; MAC_LEN],
}

impl EncString {
    /// Parse the canonical Bitwarden serialisation: `2.<iv_b64>|<ct_b64>|<mac_b64>`.
    pub fn parse(s: &str) -> Result<Self> {
        let (ty, rest) = s
            .split_once('.')
            .ok_or(Error::EncString("missing type prefix"))?;
        match ty {
            "2" => {}
            "0" | "1" => return Err(Error::EncString("legacy unauthenticated type rejected")),
            _ => return Err(Error::EncString("unknown EncString type")),
        }
        let mut parts = rest.splitn(3, '|');
        let iv_b64 = parts.next().ok_or(Error::EncString("missing iv"))?;
        let ct_b64 = parts.next().ok_or(Error::EncString("missing ciphertext"))?;
        let mac_b64 = parts.next().ok_or(Error::EncString("missing mac"))?;

        let iv_bytes = B64.decode(iv_b64)?;
        let ct = B64.decode(ct_b64)?;
        let mac_bytes = B64.decode(mac_b64)?;

        if iv_bytes.len() != IV_LEN {
            return Err(Error::EncString("iv length must be 16"));
        }
        if mac_bytes.len() != MAC_LEN {
            return Err(Error::EncString("mac length must be 32"));
        }
        let mut iv = [0u8; IV_LEN];
        iv.copy_from_slice(&iv_bytes);
        let mut mac = [0u8; MAC_LEN];
        mac.copy_from_slice(&mac_bytes);
        Ok(Self { iv, ct, mac })
    }

    /// Re-serialise to the canonical `2.<iv>|<ct>|<mac>` form.
    #[must_use]
    pub fn serialize(&self) -> String {
        format!(
            "2.{}|{}|{}",
            B64.encode(self.iv),
            B64.encode(&self.ct),
            B64.encode(self.mac)
        )
    }

    /// Encrypt `plaintext` with the given enc/mac keys and a caller-supplied IV.
    ///
    /// The caller is responsible for the IV's uniqueness; in production paths
    /// use [`Self::encrypt`] which generates a fresh random IV.
    pub fn encrypt_with_iv(
        enc_key: &[u8; KEY_LEN],
        mac_key: &[u8; KEY_LEN],
        iv: [u8; IV_LEN],
        plaintext: &[u8],
    ) -> Self {
        let cipher = Aes256CbcEnc::new(enc_key.into(), (&iv).into());
        let ct = cipher.encrypt_padded_vec_mut::<Pkcs7>(plaintext);
        let mut hmac = <HmacSha256 as Mac>::new_from_slice(mac_key)
            .expect("HMAC-SHA256 accepts any key length");
        hmac.update(&iv);
        hmac.update(&ct);
        let mut mac = [0u8; MAC_LEN];
        mac.copy_from_slice(&hmac.finalize().into_bytes());
        Self { iv, ct, mac }
    }

    /// Encrypt `plaintext` under `(enc_key, mac_key)` with a freshly drawn IV.
    pub fn encrypt(enc_key: &[u8; KEY_LEN], mac_key: &[u8; KEY_LEN], plaintext: &[u8]) -> Self {
        let mut iv = [0u8; IV_LEN];
        getrandom::getrandom(&mut iv).expect("OS RNG must be available");
        Self::encrypt_with_iv(enc_key, mac_key, iv, plaintext)
    }

    /// Verify the MAC in constant time, then decrypt.
    ///
    /// Returns `Err(Error::MacMismatch)` before touching the cipher when MAC
    /// verification fails — Encrypt-then-MAC discipline.
    pub fn decrypt(&self, enc_key: &[u8; KEY_LEN], mac_key: &[u8; KEY_LEN]) -> Result<Vec<u8>> {
        let mut hmac = <HmacSha256 as Mac>::new_from_slice(mac_key)
            .expect("HMAC-SHA256 accepts any key length");
        hmac.update(&self.iv);
        hmac.update(&self.ct);
        let computed = hmac.finalize().into_bytes();

        // subtle::ConstantTimeEq for defense-in-depth even though hmac's
        // verify_slice is also constant-time.
        if computed.ct_eq(&self.mac).unwrap_u8() != 1 {
            return Err(Error::MacMismatch);
        }

        let cipher = Aes256CbcDec::new(enc_key.into(), (&self.iv).into());
        let mut buf = self.ct.clone();
        let pt = cipher
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .map_err(|_| Error::Unpad)?;
        let out = pt.to_vec();
        buf.zeroize();
        Ok(out)
    }

    /// Borrow the IV.
    #[must_use]
    pub fn iv(&self) -> &[u8; IV_LEN] {
        &self.iv
    }
    /// Borrow the ciphertext.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ct
    }
    /// Borrow the MAC tag.
    #[must_use]
    pub fn mac(&self) -> &[u8; MAC_LEN] {
        &self.mac
    }
}

impl Drop for EncString {
    fn drop(&mut self) {
        self.ct.zeroize();
        self.iv.zeroize();
        self.mac.zeroize();
    }
}

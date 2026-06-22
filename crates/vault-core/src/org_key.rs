// SPDX-License-Identifier: GPL-3.0-or-later

//! Organization keys — RSA-2048-OAEP-SHA1 unwrapping.
//!
//! Personal ciphers decrypt under the user symmetric key; **organization**
//! ciphers decrypt under that organization's key. The org key is delivered in
//! `/sync` (`profile.organizations[].key`) as a Bitwarden **type-4** `EncString`:
//! the 64-byte org key (`enc(32)‖mac(32)`) RSA-OAEP-SHA1-encrypted under the
//! account's public key. The matching private key arrives as
//! `profile.privateKey` — a **type-2** (AES) `EncString` wrapping the PKCS#8 DER
//! private key under the user key.
//!
//! `ring` (Vault's symmetric crypto) has no RSA decryption, so this is the one
//! place the `rsa` crate is used — see its note in `Cargo.toml` re: the audit
//! ignore. Decryption here is local and one-shot (at unlock), never a network
//! oracle.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use rsa::Oaep;
use rsa::RsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use zeroize::Zeroizing;

use crate::enc_string::EncString;
use crate::error::{Error, Result};

/// The account's RSA private key, recovered from `profile.privateKey`. Used to
/// unwrap each organization's symmetric key.
pub struct AccountKey(RsaPrivateKey);

impl AccountKey {
    /// Recover the account private key from its `profile.privateKey` `EncString`
    /// — a type-2 (AES) `EncString` wrapping the PKCS#8 DER key under the user key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MacMismatch`] / [`Error::Unpad`] if the `EncString` fails
    /// under the user key, or [`Error::Rsa`] if the plaintext is not a valid
    /// PKCS#8 RSA private key.
    pub fn from_protected(
        private_key_enc: &str,
        user_enc: &[u8; 32],
        user_mac: &[u8; 32],
    ) -> Result<Self> {
        // `der` holds the raw private key; `Zeroizing` scrubs it after parsing.
        let der = Zeroizing::new(EncString::parse(private_key_enc)?.decrypt(user_enc, user_mac)?);
        let key = RsaPrivateKey::from_pkcs8_der(&der)
            .map_err(|_| Error::Rsa("invalid PKCS#8 RSA private key"))?;
        Ok(Self(key))
    }

    /// RSA-OAEP-SHA1-decrypt a type-4 organization-key `EncString` and split the
    /// 64-byte result into its `(enc, mac)` halves.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EncString`] if `org_key_enc` is not a 64-byte type-4
    /// `EncString`, [`Error::Base64`] on a malformed payload, or [`Error::Rsa`] if
    /// OAEP decryption fails.
    pub fn decrypt_org_key(&self, org_key_enc: &str) -> Result<([u8; 32], [u8; 32])> {
        let ciphertext = parse_type4(org_key_enc)?;
        // OAEP with SHA-1 for both the label hash and MGF1 (Bitwarden type 4).
        let raw = Zeroizing::new(
            self.0
                .decrypt(Oaep::new::<sha1::Sha1>(), &ciphertext)
                .map_err(|_| Error::Rsa("RSA-OAEP decryption failed"))?,
        );
        if raw.len() != 64 {
            return Err(Error::EncString("organization key must be 64 bytes"));
        }
        let mut enc = [0u8; 32];
        let mut mac = [0u8; 32];
        enc.copy_from_slice(&raw[..32]);
        mac.copy_from_slice(&raw[32..]);
        Ok((enc, mac))
    }
}

impl core::fmt::Debug for AccountKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never render key material.
        f.write_str("AccountKey(..)")
    }
}

/// Parse a Bitwarden **type-4** `EncString` — `"4.<base64 RSA ciphertext>"` — into
/// its raw ciphertext bytes. Type 4 (`Rsa2048_OaepSha1_B64`) is a single base64
/// payload with no IV or MAC; RSA-OAEP is itself the authenticated envelope.
fn parse_type4(s: &str) -> Result<Vec<u8>> {
    let rest = s
        .strip_prefix("4.")
        .ok_or(Error::EncString("not a type-4 (RSA) EncString"))?;
    Ok(B64.decode(rest)?)
}

#[cfg(test)]
mod tests {
    use super::AccountKey;
    use crate::enc_string::EncString;
    use base64::Engine as _;
    use rand::SeedableRng as _;
    use rand::rngs::StdRng;
    use rsa::RsaPrivateKey;
    use rsa::pkcs8::EncodePrivateKey;
    use rsa::traits::PublicKeyParts as _;
    use rsa::{Oaep, RsaPublicKey};

    const USER_ENC: [u8; 32] = [1u8; 32];
    const USER_MAC: [u8; 32] = [2u8; 32];

    // A deterministic small-but-real RSA-2048 key would be ideal, but generating
    // one needs an RNG. `rand` is a dev-dependency; use it here only.
    fn test_key() -> RsaPrivateKey {
        let mut rng = StdRng::seed_from_u64(42);
        RsaPrivateKey::new(&mut rng, 2048).expect("generate test key")
    }

    /// End-to-end: wrap the private key (type-2 under the user key) and an org
    /// key (type-4 under the public key), then recover both and check the split.
    #[test]
    fn unwraps_org_key_through_account_key() {
        let priv_key = test_key();
        let pub_key = RsaPublicKey::from(&priv_key);
        assert_eq!(pub_key.size(), 256, "RSA-2048");

        // profile.privateKey: PKCS#8 DER, AES-wrapped under the user key.
        let der = priv_key.to_pkcs8_der().expect("pkcs8").as_bytes().to_vec();
        let protected = EncString::encrypt(&USER_ENC, &USER_MAC, &der).serialize();

        // An org key (64 bytes) RSA-OAEP-SHA1-wrapped under the public key.
        let mut org = [0u8; 64];
        org[..32].copy_from_slice(&[7u8; 32]);
        org[32..].copy_from_slice(&[8u8; 32]);
        let mut rng = StdRng::seed_from_u64(7);
        let wrapped = pub_key
            .encrypt(&mut rng, Oaep::new::<sha1::Sha1>(), &org)
            .expect("wrap org key");
        let type4 = format!(
            "4.{}",
            base64::engine::general_purpose::STANDARD.encode(&wrapped)
        );

        let account = AccountKey::from_protected(&protected, &USER_ENC, &USER_MAC).unwrap();
        let (enc, mac) = account.decrypt_org_key(&type4).unwrap();
        assert_eq!(enc, [7u8; 32]);
        assert_eq!(mac, [8u8; 32]);
    }

    #[test]
    fn rejects_non_type4() {
        let account = AccountKey::from_protected(
            &EncString::encrypt(
                &USER_ENC,
                &USER_MAC,
                test_key().to_pkcs8_der().unwrap().as_bytes(),
            )
            .serialize(),
            &USER_ENC,
            &USER_MAC,
        )
        .unwrap();
        // A type-2 string is not a valid org-key envelope.
        assert!(account.decrypt_org_key("2.aXY=|Y3Q=|bWFj").is_err());
    }
}

// SPDX-License-Identifier: GPL-3.0-or-later

//! Vault core — crypto primitives, KDF, `EncString` parsing, and the
//! encrypted-export decoder.
//!
//! Stability: pre-1.0, every API may change. See PRD §9.1.

#![forbid(unsafe_code)]

pub mod cipher;
pub mod enc_string;
pub mod error;
pub mod export;
pub mod generate;
pub mod kdf;
pub mod login;
pub mod org_key;
pub mod totp;
/// EFF diceware wordlist (CC-BY-3.0 data; see `REUSE.toml`) for passphrases.
mod wordlist;

pub use cipher::{Cipher, DecryptOptions, Login, PlainCipher, decrypt_user_key};
pub use enc_string::EncString;
pub use error::{Error, Result};
pub use export::EncryptedExport;
pub use generate::{GenerateOptions, PassphraseOptions, generate_passphrase, generate_password};
pub use kdf::{KdfParams, KdfType, derive_master_key, stretch_master_key};
pub use login::master_password_hash;
pub use org_key::AccountKey;

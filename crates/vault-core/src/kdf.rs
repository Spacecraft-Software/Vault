// SPDX-License-Identifier: GPL-3.0-or-later

//! KDF abstraction — PBKDF2-SHA-256 and Argon2id.
//!
//! Bitwarden accounts and password-protected exports declare one of these
//! KDFs and its parameters in the envelope; Vault honours whatever the
//! account advertises and never silently downgrades.

use argon2::{Algorithm, Argon2, Params, Version};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha256;

use crate::error::{Error, Result};

/// Bitwarden KDF discriminant. Values match the wire protocol's `kdfType` field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[repr(u8)]
#[serde(try_from = "u8", into = "u8")]
pub enum KdfType {
    /// PBKDF2-SHA-256 (Bitwarden `kdfType: 0`).
    Pbkdf2Sha256 = 0,
    /// Argon2id (Bitwarden `kdfType: 1`).
    Argon2id = 1,
}

impl TryFrom<u8> for KdfType {
    type Error = Error;
    fn try_from(v: u8) -> Result<Self> {
        match v {
            0 => Ok(Self::Pbkdf2Sha256),
            1 => Ok(Self::Argon2id),
            _ => Err(Error::UnsupportedExport("unknown kdfType")),
        }
    }
}

impl From<KdfType> for u8 {
    fn from(k: KdfType) -> Self {
        k as Self
    }
}

/// Parameters as supplied by the server / export envelope.
#[derive(Clone, Copy, Debug)]
pub struct KdfParams {
    /// Which KDF to run.
    pub kind: KdfType,
    /// PBKDF2 iteration count, or Argon2 iteration count (`t_cost`).
    pub iterations: u32,
    /// Argon2 memory cost in KiB (ignored for PBKDF2).
    pub memory_kib: Option<u32>,
    /// Argon2 parallelism lanes (ignored for PBKDF2).
    pub parallelism: Option<u32>,
}

impl KdfParams {
    /// Bitwarden's current default for PBKDF2 password vaults: `600_000` iterations.
    #[must_use]
    pub const fn pbkdf2_default() -> Self {
        Self {
            kind: KdfType::Pbkdf2Sha256,
            iterations: 600_000,
            memory_kib: None,
            parallelism: None,
        }
    }

    /// Bitwarden's current default for Argon2id vaults: 3 iters, 64 MiB, 4 lanes.
    #[must_use]
    pub const fn argon2id_default() -> Self {
        Self {
            kind: KdfType::Argon2id,
            iterations: 3,
            memory_kib: Some(65_536),
            parallelism: Some(4),
        }
    }
}

/// Derive a 32-byte master key from `password` and `salt` under `params`.
///
/// For PBKDF2 the salt is used directly. For Argon2id, Bitwarden first
/// SHA-256-hashes the salt to a fixed 32-byte string before passing it to
/// Argon2 — this matches the official clients and is what the server expects.
///
/// # Errors
///
/// Returns [`Error::Kdf`] for invalid parameters (zero iterations, missing
/// Argon2 memory/lanes) and [`Error::Argon2`] if Argon2id hashing fails.
pub fn derive_master_key(password: &[u8], salt: &[u8], params: KdfParams) -> Result<[u8; 32]> {
    if params.iterations == 0 {
        return Err(Error::Kdf("iterations must be > 0"));
    }
    let mut out = [0u8; 32];
    match params.kind {
        KdfType::Pbkdf2Sha256 => {
            pbkdf2::<Hmac<Sha256>>(password, salt, params.iterations, &mut out)
                .map_err(|_| Error::Kdf("pbkdf2 output length"))?;
        }
        KdfType::Argon2id => {
            use sha2::Digest;
            let salt_hash: [u8; 32] = Sha256::digest(salt).into();
            let memory = params
                .memory_kib
                .ok_or(Error::Kdf("argon2 memory missing"))?;
            let lanes = params
                .parallelism
                .ok_or(Error::Kdf("argon2 lanes missing"))?;
            let argon_params = Params::new(memory, params.iterations, lanes, Some(32))?;
            let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
            argon.hash_password_into(password, &salt_hash, &mut out)?;
        }
    }
    Ok(out)
}

/// HKDF-SHA-256 expand a 32-byte master key into a 64-byte `(enc, mac)` pair.
///
/// Bitwarden uses a fixed `info` of `"enc"` for the encryption half and
/// `"mac"` for the MAC half, with an empty salt. This mirrors the official
/// clients' `stretchKey` routine.
///
/// # Errors
///
/// Returns [`Error::Hkdf`] if HKDF-SHA-256 expansion fails (output length out
/// of range — unreachable for the fixed 32-byte outputs here).
pub fn stretch_master_key(master: &[u8; 32]) -> Result<([u8; 32], [u8; 32])> {
    let hk = hkdf::Hkdf::<Sha256>::from_prk(master).map_err(|_| Error::Hkdf)?;
    let mut enc = [0u8; 32];
    let mut mac = [0u8; 32];
    hk.expand(b"enc", &mut enc).map_err(|_| Error::Hkdf)?;
    hk.expand(b"mac", &mut mac).map_err(|_| Error::Hkdf)?;
    Ok((enc, mac))
}

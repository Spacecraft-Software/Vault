// SPDX-License-Identifier: GPL-3.0-or-later

//! Password generator — uniform sampling over user-selectable ASCII classes.
//!
//! No KDF, no entropy mixing — just OS `getrandom` plus rejection sampling
//! to avoid the modulo bias you get from `byte % pool.len()`. The output is
//! returned in a [`Zeroizing<String>`] so the caller can hand it to a
//! clipboard or the agent and trust the buffer is wiped on drop.

use zeroize::Zeroizing;

use crate::error::{Error, Result};

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
/// Symbol set chosen to match Bitwarden's default symbol pool.
const SYMBOLS: &[u8] = b"!@#$%^&*";

/// Options for [`generate_password`].
///
/// Defaults match Bitwarden's modern recommendation: 20 chars, letters and
/// digits, symbols off. Toggle `symbols` to widen the alphabet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(clippy::struct_excessive_bools)]
pub struct GenerateOptions {
    /// Total password length in characters.
    pub length: usize,
    /// Include lowercase letters (`a–z`).
    pub lowercase: bool,
    /// Include uppercase letters (`A–Z`).
    pub uppercase: bool,
    /// Include digits (`0–9`).
    pub digits: bool,
    /// Include the symbol pool (`!@#$%^&*`).
    pub symbols: bool,
}

impl Default for GenerateOptions {
    fn default() -> Self {
        Self {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: false,
        }
    }
}

/// Generate a password under `opts`.
///
/// Guarantees at least one character from each enabled class, then fills the
/// remaining positions uniformly from the union, then Fisher–Yates shuffles
/// so the "one per class" prefix isn't predictable.
///
/// # Errors
///
/// Returns [`Error::Generate`] when no character class is enabled, when
/// `opts.length` is zero, when `opts.length` is smaller than the number of
/// enabled classes (so the "at least one of each" guarantee can't be met),
/// or when the OS RNG (`getrandom`) fails.
pub fn generate_password(opts: &GenerateOptions) -> Result<Zeroizing<String>> {
    if opts.length == 0 {
        return Err(Error::Generate("length must be greater than zero"));
    }

    let pools: Vec<&[u8]> = [
        (opts.lowercase, LOWER),
        (opts.uppercase, UPPER),
        (opts.digits, DIGITS),
        (opts.symbols, SYMBOLS),
    ]
    .into_iter()
    .filter_map(|(on, pool)| on.then_some(pool))
    .collect();

    if pools.is_empty() {
        return Err(Error::Generate(
            "at least one character class must be enabled",
        ));
    }
    if opts.length < pools.len() {
        return Err(Error::Generate(
            "length must be at least the number of enabled character classes",
        ));
    }

    let union: Vec<u8> = pools.iter().flat_map(|p| p.iter().copied()).collect();

    let mut out: Vec<u8> = Vec::with_capacity(opts.length);
    for pool in &pools {
        out.push(pool[sample_index(pool.len())?]);
    }
    while out.len() < opts.length {
        out.push(union[sample_index(union.len())?]);
    }
    for i in (1..out.len()).rev() {
        let j = sample_index(i + 1)?;
        out.swap(i, j);
    }

    // All bytes came from ASCII-only pools above, so this can't fail.
    let s = String::from_utf8(out).map_err(|_| Error::Generate("non-ascii byte in pool — bug"))?;
    Ok(Zeroizing::new(s))
}

/// Uniform sample of `[0, n)` via rejection sampling on a 64-bit draw.
fn sample_index(n: usize) -> Result<usize> {
    debug_assert!(n > 0);
    let n_u64 = u64::try_from(n).map_err(|_| Error::Generate("pool too large"))?;
    // 2^64 mod n, computed without overflow.
    let reject_zone = (u64::MAX % n_u64 + 1) % n_u64;
    loop {
        let mut buf = [0u8; 8];
        getrandom::getrandom(&mut buf).map_err(|_| Error::Generate("getrandom failed"))?;
        let v = u64::from_le_bytes(buf);
        if reject_zone == 0 || v <= u64::MAX - reject_zone {
            return Ok(usize::try_from(v % n_u64).unwrap_or(0));
        }
    }
}

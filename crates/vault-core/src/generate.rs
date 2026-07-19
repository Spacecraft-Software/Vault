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

/// Word-count bounds for [`generate_passphrase`] (matches Bitwarden's range).
const PASSPHRASE_MIN_WORDS: usize = 3;
const PASSPHRASE_MAX_WORDS: usize = 20;

/// Options for [`generate_passphrase`].
///
/// Defaults match Bitwarden's: 3 words, `-` separator, no capitalization, no
/// number. Six or more words is the usual "strong passphrase" recommendation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PassphraseOptions {
    /// Number of words (validated to `3..=20`).
    pub words: usize,
    /// String joining the words (e.g. `"-"`); may be empty.
    pub separator: String,
    /// Capitalize the first letter of each word.
    pub capitalize: bool,
    /// Append a random digit to one random word.
    pub include_number: bool,
}

impl Default for PassphraseOptions {
    fn default() -> Self {
        Self {
            words: PASSPHRASE_MIN_WORDS,
            separator: "-".to_owned(),
            capitalize: false,
            include_number: false,
        }
    }
}

/// Generate a diceware passphrase under `opts` from the EFF large wordlist.
///
/// Words are drawn uniformly **with replacement** (independent draws; the
/// entropy is `words * log2(7776)`, ~12.9 bits each). With `capitalize`, each
/// word's first letter is upper-cased; with `include_number`, a random digit is
/// appended to one random word (matching Bitwarden). Words are joined by
/// `separator`. The result is returned in a [`Zeroizing<String>`].
///
/// # Errors
///
/// Returns [`Error::Generate`] when `opts.words` is outside `3..=20`, or when
/// the OS RNG (`getrandom`) fails.
pub fn generate_passphrase(opts: &PassphraseOptions) -> Result<Zeroizing<String>> {
    if opts.words < PASSPHRASE_MIN_WORDS || opts.words > PASSPHRASE_MAX_WORDS {
        return Err(Error::Generate(
            "passphrase word count must be between 3 and 20",
        ));
    }

    let list = crate::wordlist::EFF_LONG;
    let mut words: Vec<String> = Vec::with_capacity(opts.words);
    for _ in 0..opts.words {
        let mut word = list[sample_index(list.len())?].to_owned();
        if opts.capitalize {
            capitalize_first(&mut word);
        }
        words.push(word);
    }

    if opts.include_number {
        // Append a random digit to one random word (Bitwarden behavior).
        let target = sample_index(words.len())?;
        let digit = u8::try_from(sample_index(10)?).unwrap_or(0);
        words[target].push(char::from(b'0' + digit));
    }

    Ok(Zeroizing::new(words.join(&opts.separator)))
}

/// Upper-case the first character of `w` in place. EFF words are ASCII, so the
/// first char is one byte; `get_mut(..1)` returns `None` on an empty string.
fn capitalize_first(w: &mut str) {
    if let Some(head) = w.get_mut(..1) {
        head.make_ascii_uppercase();
    }
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

#[cfg(test)]
mod tests {
    use super::{PassphraseOptions, generate_passphrase};

    fn pp(words: usize, sep: &str, capitalize: bool, include_number: bool) -> PassphraseOptions {
        PassphraseOptions {
            words,
            separator: sep.to_owned(),
            capitalize,
            include_number,
        }
    }

    #[test]
    fn passphrase_default_matches_bitwarden() {
        let d = PassphraseOptions::default();
        assert_eq!(d.words, 3);
        assert_eq!(d.separator, "-");
        assert!(!d.capitalize);
        assert!(!d.include_number);
    }

    // A separator that never appears in EFF words (which are [a-z] + '-'), so
    // splitting is unambiguous.
    const SEP: &str = "|";

    #[test]
    fn passphrase_word_count_and_membership() {
        let s = generate_passphrase(&pp(5, SEP, false, false)).unwrap();
        let parts: Vec<&str> = s.split(SEP).collect();
        assert_eq!(parts.len(), 5);
        for w in parts {
            assert!(
                crate::wordlist::EFF_LONG.contains(&w),
                "{w} not in EFF list"
            );
        }
    }

    #[test]
    fn passphrase_capitalize_uppercases_each_word() {
        let s = generate_passphrase(&pp(5, SEP, true, false)).unwrap();
        for w in s.split(SEP) {
            assert!(
                w.chars().next().unwrap().is_ascii_uppercase(),
                "{w} not capitalized"
            );
            let lower = w.to_ascii_lowercase();
            assert!(crate::wordlist::EFF_LONG.contains(&lower.as_str()));
        }
    }

    #[test]
    fn passphrase_include_number_appends_one_digit() {
        let s = generate_passphrase(&pp(5, SEP, false, true)).unwrap();
        let parts: Vec<&str> = s.split(SEP).collect();
        assert_eq!(parts.len(), 5);
        let numbered = parts
            .iter()
            .filter(|w| w.chars().any(|c| c.is_ascii_digit()))
            .count();
        assert_eq!(numbered, 1, "exactly one word gets a digit");
        for w in parts {
            let base = w.trim_end_matches(|c: char| c.is_ascii_digit());
            assert!(
                crate::wordlist::EFF_LONG.contains(&base),
                "{base} not in list"
            );
        }
    }

    #[test]
    fn passphrase_word_bounds_enforced() {
        assert!(generate_passphrase(&pp(2, "-", false, false)).is_err());
        assert!(generate_passphrase(&pp(21, "-", false, false)).is_err());
        assert!(generate_passphrase(&pp(3, "-", false, false)).is_ok());
        assert!(generate_passphrase(&pp(20, "-", false, false)).is_ok());
    }

    #[test]
    fn passphrase_distinct_across_calls() {
        let opts = pp(6, "-", false, false);
        let a = generate_passphrase(&opts).unwrap();
        let b = generate_passphrase(&opts).unwrap();
        assert_ne!(a.as_str(), b.as_str());
    }
}

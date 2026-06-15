// SPDX-License-Identifier: GPL-3.0-or-later

//! Time-based one-time passwords (RFC 6238) from a stored Bitwarden `totp`
//! field.
//!
//! The stored value is either a bare base32 secret or an
//! `otpauth://totp/LABEL?secret=…&algorithm=…&digits=…&period=…` URI. [`now`]
//! parses it and returns the current code; the secret never needs to leave the
//! caller (the agent), only the short numeric code does.
//!
//! Scope: the standard authenticator algorithms (SHA1 default, SHA256, SHA512).
//! `otpauth://hotp/…`, Steam, and other non-standard types are rejected.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use crate::error::{Error, Result};

/// Supported HMAC hash algorithms for TOTP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl Algorithm {
    fn parse(s: &str) -> Result<Self> {
        match s.trim().to_ascii_uppercase().as_str() {
            "SHA1" => Ok(Self::Sha1),
            "SHA256" => Ok(Self::Sha256),
            "SHA512" => Ok(Self::Sha512),
            _ => Err(Error::Totp("unsupported TOTP algorithm")),
        }
    }
}

/// Parsed TOTP parameters: the decoded secret plus the generation knobs.
struct TotpParams {
    secret: Vec<u8>,
    algorithm: Algorithm,
    digits: u32,
    period: u64,
}

/// Current TOTP code for a stored `totp` value (bare base32 secret or
/// `otpauth://` URI).
///
/// # Errors
///
/// Returns [`Error::Totp`] if the value can't be parsed, the secret isn't valid
/// base32, or the system clock is before the Unix epoch.
pub fn now(secret_or_uri: &str) -> Result<String> {
    let unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::Totp("system clock is before the Unix epoch"))?
        .as_secs();
    let params = parse(secret_or_uri)?;
    at(&params, unix)
}

/// Parse a bare base32 secret or an `otpauth://totp/…` URI into [`TotpParams`].
fn parse(s: &str) -> Result<TotpParams> {
    let s = s.trim();
    let Some(rest) = s.strip_prefix("otpauth://") else {
        // Bare secret: standard defaults (SHA1, 6 digits, 30 s).
        return Ok(TotpParams {
            secret: base32_decode(s)?,
            algorithm: Algorithm::Sha1,
            digits: 6,
            period: 30,
        });
    };
    // Only the time-based variant is supported (not `hotp`, `steam`, …).
    let rest = rest
        .strip_prefix("totp/")
        .ok_or(Error::Totp("unsupported otpauth type (only totp)"))?;
    let query = rest.split_once('?').map_or("", |(_, q)| q);

    let mut secret = None;
    let mut algorithm = Algorithm::Sha1;
    let mut digits = 6u32;
    let mut period = 30u64;
    for pair in query.split('&') {
        let Some((k, v)) = pair.split_once('=') else {
            continue;
        };
        match k.to_ascii_lowercase().as_str() {
            "secret" => secret = Some(base32_decode(v)?),
            "algorithm" => algorithm = Algorithm::parse(v)?,
            "digits" => {
                digits = v.parse().map_err(|_| Error::Totp("invalid digits"))?;
            }
            "period" => {
                period = v.parse().map_err(|_| Error::Totp("invalid period"))?;
            }
            _ => {}
        }
    }
    Ok(TotpParams {
        secret: secret.ok_or(Error::Totp("otpauth URI has no secret"))?,
        algorithm,
        // Clamp to a sane range; 10^digits must stay within u32.
        digits: digits.clamp(1, 9),
        period: period.max(1),
    })
}

/// Compute the code for `params` at `unix_secs` (RFC 6238 / RFC 4226 HOTP):
/// HMAC over the 8-byte big-endian counter, then dynamic truncation.
fn at(params: &TotpParams, unix_secs: u64) -> Result<String> {
    let counter = unix_secs / params.period;
    // One arm per concrete digest — the `Hmac<D>` trait bounds don't generalize
    // cleanly, so a macro keeps the three paths identical without a generic.
    macro_rules! code {
        ($hash:ty) => {{
            let mut mac = <Hmac<$hash>>::new_from_slice(&params.secret)
                .map_err(|_| Error::Totp("invalid HMAC key"))?;
            mac.update(&counter.to_be_bytes());
            truncate(&mac.finalize().into_bytes(), params.digits)
        }};
    }
    let code = match params.algorithm {
        Algorithm::Sha1 => code!(Sha1),
        Algorithm::Sha256 => code!(Sha256),
        Algorithm::Sha512 => code!(Sha512),
    };
    Ok(code)
}

/// Dynamic truncation (RFC 4226 §5.3): the low nibble of the last byte picks a
/// 4-byte window; mask the high bit; reduce modulo 10^`digits`, zero-padded.
fn truncate(hash: &[u8], digits: u32) -> String {
    let offset = usize::from(hash[hash.len() - 1] & 0x0f);
    let bin = (u32::from(hash[offset]) & 0x7f) << 24
        | u32::from(hash[offset + 1]) << 16
        | u32::from(hash[offset + 2]) << 8
        | u32::from(hash[offset + 3]);
    let width = digits as usize;
    let modulo = 10u32.pow(digits);
    format!("{:0width$}", bin % modulo)
}

/// Decode an RFC 4648 base32 string (A–Z, 2–7; case-insensitive; `=`/whitespace
/// ignored) into bytes.
fn base32_decode(s: &str) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for c in s.chars() {
        if c == '=' || c.is_whitespace() {
            continue;
        }
        let uc = c.to_ascii_uppercase();
        let val = match uc {
            'A'..='Z' => u32::from(uc) - u32::from('A'),
            '2'..='7' => u32::from(uc) - u32::from('2') + 26,
            _ => return Err(Error::Totp("invalid base32 character in TOTP secret")),
        };
        buffer = (buffer << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buffer >> bits) & 0xff).unwrap_or(0));
        }
    }
    if out.is_empty() {
        return Err(Error::Totp("empty TOTP secret"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{Algorithm, TotpParams, at, base32_decode, parse};

    // RFC 6238 Appendix B uses the ASCII seed "12345678901234567890".
    const SEED: &[u8] = b"12345678901234567890";
    const SEED_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn base32_decodes_rfc_seed() {
        assert_eq!(base32_decode(SEED_B32).unwrap(), SEED);
        // Case-insensitive and tolerant of spaces.
        assert_eq!(base32_decode("gezd gnbv").unwrap(), b"12345");
        assert!(base32_decode("!!!").is_err());
        assert!(base32_decode("").is_err());
    }

    #[test]
    fn rfc6238_sha1_vector() {
        // RFC 6238: T=59 s, 8 digits, SHA1 → 94287082.
        let params = TotpParams {
            secret: SEED.to_vec(),
            algorithm: Algorithm::Sha1,
            digits: 8,
            period: 30,
        };
        assert_eq!(at(&params, 59).unwrap(), "94287082");
        // 6-digit default at the same instant is the last 6 of the truncation.
        let p6 = TotpParams {
            digits: 6,
            ..params
        };
        assert_eq!(p6.digits, 6);
        let code = at(&p6, 59).unwrap();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn parse_bare_secret_and_otpauth_uri() {
        let bare = parse(SEED_B32).unwrap();
        assert_eq!(bare.secret, SEED);
        assert_eq!(bare.algorithm, Algorithm::Sha1);
        assert_eq!(bare.digits, 6);
        assert_eq!(bare.period, 30);

        let uri = format!(
            "otpauth://totp/Example:me@x.org?secret={SEED_B32}&algorithm=SHA256&digits=8&period=60"
        );
        let p = parse(&uri).unwrap();
        assert_eq!(p.secret, SEED);
        assert_eq!(p.algorithm, Algorithm::Sha256);
        assert_eq!(p.digits, 8);
        assert_eq!(p.period, 60);

        assert!(parse("otpauth://hotp/x?secret=AAAA").is_err());
        assert!(parse("otpauth://totp/x?digits=6").is_err()); // no secret
    }

    #[test]
    fn parse_clamps_digits() {
        let uri = format!("otpauth://totp/x?secret={SEED_B32}&digits=99");
        assert_eq!(parse(&uri).unwrap().digits, 9);
    }
}

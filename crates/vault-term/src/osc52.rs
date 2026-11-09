// SPDX-License-Identifier: GPL-3.0-or-later

//! OSC 52 clipboard write (Tier 1).
//!
//! The sequence is `OSC 52 ; c ; <base64> ST`. It is sent unwrapped even
//! inside tmux: tmux with `set-clipboard on` consumes OSC 52 itself and
//! forwards it to the outer terminal, whereas a `DCS tmux;` passthrough wrapper
//! additionally needs `allow-passthrough`, which is off by default since tmux
//! 3.3. There is no query for write support, so callers confirm every copy in
//! their own UI and offer a way to see the value.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;

/// Largest base64 payload sent, in bytes.
///
/// Several terminals and tmux truncate or drop OSC 52 sequences around
/// 100 KB; staying under that keeps behaviour predictable. Vault copies
/// passwords and short fields, so this is never close in practice.
pub const MAX_BASE64: usize = 100_000;

/// The payload was too large to send in one OSC 52 sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TooLarge {
    /// Size of the base64 payload that was refused.
    pub base64_len: usize,
}

impl fmt::Display for TooLarge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "value too large for the terminal clipboard ({} > {MAX_BASE64} base64 bytes)",
            self.base64_len
        )
    }
}

impl std::error::Error for TooLarge {}

/// The OSC 52 sequence that places `value` on the clipboard.
///
/// # Errors
///
/// Returns [`TooLarge`] when the encoded payload exceeds [`MAX_BASE64`].
pub fn copy_sequence(value: &str) -> Result<String, TooLarge> {
    let b64 = B64.encode(value.as_bytes());
    if b64.len() > MAX_BASE64 {
        return Err(TooLarge {
            base64_len: b64.len(),
        });
    }
    Ok(format!("\x1b]52;c;{b64}\x1b\\"))
}

/// The OSC 52 sequence that clears the clipboard (`!` payload).
#[must_use]
pub const fn clear_sequence() -> &'static str {
    "\x1b]52;c;!\x1b\\"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_encodes_base64_and_ends_with_st() {
        // "hi" -> aGk=
        assert_eq!(copy_sequence("hi").as_deref(), Ok("\x1b]52;c;aGk=\x1b\\"));
    }

    #[test]
    fn clear_uses_bang_payload() {
        assert_eq!(clear_sequence(), "\x1b]52;c;!\x1b\\");
    }

    #[test]
    fn oversized_payload_is_refused() {
        let big = "x".repeat(MAX_BASE64);
        let err = copy_sequence(&big).expect_err("too large");
        assert!(err.base64_len > MAX_BASE64);
        assert!(copy_sequence(&"x".repeat(1000)).is_ok());
    }
}

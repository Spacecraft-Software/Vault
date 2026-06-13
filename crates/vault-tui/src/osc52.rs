// SPDX-License-Identifier: GPL-3.0-or-later

//! OSC52 — copy through the terminal itself (PRD §7.5's SSH/tmux fallback).
//!
//! When the agent reports `ClipboardUnavailable` (headless box, no display —
//! typical over SSH), the TUI can still copy: terminals that support OSC52
//! accept a base64 payload in an escape sequence and place it on the *local*
//! clipboard, tunnelling through SSH for free. This must run client-side —
//! the agent is a detached daemon with no terminal to escape to. Inside tmux
//! the sequence needs the DCS passthrough wrapper (and `set-clipboard on` in
//! the user's tmux config).

use std::io::{self, Write};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

/// Place `value` on the clipboard via the controlling terminal.
///
/// # Errors
///
/// Returns an error when stdout can't be written or flushed.
pub fn copy(value: &str) -> io::Result<()> {
    emit(&sequence(value, in_tmux()))
}

/// Ask the terminal to clear the selection we set (`!` payload per spec).
/// Best-effort: terminals that ignore it simply keep the old contents.
///
/// # Errors
///
/// Returns an error when stdout can't be written or flushed.
pub fn clear() -> io::Result<()> {
    emit(&clear_sequence(in_tmux()))
}

fn in_tmux() -> bool {
    std::env::var_os("TMUX").is_some_and(|v| !v.is_empty())
}

fn emit(seq: &str) -> io::Result<()> {
    let mut out = io::stdout();
    out.write_all(seq.as_bytes())?;
    out.flush()
}

/// The OSC52 set-clipboard sequence: `ESC ] 52 ; c ; <base64> BEL`, wrapped
/// for tmux passthrough when `tmux` is set.
fn sequence(value: &str, tmux: bool) -> String {
    let seq = format!("\u{1b}]52;c;{}\u{7}", B64.encode(value.as_bytes()));
    if tmux { tmux_wrap(&seq) } else { seq }
}

/// The OSC52 clear sequence — `!` instead of a payload.
fn clear_sequence(tmux: bool) -> String {
    let seq = "\u{1b}]52;c;!\u{7}".to_owned();
    if tmux { tmux_wrap(&seq) } else { seq }
}

/// tmux DCS passthrough: `ESC P tmux;` + payload with every ESC doubled +
/// `ESC \`. Requires `set-clipboard on` in the user's tmux configuration.
fn tmux_wrap(seq: &str) -> String {
    let doubled = seq.replace('\u{1b}', "\u{1b}\u{1b}");
    format!("\u{1b}Ptmux;{doubled}\u{1b}\\")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence_encodes_base64_payload() {
        // "hi" -> aGk=
        assert_eq!(sequence("hi", false), "\u{1b}]52;c;aGk=\u{7}");
    }

    #[test]
    fn clear_sequence_uses_bang_payload() {
        assert_eq!(clear_sequence(false), "\u{1b}]52;c;!\u{7}");
    }

    #[test]
    fn tmux_wrap_doubles_escapes_inside_dcs() {
        let s = sequence("hi", true);
        assert!(s.starts_with("\u{1b}Ptmux;"));
        assert!(s.ends_with("\u{1b}\\"));
        assert!(
            s.contains("\u{1b}\u{1b}]52;c;aGk=\u{7}"),
            "inner ESC must be doubled: {s:?}"
        );
    }
}

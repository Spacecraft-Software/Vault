// SPDX-License-Identifier: GPL-3.0-or-later

//! OSC 9;4 taskbar / tab progress (Tier 2).
//!
//! Many terminals treat `OSC 9 ; <text>` as "show a desktop notification", so
//! on those `OSC 9;4;3` pops a notification reading `4;3`. No query tells the
//! two meanings apart, so emission is **allow-list only** ([`supported`]);
//! an unknown terminal gets nothing unless the user forces `+progress`.
//!
//! The indicator is decorative. Callers always report progress in their own
//! output as well (the TUI's status line, the CLI's stderr line).

use crate::TermEnv;

/// First `WezTerm` build that renders OSC 9;4 instead of notifying, as the
/// leading `YYYYMMDD` of its version. The 20240203 stable release still shows
/// a notification; nightlies from 2025-02-10 show progress in the tab bar.
const WEZTERM_MIN_DATE: u32 = 20_250_210; // 2025-02-10

/// First iTerm2 release that renders OSC 9;4 (3.6); earlier ones notify.
const ITERM2_MIN: (u32, u32) = (3, 6);

/// `TERM_PROGRAM` substrings (lower-cased) of terminals that render OSC 9;4
/// in every release that sets that value: Ghostty, VS Code, Rio, contour.
const PROGRAM_ALLOW: &[&str] = &["ghostty", "vscode", "rio", "contour"];

/// The progress state to show.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProgressState {
    /// Remove the indicator.
    Clear,
    /// Determinate progress, percent clamped to 0–100.
    Normal(u8),
    /// Error (red).
    Error,
    /// Indeterminate (spinner / pulse).
    Indeterminate,
    /// Paused / warning (yellow).
    Paused,
}

/// The OSC 9;4 sequence for `state`, terminated with `ST`.
#[must_use]
pub fn sequence(state: ProgressState) -> String {
    let (code, pct) = match state {
        ProgressState::Clear => (0, 0),
        ProgressState::Normal(p) => (1, p.min(100)),
        ProgressState::Error => (2, 0),
        ProgressState::Indeterminate => (3, 0),
        ProgressState::Paused => (4, 0),
    };
    format!("\x1b]9;4;{code};{pct}\x1b\\")
}

/// Whether the terminal is known to render OSC 9;4 as progress.
///
/// Identity hints come from the environment and, when the caller probed one,
/// the XTVERSION reply (which survives SSH, unlike environment variables).
/// Inside a multiplexer this returns `false`: skipping is allowed there and
/// avoids passthrough configuration the user may not have.
///
/// kitty is deliberately absent: older releases treat OSC 9 as a
/// notification, and no first-supporting kitty version has been verified for
/// this list yet. kitty users can opt in with `+progress`.
#[must_use]
pub fn supported(env: &TermEnv, xtversion: Option<&str>) -> bool {
    if env.multiplexer().is_some() {
        return false;
    }
    if env.windows_terminal() || env.conemu() {
        return true;
    }
    if env.term().is_some_and(|t| t.starts_with("foot")) {
        return true;
    }
    if let Some(prog) = env.term_program() {
        let lower = prog.to_ascii_lowercase();
        if PROGRAM_ALLOW.iter().any(|p| lower.contains(p)) {
            return true;
        }
        let version = env.term_program_version();
        if lower == "wezterm" {
            return version.is_some_and(wezterm_ok);
        }
        if lower == "iterm.app" {
            return version.is_some_and(iterm2_ok);
        }
    }
    xtversion.is_some_and(xtversion_ok)
}

/// The XTVERSION form of the allow-list, for when the environment did not
/// travel (SSH).
fn xtversion_ok(id: &str) -> bool {
    let lower = id.to_ascii_lowercase();
    if lower.starts_with("ghostty") || lower.starts_with("foot") {
        return true;
    }
    if let Some(v) = lower.strip_prefix("wezterm ") {
        return wezterm_ok(v);
    }
    if let Some(v) = lower.strip_prefix("iterm2 ") {
        return iterm2_ok(v);
    }
    false
}

/// `WezTerm` versions look like `20240203-110809-5046fc22`.
fn wezterm_ok(version: &str) -> bool {
    version
        .get(..8)
        .filter(|d| d.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|d| d.parse::<u32>().ok())
        .is_some_and(|d| d >= WEZTERM_MIN_DATE)
}

/// iTerm2 versions look like `3.6.2`.
fn iterm2_ok(version: &str) -> bool {
    let mut parts = version.trim().split('.').map(str::parse::<u32>);
    match (parts.next(), parts.next()) {
        (Some(Ok(major)), Some(Ok(minor))) => (major, minor) >= ITERM2_MIN,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::env_of;

    #[test]
    fn sequences() {
        assert_eq!(sequence(ProgressState::Clear), "\x1b]9;4;0;0\x1b\\");
        assert_eq!(sequence(ProgressState::Indeterminate), "\x1b]9;4;3;0\x1b\\");
        assert_eq!(sequence(ProgressState::Normal(250)), "\x1b]9;4;1;100\x1b\\");
    }

    #[test]
    fn unknown_terminal_gets_nothing() {
        assert!(!supported(&env_of(&[("TERM", "xterm-256color")]), None));
        assert!(!supported(
            &env_of(&[("TERM", "xterm-kitty")]),
            Some("kitty(0.40.0)")
        ));
        assert!(!supported(
            &env_of(&[("TERM_PROGRAM", "Apple_Terminal")]),
            None
        ));
    }

    #[test]
    fn allow_listed_by_environment() {
        assert!(supported(&env_of(&[("WT_SESSION", "abc")]), None));
        assert!(supported(&env_of(&[("ConEmuANSI", "ON")]), None));
        assert!(supported(&env_of(&[("TERM", "foot-extra")]), None));
        assert!(supported(&env_of(&[("TERM_PROGRAM", "ghostty")]), None));
        assert!(supported(&env_of(&[("TERM_PROGRAM", "vscode")]), None));
    }

    #[test]
    fn wezterm_stable_is_refused_and_nightly_allowed() {
        let stable = env_of(&[
            ("TERM_PROGRAM", "WezTerm"),
            ("TERM_PROGRAM_VERSION", "20240203-110809-5046fc22"),
        ]);
        assert!(!supported(&stable, None), "stable shows a notification");
        let nightly = env_of(&[
            ("TERM_PROGRAM", "WezTerm"),
            ("TERM_PROGRAM_VERSION", "20250210-074021-bd8ac3d5"),
        ]);
        assert!(supported(&nightly, None));
        assert!(!supported(&env_of(&[("TERM_PROGRAM", "WezTerm")]), None));
    }

    #[test]
    fn iterm2_needs_3_6() {
        let old = env_of(&[
            ("TERM_PROGRAM", "iTerm.app"),
            ("TERM_PROGRAM_VERSION", "3.5.11"),
        ]);
        assert!(!supported(&old, None));
        let new = env_of(&[
            ("TERM_PROGRAM", "iTerm.app"),
            ("TERM_PROGRAM_VERSION", "3.6.0"),
        ]);
        assert!(supported(&new, None));
    }

    #[test]
    fn xtversion_covers_ssh_sessions() {
        let bare = env_of(&[("TERM", "xterm-256color")]);
        assert!(supported(&bare, Some("WezTerm 20250301-000000-abcdef12")));
        assert!(!supported(&bare, Some("WezTerm 20240203-110809-5046fc22")));
        assert!(supported(&bare, Some("ghostty 1.1.3")));
        assert!(supported(&bare, Some("foot(1.16.2)")));
        assert!(!supported(&bare, Some("iTerm2 3.5.0")));
    }

    #[test]
    fn multiplexer_skips_even_allow_listed_terminals() {
        let e = env_of(&[("TERM_PROGRAM", "ghostty"), ("TMUX", "/tmp/t,1,0")]);
        assert!(!supported(&e, Some("ghostty 1.1.3")));
    }
}

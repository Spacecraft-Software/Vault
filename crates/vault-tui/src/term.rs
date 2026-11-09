// SPDX-License-Identifier: GPL-3.0-or-later

//! Terminal session: mode setup, the startup protocol probe, and restore on
//! every exit path.
//!
//! The policy (gate, overrides, allow-lists, sequence bytes) lives in
//! `vault-term`; this module owns the I/O. Setup order is raw mode → alternate
//! screen + bracketed paste → probe → push kitty keyboard flags. [`restore`]
//! undoes it in reverse and is idempotent, so the drop guard, the panic hook
//! and the signal path can all call it and only the first call does anything.
//!
//! Vault shows no images and has no mouse-interactive regions, so of the
//! Spacecraft terminal protocols it speaks three: the kitty keyboard protocol,
//! OSC 52 clipboard write and OSC 9;4 progress.

use std::fs::{File, OpenOptions};
use std::io::{self, IsTerminal, Read, Write};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crossterm::event::{DisableBracketedPaste, EnableBracketedPaste};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use vault_term::probe::{self, ProbeReport, ReplyParser};
use vault_term::progress::{self, ProgressState};
use vault_term::{Overrides, Protocol, TermEnv, osc52};

/// How long the startup probe waits for the DA1 fence before treating every
/// unanswered feature as unsupported. Local terminals answer in a few
/// milliseconds; 200 ms leaves room for SSH without a noticeable start delay.
const PROBE_DEADLINE: Duration = Duration::from_millis(200);

/// Quiet period that ends the post-probe drain, which swallows late replies so
/// none leak into the input stream as typed text.
const DRAIN_QUIET: Duration = Duration::from_millis(20);

/// Upper bound on drain reads, so a user typing continuously during startup
/// cannot hold the drain open.
const DRAIN_MAX_READS: usize = 64;

/// Kitty keyboard push with flag 1 (disambiguate escape codes) only: enough to
/// tell `Esc` from the start of a sequence and `Ctrl+I` from `Tab`. No binding
/// needs key-release or text reporting, so no other flag is requested.
const KITTY_PUSH: &[u8] = b"\x1b[>1u";

/// Kitty keyboard pop of the one entry pushed by [`KITTY_PUSH`].
const KITTY_POP: &[u8] = b"\x1b[<u";

/// Protocols resolved for this session (detection, then overrides).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Caps {
    /// Kitty keyboard flags were pushed.
    pub keyboard: bool,
    /// OSC 52 clipboard write may be sent.
    pub clipboard: bool,
    /// OSC 9;4 progress may be sent.
    pub progress: bool,
}

/// Resolved once in [`enter`]; read by the copy and progress helpers.
static CAPS: OnceLock<Caps> = OnceLock::new();

/// Raw mode, alternate screen and bracketed paste are active.
static SCREEN_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Kitty keyboard flags are pushed and must be popped.
static KEYBOARD_PUSHED: AtomicBool = AtomicBool::new(false);

/// An OSC 9;4 indicator is showing and must be cleared.
static PROGRESS_ACTIVE: AtomicBool = AtomicBool::new(false);

/// The session's resolved protocols (all off before [`enter`]).
pub fn caps() -> Caps {
    CAPS.get().copied().unwrap_or_default()
}

/// Take over the terminal and resolve the protocols for this session.
///
/// A failed probe never stops startup: it only means "nothing supported".
///
/// # Errors
///
/// Returns an error when raw mode or the alternate screen cannot be entered.
pub fn enter(env: &TermEnv, overrides: Overrides) -> io::Result<Caps> {
    enable_raw_mode()?;
    SCREEN_ACTIVE.store(true, Ordering::SeqCst);
    let mut out = io::stdout();
    execute!(out, EnterAlternateScreen, EnableBracketedPaste)?;

    let allowed = env.protocols_allowed(out.is_terminal());
    let report = if allowed && probe_needed(overrides) {
        probe_tty(PROBE_DEADLINE).unwrap_or_default()
    } else {
        ProbeReport::default()
    };
    let caps = resolve(env, allowed, &report, overrides);
    if caps.keyboard {
        // Pushed after entering the alternate screen: the main and alternate
        // screens keep separate flag stacks.
        out.write_all(KITTY_PUSH)?;
        out.flush()?;
        KEYBOARD_PUSHED.store(true, Ordering::SeqCst);
    }
    let _ = CAPS.set(caps);
    Ok(caps)
}

/// Whether the probe can change any decision: it answers for the keyboard
/// protocol and (via XTVERSION) for progress. When the user forced both, a
/// probe would only send bytes nobody reads, so none is sent (§2.1).
const fn probe_needed(overrides: Overrides) -> bool {
    overrides.forced(Protocol::Keyboard).is_none() || overrides.forced(Protocol::Progress).is_none()
}

/// Detection plus overrides. Pure, so the decision table is unit-tested.
fn resolve(env: &TermEnv, allowed: bool, report: &ProbeReport, overrides: Overrides) -> Caps {
    if !allowed {
        // The §2.1 gate cannot be lifted by an override.
        return Caps::default();
    }
    Caps {
        keyboard: overrides.resolve(Protocol::Keyboard, report.kitty_keyboard.is_some()),
        // OSC 52 write has no query: send it whenever the gate passes, and let
        // the UI confirm every copy so a silent failure is visible.
        clipboard: overrides.resolve(Protocol::Clipboard, true),
        progress: overrides.resolve(
            Protocol::Progress,
            progress::supported(env, report.xtversion.as_deref()),
        ),
    }
}

/// Undo everything [`enter`] and the session turned on, in reverse order:
/// pop keyboard flags → clear progress → leave the alternate screen → leave
/// raw mode. Best-effort and idempotent.
pub fn restore() {
    let mut out = io::stdout();
    if KEYBOARD_PUSHED.swap(false, Ordering::SeqCst) {
        let _ = out.write_all(KITTY_POP);
    }
    if PROGRESS_ACTIVE.swap(false, Ordering::SeqCst) {
        let _ = out.write_all(progress::sequence(ProgressState::Clear).as_bytes());
    }
    let _ = out.flush();
    if SCREEN_ACTIVE.swap(false, Ordering::SeqCst) {
        let _ = execute!(out, DisableBracketedPaste, LeaveAlternateScreen);
        let _ = disable_raw_mode();
    }
}

/// Drop guard that runs [`restore`].
#[derive(Debug)]
pub struct Guard;

impl Drop for Guard {
    fn drop(&mut self) {
        restore();
    }
}

/// Chain [`restore`] in front of the existing panic hook, so the panic message
/// prints on a sane terminal and the shell never inherits pushed key flags.
pub fn install_panic_hook() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore();
        default(info);
    }));
}

/// Show the indeterminate OSC 9;4 indicator, when the session allows it.
pub fn progress_begin() {
    if caps().progress && !PROGRESS_ACTIVE.swap(true, Ordering::SeqCst) {
        emit(progress::sequence(ProgressState::Indeterminate).as_bytes());
    }
}

/// Clear the OSC 9;4 indicator if one is showing.
pub fn progress_end() {
    if PROGRESS_ACTIVE.swap(false, Ordering::SeqCst) {
        emit(progress::sequence(ProgressState::Clear).as_bytes());
    }
}

/// Why an OSC 52 copy was not sent.
#[derive(Debug)]
pub enum CopyError {
    /// The session does not allow OSC 52 (dumb terminal or `-clipboard`).
    Disabled,
    /// The value is over the OSC 52 size cap.
    TooLarge(osc52::TooLarge),
    /// Writing to the terminal failed.
    Io(io::Error),
}

impl std::fmt::Display for CopyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disabled => f.write_str("terminal clipboard (OSC 52) is off for this terminal"),
            Self::TooLarge(e) => e.fmt(f),
            Self::Io(e) => write!(f, "OSC 52 write failed: {e}"),
        }
    }
}

/// Place `value` on the clipboard through the terminal (OSC 52).
///
/// # Errors
///
/// See [`CopyError`].
pub fn osc52_copy(value: &str) -> Result<(), CopyError> {
    if !caps().clipboard {
        return Err(CopyError::Disabled);
    }
    let seq = osc52::copy_sequence(value).map_err(CopyError::TooLarge)?;
    write_flush(seq.as_bytes()).map_err(CopyError::Io)
}

/// Clear the clipboard set through OSC 52. A no-op when OSC 52 is off.
pub fn osc52_clear() {
    if caps().clipboard {
        emit(osc52::clear_sequence().as_bytes());
    }
}

fn emit(bytes: &[u8]) {
    let _ = write_flush(bytes);
}

fn write_flush(bytes: &[u8]) -> io::Result<()> {
    let mut out = io::stdout();
    out.write_all(bytes)?;
    out.flush()
}

/// Run the DA1-fenced probe on the controlling terminal. Must run in raw mode
/// and before anything else reads input.
///
/// Any key the user types inside the probe window is discarded with the
/// replies; at 200 ms at startup, that costs nothing in practice.
fn probe_tty(deadline: Duration) -> io::Result<ProbeReport> {
    let mut tty = OpenOptions::new().read(true).write(true).open("/dev/tty")?;
    tty.write_all(probe::QUERY)?;
    tty.flush()?;

    let mut parser = ReplyParser::new();
    let end = Instant::now() + deadline;
    let mut buf = [0u8; 1024];
    while let Some(left) = end.checked_duration_since(Instant::now()) {
        match wait_readable(&tty, left) {
            Ok(true) => {}
            Ok(false) => break, // deadline: unanswered features stay off
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
        let n = tty.read(&mut buf)?;
        if n == 0 || parser.feed(&buf[..n]) {
            break;
        }
    }
    drain(&mut tty);
    Ok(parser.into_report())
}

/// Swallow late replies until the terminal has been quiet for [`DRAIN_QUIET`].
fn drain(tty: &mut File) {
    let mut buf = [0u8; 256];
    for _ in 0..DRAIN_MAX_READS {
        match wait_readable(tty, DRAIN_QUIET) {
            Ok(true) if tty.read(&mut buf).is_ok_and(|n| n > 0) => {}
            _ => break,
        }
    }
}

/// `poll(2)` the TTY for input, at most `timeout`. Never a blocking read.
fn wait_readable(tty: &File, timeout: Duration) -> io::Result<bool> {
    let ts = Timespec {
        tv_sec: i64::try_from(timeout.as_secs()).unwrap_or(i64::MAX),
        tv_nsec: i64::from(timeout.subsec_nanos()),
    };
    let mut fds = [PollFd::new(tty, PollFlags::IN)];
    Ok(poll(&mut fds, Some(&ts))? > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> TermEnv {
        TermEnv::from_lookup(|k| {
            pairs
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| (*v).to_owned())
        })
    }

    fn report(kitty: bool, xtversion: Option<&str>) -> ProbeReport {
        ProbeReport {
            kitty_keyboard: kitty.then_some(0),
            xtversion: xtversion.map(str::to_owned),
            da1: true,
        }
    }

    #[test]
    fn closed_gate_turns_everything_off_even_when_forced() {
        let e = env(&[("TERM_PROGRAM", "ghostty")]);
        let forced = Overrides::parse("+all").expect("parse");
        assert_eq!(
            resolve(&e, false, &report(true, None), forced),
            Caps::default()
        );
    }

    #[test]
    fn detection_drives_the_defaults() {
        let e = env(&[("TERM", "xterm-256color")]);
        let caps = resolve(&e, true, &report(true, None), Overrides::new());
        assert_eq!(
            caps,
            Caps {
                keyboard: true,
                clipboard: true,
                progress: false,
            }
        );
        let ghostty = env(&[("TERM_PROGRAM", "ghostty")]);
        let caps = resolve(&ghostty, true, &report(false, None), Overrides::new());
        assert!(!caps.keyboard, "no CSI ? u reply means no push");
        assert!(caps.progress);
    }

    #[test]
    fn probe_skipped_only_when_every_probed_protocol_is_forced() {
        assert!(probe_needed(Overrides::new()));
        assert!(probe_needed(Overrides::parse("-keyboard").expect("parse")));
        assert!(!probe_needed(Overrides::parse("-all").expect("parse")));
        assert!(!probe_needed(
            Overrides::parse("+keyboard,-progress").expect("parse")
        ));
    }

    #[test]
    fn overrides_beat_detection() {
        let e = env(&[("TERM", "xterm-256color")]);
        let o = Overrides::parse("-keyboard,-clipboard,+progress").expect("parse");
        let caps = resolve(&e, true, &report(true, None), o);
        assert_eq!(
            caps,
            Caps {
                keyboard: false,
                clipboard: false,
                progress: true,
            }
        );
    }
}

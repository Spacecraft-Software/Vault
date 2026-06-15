// SPDX-License-Identifier: GPL-3.0-or-later

//! Clipboard backends (PRD §7.5) — the agent-side abstraction.
//!
//! The agent owns one [`Backend`] for its lifetime (on X11 the owning process
//! serves the selection, so the handle can't be transient). `arboard` covers
//! Wayland, X11, and macOS; when it can't initialise (headless box, no
//! display) the agent runs with no backend and `Copy`/`CopyText` decline with
//! a typed `ClipboardUnavailable` — clients fall back from there (the TUI
//! emits OSC52 itself; a daemon has no terminal to escape to, so OSC52 can
//! never live here). The trait exists so tests can inject a fake and so a
//! config-selected backend can slot in later without touching `AgentState`.

use vault_ipc::proto::Error as IpcError;

/// One system clipboard the agent can write to.
///
/// Object-safe and `Send` so the boxed backend can live inside the
/// tokio-shared `AgentState`.
pub trait Backend: Send {
    /// Short identifier surfaced in `Status.clipboard_backend`.
    fn name(&self) -> &'static str;

    /// Place `value` on the clipboard.
    ///
    /// # Errors
    ///
    /// Returns an [`IpcError`] when the underlying clipboard write fails.
    fn set_text(&mut self, value: &str) -> Result<(), IpcError>;

    /// Current clipboard contents, `None` if unreadable.
    fn get_text(&mut self) -> Option<String>;

    /// Best-effort clear; errors are not actionable mid-shutdown.
    fn clear(&mut self);
}

/// The `arboard`-backed system clipboard (Wayland / X11 / macOS).
pub struct Arboard(arboard::Clipboard);

impl Backend for Arboard {
    fn name(&self) -> &'static str {
        "arboard"
    }

    fn set_text(&mut self, value: &str) -> Result<(), IpcError> {
        self.0
            .set_text(value.to_owned())
            .map_err(|e| IpcError::Internal(format!("clipboard write failed: {e}")))
    }

    fn get_text(&mut self) -> Option<String> {
        self.0.get_text().ok()
    }

    fn clear(&mut self) {
        let _ = self.0.clear();
    }
}

/// Which clipboard backend the agent should use (`clipboard.backend`, PRD §7.5).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BackendChoice {
    /// Detect the native backend; if unavailable, decline so the client copies
    /// via OSC52. The default and pre-config behavior.
    #[default]
    Auto,
    /// Force the native (`arboard`) backend; warn if it can't initialise.
    Arboard,
    /// Use no native backend — the agent always declines, so the client (TUI)
    /// copies through the terminal (OSC52). For SSH/tmux sessions.
    Osc52,
}

impl BackendChoice {
    /// Canonical string form (matches the config values), for logs and `Status`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Arboard => "arboard",
            Self::Osc52 => "osc52",
        }
    }
}

/// Select the agent's clipboard backend for `choice`. `Osc52` deliberately
/// yields `None` so the agent declines and the client copies via the terminal.
pub fn select(choice: BackendChoice) -> Option<Box<dyn Backend>> {
    match choice {
        BackendChoice::Auto => detect(),
        BackendChoice::Arboard => {
            let backend = detect();
            if backend.is_none() {
                eprintln!(
                    "vault-agent: clipboard.backend={} requested but unavailable; copies will be declined",
                    choice.as_str()
                );
            }
            backend
        }
        BackendChoice::Osc52 => {
            eprintln!(
                "vault-agent: clipboard.backend={} — declining agent-side copies so the client copies via the terminal",
                choice.as_str()
            );
            None
        }
    }
}

/// Detect a usable backend, degrading to `None` (with a warning) when no
/// display/compositor is reachable — copy requests then decline cleanly.
pub fn detect() -> Option<Box<dyn Backend>> {
    match arboard::Clipboard::new() {
        Ok(cb) => Some(Box::new(Arboard(cb))),
        Err(e) => {
            eprintln!("vault-agent: clipboard unavailable, copy will be declined: {e}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::BackendChoice;

    #[test]
    fn backend_choice_as_str_and_default() {
        assert_eq!(BackendChoice::Auto.as_str(), "auto");
        assert_eq!(BackendChoice::Arboard.as_str(), "arboard");
        assert_eq!(BackendChoice::Osc52.as_str(), "osc52");
        assert_eq!(BackendChoice::default(), BackendChoice::Auto);
    }

    #[test]
    fn select_osc52_uses_no_native_backend() {
        // CI-safe: Osc52 never touches the system clipboard.
        assert!(super::select(BackendChoice::Osc52).is_none());
    }
}

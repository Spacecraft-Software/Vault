// SPDX-License-Identifier: GPL-3.0-or-later

//! A snapshot of the environment variables that drive terminal-protocol
//! decisions. Captured once at startup so every decision in a run agrees, and
//! constructible from a closure so tests never touch the process environment.

/// The terminal multiplexer the program runs inside, if any.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Multiplexer {
    /// tmux (`TMUX`).
    Tmux,
    /// zellij (`ZELLIJ`).
    Zellij,
    /// GNU screen (`STY`).
    Screen,
}

/// Environment variables relevant to terminal protocols.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TermEnv {
    ai_agent: Option<String>,
    agent: Option<String>,
    ci: Option<String>,
    term: Option<String>,
    term_program: Option<String>,
    term_program_version: Option<String>,
    wt_session: Option<String>,
    conemu_pid: Option<String>,
    conemu_ansi: Option<String>,
    tmux: Option<String>,
    zellij: Option<String>,
    sty: Option<String>,
    overrides: Option<String>,
}

impl TermEnv {
    /// Snapshot the current process environment.
    #[must_use]
    pub fn from_process() -> Self {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Build a snapshot from an arbitrary lookup (tests, or a caller that
    /// already holds the environment).
    #[must_use]
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Self {
        Self {
            ai_agent: lookup("AI_AGENT"),
            agent: lookup("AGENT"),
            ci: lookup("CI"),
            term: lookup("TERM"),
            term_program: lookup("TERM_PROGRAM"),
            term_program_version: lookup("TERM_PROGRAM_VERSION"),
            wt_session: lookup("WT_SESSION"),
            conemu_pid: lookup("ConEmuPID"),
            conemu_ansi: lookup("ConEmuANSI"),
            tmux: lookup("TMUX"),
            zellij: lookup("ZELLIJ"),
            sty: lookup("STY"),
            overrides: lookup(crate::OVERRIDES_ENV),
        }
    }

    /// Agent or CI mode (Spacecraft CLI Standard §5).
    ///
    /// Presence-based: `AI_AGENT` or `AGENT` set to *any* non-empty value
    /// counts (real harnesses export descriptive strings, never just `1`).
    /// `CI` is the one value-carrying variable: it counts unless it is empty,
    /// `0` or `false`.
    #[must_use]
    pub fn is_agent(&self) -> bool {
        let ci_truthy = self.ci.as_deref().is_some_and(|v| {
            let v = v.trim();
            !v.is_empty() && v != "0" && !v.eq_ignore_ascii_case("false")
        });
        set(self.ai_agent.as_ref()) || set(self.agent.as_ref()) || ci_truthy
    }

    /// `TERM` is unset, empty, or `dumb`.
    #[must_use]
    pub fn is_dumb(&self) -> bool {
        self.term
            .as_deref()
            .is_none_or(|t| t.is_empty() || t == "dumb")
    }

    /// The hard gate of §2.1: whether any protocol sequence or probe may be
    /// sent to a stream whose TTY-ness is `is_tty`. A user override can turn
    /// a protocol off but can never lift this gate.
    #[must_use]
    pub fn protocols_allowed(&self, is_tty: bool) -> bool {
        is_tty && !self.is_agent() && !self.is_dumb()
    }

    /// The multiplexer in use, detected from `TMUX`, `ZELLIJ` or `STY`.
    #[must_use]
    pub fn multiplexer(&self) -> Option<Multiplexer> {
        if set(self.tmux.as_ref()) {
            Some(Multiplexer::Tmux)
        } else if set(self.zellij.as_ref()) {
            Some(Multiplexer::Zellij)
        } else if set(self.sty.as_ref()) {
            Some(Multiplexer::Screen)
        } else {
            None
        }
    }

    /// The raw `SPACECRAFT_TERM_PROTOCOLS` value, if set.
    #[must_use]
    pub fn overrides(&self) -> Option<&str> {
        self.overrides.as_deref()
    }

    pub(crate) fn term(&self) -> Option<&str> {
        self.term.as_deref()
    }

    pub(crate) fn term_program(&self) -> Option<&str> {
        self.term_program.as_deref()
    }

    pub(crate) fn term_program_version(&self) -> Option<&str> {
        self.term_program_version.as_deref()
    }

    pub(crate) fn windows_terminal(&self) -> bool {
        set(self.wt_session.as_ref())
    }

    pub(crate) fn conemu(&self) -> bool {
        set(self.conemu_pid.as_ref())
            || self
                .conemu_ansi
                .as_deref()
                .is_some_and(|v| v.eq_ignore_ascii_case("on"))
    }
}

fn set(v: Option<&String>) -> bool {
    v.is_some_and(|s| !s.is_empty())
}

#[cfg(test)]
pub fn env_of(pairs: &[(&str, &str)]) -> TermEnv {
    TermEnv::from_lookup(|k| {
        pairs
            .iter()
            .find(|(name, _)| *name == k)
            .map(|(_, v)| (*v).to_owned())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_detection_is_presence_based() {
        // The value a live Claude Code session exports — not `1`.
        assert!(env_of(&[("AI_AGENT", "claude-code_2-1-218_agent")]).is_agent());
        assert!(env_of(&[("AGENT", "x")]).is_agent());
        assert!(!env_of(&[("AI_AGENT", "")]).is_agent());
        assert!(!env_of(&[]).is_agent());
    }

    #[test]
    fn ci_is_value_based() {
        assert!(env_of(&[("CI", "true")]).is_agent());
        assert!(env_of(&[("CI", "1")]).is_agent());
        assert!(!env_of(&[("CI", "false")]).is_agent());
        assert!(!env_of(&[("CI", "FALSE")]).is_agent());
        assert!(!env_of(&[("CI", "0")]).is_agent());
        assert!(!env_of(&[("CI", "")]).is_agent());
    }

    #[test]
    fn gate_requires_tty_human_and_real_term() {
        let ok = env_of(&[("TERM", "xterm-256color")]);
        assert!(ok.protocols_allowed(true));
        assert!(!ok.protocols_allowed(false), "non-TTY must block");
        assert!(
            !env_of(&[]).protocols_allowed(true),
            "unset TERM must block"
        );
        assert!(!env_of(&[("TERM", "dumb")]).protocols_allowed(true));
        assert!(
            !env_of(&[("TERM", "xterm"), ("AI_AGENT", "a")]).protocols_allowed(true),
            "agent mode must block"
        );
    }

    #[test]
    fn multiplexer_detection() {
        assert_eq!(
            env_of(&[("TMUX", "/tmp/tmux-1000/default,1,0")]).multiplexer(),
            Some(Multiplexer::Tmux)
        );
        assert_eq!(
            env_of(&[("ZELLIJ", "0")]).multiplexer(),
            Some(Multiplexer::Zellij)
        );
        assert_eq!(
            env_of(&[("STY", "1.pts")]).multiplexer(),
            Some(Multiplexer::Screen)
        );
        assert_eq!(env_of(&[("TMUX", "")]).multiplexer(), None);
    }
}

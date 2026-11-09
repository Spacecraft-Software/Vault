// SPDX-License-Identifier: GPL-3.0-or-later

//! User overrides for terminal protocols (§2.5).
//!
//! Syntax, shared by `--term-protocols` and `SPACECRAFT_TERM_PROTOCOLS`: a
//! comma-separated list of `+name` (force on), `-name` (force off) or a bare
//! `name` (same as `+name`). `all` addresses every protocol. Items apply left
//! to right, so `-all,+clipboard` leaves only the clipboard forced on. The
//! flag is layered over the variable ([`Overrides::layered`]), so the flag
//! wins wherever both name a protocol.

use std::fmt;

/// A terminal protocol a Spacecraft program may speak.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Protocol {
    /// Kitty keyboard protocol (`CSI > flags u`).
    Keyboard,
    /// Kitty graphics and its fallback ladder.
    Graphics,
    /// Kitty graphics animation.
    Animation,
    /// OSC 52 clipboard write.
    Clipboard,
    /// OSC 5522 rich clipboard.
    ClipboardRich,
    /// OSC 9;4 progress.
    Progress,
    /// OSC 22 pointer shape.
    Pointer,
}

impl Protocol {
    /// Every protocol, in the order used by `all` and by diagnostics.
    pub const ALL: [Self; 7] = [
        Self::Keyboard,
        Self::Graphics,
        Self::Animation,
        Self::Clipboard,
        Self::ClipboardRich,
        Self::Progress,
        Self::Pointer,
    ];

    /// The override name of this protocol.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Keyboard => "keyboard",
            Self::Graphics => "graphics",
            Self::Animation => "animation",
            Self::Clipboard => "clipboard",
            Self::ClipboardRich => "clipboard-rich",
            Self::Progress => "progress",
            Self::Pointer => "pointer",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.name() == name)
    }

    const fn index(self) -> usize {
        self as usize
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Per-protocol forced state: `Some(true)` on, `Some(false)` off, `None`
/// follow detection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Overrides([Option<bool>; Protocol::ALL.len()]);

impl Overrides {
    /// No overrides: every protocol follows detection.
    #[must_use]
    pub const fn new() -> Self {
        Self([None; Protocol::ALL.len()])
    }

    /// Parse an override list.
    ///
    /// # Errors
    ///
    /// Returns [`ParseOverridesError`] naming the first item that is not a
    /// known protocol or `all`.
    pub fn parse(list: &str) -> Result<Self, ParseOverridesError> {
        let mut out = Self::new();
        for item in list.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let (on, name) = item.strip_prefix('+').map_or_else(
                || item.strip_prefix('-').map_or((true, item), |n| (false, n)),
                |n| (true, n),
            );
            if name == "all" {
                out.0 = [Some(on); Protocol::ALL.len()];
            } else if let Some(p) = Protocol::from_name(name) {
                out.0[p.index()] = Some(on);
            } else {
                return Err(ParseOverridesError {
                    item: item.to_owned(),
                });
            }
        }
        Ok(out)
    }

    /// `higher` layered over `self`: wherever `higher` forces a protocol, its
    /// value wins. Used as `env.layered(flag)`.
    #[must_use]
    pub fn layered(self, higher: Self) -> Self {
        let mut out = self;
        for (slot, hi) in out.0.iter_mut().zip(higher.0) {
            if hi.is_some() {
                *slot = hi;
            }
        }
        out
    }

    /// The forced state of `p`, if any.
    #[must_use]
    pub const fn forced(&self, p: Protocol) -> Option<bool> {
        self.0[p.index()]
    }

    /// Resolve `p`: the override when one exists, else `detected`.
    #[must_use]
    pub fn resolve(&self, p: Protocol, detected: bool) -> bool {
        self.forced(p).unwrap_or(detected)
    }
}

/// An override list named something that is not a protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseOverridesError {
    item: String,
}

impl fmt::Display for ParseOverridesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unknown terminal protocol '{}' (expected +/-name with name one of: all",
            self.item
        )?;
        for p in Protocol::ALL {
            write!(f, ", {p}")?;
        }
        f.write_str(")")
    }
}

impl std::error::Error for ParseOverridesError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_list_forces_nothing() {
        let o = Overrides::parse("").expect("empty parses");
        assert_eq!(o, Overrides::new());
        assert!(o.resolve(Protocol::Keyboard, true));
        assert!(!o.resolve(Protocol::Keyboard, false));
    }

    #[test]
    fn plus_minus_and_bare_names() {
        let o = Overrides::parse("-graphics, +progress,keyboard").expect("parses");
        assert_eq!(o.forced(Protocol::Graphics), Some(false));
        assert_eq!(o.forced(Protocol::Progress), Some(true));
        assert_eq!(o.forced(Protocol::Keyboard), Some(true));
        assert_eq!(o.forced(Protocol::Clipboard), None);
    }

    #[test]
    fn all_then_exception_applies_left_to_right() {
        let o = Overrides::parse("-all,+clipboard").expect("parses");
        assert_eq!(o.forced(Protocol::Clipboard), Some(true));
        for p in Protocol::ALL
            .into_iter()
            .filter(|p| *p != Protocol::Clipboard)
        {
            assert_eq!(o.forced(p), Some(false), "{p}");
        }
    }

    #[test]
    fn flag_beats_variable() {
        let env = Overrides::parse("-all").expect("env");
        let flag = Overrides::parse("+progress").expect("flag");
        let o = env.layered(flag);
        assert_eq!(o.forced(Protocol::Progress), Some(true));
        assert_eq!(o.forced(Protocol::Keyboard), Some(false));
    }

    #[test]
    fn unknown_name_is_rejected_with_the_item() {
        let e = Overrides::parse("+progress,-sparkles").expect_err("must fail");
        assert!(e.to_string().contains("'-sparkles'"), "{e}");
        assert!(Overrides::parse("+").is_err());
    }
}

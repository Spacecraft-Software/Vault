// SPDX-License-Identifier: GPL-3.0-or-later

//! The startup probe's queries and an incremental parser for the replies.
//!
//! The caller writes [`QUERY`] in one write, then feeds whatever it reads
//! into a [`ReplyParser`] until [`ReplyParser::feed`] reports that the DA1
//! reply arrived or its deadline passes. Terminals answer in order and every
//! terminal answers DA1, so anything still unanswered at that point is
//! unsupported. The parser copes with replies split across reads and
//! interleaved with ordinary key presses, which it ignores.

/// The probe: kitty keyboard flags (`CSI ? u`), terminal identity
/// (XTVERSION, `CSI > 0 q`), then the DA1 fence (`CSI c`), which must be last.
pub const QUERY: &[u8] = b"\x1b[?u\x1b[>0q\x1b[c";

/// Longest reply body kept, in bytes. Real replies are well under 100 bytes;
/// the cap stops a misbehaving terminal from growing the buffer without bound.
/// Bytes past the cap are dropped and the reply is still terminated normally.
const MAX_REPLY: usize = 256;

/// What the probe learned. Everything defaults to "not supported".
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProbeReport {
    /// Kitty keyboard flags currently in effect, when the terminal answered
    /// `CSI ? u` (a reply of `0` still proves support).
    pub kitty_keyboard: Option<u16>,
    /// The XTVERSION identity string, e.g. `WezTerm 20240203-110809-5046fc22`
    /// or `foot(1.16.2)`. A hint only, never proof of a feature.
    pub xtversion: Option<String>,
    /// The DA1 fence reply arrived.
    pub da1: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Ground,
    Esc,
    Csi,
    Dcs,
    DcsEsc,
    /// OSC / APC / PM / SOS: skipped until `BEL` or `ST`.
    Str,
    StrEsc,
}

/// Incremental parser for probe replies.
#[derive(Clone, Debug)]
pub struct ReplyParser {
    state: State,
    buf: Vec<u8>,
    report: ProbeReport,
}

impl Default for ReplyParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplyParser {
    /// A parser that has seen nothing yet.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: State::Ground,
            buf: Vec::new(),
            report: ProbeReport {
                kitty_keyboard: None,
                xtversion: None,
                da1: false,
            },
        }
    }

    /// Feed the next chunk of input. Returns `true` once the DA1 reply has
    /// been seen, at which point the caller stops reading.
    pub fn feed(&mut self, bytes: &[u8]) -> bool {
        for &b in bytes {
            self.step(b);
        }
        self.report.da1
    }

    /// The report so far.
    #[must_use]
    pub const fn report(&self) -> &ProbeReport {
        &self.report
    }

    /// Consume the parser, yielding its report.
    #[must_use]
    pub fn into_report(self) -> ProbeReport {
        self.report
    }

    fn push(&mut self, b: u8) {
        if self.buf.len() < MAX_REPLY {
            self.buf.push(b);
        }
    }

    fn step(&mut self, b: u8) {
        const ESC: u8 = 0x1b;
        const BEL: u8 = 0x07;
        self.state = match (self.state, b) {
            (State::Esc, b'[') => {
                self.buf.clear();
                State::Csi
            }
            (State::Esc, b'P') => {
                self.buf.clear();
                State::Dcs
            }
            (State::Esc, b']' | b'_' | b'^' | b'X') => State::Str,
            // ESC starts an escape sequence; inside a CSI it aborts it (a lone
            // Esc key press, or a truncated reply) and starts over.
            (State::Ground | State::Esc | State::Csi, ESC) => State::Esc,
            (State::Csi, 0x40..=0x7e) => {
                self.finish_csi(b);
                State::Ground
            }
            (State::Csi, _) => {
                self.push(b);
                State::Csi
            }
            (State::Dcs, ESC) => State::DcsEsc,
            (State::Dcs, _) => {
                self.push(b);
                State::Dcs
            }
            (State::DcsEsc, b'\\') => {
                self.finish_dcs();
                State::Ground
            }
            (State::Str, ESC) => State::StrEsc,
            // A string terminator, or any byte that does not continue a
            // sequence, returns to ground.
            (State::Str, BEL)
            | (State::StrEsc, b'\\')
            | (State::Ground | State::Esc | State::DcsEsc, _) => State::Ground,
            (State::Str | State::StrEsc, _) => State::Str,
        };
    }

    fn finish_csi(&mut self, fin: u8) {
        let Some(params) = self.buf.strip_prefix(b"?") else {
            return; // a key press or an unrelated reply
        };
        match fin {
            b'u' => {
                if let Some(flags) = std::str::from_utf8(params)
                    .ok()
                    .and_then(|s| s.parse::<u16>().ok())
                {
                    self.report.kitty_keyboard = Some(flags);
                }
            }
            b'c' => self.report.da1 = true,
            _ => {}
        }
    }

    fn finish_dcs(&mut self) {
        if let Some(id) = self.buf.strip_prefix(b">|") {
            let id = String::from_utf8_lossy(id).trim().to_owned();
            if !id.is_empty() {
                self.report.xtversion = Some(id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(bytes: &[u8]) -> (bool, ProbeReport) {
        let mut p = ReplyParser::new();
        let done = p.feed(bytes);
        (done, p.into_report())
    }

    #[test]
    fn full_reply_from_a_kitty_keyboard_terminal() {
        let (done, r) = parse(b"\x1b[?0u\x1bP>|foot(1.16.2)\x1b\\\x1b[?62;4;22c");
        assert!(done);
        assert_eq!(r.kitty_keyboard, Some(0));
        assert_eq!(r.xtversion.as_deref(), Some("foot(1.16.2)"));
    }

    #[test]
    fn da1_only_means_unsupported() {
        let (done, r) = parse(b"\x1b[?1;2c");
        assert!(done);
        assert_eq!(r.kitty_keyboard, None);
        assert_eq!(r.xtversion, None);
    }

    #[test]
    fn replies_split_across_reads() {
        let mut p = ReplyParser::new();
        assert!(!p.feed(b"\x1b[?"));
        assert!(!p.feed(b"1u\x1bP>|WezTerm 2024"));
        assert!(!p.feed(b"0203-110809-5046fc22\x1b"));
        assert!(!p.feed(b"\\\x1b[?65;4"));
        assert!(p.feed(b";6c"));
        let r = p.into_report();
        assert_eq!(r.kitty_keyboard, Some(1));
        assert_eq!(
            r.xtversion.as_deref(),
            Some("WezTerm 20240203-110809-5046fc22")
        );
    }

    #[test]
    fn key_presses_and_unrelated_sequences_are_ignored() {
        // Typed text, an arrow key, an OSC with BEL, then the DA1 reply.
        let (done, r) = parse(b"ab\x1b[A\x1b]11;rgb:0/0/0\x07\x1b[?6c");
        assert!(done);
        assert_eq!(r.kitty_keyboard, None);
    }

    #[test]
    fn lone_esc_then_reply_still_parses() {
        let (done, r) = parse(b"\x1b\x1b[?5u\x1b[?1c");
        assert!(done);
        assert_eq!(r.kitty_keyboard, Some(5));
    }

    #[test]
    fn oversized_reply_is_bounded() {
        let mut bytes = b"\x1bP>|".to_vec();
        bytes.extend(std::iter::repeat_n(b'x', 10_000));
        bytes.extend_from_slice(b"\x1b\\\x1b[?1c");
        let (done, r) = parse(&bytes);
        assert!(done);
        assert_eq!(r.xtversion.map(|s| s.len()), Some(MAX_REPLY - 2));
    }
}

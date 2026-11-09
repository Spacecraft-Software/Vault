// SPDX-License-Identifier: GPL-3.0-or-later

//! Vault terminal-protocol policy, shared by `vault` (CLI) and `vault-tui`.
//!
//! This crate decides *whether* and *what* to send to a terminal. It does no
//! terminal I/O: the TUI owns raw mode and the startup probe, and the CLI owns
//! its stderr spinner. Everything here is pure, so every decision is
//! unit-tested without a terminal.
//!
//! The rules come from the Spacecraft `spacecraft-tui-protocols` skill:
//!
//! - **Gate first** ([`TermEnv::protocols_allowed`]): no sequence and no probe
//!   when the stream is not a TTY, in agent or CI mode, or when `TERM` is
//!   `dumb` or unset.
//! - **Probe once, fenced by DA1** ([`probe`]): the reply parser treats the DA1
//!   reply as the end of the exchange, so an unanswered feature is unsupported.
//! - **Never send a sequence another meaning can catch** ([`progress`]): OSC
//!   9;4 goes only to terminals on an allow-list, because older ones show
//!   `OSC 9` as a desktop notification.
//! - **User override** ([`overrides`]): `--term-protocols` and
//!   `SPACECRAFT_TERM_PROTOCOLS` beat detection, and the flag beats the
//!   variable.
//!
//! Vault shows no images and has no mouse-interactive regions, so the
//! graphics, animation and pointer-shape protocols are recognised by the
//! override parser (for a uniform syntax across Spacecraft programs) but never
//! emitted.

#![forbid(unsafe_code)]

mod env;
pub mod osc52;
pub mod overrides;
pub mod probe;
pub mod progress;

pub use env::{Multiplexer, TermEnv};
pub use overrides::{Overrides, ParseOverridesError, Protocol};

/// Name of the environment variable carrying protocol overrides (§2.5).
pub const OVERRIDES_ENV: &str = "SPACECRAFT_TERM_PROTOCOLS";

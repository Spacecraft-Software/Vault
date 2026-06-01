// SPDX-License-Identifier: GPL-3.0-or-later

//! Vault theme — Steelbore palette tokens per Spacecraft Software Standard §9.
//!
//! Stub crate at M0. See PRD §6 (TUI) for usage.

#![forbid(unsafe_code)]

/// Steelbore palette — Standard §9.
pub mod steelbore {
    /// Void Navy — primary background.
    pub const VOID_NAVY: &str = "#000027";
    /// Molten Amber — primary foreground / accent.
    pub const MOLTEN_AMBER: &str = "#D98E32";
    /// Cool steel accent.
    pub const STEEL_BLUE: &str = "#4B7EB0";
    /// Success.
    pub const SUCCESS: &str = "#50FA7B";
    /// Error.
    pub const ERROR: &str = "#FF5C5C";
    /// Info.
    pub const INFO: &str = "#8BE9FD";
}

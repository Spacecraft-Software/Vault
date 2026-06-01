// SPDX-License-Identifier: GPL-3.0-or-later

//! Vault CLI — `vault` binary entry point.
//!
//! M0 surface: `--version`, `--help`. Subcommands land in M3+ per PRD §12.

use clap::{CommandFactory, Parser};

const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Standard §13.2 attribution block — surfaced via `--version`, `--help` footer,
/// README, and the TUI About screen.
const ATTRIBUTION: &str = "\
Maintained by Mohamed Hammad <Mohamed.Hammad@SpacecraftSoftware.org>
Copyright (C) 2026 Mohamed Hammad & Spacecraft Software  |  License: GPL-3.0-or-later
https://Vault.SpacecraftSoftware.org/";

#[derive(Parser, Debug)]
#[command(
    name = "vault",
    version = PKG_VERSION,
    about = "Vault — Bitwarden client for the terminal",
    long_about = "Vault is a terminal-native Bitwarden client. Two front-ends share a single Rust engine: a cruxpass-style TUI and an rbw-style CLI. See https://Vault.SpacecraftSoftware.org/.",
    after_help = ATTRIBUTION,
    after_long_help = ATTRIBUTION,
    disable_version_flag = true,
)]
struct Cli {
    /// Print version and attribution, then exit.
    #[arg(short = 'V', long = "version", global = true)]
    version: bool,
}

fn main() {
    let cli = Cli::parse();

    if cli.version {
        println!("vault {PKG_VERSION}");
        println!();
        println!("{ATTRIBUTION}");
        return;
    }

    let mut cmd = Cli::command();
    let _ = cmd.print_long_help();
    println!();
}

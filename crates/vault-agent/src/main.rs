// SPDX-License-Identifier: GPL-3.0-or-later

//! Vault agent — long-lived daemon that holds the user symmetric key.
//!
//! Run with no arguments to bind the default socket
//! (`$XDG_RUNTIME_DIR/vault/agent.sock`). Override with `--socket PATH` or
//! `VAULT_AGENT_SOCK`. The agent does NOT yet daemonise itself — start it
//! with `nohup vault-agent &` or run it under a systemd user unit. M5 adds
//! auto-spawn from the CLI.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use tokio::sync::Mutex;

use vault_ipc::default_socket_path;

mod server;
mod state;
mod unlock;

use state::AgentState;

const ATTRIBUTION: &str = "\
Maintained by Mohamed Hammad <Mohamed.Hammad@SpacecraftSoftware.org>
Copyright (C) 2026 Mohamed Hammad & Spacecraft Software  |  License: GPL-3.0-or-later
https://Vault.SpacecraftSoftware.org/";

#[derive(Parser, Debug)]
#[command(
    name = "vault-agent",
    version = env!("CARGO_PKG_VERSION"),
    about = "Vault agent — holds the unwrapped user key behind a Unix socket",
    after_help = ATTRIBUTION,
    after_long_help = ATTRIBUTION,
)]
struct Args {
    /// Bind path. Defaults to `$VAULT_AGENT_SOCK` or `$XDG_RUNTIME_DIR/vault/agent.sock`.
    #[arg(long, short = 's')]
    socket: Option<PathBuf>,
    /// Idle-lock timeout in seconds. The agent zeroises its keys after this
    /// many seconds with no client activity. `0` disables auto-lock.
    #[arg(long, default_value_t = 900)]
    idle_lock_secs: u64,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let path = pick_socket(args.socket)?;
    let state = Arc::new(Mutex::new(AgentState::new(args.idle_lock_secs)));

    if args.idle_lock_secs > 0 {
        let st = state.clone();
        tokio::spawn(server::idle_lock_loop(st));
    }

    server::run(path, state).await?;
    Ok(())
}

fn pick_socket(cli: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    if let Some(p) = cli {
        return Ok(p);
    }
    if let Ok(env_path) = std::env::var("VAULT_AGENT_SOCK") {
        if let Some(p) = vault_ipc::sanitize_socket_path(&env_path) {
            return Ok(p);
        }
        anyhow::bail!("VAULT_AGENT_SOCK is not an absolute path: {env_path}");
    }
    default_socket_path().ok_or_else(|| anyhow::anyhow!("no XDG_RUNTIME_DIR / TMPDIR available"))
}

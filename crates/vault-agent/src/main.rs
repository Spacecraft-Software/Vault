// SPDX-License-Identifier: GPL-3.0-or-later

//! Vault agent — long-lived daemon that holds the user symmetric key.
//!
//! Run with no arguments to bind the default socket
//! (`$XDG_RUNTIME_DIR/vault/agent.sock`). Override with `--socket PATH` or
//! `VAULT_AGENT_SOCK`. The agent does not daemonise itself: the normal start
//! path is the CLI's auto-spawn — any `vault` verb starts it detached when
//! the socket is dead, logging to `agent.log` beside the socket — and a
//! systemd user unit works too.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use tokio::sync::Mutex;

use vault_ipc::default_socket_path;

#[cfg(feature = "clipboard")]
mod clipboard;
mod server;
mod session;
mod state;
mod unlock;

use state::AgentState;

const ATTRIBUTION: &str = "\
Maintained by Mohamed Hammad <Mohamed.Hammad@SpacecraftSoftware.org>
Copyright (C) 2026 Mohamed Hammad & Spacecraft Software  |  License: GPL-3.0-or-later
https://Vault.SpacecraftSoftware.org/";

/// `--version` payload — mirrors `vault`'s: clap shows `after_help` only on
/// `--help`, so the §13.2 attribution block rides in `long_version`.
const LONG_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    "\n",
    "Maintained by Mohamed Hammad <Mohamed.Hammad@SpacecraftSoftware.org>\n",
    "Copyright (C) 2026 Mohamed Hammad & Spacecraft Software  |  License: GPL-3.0-or-later\n",
    "https://Vault.SpacecraftSoftware.org/",
);

#[derive(Parser, Debug)]
#[command(
    name = "vault-agent",
    version = env!("CARGO_PKG_VERSION"),
    long_version = LONG_VERSION,
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
    /// Default seconds before a copied secret is wiped from the clipboard
    /// when the client doesn't specify; `0` disables the default auto-clear.
    /// Falls back to `$VAULT_CLIPBOARD_CLEAR_SECS`, then 30. No effect on a
    /// build without clipboard support.
    #[arg(long)]
    clipboard_clear_secs: Option<u64>,
    /// Mirror the user key into the Linux kernel session keyring on unlock so a
    /// restarted agent resumes without the master password, within the
    /// idle-lock TTL (opt-in; PRD §7.3 carve-out). No effect on non-Linux.
    #[arg(long)]
    session_keyring: bool,
    /// Seconds between background `/sync`es while unlocked; `0` disables. Keeps
    /// the cache fresh without a manual `vault sync`.
    #[arg(long, default_value_t = 0)]
    sync_interval_secs: u64,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let path = pick_socket(args.socket)?;
    #[cfg(feature = "clipboard")]
    let agent = {
        let mut a = AgentState::new(args.idle_lock_secs);
        a.clipboard_clear_secs = resolve_clear_secs(
            args.clipboard_clear_secs,
            std::env::var("VAULT_CLIPBOARD_CLEAR_SECS").ok().as_deref(),
        );
        a
    };
    #[cfg(not(feature = "clipboard"))]
    let agent = AgentState::new(args.idle_lock_secs);
    let mut agent = agent;
    agent.session_keyring = args.session_keyring;
    agent.sync_interval_secs = args.sync_interval_secs;
    // Opt-in: resume an unlocked session left in the kernel keyring by a prior
    // agent (e.g. after a crash / restart), within its idle-lock deadline.
    try_resume(&mut agent);
    let state = Arc::new(Mutex::new(agent));

    if args.idle_lock_secs > 0 {
        let st = state.clone();
        tokio::spawn(server::idle_lock_loop(st));
    }

    if args.sync_interval_secs > 0 {
        let st = state.clone();
        tokio::spawn(server::scheduled_sync_loop(st));
    }

    // PRD §7.3: lock on SIGTERM. Locking also sweeps a still-pending
    // clipboard copy; the socket file is removed so the next CLI call
    // auto-spawns cleanly instead of hitting a stale socket.
    {
        let st = state.clone();
        let sock = path.clone();
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::spawn(async move {
            term.recv().await;
            st.lock().await.lock();
            let _ = std::fs::remove_file(&sock);
            eprintln!("vault-agent: SIGTERM — keys dropped, exiting");
            std::process::exit(0);
        });
    }

    server::run(path, state).await?;
    Ok(())
}

/// Effective default auto-clear interval: `--clipboard-clear-secs` wins, then
/// `$VAULT_CLIPBOARD_CLEAR_SECS` (ignored when unparsable), then 30 s.
#[cfg(feature = "clipboard")]
fn resolve_clear_secs(flag: Option<u64>, env: Option<&str>) -> u64 {
    flag.or_else(|| env.and_then(|v| v.parse().ok()))
        .unwrap_or(30)
}

/// Opt-in session resume: if a prior agent left an unlocked session in the
/// kernel keyring and it hasn't passed its idle-lock deadline, rebuild the
/// vault from it + the on-disk cache so the agent comes up unlocked. Any
/// failure (disabled, no entry, expired, missing cache) leaves it locked.
fn try_resume(agent: &mut AgentState) {
    if !agent.session_keyring {
        return;
    }
    let Some(blob) = session::load() else {
        return;
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    // deadline_unix == 0 means "no expiry" (idle-lock disabled).
    if blob.deadline_unix != 0 && now >= blob.deadline_unix {
        session::clear();
        return;
    }
    let Some(cache) = unlock::load_cache(&blob.server, &blob.email) else {
        return;
    };
    let user_enc = zeroize::Zeroizing::new(blob.user_enc);
    let user_mac = zeroize::Zeroizing::new(blob.user_mac);
    match unlock::vault_from_user_key(&cache, &blob.server, &blob.email, user_enc, user_mac) {
        Ok(vault) => {
            agent.vault = Some(vault);
            agent.touch();
            eprintln!("vault-agent: resumed session from kernel keyring");
        }
        Err(e) => eprintln!("vault-agent: keyring resume failed: {e}"),
    }
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

#[cfg(test)]
mod tests {
    #[cfg(feature = "clipboard")]
    #[test]
    fn resolve_clear_secs_precedence() {
        use super::resolve_clear_secs;
        assert_eq!(resolve_clear_secs(Some(45), Some("60")), 45, "flag wins");
        assert_eq!(resolve_clear_secs(None, Some("60")), 60, "env next");
        assert_eq!(
            resolve_clear_secs(None, Some("nope")),
            30,
            "bad env ignored"
        );
        assert_eq!(resolve_clear_secs(None, None), 30, "default");
        assert_eq!(resolve_clear_secs(Some(0), Some("60")), 0, "0 disables");
    }
}

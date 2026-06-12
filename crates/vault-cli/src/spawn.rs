// SPDX-License-Identifier: GPL-3.0-or-later

//! Agent auto-spawn — start `vault-agent` when the socket is dead (PRD §7.3).
//!
//! The CLI is the daemon's launcher of last resort: when a connect fails with
//! "not found" / "connection refused", it locates the agent binary, starts it
//! detached (own process group, stdout/stderr appended to `agent.log` beside
//! the socket), and polls the socket until the agent accepts. The agent still
//! binds and chmods the socket itself — the CLI only waits for it. Disable
//! with the global `--no-auto-spawn` flag.

use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use tokio::net::UnixStream;

/// How long to wait for a freshly spawned agent to accept connections.
/// Generous against a cold page cache; a warm spawn binds in single-digit
/// milliseconds, and the poll loop returns as soon as the connect lands.
const SPAWN_DEADLINE: Duration = Duration::from_secs(2);

/// Poll interval while waiting for the socket to come up — small enough to
/// keep the PRD §9 warm-`get` budget plausible on the first post-spawn call.
const SPAWN_POLL: Duration = Duration::from_millis(25);

/// Whether `e` means "no live agent behind this path" — a missing socket file
/// or a stale one nobody is accepting on. These are the only two outcomes
/// worth a spawn attempt; anything else (e.g. permissions) needs the user.
pub fn socket_is_dead(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
    )
}

/// Locate the agent binary: `$VAULT_AGENT_BIN` override first, then a
/// `vault-agent` sibling of the current executable (the layout both
/// `cargo build` and `cargo install` produce), then bare `vault-agent`
/// resolved through `$PATH`.
fn agent_binary() -> PathBuf {
    let sibling = std::env::current_exe().ok().and_then(|exe| {
        let p = exe.parent()?.join("vault-agent");
        p.is_file().then_some(p)
    });
    resolve_binary(std::env::var_os("VAULT_AGENT_BIN"), sibling)
}

/// Pure precedence behind [`agent_binary`]: a non-empty override wins, then
/// the pre-checked sibling, then `$PATH` lookup by name.
fn resolve_binary(overridden: Option<OsString>, sibling: Option<PathBuf>) -> PathBuf {
    if let Some(p) = overridden
        && !p.is_empty()
    {
        return PathBuf::from(p);
    }
    sibling.unwrap_or_else(|| PathBuf::from("vault-agent"))
}

/// Start the agent for `socket` and wait for it to accept. Returns the first
/// accepted stream so the caller doesn't race a second connect.
///
/// # Errors
///
/// Returns a user-facing message when the binary can't be started or the
/// agent doesn't come up within the deadline.
pub async fn spawn_and_connect(socket: &Path) -> Result<UnixStream, String> {
    let bin = agent_binary();
    let child = Command::new(&bin)
        .arg("--socket")
        .arg(socket)
        // Own process group: a Ctrl+C aimed at the CLI must not take the
        // freshly started daemon down with it.
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(agent_log(socket))
        .spawn()
        .map_err(|e| format!("could not start {}: {e}", bin.display()))?;
    eprintln!("vault: started vault-agent (pid {})", child.id());
    await_socket(socket, SPAWN_DEADLINE).await.ok_or_else(|| {
        format!(
            "vault-agent did not come up within {}s — see agent.log next to the socket",
            SPAWN_DEADLINE.as_secs()
        )
    })
}

/// Where the spawned agent's stderr goes: `agent.log` beside the socket, in
/// the directory the agent will chmod 0700 on bind (pre-created here with the
/// same mode so the log never sits in a wider directory). Falls back to null
/// rather than failing the spawn over logging.
fn agent_log(socket: &Path) -> Stdio {
    let Some(dir) = socket.parent() else {
        return Stdio::null();
    };
    fs::create_dir_all(dir)
        .and_then(|()| fs::set_permissions(dir, fs::Permissions::from_mode(0o700)))
        .and_then(|()| {
            fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(dir.join("agent.log"))
        })
        .map_or_else(|_| Stdio::null(), Stdio::from)
}

/// Poll-connect until the socket accepts or the deadline passes.
async fn await_socket(socket: &Path, deadline: Duration) -> Option<UnixStream> {
    let start = std::time::Instant::now();
    while start.elapsed() < deadline {
        if let Ok(s) = UnixStream::connect(socket).await {
            return Some(s);
        }
        tokio::time::sleep(SPAWN_POLL).await;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_binary_prefers_override_then_sibling_then_path() {
        let over = Some(OsString::from("/opt/vault-agent"));
        let sib = Some(PathBuf::from("/bin-dir/vault-agent"));
        assert_eq!(
            resolve_binary(over, sib.clone()),
            PathBuf::from("/opt/vault-agent")
        );
        // An empty override is treated as unset.
        assert_eq!(
            resolve_binary(Some(OsString::new()), sib.clone()),
            PathBuf::from("/bin-dir/vault-agent")
        );
        assert_eq!(
            resolve_binary(None, sib),
            PathBuf::from("/bin-dir/vault-agent")
        );
        assert_eq!(resolve_binary(None, None), PathBuf::from("vault-agent"));
    }

    #[test]
    fn socket_is_dead_only_for_missing_or_refused() {
        assert!(socket_is_dead(&io::Error::from(io::ErrorKind::NotFound)));
        assert!(socket_is_dead(&io::Error::from(
            io::ErrorKind::ConnectionRefused
        )));
        assert!(!socket_is_dead(&io::Error::from(
            io::ErrorKind::PermissionDenied
        )));
    }

    /// The poll loop must pick up a socket that starts accepting *after* the
    /// first attempt — that's the whole point of polling.
    #[tokio::test(flavor = "current_thread")]
    async fn await_socket_picks_up_a_late_listener() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("agent.sock");
        let bind_path = path.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(60)).await;
            let listener = tokio::net::UnixListener::bind(&bind_path).expect("bind");
            // Hold the listener long enough for the poll loop to connect.
            let _ = listener.accept().await;
        });
        let got = await_socket(&path, Duration::from_secs(2)).await;
        assert!(got.is_some(), "poll loop missed the late listener");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn await_socket_gives_up_after_the_deadline() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("never.sock");
        let got = await_socket(&path, Duration::from_millis(80)).await;
        assert!(got.is_none());
    }
}

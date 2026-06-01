// SPDX-License-Identifier: GPL-3.0-or-later

//! Default agent socket path.
//!
//! Convention: `$XDG_RUNTIME_DIR/vault/agent.sock` when `$XDG_RUNTIME_DIR` is
//! set (the typical systemd-managed `/run/user/<uid>/`), else
//! `$TMPDIR/vault-<uid>/agent.sock`. The directory is created with mode 0700
//! and the socket with mode 0600 by the agent on bind.

use std::path::PathBuf;

/// Compute the canonical socket path for this user. Returns `None` if no
/// suitable directory can be derived (very locked-down sandboxes).
#[must_use]
pub fn default_socket_path() -> Option<PathBuf> {
    if let Some(rt) = std::env::var_os("XDG_RUNTIME_DIR") {
        let mut p = PathBuf::from(rt);
        p.push("vault");
        p.push("agent.sock");
        return Some(p);
    }
    let tmp = std::env::temp_dir();
    let uid = uid_string();
    Some(tmp.join(format!("vault-{uid}")).join("agent.sock"))
}

/// Reject obviously-traversal-y socket overrides; the caller (CLI / agent)
/// uses this when honouring `VAULT_AGENT_SOCK`. Allows absolute paths only.
#[must_use]
pub fn sanitize_socket_path(p: &str) -> Option<PathBuf> {
    if p.is_empty() {
        return None;
    }
    let pb = PathBuf::from(p);
    if !pb.is_absolute() {
        return None;
    }
    Some(pb)
}

fn uid_string() -> String {
    // Reading /proc/self/status avoids the `libc` dep at this layer.
    if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
        for line in s.lines() {
            if let Some(rest) = line.strip_prefix("Uid:") {
                if let Some(uid) = rest.split_whitespace().next() {
                    return uid.to_owned();
                }
            }
        }
    }
    "unknown".to_owned()
}

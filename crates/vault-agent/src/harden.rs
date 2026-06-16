// SPDX-License-Identifier: GPL-3.0-or-later

//! Process anti-leak hardening, run once at agent startup.
//!
//! The agent holds the unwrapped user key (and refresh token) in memory. This
//! locks down two ways that material could escape the process:
//!
//! - **Core dumps** — a crash must not write key bytes to a core file on disk.
//! - **ptrace** — another process running as the same user must not be able to
//!   attach a debugger and read the agent's memory.
//!
//! Both are handled by [`secmem_proc::harden_process`] (lowers `RLIMIT_CORE`
//! and sets the process non-dumpable via the audited `rustix` syscall layer),
//! which keeps this crate's `#![forbid(unsafe_code)]` intact.
//!
//! This does **not** yet cover swap exposure (`mlock`); that's a tracked
//! follow-up. mlock is out of scope here.

/// Harden the current process against core dumps and ptrace. Best-effort: if a
/// step fails (e.g. a sandbox that restricts `setrlimit`), log a warning and
/// keep running — a partial-hardening failure must never take the agent down.
pub fn harden_process() {
    if let Err(e) = secmem_proc::harden_process() {
        eprintln!("vault-agent: process hardening incomplete (continuing): {e}");
    }
}

#[cfg(target_os = "linux")]
#[cfg(test)]
mod tests {
    /// After hardening, the process must be marked non-dumpable — that's what
    /// blocks core dumps and same-user ptrace. Where `/proc/self/status`
    /// exposes the `Dumpable` field (a normal kernel) we assert it is `0`; some
    /// sandboxed `/proc` mounts omit the field, in which case there is nothing
    /// to check (the call still must not panic). `PR_SET_DUMPABLE(0)` is
    /// unprivileged, so the assertion is deterministic where it applies.
    #[test]
    fn harden_sets_process_non_dumpable() {
        super::harden_process();
        let status = std::fs::read_to_string("/proc/self/status").expect("read /proc/self/status");
        if let Some(dumpable) = status
            .lines()
            .find_map(|l| l.strip_prefix("Dumpable:"))
            .map(str::trim)
        {
            assert_eq!(
                dumpable, "0",
                "process should be non-dumpable after hardening"
            );
        }
    }
}

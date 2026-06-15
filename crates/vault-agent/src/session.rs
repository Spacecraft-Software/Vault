// SPDX-License-Identifier: GPL-3.0-or-later

//! Optional session resume across agent restarts, backed by the Linux kernel
//! **session keyring**.
//!
//! When `agent.session_keyring` is enabled, an unlock stashes the user key (and
//! just enough metadata to find the on-disk cache) in the kernel session
//! keyring — kernel memory, never on disk, never swapped, possessor-gated, and
//! evicted on logout. A restarted agent reads it back and rebuilds the unlocked
//! [`Vault`](crate::state::Vault) without the master password, but only until
//! the idle-lock **deadline**: the keyring entry carries a kernel timeout, so a
//! dead agent's session self-expires.
//!
//! This is the opt-in carve-out to PRD §7.3 / G4 ("master key never resident
//! outside the agent process"): the key may *also* live in the kernel session
//! keyring while the feature is on. The default is off.
//!
//! On non-Linux targets every operation is a no-op (`load` is always `None`),
//! so callers degrade cleanly to a password/PIN unlock.

use serde::{Deserialize, Serialize};

/// Keyring entry name within the session keyring. Single-account: the blob
/// itself carries which account (server/email) the cache belongs to.
#[cfg(target_os = "linux")]
const KEY_DESC: &str = "vault-agent:session";

/// Everything needed to rebuild an unlocked vault without the master password:
/// the user key halves, the account (to locate the on-disk cache), and the
/// idle-lock deadline that bounds resume. The key bytes are zeroized on drop.
#[derive(Serialize, Deserialize)]
pub struct SessionBlob {
    /// Server origin the session is bound to.
    pub server: String,
    /// Account email (lower-cased).
    pub email: String,
    /// User symmetric encryption key.
    pub user_enc: [u8; 32],
    /// User symmetric MAC key.
    pub user_mac: [u8; 32],
    /// Seconds since the Unix epoch after which resume is refused.
    pub deadline_unix: u64,
}

impl Drop for SessionBlob {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.user_enc.zeroize();
        self.user_mac.zeroize();
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use super::{KEY_DESC, SessionBlob};
    use linux_keyutils::{KeyRing, KeyRingIdentifier};
    use zeroize::Zeroizing;

    /// The user's kernel **session** keyring (shared across the login session,
    /// inherited by the detached auto-spawned agent), or `None` if unavailable.
    fn session_ring() -> Option<KeyRing> {
        KeyRing::from_special_id(KeyRingIdentifier::Session, false).ok()
    }

    /// Store (or replace) the session blob and bound it with a kernel timeout
    /// of `ttl_secs` (0 = no timeout, mirroring a disabled idle-lock). Best
    /// effort: a keyring failure just means no resume — never fail an unlock.
    pub fn store(blob: &SessionBlob, ttl_secs: u64) {
        let Some(ring) = session_ring() else {
            return;
        };
        let bytes = match serde_json::to_vec(blob) {
            Ok(b) => Zeroizing::new(b),
            Err(_) => return,
        };
        // add_key on an existing description replaces the payload (kernel
        // semantics), so this both creates and refreshes.
        match ring.add_key(KEY_DESC, bytes.as_slice()) {
            Ok(key) => {
                if ttl_secs > 0 {
                    let secs = usize::try_from(ttl_secs).unwrap_or(usize::MAX);
                    let _ = key.set_timeout(secs);
                }
            }
            Err(e) => eprintln!("vault-agent: session keyring store failed: {e:?}"),
        }
    }

    /// Read the session blob back, or `None` when absent/expired/unavailable.
    pub fn load() -> Option<SessionBlob> {
        let ring = session_ring()?;
        let key = ring.search(KEY_DESC).ok()?;
        let raw = Zeroizing::new(key.read_to_vec().ok()?);
        serde_json::from_slice(&raw).ok()
    }

    /// Remove the stored session. A no-op when none is present.
    pub fn clear() {
        if let Some(ring) = session_ring()
            && let Ok(key) = ring.search(KEY_DESC)
        {
            let _ = key.invalidate();
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::SessionBlob;

    pub fn store(_blob: &SessionBlob, _ttl_secs: u64) {}

    #[must_use]
    pub fn load() -> Option<SessionBlob> {
        None
    }

    pub fn clear() {}
}

pub use imp::{clear, load, store};

#[cfg(test)]
mod tests {
    use super::SessionBlob;

    fn sample() -> SessionBlob {
        SessionBlob {
            server: "https://vault.example.org".into(),
            email: "me@example.org".into(),
            user_enc: [7u8; 32],
            user_mac: [9u8; 32],
            deadline_unix: 1_900_000_000,
        }
    }

    #[test]
    fn blob_serde_round_trip() {
        let blob = sample();
        let bytes = serde_json::to_vec(&blob).unwrap();
        let back: SessionBlob = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.server, "https://vault.example.org");
        assert_eq!(back.email, "me@example.org");
        assert_eq!(back.user_enc, [7u8; 32]);
        assert_eq!(back.user_mac, [9u8; 32]);
        assert_eq!(back.deadline_unix, 1_900_000_000);
    }

    /// On a host with a working session keyring, store → load → clear round
    /// trips. Skips (does not fail) where the keyring is unavailable, and is a
    /// pure no-op assertion on non-Linux.
    #[test]
    fn store_load_clear_round_trip() {
        super::store(&sample(), 60);
        let Some(got) = super::load() else {
            // No keyring here (non-Linux, or a sandbox without one) — fine.
            eprintln!("session keyring unavailable; skipping round-trip assertions");
            return;
        };
        assert_eq!(got.user_enc, [7u8; 32]);
        assert_eq!(got.email, "me@example.org");
        super::clear();
        assert!(super::load().is_none(), "clear() must remove the entry");
    }
}

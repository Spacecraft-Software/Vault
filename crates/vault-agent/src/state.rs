// SPDX-License-Identifier: GPL-3.0-or-later

//! Agent state — locked / unlocked, key custody, in-memory item index.
//!
//! `AgentState` is the single source of truth inside the agent process. The
//! UDS server holds it in an `Arc<Mutex<_>>` and every request handler
//! acquires the lock for the duration of one operation. M3's request rate
//! (interactive `vault get` / `vault list` calls) makes that coarse mutex
//! the right shape; finer-grained locking can come later if a TUI ever
//! drives many parallel reads.

use std::time::Instant;

use zeroize::Zeroizing;

use vault_api::BitwardenClient;
use vault_core::cipher::{Cipher, DecryptOptions};
use vault_ipc::proto::{Error as IpcError, Field, Item, ListEntry, Removed, Status};

/// In-memory keys + ciphers held while the agent is unlocked.
pub struct Vault {
    /// Server origin the unlocked session is bound to.
    pub server: String,
    /// Account email the agent is unlocked for (lower-cased).
    pub email: String,
    /// User symmetric encryption key.
    pub user_enc: Zeroizing<[u8; 32]>,
    /// User symmetric MAC key.
    pub user_mac: Zeroizing<[u8; 32]>,
    /// Most recent `/sync` ciphers, encrypted at rest in memory until
    /// `decrypt_*` opens a specific field.
    pub ciphers: Vec<Cipher>,
    /// Folder id → decrypted folder name.
    pub folders: std::collections::HashMap<String, String>,
    /// Authenticated REST client, reused by `Sync`/`Remove`/`Edit`/`Add` for
    /// the lifetime of the unlock. Holds the access token internally; dropped
    /// when the agent locks.
    pub client: BitwardenClient,
    /// Most recent sync time (ISO 8601 UTC), or `None` if never synced.
    pub last_sync: Option<String>,
}

/// Top-level agent state.
pub struct AgentState {
    /// `None` when locked; `Some` when unlocked.
    pub vault: Option<Vault>,
    /// Last activity timestamp, for the idle-lock policy.
    pub last_activity: Instant,
    /// Idle timeout in seconds; after this with no activity the agent locks.
    pub idle_lock_secs: u64,
    /// Set by `Request::Quit` to ask the accept loop to exit cleanly.
    pub shutdown_requested: bool,
}

impl AgentState {
    /// Fresh agent — locked, just-touched.
    #[must_use]
    pub fn new(idle_lock_secs: u64) -> Self {
        Self {
            vault: None,
            last_activity: Instant::now(),
            idle_lock_secs,
            shutdown_requested: false,
        }
    }

    /// Whether the agent currently holds the user key.
    #[must_use]
    pub const fn is_unlocked(&self) -> bool {
        self.vault.is_some()
    }

    /// Mark a request as just-handled (resets the idle-lock countdown).
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Whether the idle-lock policy says it's time to drop keys.
    #[must_use]
    pub fn idle_lock_due(&self) -> bool {
        self.is_unlocked() && self.last_activity.elapsed().as_secs() >= self.idle_lock_secs
    }

    /// Zero out the vault keys and access token.
    pub fn lock(&mut self) {
        self.vault = None;
    }

    /// Build a `Status` snapshot for `Request::Status` / `Request::Ping`.
    #[must_use]
    pub fn status_snapshot(&self) -> Status {
        let (server, email, items, last_sync) =
            self.vault.as_ref().map_or((None, None, None, None), |v| {
                (
                    Some(v.server.clone()),
                    Some(v.email.clone()),
                    Some(v.ciphers.len()),
                    v.last_sync.clone(),
                )
            });
        Status {
            unlocked: self.is_unlocked(),
            server,
            email,
            items,
            last_sync,
            agent_version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }

    /// Decrypt every cipher's name (and optionally username) for `vault list`.
    pub fn list_entries(&self) -> Result<Vec<ListEntry>, IpcError> {
        let v = self.vault.as_ref().ok_or(IpcError::Locked)?;
        let mut out = Vec::with_capacity(v.ciphers.len());
        for c in &v.ciphers {
            // For ListEntry we want name + username (login items). Username
            // is cheap; decrypt it eagerly even though the wire shape allows
            // None — rbw users expect to see it next to the name.
            let opts = if c.cipher_type == 1 {
                DecryptOptions::username_only()
            } else {
                DecryptOptions::default()
            };
            let plain = c
                .decrypt(&v.user_enc, &v.user_mac, opts)
                .map_err(|e| IpcError::Decrypt(e.to_string()))?;
            let Some(name) = plain.name.clone() else {
                continue; // skip unnamed items in the list view
            };
            let folder = c
                .folder_id
                .as_deref()
                .and_then(|fid| v.folders.get(fid).cloned());
            out.push(ListEntry {
                id: c.id.clone(),
                name,
                cipher_type: c.cipher_type,
                username: plain.username.clone(),
                folder,
            });
        }
        out.sort_by_key(|e| e.name.to_lowercase());
        Ok(out)
    }

    /// Resolve `selector` to exactly one cipher index in `self.vault.ciphers`.
    ///
    /// Matching order:
    /// 1. Exact `Cipher.id` equality (server UUIDs are unique). One match
    ///    wins outright, even if a different cipher happens to be named
    ///    that UUID.
    /// 2. Otherwise, case-insensitive decrypted-name match.
    ///
    /// Returns `NoSuchItem` if nothing matches and `AmbiguousItem` if the
    /// name resolves to more than one cipher.
    fn resolve_cipher(&self, selector: &str) -> Result<usize, IpcError> {
        let v = self.vault.as_ref().ok_or(IpcError::Locked)?;
        if let Some(idx) = v.ciphers.iter().position(|c| c.id == selector) {
            return Ok(idx);
        }
        let sel_lower = selector.to_lowercase();
        let mut matches: Vec<(usize, String)> = Vec::new();
        for (idx, c) in v.ciphers.iter().enumerate() {
            let name = c
                .decrypt_name(&v.user_enc, &v.user_mac)
                .map_err(|e| IpcError::Decrypt(e.to_string()))?;
            if let Some(n) = name
                && n.to_lowercase() == sel_lower
            {
                matches.push((idx, c.id.clone()));
            }
        }
        match matches.len() {
            0 => Err(IpcError::NoSuchItem(selector.to_owned())),
            1 => Ok(matches[0].0),
            _ => Err(IpcError::AmbiguousItem {
                name: selector.to_owned(),
                ids: matches.into_iter().map(|(_, id)| id).collect(),
            }),
        }
    }

    /// Server-call: DELETE the cipher referenced by `selector`, then drop
    /// it from the in-memory cache so subsequent `list`/`get` reflect it.
    /// The on-disk encrypted cache is intentionally not patched — the next
    /// `unlock` will re-pull `/sync` and overwrite it.
    pub async fn remove_cipher(&mut self, selector: &str) -> Result<Removed, IpcError> {
        let idx = self.resolve_cipher(selector)?;
        let v = self.vault.as_mut().ok_or(IpcError::Locked)?;
        let id = v.ciphers[idx].id.clone();
        let name = v.ciphers[idx]
            .decrypt_name(&v.user_enc, &v.user_mac)
            .map_err(|e| IpcError::Decrypt(e.to_string()))?
            .unwrap_or_else(|| "<unnamed>".to_owned());
        v.client
            .delete_cipher(&id)
            .await
            .map_err(|e| IpcError::Network(e.to_string()))?;
        v.ciphers.remove(idx);
        Ok(Removed { id, name })
    }

    /// Decrypt the named field on the cipher matching `query` (case-insensitive).
    pub fn get_item(&self, query: &str, field: Field) -> Result<Item, IpcError> {
        let v = self.vault.as_ref().ok_or(IpcError::Locked)?;
        let query_lower = query.to_lowercase();
        let mut matched: Option<(&Cipher, String)> = None;
        for c in &v.ciphers {
            let name = c
                .decrypt_name(&v.user_enc, &v.user_mac)
                .map_err(|e| IpcError::Decrypt(e.to_string()))?;
            if let Some(n) = name
                && n.to_lowercase() == query_lower
            {
                matched = Some((c, n));
                break;
            }
        }
        let (cipher, name) = matched.ok_or_else(|| IpcError::NoSuchItem(query.to_owned()))?;

        let opts = match field {
            Field::Password => DecryptOptions {
                password: true,
                ..DecryptOptions::default()
            },
            Field::Username => DecryptOptions {
                username: true,
                ..DecryptOptions::default()
            },
            Field::Totp => DecryptOptions {
                totp: true,
                ..DecryptOptions::default()
            },
            Field::Notes => DecryptOptions {
                notes: true,
                ..DecryptOptions::default()
            },
            Field::Uri => DecryptOptions {
                primary_uri: true,
                ..DecryptOptions::default()
            },
        };
        let plain = cipher
            .decrypt(&v.user_enc, &v.user_mac, opts)
            .map_err(|e| IpcError::Decrypt(e.to_string()))?;
        let value = match field {
            Field::Password => plain.password.clone(),
            Field::Username => plain.username.clone(),
            Field::Totp => plain.totp.clone(),
            Field::Notes => plain.notes.clone(),
            Field::Uri => plain.primary_uri.clone(),
        };
        let value = value.ok_or_else(|| IpcError::NoSuchField {
            item: name.clone(),
            field: format!("{field:?}").to_lowercase(),
        })?;
        Ok(Item {
            id: cipher.id.clone(),
            name,
            cipher_type: cipher.cipher_type,
            field,
            value,
        })
    }
}

#[cfg(test)]
mod tests {
    // Tests reach into the past with plain `Instant`/`Duration` arithmetic to
    // simulate idle time; the checked-subtraction and unit-readability lints
    // are noise for fixed test constants.
    #![allow(clippy::unchecked_time_subtraction, clippy::duration_suboptimal_units)]

    use std::time::{Duration, Instant};

    use super::*;

    #[test]
    fn new_state_is_locked() {
        let s = AgentState::new(900);
        assert!(!s.is_unlocked());
        let snap = s.status_snapshot();
        assert!(!snap.unlocked);
        assert!(snap.server.is_none());
        assert!(snap.email.is_none());
        assert!(snap.items.is_none());
        assert_eq!(snap.agent_version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn lock_clears_vault() {
        let mut s = AgentState::new(900);
        s.vault = Some(stub_vault());
        assert!(s.is_unlocked());
        s.lock();
        assert!(!s.is_unlocked());
    }

    #[test]
    fn idle_lock_due_only_when_unlocked_and_expired() {
        let mut s = AgentState::new(60);
        // Locked agents are never "idle-lock due" — there's nothing to drop.
        s.last_activity = Instant::now() - Duration::from_secs(3600);
        assert!(!s.idle_lock_due());
        s.vault = Some(stub_vault());
        assert!(s.idle_lock_due());
        s.touch();
        assert!(!s.idle_lock_due());
    }

    #[test]
    fn idle_lock_disabled_when_secs_is_zero_via_main_skip() {
        // `main.rs` skips spawning the loop when `idle_lock_secs == 0`,
        // but `idle_lock_due` itself still evaluates honestly — verify it
        // reports "due" the moment any time has passed under a zero budget,
        // so the main-side guard is the *only* policy gate.
        let mut s = AgentState::new(0);
        s.vault = Some(stub_vault());
        s.last_activity = Instant::now() - Duration::from_millis(1);
        assert!(s.idle_lock_due());
    }

    #[test]
    fn list_entries_errors_when_locked() {
        let s = AgentState::new(900);
        assert!(matches!(s.list_entries(), Err(IpcError::Locked)));
        assert!(matches!(
            s.get_item("anything", Field::Password),
            Err(IpcError::Locked)
        ));
    }

    #[test]
    fn resolve_cipher_matches_by_id_then_name() {
        let enc = [7u8; 32];
        let mac = [9u8; 32];
        let mut v = stub_vault();
        v.user_enc = Zeroizing::new(enc);
        v.user_mac = Zeroizing::new(mac);
        v.ciphers.push(make_cipher(
            "00000000-0000-0000-0000-000000000001",
            "github",
            &enc,
            &mac,
        ));
        v.ciphers.push(make_cipher(
            "00000000-0000-0000-0000-000000000002",
            "GitLab",
            &enc,
            &mac,
        ));

        let mut s = AgentState::new(900);
        s.vault = Some(v);

        assert_eq!(
            s.resolve_cipher("00000000-0000-0000-0000-000000000002")
                .unwrap(),
            1
        );
        // Name match is case-insensitive.
        assert_eq!(s.resolve_cipher("gitlab").unwrap(), 1);
        assert!(matches!(
            s.resolve_cipher("not-there"),
            Err(IpcError::NoSuchItem(_))
        ));
    }

    #[test]
    fn resolve_cipher_rejects_ambiguous_name() {
        let enc = [3u8; 32];
        let mac = [4u8; 32];
        let mut v = stub_vault();
        v.user_enc = Zeroizing::new(enc);
        v.user_mac = Zeroizing::new(mac);
        v.ciphers.push(make_cipher(
            "00000000-0000-0000-0000-0000000000aa",
            "duplicate",
            &enc,
            &mac,
        ));
        v.ciphers.push(make_cipher(
            "00000000-0000-0000-0000-0000000000bb",
            "DUPLICATE",
            &enc,
            &mac,
        ));

        let mut s = AgentState::new(900);
        s.vault = Some(v);

        match s.resolve_cipher("duplicate") {
            Err(IpcError::AmbiguousItem { name, ids }) => {
                assert_eq!(name, "duplicate");
                assert_eq!(ids.len(), 2);
                assert!(ids.contains(&"00000000-0000-0000-0000-0000000000aa".to_owned()));
                assert!(ids.contains(&"00000000-0000-0000-0000-0000000000bb".to_owned()));
            }
            other => panic!("expected AmbiguousItem, got {other:?}"),
        }
    }

    fn make_cipher(id: &str, plain_name: &str, enc: &[u8; 32], mac: &[u8; 32]) -> Cipher {
        let enc_name = vault_core::EncString::encrypt(enc, mac, plain_name.as_bytes()).serialize();
        Cipher {
            id: id.to_owned(),
            cipher_type: 1,
            name: Some(enc_name),
            ..Cipher::default()
        }
    }

    fn stub_vault() -> Vault {
        let urls = vault_api::BaseUrls::self_hosted("https://vault.example.org").unwrap();
        let client = vault_api::BitwardenClient::new(urls, uuid::Uuid::nil(), "vault-agent-test")
            .expect("client");
        Vault {
            server: "https://vault.example.org".into(),
            email: "alice@example.org".into(),
            user_enc: Zeroizing::new([0u8; 32]),
            user_mac: Zeroizing::new([0u8; 32]),
            ciphers: Vec::new(),
            folders: std::collections::HashMap::new(),
            client,
            last_sync: None,
        }
    }
}

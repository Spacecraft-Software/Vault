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
use vault_core::EncString;
use vault_core::cipher::{Cipher, DecryptOptions, Login, LoginUri, PlainCipher};
use vault_ipc::proto::{Error as IpcError, Field, Item, ListEntry, Removed, Saved, Status};

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
    /// Clipboard handle for `Request::Copy`. `None` when no backend is
    /// available (headless / init failed); copy requests then decline cleanly.
    /// The handle must outlive its writes — on X11 the owning process serves
    /// the selection — so it lives here for the agent's lifetime.
    #[cfg(feature = "clipboard")]
    pub clipboard: Option<arboard::Clipboard>,
}

/// Plaintext field overlay for `add_cipher` / `edit_cipher`. Every field is
/// optional: `add_cipher` requires `name`, while `edit_cipher` treats `None`
/// as "leave the current value unchanged". Secret fields arrive as raw bytes
/// and are wiped once encrypted.
#[derive(Default)]
pub struct CipherWrite {
    /// Display name.
    pub name: Option<String>,
    /// Folder name or id (resolved against the unlocked folder map).
    pub folder: Option<String>,
    /// Free-form notes.
    pub notes: Option<String>,
    /// Login username.
    pub username: Option<String>,
    /// Login password (secret).
    pub password: Option<Vec<u8>>,
    /// TOTP secret / URI (secret).
    pub totp: Option<Vec<u8>>,
    /// Primary login URI.
    pub uri: Option<String>,
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
            #[cfg(feature = "clipboard")]
            clipboard: init_clipboard(),
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

    /// Resolve a folder selector (id or case-insensitive name) to a folder id.
    /// `None` selects the unfiled root. Errors if a non-empty selector matches
    /// no known folder.
    fn resolve_folder(&self, folder: Option<&str>) -> Result<Option<String>, IpcError> {
        let Some(folder) = folder else {
            return Ok(None);
        };
        let v = self.vault.as_ref().ok_or(IpcError::Locked)?;
        if v.folders.contains_key(folder) {
            return Ok(Some(folder.to_owned()));
        }
        let lower = folder.to_lowercase();
        for (id, name) in &v.folders {
            if name.to_lowercase() == lower {
                return Ok(Some(id.clone()));
            }
        }
        Err(IpcError::NoSuchItem(format!("folder '{folder}'")))
    }

    /// Create a new cipher: encrypt the plaintext fields under the user key,
    /// `POST` it, and splice the server-assigned cipher into the in-memory
    /// cache. `cipher_type` is `1` (login) or `2` (secure note).
    pub async fn add_cipher(&mut self, cipher_type: u8, w: CipherWrite) -> Result<Saved, IpcError> {
        let folder_id = self.resolve_folder(w.folder.as_deref())?;
        let v = self.vault.as_mut().ok_or(IpcError::Locked)?;
        let name = w
            .name
            .clone()
            .ok_or_else(|| IpcError::Internal("add requires a name".to_owned()))?;
        // `plain` owns every plaintext value; `PlainCipher::drop` scrubs the
        // secret fields (password/totp/notes) when it falls out of scope.
        let plain = PlainCipher {
            id: String::new(),
            cipher_type,
            folder_id,
            name: w.name,
            notes: w.notes,
            username: w.username,
            password: bytes_to_string(w.password)?,
            totp: bytes_to_string(w.totp)?,
            primary_uri: w.uri,
        };
        let mut cipher = Cipher::from_plain(&plain, &v.user_enc, &v.user_mac);
        let id = v
            .client
            .create_cipher(&cipher)
            .await
            .map_err(|e| IpcError::Network(e.to_string()))?;
        cipher.id.clone_from(&id);
        v.ciphers.push(cipher);
        Ok(Saved { id, name })
    }

    /// Edit an existing cipher: clone the encrypted original, re-encrypt only
    /// the fields the caller changed, `PUT` it, and replace it in the cache.
    ///
    /// Working from the original encrypted `Cipher` (rather than a `PlainCipher`
    /// round-trip) means every field Vault doesn't individually edit —
    /// secondary URIs, custom fields, organization membership — is preserved
    /// verbatim. Only changed fields are re-encrypted under fresh IVs.
    pub async fn edit_cipher(&mut self, selector: &str, w: CipherWrite) -> Result<Saved, IpcError> {
        let idx = self.resolve_cipher(selector)?;
        let folder_id = self.resolve_folder(w.folder.as_deref())?;
        // Decode secrets before borrowing the vault mutably; `Zeroizing` scrubs
        // the plaintext when the locals drop at the end of this call.
        let password = bytes_to_string(w.password)?.map(Zeroizing::new);
        let totp = bytes_to_string(w.totp)?.map(Zeroizing::new);
        let v = self.vault.as_mut().ok_or(IpcError::Locked)?;

        let mut cipher = v.ciphers[idx].clone();
        let overlay = EditOverlay {
            name: w.name.as_deref(),
            folder_id,
            folder_provided: w.folder.is_some(),
            notes: w.notes.as_deref(),
            username: w.username.as_deref(),
            password: password.as_ref().map(|z| z.as_str()),
            totp: totp.as_ref().map(|z| z.as_str()),
            uri: w.uri.as_deref(),
        };
        apply_cipher_edits(&mut cipher, &overlay, &v.user_enc, &v.user_mac);

        let id = cipher.id.clone();
        v.client
            .update_cipher(&id, &cipher)
            .await
            .map_err(|e| IpcError::Network(e.to_string()))?;
        let name = cipher
            .decrypt_name(&v.user_enc, &v.user_mac)
            .map_err(|e| IpcError::Decrypt(e.to_string()))?
            .unwrap_or_default();
        v.ciphers[idx] = cipher;
        Ok(Saved { id, name })
    }

    /// Re-pull `/sync` over the existing authenticated session and replace the
    /// in-memory ciphers, folder map, and `last_sync` stamp. Requires an
    /// unlocked agent.
    ///
    /// Like `unlock`, this refreshes only the in-memory vault — the on-disk
    /// encrypted cache is not (yet) written by the agent. Known limitation: a
    /// `sync` long after `unlock` can fail with a `401` once the access token
    /// expires; there is no refresh-token flow in M4, so that surfaces as
    /// `IpcError::Network` (shared with `add`/`edit`/`remove`).
    pub async fn resync(&mut self) -> Result<(), IpcError> {
        let v = self.vault.as_mut().ok_or(IpcError::Locked)?;
        let sync = v
            .client
            .sync()
            .await
            .map_err(|e| IpcError::Network(e.to_string()))?;
        let (ciphers, folders) =
            crate::unlock::ciphers_and_folders(&sync, &v.user_enc, &v.user_mac);
        v.ciphers = ciphers;
        v.folders = folders;
        v.last_sync = crate::unlock::now_iso();
        Ok(())
    }

    /// Decrypt one `field` on a single cipher.
    ///
    /// When `id` is `Some`, the lookup targets that exact cipher id — the only
    /// reliable path when several items share a name. When `id` is `None`, it
    /// falls back to a case-insensitive match on `query` and returns the first
    /// hit (the long-standing CLI behavior). `query` is also the error label.
    pub fn get_item(&self, id: Option<&str>, query: &str, field: Field) -> Result<Item, IpcError> {
        let v = self.vault.as_ref().ok_or(IpcError::Locked)?;
        let query_lower = query.to_lowercase();
        let mut matched: Option<(&Cipher, String)> = None;
        for c in &v.ciphers {
            let name = c
                .decrypt_name(&v.user_enc, &v.user_mac)
                .map_err(|e| IpcError::Decrypt(e.to_string()))?;
            let hit = id.map_or_else(
                || {
                    name.as_deref()
                        .is_some_and(|n| n.to_lowercase() == query_lower)
                },
                |want| c.id == want,
            );
            if hit {
                // Fall back to the query string for the display name on the
                // rare cipher with no decryptable name.
                matched = Some((c, name.unwrap_or_else(|| query.to_owned())));
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

    /// Place `value` on the system clipboard. Errors if no backend is available
    /// so the caller can report it instead of silently dropping the copy.
    #[cfg(feature = "clipboard")]
    pub fn clipboard_set(&mut self, value: &str) -> Result<(), IpcError> {
        let cb = self
            .clipboard
            .as_mut()
            .ok_or_else(|| IpcError::Internal("clipboard backend unavailable".to_owned()))?;
        cb.set_text(value.to_owned())
            .map_err(|e| IpcError::Internal(format!("clipboard write failed: {e}")))
    }

    /// Clear the clipboard if it still holds `written` (the value we copied), or
    /// if its contents can't be read. Leaves anything the user has since copied
    /// untouched. Invoked by the scheduled auto-clear task; never errors.
    #[cfg(feature = "clipboard")]
    pub fn clipboard_clear_if_ours(&mut self, written: &str) {
        let Some(cb) = self.clipboard.as_mut() else {
            return;
        };
        let current = cb.get_text().ok();
        if should_clear_clipboard(current.as_deref(), written) {
            // Best-effort: a failed clear is no worse than the timer never
            // having run; the next copy will overwrite regardless.
            let _ = cb.clear();
        }
    }
}

/// Build a clipboard handle, degrading to `None` (with a warning) when no
/// backend is reachable — e.g. a headless server with no display. Copy requests
/// then return a clean error rather than the agent failing to start.
#[cfg(feature = "clipboard")]
fn init_clipboard() -> Option<arboard::Clipboard> {
    match arboard::Clipboard::new() {
        Ok(cb) => Some(cb),
        Err(e) => {
            eprintln!("vault-agent: clipboard unavailable, copy will be declined: {e}");
            None
        }
    }
}

/// Whether the auto-clear task should wipe the clipboard.
///
/// `current` is the clipboard's present contents (`None` if it couldn't be
/// read). Clear when it still holds exactly what we wrote, and also when it
/// can't be read — failing safe so a secret is never stranded. When it holds
/// something else, the user (or another app) has replaced it, so leave it be.
#[cfg(feature = "clipboard")]
fn should_clear_clipboard(current: Option<&str>, written: &str) -> bool {
    current.is_none_or(|c| c == written)
}

/// Decode an optional secret byte buffer into a `String`, zeroising the bytes
/// if they turn out not to be valid UTF-8 (the only failure path).
fn bytes_to_string(bytes: Option<Vec<u8>>) -> Result<Option<String>, IpcError> {
    bytes.map_or(Ok(None), |b| match String::from_utf8(b) {
        Ok(s) => Ok(Some(s)),
        Err(e) => {
            // Scrub the rejected bytes on the way out (they may be a secret).
            drop(Zeroizing::new(e.into_bytes()));
            Err(IpcError::Internal("secret was not valid UTF-8".to_owned()))
        }
    })
}

/// Borrowed plaintext overlay for [`apply_cipher_edits`]. A `None` field is
/// left unchanged; a `Some` field is re-encrypted onto the cipher.
struct EditOverlay<'a> {
    name: Option<&'a str>,
    folder_id: Option<String>,
    /// Whether the caller asked to change the folder at all (so clearing to the
    /// unfiled root, `folder_id == None`, is distinguishable from "unchanged").
    folder_provided: bool,
    notes: Option<&'a str>,
    username: Option<&'a str>,
    password: Option<&'a str>,
    totp: Option<&'a str>,
    uri: Option<&'a str>,
}

/// Apply `o` to an already-encrypted `cipher` in place, re-encrypting only the
/// changed fields under fresh IVs. Everything not named in the overlay —
/// secondary URIs, custom `fields`, `organization_id` — is preserved verbatim.
fn apply_cipher_edits(
    cipher: &mut Cipher,
    o: &EditOverlay,
    enc_key: &[u8; 32],
    mac_key: &[u8; 32],
) {
    let enc = |s: &str| EncString::encrypt(enc_key, mac_key, s.as_bytes()).serialize();
    if let Some(name) = o.name {
        cipher.name = Some(enc(name));
    }
    if o.folder_provided {
        cipher.folder_id.clone_from(&o.folder_id);
    }
    if let Some(notes) = o.notes {
        cipher.notes = Some(enc(notes));
    }
    // Touch the login object only when a login field actually changes.
    if o.username.is_some() || o.password.is_some() || o.totp.is_some() || o.uri.is_some() {
        let login = cipher.login.get_or_insert_with(Login::default);
        if let Some(u) = o.username {
            login.username = Some(enc(u));
        }
        if let Some(p) = o.password {
            login.password = Some(enc(p));
        }
        if let Some(t) = o.totp {
            login.totp = Some(enc(t));
        }
        if let Some(uri) = o.uri {
            // Replace the primary (first) URI, keeping any secondary URIs.
            let mut uris = login.uris.take().unwrap_or_default();
            let encoded = enc(uri);
            if let Some(first) = uris.first_mut() {
                first.uri = Some(encoded);
            } else {
                uris.push(LoginUri { uri: Some(encoded) });
            }
            login.uris = Some(uris);
        }
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
            s.get_item(None, "anything", Field::Password),
            Err(IpcError::Locked)
        ));
    }

    #[test]
    fn get_item_targets_exact_id_among_duplicate_names() {
        let enc = [11u8; 32];
        let mac = [12u8; 32];
        let mut v = stub_vault();
        v.user_enc = Zeroizing::new(enc);
        v.user_mac = Zeroizing::new(mac);
        v.ciphers.push(login_with_password(
            "id-first",
            "dup",
            "first-secret",
            &enc,
            &mac,
        ));
        v.ciphers.push(login_with_password(
            "id-second",
            "dup",
            "second-secret",
            &enc,
            &mac,
        ));
        let mut s = AgentState::new(900);
        s.vault = Some(v);

        // Id-targeting reaches the exact cipher, not the first by name.
        let item = s
            .get_item(Some("id-second"), "dup", Field::Password)
            .unwrap();
        assert_eq!(item.id, "id-second");
        assert_eq!(item.value, "second-secret");

        // Name-only fallback returns the first match (documents the footgun the
        // id path exists to avoid).
        let item = s.get_item(None, "dup", Field::Password).unwrap();
        assert_eq!(item.id, "id-first");
        assert_eq!(item.value, "first-secret");
    }

    #[cfg(feature = "clipboard")]
    #[test]
    fn should_clear_only_when_ours_or_unreadable() {
        // Still holds our value → clear.
        assert!(should_clear_clipboard(Some("secret"), "secret"));
        // Holds something the user copied since → leave it.
        assert!(!should_clear_clipboard(Some("other"), "secret"));
        // Unreadable → fail safe and clear.
        assert!(should_clear_clipboard(None, "secret"));
    }

    #[cfg(feature = "clipboard")]
    #[test]
    fn clipboard_set_errors_when_no_backend() {
        // Headless / failed init: copy must decline cleanly, not panic.
        let mut s = AgentState::new(900);
        s.clipboard = None;
        assert!(matches!(
            s.clipboard_set("secret"),
            Err(IpcError::Internal(_))
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

    #[test]
    fn resolve_folder_matches_id_then_name_else_errors() {
        let mut v = stub_vault();
        v.folders.insert("fid-1".to_owned(), "Work".to_owned());
        v.folders.insert("fid-2".to_owned(), "Personal".to_owned());
        let mut s = AgentState::new(900);
        s.vault = Some(v);

        // No selector → unfiled root.
        assert_eq!(s.resolve_folder(None).unwrap(), None);
        // Exact id wins.
        assert_eq!(
            s.resolve_folder(Some("fid-2")).unwrap().as_deref(),
            Some("fid-2")
        );
        // Case-insensitive name resolves to the id.
        assert_eq!(
            s.resolve_folder(Some("work")).unwrap().as_deref(),
            Some("fid-1")
        );
        // Unknown folder is an error, not a silent unfile.
        assert!(matches!(
            s.resolve_folder(Some("nope")),
            Err(IpcError::NoSuchItem(_))
        ));
    }

    #[test]
    fn edit_preserves_secondary_uris_on_unrelated_change() {
        let enc = [5u8; 32];
        let mac = [6u8; 32];
        let mut cipher = login_with_two_uris(&enc, &mac);

        // Change only the name; the URI list must be untouched.
        let overlay = EditOverlay {
            name: Some("new name"),
            folder_id: None,
            folder_provided: false,
            notes: None,
            username: None,
            password: None,
            totp: None,
            uri: None,
        };
        apply_cipher_edits(&mut cipher, &overlay, &enc, &mac);

        let uris = cipher.login.as_ref().unwrap().uris.as_ref().unwrap();
        assert_eq!(uris.len(), 2, "secondary URI dropped by a name-only edit");
        assert_eq!(
            cipher.decrypt_name(&enc, &mac).unwrap().as_deref(),
            Some("new name")
        );
        assert_eq!(decrypt_uri(&uris[1], &enc, &mac), "https://two.example");
    }

    #[test]
    fn edit_uri_replaces_primary_keeps_secondary() {
        let enc = [7u8; 32];
        let mac = [8u8; 32];
        let mut cipher = login_with_two_uris(&enc, &mac);

        let overlay = EditOverlay {
            name: None,
            folder_id: None,
            folder_provided: false,
            notes: None,
            username: None,
            password: None,
            totp: None,
            uri: Some("https://new.example"),
        };
        apply_cipher_edits(&mut cipher, &overlay, &enc, &mac);

        let uris = cipher.login.as_ref().unwrap().uris.as_ref().unwrap();
        assert_eq!(uris.len(), 2);
        assert_eq!(decrypt_uri(&uris[0], &enc, &mac), "https://new.example");
        assert_eq!(decrypt_uri(&uris[1], &enc, &mac), "https://two.example");
    }

    fn login_with_two_uris(enc: &[u8; 32], mac: &[u8; 32]) -> Cipher {
        let uri = |s: &str| LoginUri {
            uri: Some(vault_core::EncString::encrypt(enc, mac, s.as_bytes()).serialize()),
        };
        Cipher {
            id: "id-1".to_owned(),
            cipher_type: 1,
            name: Some(vault_core::EncString::encrypt(enc, mac, b"old name").serialize()),
            login: Some(Login {
                uris: Some(vec![uri("https://one.example"), uri("https://two.example")]),
                ..Login::default()
            }),
            ..Cipher::default()
        }
    }

    fn decrypt_uri(u: &LoginUri, enc: &[u8; 32], mac: &[u8; 32]) -> String {
        let parsed = vault_core::EncString::parse(u.uri.as_deref().unwrap()).unwrap();
        String::from_utf8(parsed.decrypt(enc, mac).unwrap()).unwrap()
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

    fn login_with_password(
        id: &str,
        plain_name: &str,
        password: &str,
        enc: &[u8; 32],
        mac: &[u8; 32],
    ) -> Cipher {
        let e = |s: &str| vault_core::EncString::encrypt(enc, mac, s.as_bytes()).serialize();
        Cipher {
            id: id.to_owned(),
            cipher_type: 1,
            name: Some(e(plain_name)),
            login: Some(Login {
                password: Some(e(password)),
                ..Login::default()
            }),
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

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
use vault_core::cipher::{
    Card, Cipher, DecryptOptions, Identity, Login, LoginUri, PlainCard, PlainCipher, PlainIdentity,
};
use vault_ipc::proto::{Error as IpcError, Field, Item, ListEntry, Removed, Saved, Status};

use crate::sealed::SealedKey;

/// In-memory keys + ciphers held while the agent is unlocked.
pub struct Vault {
    /// Server origin the unlocked session is bound to.
    pub server: String,
    /// Account email the agent is unlocked for (lower-cased).
    pub email: String,
    /// User symmetric encryption key (mlocked + zeroized; see [`SealedKey`]).
    pub user_enc: SealedKey,
    /// User symmetric MAC key (mlocked + zeroized; see [`SealedKey`]).
    pub user_mac: SealedKey,
    /// Most recent `/sync` ciphers, encrypted at rest in memory until
    /// `decrypt_*` opens a specific field.
    pub ciphers: Vec<Cipher>,
    /// Folder id → decrypted folder name.
    pub folders: std::collections::HashMap<String, String>,
    /// Organization id → that org's symmetric `(enc, mac)` key, unwrapped from
    /// `profile.organizations[]` via the account RSA key at unlock. Organization
    /// ciphers (`organization_id` set) decrypt under their org key, not the user
    /// key; an org absent here (key couldn't be unwrapped) leaves its ciphers
    /// undecryptable and they are skipped, as before.
    pub org_keys: std::collections::HashMap<String, ([u8; 32], [u8; 32])>,
    /// Authenticated REST client for `Sync`/`Remove`/`Edit`/`Add`, holding the
    /// access token. `Some` for an online unlock; `None` for a session unlocked
    /// from the local cache (offline) — server ops then return `Error::Offline`.
    pub client: Option<BitwardenClient>,
    /// The account's protected user key (login token `Key`) and KDF params,
    /// carried so a refresh (`resync`) can re-persist the cache without
    /// re-reading the file, and so offline unlock can round-trip them.
    pub protected_user_key: String,
    /// Account KDF parameters (for offline master-key derivation / re-persist).
    pub kdf: vault_core::kdf::KdfParams,
    /// `OAuth2` refresh token (decrypted, in memory) when one is available — from
    /// the login token on an online unlock, or decrypted from the cache on an
    /// offline/PIN unlock. Lets a token-less session go online via
    /// [`Vault::ensure_online`] and is persisted (encrypted) by `persist_cache`.
    pub refresh_token: Option<Zeroizing<String>>,
    /// Stable device id this session unlocked with (persisted to the cache).
    pub device_id: String,
    /// Most recent sync time (ISO 8601 UTC), or `None` if never synced.
    pub last_sync: Option<String>,
}

impl Vault {
    /// The `(enc, mac)` key a given cipher's fields are encrypted under: its
    /// organization's key when the cipher is org-owned and we hold that key,
    /// otherwise the user key. The returned pair is what's handed to
    /// [`Cipher::decrypt`] / [`Cipher::decrypt_name`] — which then resolve any
    /// per-cipher key on top of it.
    fn base_keys(&self, cipher: &Cipher) -> (&[u8; 32], &[u8; 32]) {
        if let Some(oid) = cipher.organization_id.as_deref()
            && let Some((enc, mac)) = self.org_keys.get(oid)
        {
            return (enc, mac);
        }
        (&self.user_enc, &self.user_mac)
    }

    /// Encrypt the `/sync` response under the user key and write the account's
    /// cache (payload + protected user key + KDF + device id) to disk
    /// atomically, so a later `unlock` can reconstruct this vault offline.
    ///
    /// # Errors
    ///
    /// Returns [`IpcError::Internal`] if the data dir can't be located, the
    /// `/sync` body can't be re-serialized, or the encrypted write fails.
    pub fn persist_cache(&self, sync: &vault_api::SyncResponse) -> Result<(), IpcError> {
        let dir = vault_store::default_data_dir()
            .ok_or_else(|| IpcError::Internal("no data directory".to_owned()))?
            .join(account_dir_name(&self.server, &self.email));
        let sync_bytes = serde_json::to_vec(sync)
            .map_err(|e| IpcError::Internal(format!("serialize sync: {e}")))?;
        let mut cache =
            vault_store::VaultCache::new(self.device_id.clone(), self.server.clone(), &self.email);
        cache
            .set_payload(&self.user_enc, &self.user_mac, &sync_bytes)
            .map_err(|e| IpcError::Internal(format!("encrypt cache: {e}")))?;
        cache.protected_user_key = Some(self.protected_user_key.clone());
        cache.kdf = Some(self.kdf);
        // Persist the refresh token encrypted under the user key, so a later
        // cache/PIN unlock can recover it and go online without the password.
        if let Some(rt) = self.refresh_token.as_ref() {
            cache.refresh_token =
                Some(EncString::encrypt(&self.user_enc, &self.user_mac, rt.as_bytes()).serialize());
        }
        vault_store::save_to_dir(&dir, &cache)
            .map_err(|e| IpcError::Internal(format!("write cache: {e}")))?;
        Ok(())
    }

    /// Ensure the vault has a live, authenticated client — establishing one
    /// from the held refresh token if the session was unlocked from cache
    /// (offline / PIN). Returns `Error::Offline` when there's no token and no
    /// way to get one (truly offline, or no refresh token persisted).
    ///
    /// # Errors
    ///
    /// [`IpcError::Offline`] if no client can be established;
    /// [`IpcError::Internal`] on a malformed server URL.
    pub async fn ensure_online(&mut self) -> Result<(), IpcError> {
        if self.client.is_some() {
            return Ok(());
        }
        let urls = vault_api::BaseUrls::infer_from(&self.server)
            .map_err(|e| IpcError::Internal(e.to_string()))?;
        let device =
            uuid::Uuid::parse_str(&self.device_id).unwrap_or_else(|_| uuid::Uuid::new_v4());

        // 1. Prefer the stored refresh token — cheapest, no creds re-sent.
        if let Some(refresh) = self.refresh_token.as_ref()
            && let Ok(mut client) = vault_api::BitwardenClient::with_refresh_token(
                urls.clone(),
                device,
                "vault-agent",
                rt_string(refresh),
            )
            && client.refresh().await.is_ok()
        {
            // Keep the (possibly rotated) refresh token in memory for re-persist.
            if let Some(rt) = client.refresh_token() {
                self.refresh_token = Some(Zeroizing::new(rt.to_owned()));
            }
            self.client = Some(client);
            return Ok(());
        }

        // 2. Fall back to a stored API key: the client_credentials grant
        //    re-authenticates without 2FA or a refresh token, and needs only a
        //    live client (the user key is already in memory). This is what lets
        //    a PIN/offline session of an API-key account go online for writes.
        if let Some(dir) = vault_store::default_data_dir()
            .map(|d| d.join(account_dir_name(&self.server, &self.email)))
            && let Ok(creds) = vault_store::load_apikey_from_dir(&dir)
        {
            let mut client = vault_api::BitwardenClient::new(urls, device, "vault-agent")
                .map_err(|e| IpcError::Internal(e.to_string()))?;
            if client
                .login_api_key(&creds.client_id, creds.client_secret.as_bytes())
                .await
                .is_ok()
            {
                if let Some(rt) = client.refresh_token() {
                    self.refresh_token = Some(Zeroizing::new(rt.to_owned()));
                }
                self.client = Some(client);
                return Ok(());
            }
        }

        Err(IpcError::Offline)
    }
}

/// Clone a `Zeroizing<String>` refresh token into a plain `String` for the API
/// call (the client re-wraps it in `Zeroizing`).
fn rt_string(rt: &Zeroizing<String>) -> String {
    rt.as_str().to_owned()
}

/// Wrong-PIN attempts allowed before the PIN is wiped and a master-password
/// unlock is required (mirrors the Bitwarden default).
pub const MAX_PIN_ATTEMPTS: u32 = 5;

/// Minimum seconds between keyring-deadline re-arms on activity, so a busy
/// session doesn't issue a `set_timeout` syscall on every request.
const SESSION_REFRESH_THROTTLE_SECS: u64 = 30;

/// Seconds since the Unix epoch (0 if the clock is before the epoch).
fn now_unix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Filesystem-safe per-account cache subdirectory, keyed by host + email so
/// distinct accounts (and the same email on different servers) never collide.
/// Any character outside `[A-Za-z0-9._-]` becomes `_`.
#[must_use]
pub fn account_dir_name(server: &str, email: &str) -> String {
    let host = server
        .strip_prefix("https://")
        .or_else(|| server.strip_prefix("http://"))
        .unwrap_or(server)
        .trim_end_matches('/');
    let raw = format!("{host}_{}", email.to_lowercase());
    raw.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Top-level agent state.
pub struct AgentState {
    /// `None` when locked; `Some` when unlocked.
    pub vault: Option<Vault>,
    /// Last activity timestamp, for the idle-lock policy.
    pub last_activity: Instant,
    /// Idle timeout in seconds; after this with no activity the agent locks.
    pub idle_lock_secs: u64,
    /// When set, the user key is mirrored into the Linux kernel session keyring
    /// on unlock so a restarted agent can resume without the master password
    /// (opt-in; PRD §7.3 carve-out). Off by default; no-op on non-Linux.
    pub session_keyring: bool,
    /// Gate the keyring session behind a fingerprint (Linux). When set: idle-lock
    /// zeroises the in-memory key but **keeps** the keyring entry, the agent does
    /// not silently auto-resume, and the keyring entry's lifetime is governed by
    /// [`fingerprint_ttl_secs`](Self::fingerprint_ttl_secs) rather than the idle
    /// timeout. Requires `session_keyring` + the `fingerprint` feature.
    pub fingerprint_unlock: bool,
    /// Keyring-session lifetime under fingerprint unlock (the touch window after
    /// the last unlock); `0` = no kernel timeout (until logout / manual lock).
    pub fingerprint_ttl_secs: u64,
    /// Seconds between agent-side background `/sync`es while unlocked; `0`
    /// disables. Drives [`server::scheduled_sync_loop`](crate::server::scheduled_sync_loop).
    pub sync_interval_secs: u64,
    /// Throttle for refreshing the keyring entry's deadline on activity — we
    /// only re-arm the timeout periodically, not on every request.
    last_session_refresh: Option<Instant>,
    /// Set by `Request::Quit` to ask the accept loop to exit cleanly.
    pub shutdown_requested: bool,
    /// Clipboard backend for `Request::Copy`. `None` when no backend is
    /// available (headless / init failed); copy requests then decline cleanly.
    /// The handle must outlive its writes — on X11 the owning process serves
    /// the selection — so it lives here for the agent's lifetime.
    #[cfg(feature = "clipboard")]
    pub clipboard: Option<Box<dyn crate::clipboard::Backend>>,
    /// The configured backend mode (`clipboard.backend`). Drives `select` and
    /// lets `Status` report `osc52` even when no native backend is held.
    #[cfg(feature = "clipboard")]
    pub clipboard_backend: crate::clipboard::BackendChoice,
    /// The last value we placed on the clipboard, kept so `lock()` (and thus
    /// `Quit`, idle-lock, and SIGTERM) can sweep a still-pending copy before
    /// the timer task would have fired. Zeroised on drop.
    #[cfg(feature = "clipboard")]
    last_copied: Option<Zeroizing<String>>,
    /// Seconds before an auto-clear fires when the client doesn't specify
    /// (`--clipboard-clear-secs` / `$VAULT_CLIPBOARD_CLEAR_SECS`); `0`
    /// disables the default auto-clear.
    #[cfg(feature = "clipboard")]
    pub clipboard_clear_secs: u64,
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
    /// Card fields (card ciphers only); `number`/`code` are secret bytes.
    pub card: Option<vault_ipc::proto::CardWrite>,
    /// Identity fields (identity ciphers only); ssn/passport/license are secret
    /// bytes.
    pub identity: Option<vault_ipc::proto::IdentityWrite>,
}

impl AgentState {
    /// Fresh agent — locked, just-touched.
    #[must_use]
    pub fn new(idle_lock_secs: u64) -> Self {
        Self {
            vault: None,
            last_activity: Instant::now(),
            idle_lock_secs,
            session_keyring: false,
            fingerprint_unlock: false,
            fingerprint_ttl_secs: 0,
            sync_interval_secs: 0,
            last_session_refresh: None,
            shutdown_requested: false,
            #[cfg(feature = "clipboard")]
            clipboard: crate::clipboard::detect(),
            #[cfg(feature = "clipboard")]
            clipboard_backend: crate::clipboard::BackendChoice::Auto,
            #[cfg(feature = "clipboard")]
            last_copied: None,
            // 30 s follows common password-manager practice (and Vault PRD
            // §7.2): long enough to paste, short enough to bound exposure.
            #[cfg(feature = "clipboard")]
            clipboard_clear_secs: 30,
        }
    }

    /// Whether the agent currently holds the user key.
    #[must_use]
    pub const fn is_unlocked(&self) -> bool {
        self.vault.is_some()
    }

    /// Mark a request as just-handled (resets the idle-lock countdown). When
    /// session-keyring resume is enabled, this also re-arms the keyring entry's
    /// deadline — throttled so it's not a syscall on every request.
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
        if self.session_keyring
            && self.is_unlocked()
            && self
                .last_session_refresh
                .is_none_or(|t| t.elapsed().as_secs() >= SESSION_REFRESH_THROTTLE_SECS)
        {
            self.persist_session();
        }
    }

    /// Mirror the current session into the kernel keyring (when enabled and
    /// unlocked), bounded by the idle-lock TTL so a dead agent's session
    /// self-expires. Best effort — a keyring failure never affects the session.
    pub fn persist_session(&mut self) {
        if !self.session_keyring {
            return;
        }
        let Some(v) = self.vault.as_ref() else {
            return;
        };
        // Under fingerprint unlock the keyring entry must outlive the (short)
        // in-memory idle-lock so a touch can re-unlock, so its lifetime is the
        // fingerprint TTL; otherwise it's the idle-lock TTL. `0` for either =>
        // no deadline / no kernel timeout (idle-lock disabled, or "until logout").
        let ttl = if self.fingerprint_unlock {
            self.fingerprint_ttl_secs
        } else {
            self.idle_lock_secs
        };
        let deadline_unix = if ttl == 0 {
            0
        } else {
            now_unix().saturating_add(ttl)
        };
        let blob = crate::session::SessionBlob {
            server: v.server.clone(),
            email: v.email.clone(),
            user_enc: *v.user_enc,
            user_mac: *v.user_mac,
            deadline_unix,
        };
        crate::session::store(&blob, ttl);
        self.last_session_refresh = Some(Instant::now());
    }

    /// Resume an unlocked vault from the kernel keyring after a **verified
    /// fingerprint** (the biometric check happens in the dispatch, before this).
    /// Requires fingerprint unlock enabled and a live keyring session.
    ///
    /// # Errors
    ///
    /// [`IpcError::FingerprintUnavailable`] when fingerprint unlock is off or no
    /// resumable session remains (expired / cleared / `session_keyring` off);
    /// otherwise the typed failure from rebuilding the vault.
    pub fn resume_after_fingerprint(&mut self) -> Result<(), IpcError> {
        if !self.fingerprint_unlock {
            return Err(IpcError::FingerprintUnavailable(
                "fingerprint unlock is not enabled".to_owned(),
            ));
        }
        match crate::unlock::resume_from_keyring()? {
            Some(vault) => {
                self.vault = Some(vault);
                Ok(())
            }
            None => Err(IpcError::FingerprintUnavailable(
                "no resumable session — unlock with your master password".to_owned(),
            )),
        }
    }

    /// Whether the idle-lock policy says it's time to drop keys.
    #[must_use]
    pub fn idle_lock_due(&self) -> bool {
        self.is_unlocked() && self.last_activity.elapsed().as_secs() >= self.idle_lock_secs
    }

    /// Zero out the vault keys and access token — and sweep any still-pending
    /// clipboard copy, so a secret can't outlive the session that copied it.
    /// Used by the **process-exit** paths (`Quit` / SIGTERM): it leaves any
    /// kernel-keyring session intact so a restart can resume within the TTL.
    /// The explicit-lock paths use [`lock_and_clear_session`](Self::lock_and_clear_session).
    pub fn lock(&mut self) {
        self.vault = None;
        self.last_session_refresh = None;
        #[cfg(feature = "clipboard")]
        self.clipboard_sweep();
    }

    /// Lock **and** forget any persisted keyring session — the explicit
    /// security paths (`vault lock`, idle-lock). After this, a restart requires
    /// a full unlock. The clear is unconditional (and a cheap no-op when no
    /// entry exists), so a leftover from a previously-enabled run is swept too.
    pub fn lock_and_clear_session(&mut self) {
        crate::session::clear();
        self.lock();
    }

    /// Enroll a PIN: encrypt the unwrapped user key under a key derived from
    /// `pin` (account KDF, email salt) and store it in the cache, resetting the
    /// attempt counter. Requires an unlocked agent and an existing cache (which
    /// an online unlock always wrote).
    ///
    /// # Errors
    ///
    /// [`IpcError::Locked`] if the agent isn't unlocked, [`IpcError::Internal`]
    /// if no cache exists yet or the write fails.
    pub fn pin_enroll(&self, pin: &[u8]) -> Result<(), IpcError> {
        let v = self.vault.as_ref().ok_or(IpcError::Locked)?;
        let pin_protected =
            crate::unlock::pin_protect_user_key(&v.email, v.kdf, &v.user_enc, &v.user_mac, pin)?;
        let mut cache = crate::unlock::load_cache(&v.server, &v.email).ok_or_else(|| {
            IpcError::Internal("no cached vault — unlock online before setting a PIN".to_owned())
        })?;
        cache.pin_protected_user_key = Some(pin_protected);
        cache.pin_failures = 0;
        let dir = crate::unlock::cache_dir(&v.server, &v.email)
            .ok_or_else(|| IpcError::Internal("no data directory".to_owned()))?;
        vault_store::save_to_dir(&dir, &cache)
            .map_err(|e| IpcError::Internal(format!("write cache: {e}")))?;
        Ok(())
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
            #[cfg(feature = "clipboard")]
            clipboard_backend: self.clipboard_backend_name(),
            #[cfg(not(feature = "clipboard"))]
            clipboard_backend: None,
        }
    }

    /// Decrypt every cipher's name (and optionally username) for `vault list`.
    pub fn list_entries(&self) -> Result<Vec<ListEntry>, IpcError> {
        let v = self.vault.as_ref().ok_or(IpcError::Locked)?;
        let mut out = Vec::with_capacity(v.ciphers.len());
        let mut skipped = 0usize;
        for c in &v.ciphers {
            // For ListEntry we want name + username (login items). Username
            // is cheap; decrypt it eagerly even though the wire shape allows
            // None — rbw users expect to see it next to the name.
            let opts = if c.cipher_type == 1 {
                DecryptOptions::username_only()
            } else {
                DecryptOptions::default()
            };
            // Organization ciphers decrypt under their org key; personal ones
            // under the user key. An item we still can't decrypt (org key we
            // don't hold) must not sink the whole list — skip it and tally.
            let (base_enc, base_mac) = v.base_keys(c);
            let Ok(plain) = c.decrypt(base_enc, base_mac, opts) else {
                skipped += 1;
                continue;
            };
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
        if skipped > 0 {
            eprintln!(
                "vault-agent: list: skipped {skipped} undecryptable cipher(s) (likely organization items)"
            );
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
            // Skip items we can't decrypt rather than failing the whole lookup.
            let (base_enc, base_mac) = v.base_keys(c);
            let Ok(name) = c.decrypt_name(base_enc, base_mac) else {
                continue;
            };
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
        let (base_enc, base_mac) = v.base_keys(&v.ciphers[idx]);
        let name = v.ciphers[idx]
            .decrypt_name(base_enc, base_mac)
            .map_err(|e| IpcError::Decrypt(e.to_string()))?
            .unwrap_or_else(|| "<unnamed>".to_owned());
        v.ensure_online().await?;
        v.client
            .as_mut()
            .ok_or(IpcError::Offline)?
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
        // Decode the card/identity sub-objects before the struct literal moves
        // the other `w` fields. Their `Drop`s scrub the secret members.
        let card = if cipher_type == 3 {
            w.card.map(card_write_to_plain).transpose()?
        } else {
            None
        };
        let identity = if cipher_type == 4 {
            w.identity.map(identity_write_to_plain).transpose()?
        } else {
            None
        };
        // `plain` owns every plaintext value; `PlainCipher::drop` scrubs the
        // secret fields (password/totp/notes/card/identity) when it falls out of
        // scope.
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
            card,
            identity,
        };
        let mut cipher = Cipher::from_plain(&plain, &v.user_enc, &v.user_mac);
        v.ensure_online().await?;
        let id = v
            .client
            .as_mut()
            .ok_or(IpcError::Offline)?
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
        // Card edit: decode its secret bytes; non-secret fields stay owned for
        // borrowing into the overlay.
        let card_present = w.card.is_some();
        let (card_cardholder, card_brand, card_exp_month, card_exp_year, card_number, card_code) =
            match w.card {
                Some(cw) => (
                    cw.cardholder,
                    cw.brand,
                    cw.exp_month,
                    cw.exp_year,
                    bytes_to_string(cw.number)?.map(Zeroizing::new),
                    bytes_to_string(cw.code)?.map(Zeroizing::new),
                ),
                None => (None, None, None, None, None, None),
            };
        // Identity edit: decode into an owned `PlainIdentity` (its `Drop` scrubs
        // ssn/passport/license); the overlay borrows `&str` out of it.
        let identity_present = w.identity.is_some();
        let identity_plain = w.identity.map(identity_write_to_plain).transpose()?;
        let v = self.vault.as_mut().ok_or(IpcError::Locked)?;

        let mut cipher = v.ciphers[idx].clone();
        // Organization items are encrypted under the org key (and a per-cipher
        // key wrapped under it); the edit path re-encrypts changed fields under
        // the *user* key, which would corrupt them. Refuse until org-aware write
        // support exists — reads/copy of org items already work.
        if cipher.organization_id.is_some() {
            return Err(IpcError::Internal(
                "editing organization items is not supported yet".to_owned(),
            ));
        }
        if card_present && cipher.cipher_type != 3 {
            return Err(IpcError::Internal(
                "card fields can only be edited on a card item".to_owned(),
            ));
        }
        if identity_present && cipher.cipher_type != 4 {
            return Err(IpcError::Internal(
                "identity fields can only be edited on an identity item".to_owned(),
            ));
        }
        let card = card_present.then(|| CardEdit {
            cardholder: card_cardholder.as_deref(),
            brand: card_brand.as_deref(),
            number: card_number.as_ref().map(|z| z.as_str()),
            exp_month: card_exp_month.as_deref(),
            exp_year: card_exp_year.as_deref(),
            code: card_code.as_ref().map(|z| z.as_str()),
        });
        let identity = identity_plain.as_ref().map(|p| IdentityEdit {
            title: p.title.as_deref(),
            first_name: p.first_name.as_deref(),
            middle_name: p.middle_name.as_deref(),
            last_name: p.last_name.as_deref(),
            username: p.username.as_deref(),
            company: p.company.as_deref(),
            ssn: p.ssn.as_deref(),
            passport_number: p.passport_number.as_deref(),
            license_number: p.license_number.as_deref(),
            email: p.email.as_deref(),
            phone: p.phone.as_deref(),
            address1: p.address1.as_deref(),
            address2: p.address2.as_deref(),
            address3: p.address3.as_deref(),
            city: p.city.as_deref(),
            state: p.state.as_deref(),
            postal_code: p.postal_code.as_deref(),
            country: p.country.as_deref(),
        });
        let overlay = EditOverlay {
            name: w.name.as_deref(),
            folder_id,
            folder_provided: w.folder.is_some(),
            notes: w.notes.as_deref(),
            username: w.username.as_deref(),
            password: password.as_ref().map(|z| z.as_str()),
            totp: totp.as_ref().map(|z| z.as_str()),
            uri: w.uri.as_deref(),
            card,
            identity,
        };
        apply_cipher_edits(&mut cipher, &overlay, &v.user_enc, &v.user_mac);

        let id = cipher.id.clone();
        v.ensure_online().await?;
        v.client
            .as_mut()
            .ok_or(IpcError::Offline)?
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

    /// Re-pull `/sync` over the existing authenticated session, replace the
    /// in-memory ciphers / folder map / `last_sync`, and re-persist the
    /// encrypted cache so an offline unlock sees the refreshed vault. Requires
    /// an online session (`Error::Offline` when unlocked from cache).
    ///
    /// Known limitation: a `sync` long after `unlock` can fail with a `401`
    /// once the access token expires; there is no refresh-token flow yet, so
    /// that surfaces as `IpcError::Network`.
    pub async fn resync(&mut self) -> Result<(), IpcError> {
        let v = self.vault.as_mut().ok_or(IpcError::Locked)?;
        v.ensure_online().await?;
        let sync = v
            .client
            .as_mut()
            .ok_or(IpcError::Offline)?
            .sync()
            .await
            .map_err(|e| IpcError::Network(e.to_string()))?;
        let (ciphers, folders) =
            crate::unlock::ciphers_and_folders(&sync, &v.user_enc, &v.user_mac);
        v.org_keys = crate::unlock::build_org_keys(&sync, &v.user_enc, &v.user_mac);
        v.ciphers = ciphers;
        v.folders = folders;
        v.last_sync = crate::unlock::now_iso();
        // Refresh the on-disk cache; a write failure shouldn't fail the sync
        // (the in-memory vault is already updated), so it's best-effort.
        if let Err(e) = v.persist_cache(&sync) {
            eprintln!("vault-agent: cache persist after sync failed: {e}");
        }
        Ok(())
    }

    /// Decrypt one `field` on a single cipher.
    ///
    /// When `id` is `Some`, the lookup targets that exact cipher id — the only
    /// reliable path when several items share a name. When `id` is `None`, it
    /// falls back to a case-insensitive match on `query` and returns the first
    /// hit (the long-standing CLI behavior). `query` is also the error label.
    #[allow(clippy::too_many_lines)] // flat per-field dispatch (one arm per Field) reads best in one match
    pub fn get_item(&self, id: Option<&str>, query: &str, field: Field) -> Result<Item, IpcError> {
        let v = self.vault.as_ref().ok_or(IpcError::Locked)?;
        let query_lower = query.to_lowercase();
        let mut matched: Option<(&Cipher, String)> = None;
        for c in &v.ciphers {
            // Decrypt under the cipher's base key (org or user). Skip items we
            // still can't open (org key we don't hold) — they can't be the
            // target, and one must not abort the whole search.
            let (base_enc, base_mac) = v.base_keys(c);
            let Ok(name) = c.decrypt_name(base_enc, base_mac) else {
                continue;
            };
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
            Field::CardCardholder
            | Field::CardNumber
            | Field::CardBrand
            | Field::CardExpiry
            | Field::CardCode => DecryptOptions {
                card: true,
                ..DecryptOptions::default()
            },
            Field::IdentityName
            | Field::IdentityEmail
            | Field::IdentityPhone
            | Field::IdentityAddress
            | Field::IdentityTitle
            | Field::IdentityFirstName
            | Field::IdentityMiddleName
            | Field::IdentityLastName
            | Field::IdentityUsername
            | Field::IdentityCompany
            | Field::IdentitySsn
            | Field::IdentityPassport
            | Field::IdentityLicense
            | Field::IdentityAddress1
            | Field::IdentityAddress2
            | Field::IdentityAddress3
            | Field::IdentityCity
            | Field::IdentityState
            | Field::IdentityPostal
            | Field::IdentityCountry => DecryptOptions {
                identity: true,
                ..DecryptOptions::default()
            },
        };
        let (base_enc, base_mac) = v.base_keys(cipher);
        let plain = cipher
            .decrypt(base_enc, base_mac, opts)
            .map_err(|e| IpcError::Decrypt(e.to_string()))?;
        let value = match field {
            Field::Password => plain.password.clone(),
            Field::Username => plain.username.clone(),
            // Generate the live RFC 6238 code from the stored secret; the raw
            // secret stays in the agent (only the code crosses the socket).
            Field::Totp => match plain.totp.as_deref() {
                Some(secret) => Some(
                    vault_core::totp::now(secret)
                        .map_err(|e| IpcError::Internal(format!("totp: {e}")))?,
                ),
                None => None,
            },
            Field::Notes => plain.notes.clone(),
            Field::Uri => plain.primary_uri.clone(),
            Field::CardCardholder => plain.card.as_ref().and_then(|c| c.cardholder_name.clone()),
            Field::CardNumber => plain.card.as_ref().and_then(|c| c.number.clone()),
            Field::CardBrand => plain.card.as_ref().and_then(|c| c.brand.clone()),
            Field::CardCode => plain.card.as_ref().and_then(|c| c.code.clone()),
            Field::CardExpiry => plain.card.as_ref().and_then(card_expiry),
            Field::IdentityName => plain.identity.as_ref().and_then(identity_name),
            Field::IdentityEmail => plain.identity.as_ref().and_then(|i| i.email.clone()),
            Field::IdentityPhone => plain.identity.as_ref().and_then(|i| i.phone.clone()),
            Field::IdentityAddress => plain.identity.as_ref().and_then(identity_address),
            Field::IdentityTitle => plain.identity.as_ref().and_then(|i| i.title.clone()),
            Field::IdentityFirstName => plain.identity.as_ref().and_then(|i| i.first_name.clone()),
            Field::IdentityMiddleName => {
                plain.identity.as_ref().and_then(|i| i.middle_name.clone())
            }
            Field::IdentityLastName => plain.identity.as_ref().and_then(|i| i.last_name.clone()),
            Field::IdentityUsername => plain.identity.as_ref().and_then(|i| i.username.clone()),
            Field::IdentityCompany => plain.identity.as_ref().and_then(|i| i.company.clone()),
            Field::IdentitySsn => plain.identity.as_ref().and_then(|i| i.ssn.clone()),
            Field::IdentityPassport => plain
                .identity
                .as_ref()
                .and_then(|i| i.passport_number.clone()),
            Field::IdentityLicense => plain
                .identity
                .as_ref()
                .and_then(|i| i.license_number.clone()),
            Field::IdentityAddress1 => plain.identity.as_ref().and_then(|i| i.address1.clone()),
            Field::IdentityAddress2 => plain.identity.as_ref().and_then(|i| i.address2.clone()),
            Field::IdentityAddress3 => plain.identity.as_ref().and_then(|i| i.address3.clone()),
            Field::IdentityCity => plain.identity.as_ref().and_then(|i| i.city.clone()),
            Field::IdentityState => plain.identity.as_ref().and_then(|i| i.state.clone()),
            Field::IdentityPostal => plain.identity.as_ref().and_then(|i| i.postal_code.clone()),
            Field::IdentityCountry => plain.identity.as_ref().and_then(|i| i.country.clone()),
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

    /// Place `value` on the system clipboard and remember it for the
    /// shutdown/lock sweep. Errors with the typed `ClipboardUnavailable` when
    /// no backend exists, so clients can fall back (OSC52) instead of
    /// string-matching.
    #[cfg(feature = "clipboard")]
    pub fn clipboard_set(&mut self, value: &str) -> Result<(), IpcError> {
        let cb = self
            .clipboard
            .as_mut()
            .ok_or(IpcError::ClipboardUnavailable)?;
        cb.set_text(value)?;
        self.last_copied = Some(Zeroizing::new(value.to_owned()));
        Ok(())
    }

    /// Clear the clipboard if it still holds `written` (the value we copied), or
    /// if its contents can't be read. Leaves anything the user has since copied
    /// untouched. Invoked by the scheduled auto-clear task; never errors.
    #[cfg(feature = "clipboard")]
    pub fn clipboard_clear_if_ours(&mut self, written: &str) {
        let Some(cb) = self.clipboard.as_mut() else {
            return;
        };
        if should_clear_clipboard(cb.get_text().as_deref(), written) {
            // Best-effort: a failed clear is no worse than the timer never
            // having run; the next copy will overwrite regardless.
            cb.clear();
        }
        // The sweep only needs to remember a copy newer timers still own.
        if self.last_copied.as_deref().map(String::as_str) == Some(written) {
            self.last_copied = None;
        }
    }

    /// Sweep a still-pending copy off the clipboard. Runs on `lock()` so a
    /// copied secret never outlives the keys: the detached timer task dies
    /// with the runtime on `Quit`/SIGTERM, and this closes that gap.
    #[cfg(feature = "clipboard")]
    pub fn clipboard_sweep(&mut self) {
        if let Some(pending) = self.last_copied.take() {
            self.clipboard_clear_if_ours(&pending);
        }
    }

    /// Backend label for `Status`: the live native backend's name when held,
    /// else `"osc52"` when that mode is configured (the agent declines so the
    /// client copies via the terminal), else `None` (no clipboard available).
    #[cfg(feature = "clipboard")]
    fn clipboard_backend_name(&self) -> Option<String> {
        self.clipboard.as_ref().map_or_else(
            || {
                (self.clipboard_backend == crate::clipboard::BackendChoice::Osc52)
                    .then(|| "osc52".to_owned())
            },
            |cb| Some(cb.name().to_owned()),
        )
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

/// Compose a card's expiry as `MM/YYYY` (month zero-padded), `None` if neither
/// month nor year is present.
fn card_expiry(c: &vault_core::cipher::PlainCard) -> Option<String> {
    match (c.exp_month.as_deref(), c.exp_year.as_deref()) {
        (None, None) => None,
        (month, year) => {
            let m = month.unwrap_or_default();
            let mm = if m.len() == 1 {
                format!("0{m}")
            } else {
                m.to_owned()
            };
            Some(format!("{mm}/{}", year.unwrap_or_default()))
        }
    }
}

/// Join an identity's first/middle/last names with spaces, `None` if all empty.
fn identity_name(i: &vault_core::cipher::PlainIdentity) -> Option<String> {
    let parts: Vec<&str> = [
        i.first_name.as_deref(),
        i.middle_name.as_deref(),
        i.last_name.as_deref(),
    ]
    .into_iter()
    .flatten()
    .filter(|s| !s.is_empty())
    .collect();
    (!parts.is_empty()).then(|| parts.join(" "))
}

/// Compose an identity's address: street lines, then `City State Postal`, then
/// country — each non-empty part on its own line. `None` if nothing is set.
fn identity_address(i: &vault_core::cipher::PlainIdentity) -> Option<String> {
    let mut lines: Vec<String> = [
        i.address1.as_deref(),
        i.address2.as_deref(),
        i.address3.as_deref(),
    ]
    .into_iter()
    .flatten()
    .filter(|s| !s.is_empty())
    .map(str::to_owned)
    .collect();
    let csp: Vec<&str> = [
        i.city.as_deref(),
        i.state.as_deref(),
        i.postal_code.as_deref(),
    ]
    .into_iter()
    .flatten()
    .filter(|s| !s.is_empty())
    .collect();
    if !csp.is_empty() {
        lines.push(csp.join(" "));
    }
    if let Some(country) = i.country.as_deref().filter(|s| !s.is_empty()) {
        lines.push(country.to_owned());
    }
    (!lines.is_empty()).then(|| lines.join("\n"))
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
    /// Card fields to set (card ciphers only); `Some` per field = change it.
    card: Option<CardEdit<'a>>,
    /// Identity fields to set (identity ciphers only); `Some` per field = change.
    identity: Option<IdentityEdit<'a>>,
}

/// Card sub-overlay: borrowed plaintext for the card fields to change.
struct CardEdit<'a> {
    cardholder: Option<&'a str>,
    brand: Option<&'a str>,
    number: Option<&'a str>,
    exp_month: Option<&'a str>,
    exp_year: Option<&'a str>,
    code: Option<&'a str>,
}

/// Identity sub-overlay: borrowed plaintext for the identity fields to change.
struct IdentityEdit<'a> {
    title: Option<&'a str>,
    first_name: Option<&'a str>,
    middle_name: Option<&'a str>,
    last_name: Option<&'a str>,
    username: Option<&'a str>,
    company: Option<&'a str>,
    ssn: Option<&'a str>,
    passport_number: Option<&'a str>,
    license_number: Option<&'a str>,
    email: Option<&'a str>,
    phone: Option<&'a str>,
    address1: Option<&'a str>,
    address2: Option<&'a str>,
    address3: Option<&'a str>,
    city: Option<&'a str>,
    state: Option<&'a str>,
    postal_code: Option<&'a str>,
    country: Option<&'a str>,
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
    // Card fields (the caller already checked the cipher is a card).
    if let Some(c) = &o.card {
        let card = cipher.card.get_or_insert_with(Card::default);
        if let Some(v) = c.cardholder {
            card.cardholder_name = Some(enc(v));
        }
        if let Some(v) = c.brand {
            card.brand = Some(enc(v));
        }
        if let Some(v) = c.number {
            card.number = Some(enc(v));
        }
        if let Some(v) = c.exp_month {
            card.exp_month = Some(enc(v));
        }
        if let Some(v) = c.exp_year {
            card.exp_year = Some(enc(v));
        }
        if let Some(v) = c.code {
            card.code = Some(enc(v));
        }
    }
    // Identity fields (the caller already checked the cipher is an identity).
    if let Some(i) = &o.identity {
        let id = cipher.identity.get_or_insert_with(Identity::default);
        let set = |slot: &mut Option<String>, v: Option<&str>| {
            if let Some(v) = v {
                *slot = Some(enc(v));
            }
        };
        set(&mut id.title, i.title);
        set(&mut id.first_name, i.first_name);
        set(&mut id.middle_name, i.middle_name);
        set(&mut id.last_name, i.last_name);
        set(&mut id.username, i.username);
        set(&mut id.company, i.company);
        set(&mut id.ssn, i.ssn);
        set(&mut id.passport_number, i.passport_number);
        set(&mut id.license_number, i.license_number);
        set(&mut id.email, i.email);
        set(&mut id.phone, i.phone);
        set(&mut id.address1, i.address1);
        set(&mut id.address2, i.address2);
        set(&mut id.address3, i.address3);
        set(&mut id.city, i.city);
        set(&mut id.state, i.state);
        set(&mut id.postal_code, i.postal_code);
        set(&mut id.country, i.country);
    }
}

/// Convert a wire `IdentityWrite` to a `PlainIdentity`, decoding the secret
/// ssn/passport/license bytes to strings (zeroized on failure / on drop).
fn identity_write_to_plain(iw: vault_ipc::proto::IdentityWrite) -> Result<PlainIdentity, IpcError> {
    Ok(PlainIdentity {
        title: iw.title,
        first_name: iw.first_name,
        middle_name: iw.middle_name,
        last_name: iw.last_name,
        username: iw.username,
        company: iw.company,
        ssn: bytes_to_string(iw.ssn)?,
        passport_number: bytes_to_string(iw.passport_number)?,
        license_number: bytes_to_string(iw.license_number)?,
        email: iw.email,
        phone: iw.phone,
        address1: iw.address1,
        address2: iw.address2,
        address3: iw.address3,
        city: iw.city,
        state: iw.state,
        postal_code: iw.postal_code,
        country: iw.country,
    })
}

/// Convert a wire `CardWrite` to a `PlainCard`, decoding the secret number/code
/// bytes to strings (zeroized on failure by `bytes_to_string`).
fn card_write_to_plain(cw: vault_ipc::proto::CardWrite) -> Result<PlainCard, IpcError> {
    Ok(PlainCard {
        cardholder_name: cw.cardholder,
        brand: cw.brand,
        number: bytes_to_string(cw.number)?,
        exp_month: cw.exp_month,
        exp_year: cw.exp_year,
        code: bytes_to_string(cw.code)?,
    })
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
    fn fingerprint_resume_refused_when_disabled() {
        // With fingerprint unlock off (the default), a resume request is a clean
        // "unavailable" — never a silent unlock and never a different error.
        let mut s = AgentState::new(900);
        assert!(matches!(
            s.resume_after_fingerprint(),
            Err(IpcError::FingerprintUnavailable(_))
        ));
        assert!(!s.is_unlocked(), "must never auto-unlock");
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
        v.user_enc = SealedKey::new(enc);
        v.user_mac = SealedKey::new(mac);
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

    #[test]
    fn search_skips_undecryptable_ciphers() {
        let enc = [7u8; 32];
        let mac = [9u8; 32];
        let mut v = stub_vault();
        v.user_enc = SealedKey::new(enc);
        v.user_mac = SealedKey::new(mac);
        // An organization-like cipher whose per-item key is wrapped under a key
        // Vault doesn't hold — decrypt_name fails. It precedes the real target,
        // so neither get_item nor list_entries may abort on it.
        let wrong = [0xAAu8; 32];
        let mut material = [0u8; 64];
        material[..32].copy_from_slice(&[0xBBu8; 32]);
        material[32..].copy_from_slice(&[0xCCu8; 32]);
        v.ciphers.push(Cipher {
            id: "org-1".into(),
            cipher_type: 1,
            key: Some(vault_core::EncString::encrypt(&wrong, &wrong, &material).serialize()),
            name: Some(
                vault_core::EncString::encrypt(&[0xBBu8; 32], &[0xCCu8; 32], b"org").serialize(),
            ),
            ..Cipher::default()
        });
        v.ciphers.push(login_with_password(
            "real-1", "github", "hunter2", &enc, &mac,
        ));
        let mut s = AgentState::new(900);
        s.vault = Some(v);

        // The undecryptable cipher must not abort the reveal of a good item.
        let item = s.get_item(None, "github", Field::Password).unwrap();
        assert_eq!(item.value, "hunter2");
        // …nor the list, which simply omits it.
        let list = s.list_entries().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "github");
    }

    #[test]
    fn org_cipher_decrypts_under_org_key() {
        let user_enc = [7u8; 32];
        let user_mac = [9u8; 32];
        let org_enc = [21u8; 32];
        let org_mac = [22u8; 32];
        let mut v = stub_vault();
        v.user_enc = SealedKey::new(user_enc);
        v.user_mac = SealedKey::new(user_mac);
        v.org_keys.insert("org-1".to_owned(), (org_enc, org_mac));
        let e = |ke: &[u8; 32], km: &[u8; 32], s: &str| {
            vault_core::EncString::encrypt(ke, km, s.as_bytes()).serialize()
        };
        // An org cipher: name + password under the ORG key, not the user key.
        v.ciphers.push(Cipher {
            id: "org-c1".into(),
            cipher_type: 1,
            organization_id: Some("org-1".into()),
            name: Some(e(&org_enc, &org_mac, "shared-login")),
            login: Some(Login {
                password: Some(e(&org_enc, &org_mac, "org-secret")),
                ..Login::default()
            }),
            ..Cipher::default()
        });
        // A second org cipher whose org key we don't hold → skipped, not an error.
        v.ciphers.push(Cipher {
            id: "org-c2".into(),
            cipher_type: 1,
            organization_id: Some("org-unknown".into()),
            name: Some(e(&[1u8; 32], &[2u8; 32], "invisible")),
            ..Cipher::default()
        });
        let mut s = AgentState::new(900);
        s.vault = Some(v);

        let item = s
            .get_item(Some("org-c1"), "shared-login", Field::Password)
            .unwrap();
        assert_eq!(item.value, "org-secret", "decrypted under the org key");
        let list = s.list_entries().unwrap();
        assert_eq!(list.len(), 1, "the unknown-org cipher is skipped");
        assert_eq!(list[0].name, "shared-login");

        // Editing an org item is refused (write path would corrupt it).
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("rt");
        let err = rt
            .block_on(s.edit_cipher("org-c1", CipherWrite::default()))
            .unwrap_err();
        assert!(matches!(err, IpcError::Internal(_)), "got {err:?}");
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
        // Headless / failed init: copy must decline with the *typed* error so
        // clients can route to their OSC52 fallback.
        let mut s = AgentState::new(900);
        s.clipboard = None;
        assert!(matches!(
            s.clipboard_set("secret"),
            Err(IpcError::ClipboardUnavailable)
        ));
    }

    /// In-memory clipboard standing in for the system one, so the sweep and
    /// clear logic is testable on a headless CI box.
    #[cfg(feature = "clipboard")]
    struct FakeClipboard {
        content: Option<String>,
    }

    #[cfg(feature = "clipboard")]
    impl crate::clipboard::Backend for FakeClipboard {
        fn name(&self) -> &'static str {
            "fake"
        }
        fn set_text(&mut self, value: &str) -> Result<(), IpcError> {
            self.content = Some(value.to_owned());
            Ok(())
        }
        fn get_text(&mut self) -> Option<String> {
            self.content.clone()
        }
        fn clear(&mut self) {
            self.content = None;
        }
    }

    #[cfg(feature = "clipboard")]
    fn state_with_fake_clipboard() -> AgentState {
        let mut s = AgentState::new(900);
        s.clipboard = Some(Box::new(FakeClipboard { content: None }));
        s
    }

    #[cfg(feature = "clipboard")]
    fn fake_content(s: &mut AgentState) -> Option<String> {
        s.clipboard.as_mut().and_then(|cb| cb.get_text())
    }

    #[cfg(feature = "clipboard")]
    #[test]
    fn lock_sweeps_a_pending_copy() {
        let mut s = state_with_fake_clipboard();
        s.clipboard_set("hunter2").expect("set");
        assert_eq!(fake_content(&mut s).as_deref(), Some("hunter2"));
        s.lock();
        assert_eq!(fake_content(&mut s), None, "lock must sweep our copy");
    }

    #[cfg(feature = "clipboard")]
    #[test]
    fn sweep_leaves_foreign_clipboard_content_alone() {
        let mut s = state_with_fake_clipboard();
        s.clipboard_set("hunter2").expect("set");
        // The user copied something else after us.
        if let Some(cb) = s.clipboard.as_mut() {
            cb.set_text("user-data").expect("set");
        }
        s.lock();
        assert_eq!(
            fake_content(&mut s).as_deref(),
            Some("user-data"),
            "sweep must never clobber a newer copy"
        );
    }

    #[cfg(feature = "clipboard")]
    #[test]
    fn timer_clear_drops_the_sweep_marker() {
        let mut s = state_with_fake_clipboard();
        s.clipboard_set("hunter2").expect("set");
        // The timed clear fires (what schedule_clipboard_clear's task does).
        s.clipboard_clear_if_ours("hunter2");
        assert_eq!(fake_content(&mut s), None);
        // A later sweep has nothing left to do — and must not panic.
        s.clipboard_sweep();
        s.lock();
    }

    #[cfg(feature = "clipboard")]
    #[test]
    fn status_reports_backend_name() {
        let mut s = state_with_fake_clipboard();
        assert_eq!(
            s.status_snapshot().clipboard_backend.as_deref(),
            Some("fake")
        );
        s.clipboard = None;
        assert_eq!(s.status_snapshot().clipboard_backend, None);
    }

    #[cfg(feature = "clipboard")]
    #[test]
    fn status_reports_osc52_mode_without_a_native_backend() {
        let mut s = AgentState::new(900);
        s.clipboard = None;
        // Auto / no backend → nothing to report.
        assert_eq!(s.status_snapshot().clipboard_backend, None);
        // osc52 mode is informative even though the agent holds no backend.
        s.clipboard_backend = crate::clipboard::BackendChoice::Osc52;
        assert_eq!(
            s.status_snapshot().clipboard_backend.as_deref(),
            Some("osc52")
        );
    }

    #[test]
    fn resolve_cipher_matches_by_id_then_name() {
        let enc = [7u8; 32];
        let mac = [9u8; 32];
        let mut v = stub_vault();
        v.user_enc = SealedKey::new(enc);
        v.user_mac = SealedKey::new(mac);
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
    fn get_item_totp_generates_a_code() {
        let enc = [7u8; 32];
        let mac = [9u8; 32];
        let mut v = stub_vault();
        v.user_enc = SealedKey::new(enc);
        v.user_mac = SealedKey::new(mac);
        let e = |s: &str| vault_core::EncString::encrypt(&enc, &mac, s.as_bytes()).serialize();
        v.ciphers.push(Cipher {
            id: "totp-1".into(),
            cipher_type: 1,
            name: Some(e("github")),
            login: Some(Login {
                // The RFC 6238 base32 seed; the agent must return a code, not it.
                totp: Some(e("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")),
                ..Login::default()
            }),
            ..Cipher::default()
        });
        let mut s = AgentState::new(900);
        s.vault = Some(v);

        let item = s.get_item(Some("totp-1"), "github", Field::Totp).unwrap();
        assert_eq!(item.value.len(), 6, "default 6-digit code");
        assert!(item.value.chars().all(|c| c.is_ascii_digit()));
        assert_ne!(
            item.value, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            "must be the generated code, not the raw secret"
        );
        // A field the cipher lacks still surfaces as NoSuchField.
        assert!(matches!(
            s.get_item(Some("totp-1"), "github", Field::Username),
            Err(IpcError::NoSuchField { .. })
        ));
    }

    #[test]
    fn get_item_card_fields() {
        let enc = [7u8; 32];
        let mac = [9u8; 32];
        let mut v = stub_vault();
        v.user_enc = SealedKey::new(enc);
        v.user_mac = SealedKey::new(mac);
        let e =
            |s: &str| Some(vault_core::EncString::encrypt(&enc, &mac, s.as_bytes()).serialize());
        v.ciphers.push(Cipher {
            id: "card-1".into(),
            cipher_type: 3,
            name: Some(vault_core::EncString::encrypt(&enc, &mac, b"Visa").serialize()),
            card: Some(vault_core::cipher::Card {
                number: e("4111111111111111"),
                exp_month: e("4"),
                exp_year: e("2030"),
                code: e("123"),
                ..vault_core::cipher::Card::default()
            }),
            ..Cipher::default()
        });
        let mut s = AgentState::new(900);
        s.vault = Some(v);

        let num = s
            .get_item(Some("card-1"), "Visa", Field::CardNumber)
            .unwrap();
        assert_eq!(num.value, "4111111111111111");
        let exp = s
            .get_item(Some("card-1"), "Visa", Field::CardExpiry)
            .unwrap();
        assert_eq!(exp.value, "04/2030", "month zero-padded, joined with year");
        // No brand set → NoSuchField.
        assert!(matches!(
            s.get_item(Some("card-1"), "Visa", Field::CardBrand),
            Err(IpcError::NoSuchField { .. })
        ));
    }

    #[test]
    fn resolve_cipher_rejects_ambiguous_name() {
        let enc = [3u8; 32];
        let mac = [4u8; 32];
        let mut v = stub_vault();
        v.user_enc = SealedKey::new(enc);
        v.user_mac = SealedKey::new(mac);
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
            card: None,
            identity: None,
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
            card: None,
            identity: None,
        };
        apply_cipher_edits(&mut cipher, &overlay, &enc, &mac);

        let uris = cipher.login.as_ref().unwrap().uris.as_ref().unwrap();
        assert_eq!(uris.len(), 2);
        assert_eq!(decrypt_uri(&uris[0], &enc, &mac), "https://new.example");
        assert_eq!(decrypt_uri(&uris[1], &enc, &mac), "https://two.example");
    }

    #[test]
    fn apply_card_edits_sets_only_given_fields() {
        let enc = [0x21u8; 32];
        let mac = [0x22u8; 32];
        let e =
            |s: &str| Some(vault_core::EncString::encrypt(&enc, &mac, s.as_bytes()).serialize());
        // A card with an existing brand + number; edit only the expiry.
        let mut cipher = Cipher {
            id: "card-1".into(),
            cipher_type: 3,
            card: Some(Card {
                brand: e("Visa"),
                number: e("4111111111111111"),
                ..Card::default()
            }),
            ..Cipher::default()
        };
        let overlay = EditOverlay {
            name: None,
            folder_id: None,
            folder_provided: false,
            notes: None,
            username: None,
            password: None,
            totp: None,
            uri: None,
            card: Some(CardEdit {
                cardholder: None,
                brand: None,
                number: None,
                exp_month: Some("5"),
                exp_year: Some("2031"),
                code: None,
            }),
            identity: None,
        };
        apply_cipher_edits(&mut cipher, &overlay, &enc, &mac);

        let back = cipher
            .decrypt(
                &enc,
                &mac,
                DecryptOptions {
                    card: true,
                    ..DecryptOptions::default()
                },
            )
            .unwrap();
        let c = back.card.as_ref().unwrap();
        assert_eq!(c.exp_month.as_deref(), Some("5"), "expiry updated");
        assert_eq!(c.exp_year.as_deref(), Some("2031"));
        // Untouched fields preserved.
        assert_eq!(c.brand.as_deref(), Some("Visa"));
        assert_eq!(c.number.as_deref(), Some("4111111111111111"));
    }

    #[test]
    fn apply_identity_edits_sets_only_given_fields() {
        let enc = [0x31u8; 32];
        let mac = [0x32u8; 32];
        let e =
            |s: &str| Some(vault_core::EncString::encrypt(&enc, &mac, s.as_bytes()).serialize());
        // An identity with an existing name + ssn; edit only the email + city.
        let mut cipher = Cipher {
            id: "id-1".into(),
            cipher_type: 4,
            identity: Some(Identity {
                first_name: e("Jane"),
                last_name: e("Doe"),
                ssn: e("123-45-6789"),
                ..Identity::default()
            }),
            ..Cipher::default()
        };
        let overlay = EditOverlay {
            name: None,
            folder_id: None,
            folder_provided: false,
            notes: None,
            username: None,
            password: None,
            totp: None,
            uri: None,
            card: None,
            identity: Some(IdentityEdit {
                title: None,
                first_name: None,
                middle_name: None,
                last_name: None,
                username: None,
                company: None,
                ssn: None,
                passport_number: None,
                license_number: None,
                email: Some("jane@example.org"),
                phone: None,
                address1: None,
                address2: None,
                address3: None,
                city: Some("Amber"),
                state: None,
                postal_code: None,
                country: None,
            }),
        };
        apply_cipher_edits(&mut cipher, &overlay, &enc, &mac);

        let back = cipher
            .decrypt(
                &enc,
                &mac,
                DecryptOptions {
                    identity: true,
                    ..DecryptOptions::default()
                },
            )
            .unwrap();
        let i = back.identity.as_ref().unwrap();
        assert_eq!(i.email.as_deref(), Some("jane@example.org"), "email set");
        assert_eq!(i.city.as_deref(), Some("Amber"), "city set");
        // Untouched fields preserved.
        assert_eq!(i.first_name.as_deref(), Some("Jane"));
        assert_eq!(i.last_name.as_deref(), Some("Doe"));
        assert_eq!(i.ssn.as_deref(), Some("123-45-6789"));
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
            user_enc: SealedKey::new([0u8; 32]),
            user_mac: SealedKey::new([0u8; 32]),
            ciphers: Vec::new(),
            folders: std::collections::HashMap::new(),
            org_keys: std::collections::HashMap::new(),
            client: Some(client),
            protected_user_key: String::new(),
            kdf: vault_core::kdf::KdfParams {
                kind: vault_core::kdf::KdfType::Pbkdf2Sha256,
                iterations: 1,
                memory_kib: None,
                parallelism: None,
            },
            refresh_token: None,
            device_id: "00000000-0000-0000-0000-000000000000".into(),
            last_sync: None,
        }
    }

    /// A vault unlocked from cache (offline) — no token; server ops must
    /// decline. Used to assert the `Error::Offline` gating.
    fn offline_vault() -> Vault {
        let mut v = stub_vault();
        v.client = None;
        v
    }

    #[test]
    fn offline_session_declines_server_ops() {
        let mut s = AgentState::new(900);
        s.vault = Some(offline_vault());
        // resync needs the network session → Offline.
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("rt");
        let err = rt.block_on(s.resync()).unwrap_err();
        assert!(matches!(err, IpcError::Offline), "got {err:?}");
        // A read path still works (no ciphers, but not an error).
        assert!(s.list_entries().is_ok());
    }

    #[test]
    fn ensure_online_ok_with_client_offline_without() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("rt");
        // A live client → Ok with no network call (short-circuits).
        let mut v = stub_vault();
        assert!(rt.block_on(v.ensure_online()).is_ok());
        // No client and no refresh token → Offline (can't establish a session).
        let mut v = offline_vault();
        assert!(matches!(
            rt.block_on(v.ensure_online()),
            Err(IpcError::Offline)
        ));
    }

    #[test]
    fn scheduled_sync_on_locked_agent_is_a_safe_noop() {
        // The background-sync loop calls resync() only when unlocked, but the
        // invariant it relies on is that a locked resync is a clean `Locked`
        // skip — and that a sync never defers the idle-lock countdown.
        let mut s = AgentState::new(900);
        let before = s.last_activity;
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("rt");
        let err = rt.block_on(s.resync()).unwrap_err();
        assert!(matches!(err, IpcError::Locked), "got {err:?}");
        assert_eq!(s.last_activity, before, "resync must not touch()");
    }

    #[test]
    fn account_dir_name_is_filesystem_safe_and_distinct() {
        let a = account_dir_name("https://vault.example.org", "Me@Example.org");
        // host kept; email lower-cased; '@' sanitized to '_'.
        assert_eq!(a, "vault.example.org_me_example.org");
        // Different server, same email → different dir.
        let b = account_dir_name("https://other.example.org/", "me@example.org");
        assert_ne!(a, b);
        // Anything weird is sanitized to '_'.
        let c = account_dir_name("https://h/x?y", "a/b c");
        assert!(
            !c.contains('/') && !c.contains(' ') && !c.contains('?'),
            "{c}"
        );
    }
}

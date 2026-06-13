// SPDX-License-Identifier: GPL-3.0-or-later

//! Wire types for the Vault IPC protocol.
//!
//! Future-compat policy: requests and responses are externally-tagged enums.
//! New variants get appended; old clients receive `Response::Error` when they
//! ask for something the agent doesn't recognise. Adding optional fields to
//! existing variants is forward-compatible because all message structs are
//! serde-defaulted on the agent's read side.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Client → agent requests.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "op", content = "args", rename_all = "snake_case")]
pub enum Request {
    /// Are you up? Returns `Response::Status` regardless of locked state.
    Ping,

    /// Report locked/unlocked state and basic metadata.
    Status,

    /// Unlock the agent for `email` against `server`.
    ///
    /// The agent will run prelogin → KDF → master-password hash → login →
    /// decrypt user key, mirroring `vault-api`. The password is consumed
    /// and zeroised by the agent after derivation.
    Unlock {
        /// Server origin (`https://vault.example.org`).
        server: String,
        /// Account email — case-insensitive on the wire, lower-cased in-agent.
        email: String,
        /// Master password, sent only on the local UDS.
        password: Vec<u8>,
    },

    /// Drop all in-memory keys and access tokens. Idempotent.
    Lock,

    /// Pull `/sync` and refresh the in-memory + on-disk encrypted cache.
    /// Requires an unlocked agent.
    Sync,

    /// List all items by decrypted name. Requires an unlocked agent.
    List,

    /// Look up a single item and return one decrypted field.
    ///
    /// When `id` is `Some`, the agent targets that exact cipher id — the
    /// reliable path for a client that already knows which item it means (the
    /// TUI passes the selected row's id). When `id` is `None`, the agent falls
    /// back to a case-insensitive match on `name`, which is ambiguous if two
    /// items share a name. `name` is always carried for human-readable errors.
    Get {
        /// Exact cipher id to target, if known.
        id: Option<String>,
        /// Item name (decrypted form, e.g. `github.com`) — fallback selector
        /// and error label.
        name: String,
        /// Optional field selector — `password` is the default.
        field: Option<Field>,
    },

    /// Decrypt one field of the targeted item and place it on the agent's own
    /// clipboard, scheduling an auto-clear after `clear_after_secs`.
    ///
    /// Unlike [`Request::Get`], the plaintext value never crosses the socket:
    /// the agent reads, copies, and forgets it, so a short-lived client (or one
    /// that quits before the timer fires) can't leak or strand the secret.
    /// Targeting mirrors `Get` — `id` is exact, `name` is the fallback / label.
    /// On success the agent replies [`Response::Ok`]; a missing field, locked
    /// agent, or absent clipboard surfaces as [`Response::Error`].
    Copy {
        /// Exact cipher id to target, if known.
        id: Option<String>,
        /// Item name — fallback selector and error label.
        name: String,
        /// Field to copy — `password` is the default.
        field: Option<Field>,
        /// Seconds before the agent clears the clipboard; `None` uses the
        /// agent default, `Some(0)` disables auto-clear.
        clear_after_secs: Option<u64>,
    },

    /// Place caller-supplied text on the agent's clipboard with the same
    /// timed auto-clear as [`Request::Copy`].
    ///
    /// This is the copy path for values that don't live in the vault — e.g. a
    /// freshly generated password the user hasn't saved yet. The plaintext
    /// rides the local UDS exactly like `Unlock`'s password does, and the
    /// agent zeroises it after the clipboard write. Requires an unlocked
    /// agent, mirroring every other data verb.
    CopyText {
        /// The value to copy; secret, wiped by the agent after use.
        text: Vec<u8>,
        /// Seconds before the agent clears the clipboard; `None` uses the
        /// agent default, `Some(0)` disables auto-clear.
        clear_after_secs: Option<u64>,
    },

    /// Soft-delete a cipher by id or decrypted name.
    ///
    /// `selector` is matched against `Cipher.id` first (exact); if no id
    /// match, it's case-insensitively matched against decrypted names. If a
    /// name matches more than one cipher the agent refuses with
    /// `Error::AmbiguousItem` — the caller must retry with the explicit id.
    Remove {
        /// Cipher id (UUID) or decrypted item name.
        selector: String,
    },

    /// Create a new cipher (1 = login, 2 = secure note). All value fields
    /// arrive as plaintext on the local UDS and are encrypted inside the agent
    /// — the unwrapped user key never leaves it.
    Add {
        /// Display name (required).
        name: String,
        /// Cipher type: `1` = login, `2` = secure note.
        cipher_type: u8,
        /// Folder name (resolved to an id by the agent), or `None` for unfiled.
        folder: Option<String>,
        /// Free-form notes.
        notes: Option<String>,
        /// Login username (login type only).
        username: Option<String>,
        /// Login password (login type only); secret, wiped after encryption.
        password: Option<Vec<u8>>,
        /// TOTP secret / URI (login type only); secret, wiped after encryption.
        totp: Option<Vec<u8>>,
        /// Primary login URI (login type only).
        uri: Option<String>,
    },

    /// Edit an existing cipher. Only the `Some` fields change; `None` leaves
    /// the current value untouched. `selector` resolves like `Remove`.
    Edit {
        /// Cipher id (UUID) or decrypted item name (case-insensitive).
        selector: String,
        /// New display name.
        name: Option<String>,
        /// New folder name (resolved by the agent).
        folder: Option<String>,
        /// New notes.
        notes: Option<String>,
        /// New username.
        username: Option<String>,
        /// New password; secret, wiped after encryption.
        password: Option<Vec<u8>>,
        /// New TOTP secret / URI; secret, wiped after encryption.
        totp: Option<Vec<u8>>,
        /// New primary URI.
        uri: Option<String>,
    },

    /// Cleanly shut the agent down. Equivalent to `vault stop-agent`.
    Quit,
}

/// Agent → client responses.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum Response {
    /// Generic success with no payload (`Lock`, `Sync`, `Quit`).
    Ok,
    /// Status snapshot.
    Status(Status),
    /// `List` result.
    List(Vec<ListEntry>),
    /// `Get` result.
    Item(Item),
    /// `Remove` result — cipher was deleted on the server.
    Removed(Removed),
    /// `Add` / `Edit` result — cipher was created or updated on the server.
    Saved(Saved),
    /// `Copy` / `CopyText` result — the value is on the agent's clipboard.
    Copied(Copied),
    /// Recoverable error — operation declined or failed.
    Error(Error),
}

/// Wire shape for `Response::Copied`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Copied {
    /// Seconds until the agent's auto-clear fires for this copy — the
    /// *effective* value after the agent applied its configured default.
    /// `0` means auto-clear is disabled for this copy.
    pub clear_after_secs: u64,
}

/// Wire shape for `Response::Removed`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Removed {
    /// Server-assigned id of the cipher that was deleted.
    pub id: String,
    /// Decrypted name of the cipher that was deleted (echoed so callers can
    /// confirm what they hit without re-listing).
    pub name: String,
}

/// Wire shape for `Response::Saved` (the result of `Add` / `Edit`).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Saved {
    /// Server-assigned id of the created or updated cipher.
    pub id: String,
    /// Decrypted name, echoed so callers can confirm what they wrote.
    pub name: String,
}

/// Status snapshot returned by `Request::Status` and `Request::Ping`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Status {
    /// True if the agent currently holds the user symmetric key.
    pub unlocked: bool,
    /// Server origin the agent is bound to, if known.
    pub server: Option<String>,
    /// Account email the agent is unlocked for, if any.
    pub email: Option<String>,
    /// Item count in the in-memory cache, or `None` if locked / never synced.
    pub items: Option<usize>,
    /// Last successful `/sync` time (ISO 8601 UTC), if any.
    pub last_sync: Option<String>,
    /// Agent's `CARGO_PKG_VERSION`.
    pub agent_version: String,
    /// Name of the live clipboard backend (`"arboard"`), or `None` when the
    /// agent has no clipboard (headless build / no display). Lets clients
    /// decide up front whether `Copy` will work or an OSC52 fallback is
    /// needed. Defaulted so snapshots from older agents still decode.
    #[serde(default)]
    pub clipboard_backend: Option<String>,
}

/// Wire shape for `Response::List`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ListEntry {
    /// Server-assigned item id (UUID).
    pub id: String,
    /// Decrypted item name.
    pub name: String,
    /// Bitwarden cipher type (1 = login, 2 = secure note, 3 = card, 4 = identity).
    pub cipher_type: u8,
    /// Decrypted username for `cipher_type == 1`, otherwise `None`.
    pub username: Option<String>,
    /// Decrypted folder name, or `None` if unfiled.
    pub folder: Option<String>,
}

/// Wire shape for `Response::Item`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Item {
    /// Server-assigned item id.
    pub id: String,
    /// Decrypted item name.
    pub name: String,
    /// Bitwarden cipher type.
    pub cipher_type: u8,
    /// Decrypted field requested by `Request::Get.field`.
    pub field: Field,
    /// Decrypted value of `field`.
    pub value: String,
}

impl Drop for Item {
    fn drop(&mut self) {
        // Best-effort scrub; the client should still wipe its own copy.
        self.value.zeroize();
    }
}

/// Selectable field on `Request::Get`.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Field {
    /// `Login.Password`. The default.
    #[default]
    Password,
    /// `Login.Username`.
    Username,
    /// `Login.Totp` — TOTP secret URI, when present.
    Totp,
    /// `Notes` (any cipher type).
    Notes,
    /// First `Login.Uris[].Uri`.
    Uri,
}

/// Re-export the full cipher payload from `vault-core` when needed.
/// At M3 the agent decrypts only the requested field on the wire side; richer
/// item dumps land in M4.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Cipher {
    /// Decrypted name.
    pub name: String,
    /// Cipher type.
    pub cipher_type: u8,
}

/// Error payload shared with the client.
#[derive(Clone, Debug, Deserialize, Serialize, thiserror::Error)]
#[serde(rename_all = "snake_case", tag = "code", content = "message")]
pub enum Error {
    /// The agent is locked; client must call `Unlock` first.
    #[error("agent is locked")]
    Locked,
    /// Wrong password (or wrong email) — no key derived.
    #[error("bad password")]
    BadPassword,
    /// Network or server error.
    #[error("network: {0}")]
    Network(String),
    /// Two-factor authentication is required and not yet supported in M3.
    #[error("two-factor authentication required (not yet supported)")]
    TwoFactorRequired,
    /// No such item by the supplied name.
    #[error("no item named {0}")]
    NoSuchItem(String),
    /// Multiple items match the supplied name — operation refused.
    #[error("name {name} is ambiguous (matches {} items: {})", ids.len(), ids.join(", "))]
    AmbiguousItem {
        /// The name that matched multiple ciphers.
        name: String,
        /// Ids of every matching cipher.
        ids: Vec<String>,
    },
    /// The named item exists but lacks the requested field.
    #[error("item {item} has no {field}")]
    NoSuchField {
        /// The item that was found.
        item: String,
        /// The missing field's wire name.
        field: String,
    },
    /// Decryption of an item field failed (typically MAC mismatch).
    #[error("decrypt failed: {0}")]
    Decrypt(String),
    /// The agent has no clipboard backend (headless build or no display).
    /// Typed so clients can fall back — e.g. the TUI's OSC52 path — instead
    /// of string-matching an internal error.
    #[error("no clipboard backend available")]
    ClipboardUnavailable,
    /// Any other internal error — message is for the operator, not for parsing.
    #[error("internal: {0}")]
    Internal(String),
}

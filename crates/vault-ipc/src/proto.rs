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

    /// Look up a single item by its decrypted name (case-insensitive).
    Get {
        /// Item name (decrypted form, e.g. `github.com`).
        name: String,
        /// Optional field selector — `password` is the default.
        field: Option<Field>,
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
    /// Recoverable error — operation declined or failed.
    Error(Error),
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
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Field {
    /// `Login.Password`. The default.
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

impl Default for Field {
    fn default() -> Self {
        Self::Password
    }
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
    /// Any other internal error — message is for the operator, not for parsing.
    #[error("internal: {0}")]
    Internal(String),
}

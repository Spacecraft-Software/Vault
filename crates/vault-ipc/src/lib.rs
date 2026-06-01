// SPDX-License-Identifier: GPL-3.0-or-later

//! Vault IPC — client ↔ agent protocol.
//!
//! Frames are `u32 big-endian length || CBOR body`. Both halves use the same
//! `Request` and `Response` types, encoded by [`ciborium`]. CBOR keeps the
//! wire compact and gives us versioning slack via serde's `#[serde(other)]`
//! enum variants without needing to bump a protocol version every time we
//! add a field.

#![forbid(unsafe_code)]

pub mod proto;
pub mod socket;
pub mod transport;

pub use proto::{Cipher, Error, Field, Item, ListEntry, Request, Response, Status};
pub use socket::{default_socket_path, sanitize_socket_path};
pub use transport::{read_frame, write_frame};

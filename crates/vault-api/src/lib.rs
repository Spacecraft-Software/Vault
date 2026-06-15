// SPDX-License-Identifier: GPL-3.0-or-later

//! Vault API — Bitwarden / Vaultwarden REST client.
//!
//! Stability: pre-1.0, every API may change. See PRD §9.1.

#![forbid(unsafe_code)]

pub mod client;
pub mod error;
pub mod identity;
pub mod sync;
pub mod urls;

pub use client::{BitwardenClient, CLIENT_ID, DEVICE_TYPE_CLI, TwoFactor};
pub use error::{Error, Result};
pub use identity::{PreloginResponse, TokenResponse};
pub use sync::SyncResponse;
pub use urls::BaseUrls;

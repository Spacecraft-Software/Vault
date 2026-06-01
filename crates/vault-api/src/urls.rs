// SPDX-License-Identifier: GPL-3.0-or-later

//! Base URLs for a Bitwarden / Vaultwarden deployment.
//!
//! Bitwarden's hosted service splits the API and identity endpoints across
//! two hostnames (`api.bitwarden.com`, `identity.bitwarden.com`).
//! Self-hosted Vaultwarden serves both from the same origin under
//! `/api` and `/identity` path prefixes. `BaseUrls` accommodates both.

use url::Url;

use crate::error::{Error, Result};

/// API + identity endpoint pair for a Bitwarden-protocol server.
#[derive(Clone, Debug)]
pub struct BaseUrls {
    /// Base URL for `/sync`, `/ciphers`, etc.
    pub api: Url,
    /// Base URL for `/connect/token` and related auth flows.
    pub identity: Url,
}

impl BaseUrls {
    /// Hosted Bitwarden — `api.bitwarden.com` + `identity.bitwarden.com`.
    pub fn bitwarden_hosted() -> Self {
        Self {
            api: "https://api.bitwarden.com"
                .parse()
                .expect("static URL parses"),
            identity: "https://identity.bitwarden.com"
                .parse()
                .expect("static URL parses"),
        }
    }

    /// Vaultwarden / self-hosted — both halves are served from one origin
    /// under `/api` and `/identity`.
    pub fn self_hosted(origin: &str) -> Result<Self> {
        let mut base: Url = origin
            .parse()
            .map_err(|_| Error::BaseUrl("origin is not a valid URL"))?;
        // Guarantee a trailing slash so subsequent `.join()` calls behave.
        if !base.path().ends_with('/') {
            let p = format!("{}/", base.path());
            base.set_path(&p);
        }
        let api = base
            .join("api/")
            .map_err(|_| Error::BaseUrl("could not join /api/"))?;
        let identity = base
            .join("identity/")
            .map_err(|_| Error::BaseUrl("could not join /identity/"))?;
        Ok(Self { api, identity })
    }
}

// SPDX-License-Identifier: GPL-3.0-or-later

//! Base URLs for a Bitwarden / Vaultwarden deployment.
//!
//! Bitwarden's hosted service splits the API and identity endpoints across
//! two hostnames — `api.bitwarden.com` + `identity.bitwarden.com` for the US
//! cloud, `api.bitwarden.eu` + `identity.bitwarden.eu` for the EU cloud.
//! Self-hosted Vaultwarden serves both from the same origin under
//! `/api` and `/identity` path prefixes. `BaseUrls` accommodates all three;
//! [`BaseUrls::infer_from`] routes a configured server origin to the right one.

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
    ///
    /// # Panics
    ///
    /// Never: both URLs are compile-time string literals known to parse.
    #[must_use]
    #[allow(clippy::expect_used)] // the two literals are valid URLs; the Err arm is unreachable
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

    /// Hosted Bitwarden, EU region — `api.bitwarden.eu` + `identity.bitwarden.eu`.
    ///
    /// # Panics
    ///
    /// Never: both URLs are compile-time string literals known to parse.
    #[must_use]
    #[allow(clippy::expect_used)] // the two literals are valid URLs; the Err arm is unreachable
    pub fn bitwarden_eu() -> Self {
        Self {
            api: "https://api.bitwarden.eu"
                .parse()
                .expect("static URL parses"),
            identity: "https://identity.bitwarden.eu"
                .parse()
                .expect("static URL parses"),
        }
    }

    /// Route a configured server origin to the right endpoint pair: the hosted
    /// Bitwarden split for the `bitwarden.com` (US) and `bitwarden.eu` (EU)
    /// clouds, or the single-origin [`self_hosted`](Self::self_hosted) shape for
    /// anything else (Vaultwarden / other self-hosted). Subdomains of the cloud
    /// apexes (e.g. `vault.bitwarden.com`) route to the matching cloud; no real
    /// self-host lives under those apexes, so the suffix match is safe.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BaseUrl`] if `server` is not a valid URL, or — for the
    /// self-hosted path — if the `/api/` and `/identity/` joins fail.
    pub fn infer_from(server: &str) -> Result<Self> {
        let url: Url = server
            .parse()
            .map_err(|_| Error::BaseUrl("server is not a valid URL"))?;
        let host = url.host_str().unwrap_or_default();
        if host == "bitwarden.com" || host.ends_with(".bitwarden.com") {
            Ok(Self::bitwarden_hosted())
        } else if host == "bitwarden.eu" || host.ends_with(".bitwarden.eu") {
            Ok(Self::bitwarden_eu())
        } else {
            Self::self_hosted(server)
        }
    }

    /// Vaultwarden / self-hosted — both halves are served from one origin
    /// under `/api` and `/identity`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BaseUrl`] if `origin` is not a valid URL or the
    /// `/api/` and `/identity/` path joins fail.
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

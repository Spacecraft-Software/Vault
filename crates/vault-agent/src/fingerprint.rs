// SPDX-License-Identifier: GPL-3.0-or-later

//! Fingerprint verification via the system `fprintd` service (Linux, D-Bus).
//!
//! Used only to *gate* the keyring-held session resume — Vault never enrolls or
//! stores fingerprint templates (enrollment is OS-level via `fprintd-enroll`),
//! and a fingerprint yields only match/no-match, never key material. The match
//! decision is made **inside the agent** so a client can't bypass it over the
//! UDS. See `docs/fingerprint.md` and the `Request::UnlockFingerprint` contract.
//!
//! Real implementation is behind `cfg(all(target_os = "linux", feature =
//! "fingerprint"))`; every other build gets a stub that reports
//! [`Outcome::Unavailable`], so default/headless/macOS builds carry no D-Bus
//! dependency and fingerprint unlock degrades cleanly.

/// Result of one fingerprint verification attempt.
// `Match`/`NoMatch` are produced only by the real (feature+Linux) implementation;
// the stub yields only `Unavailable`, so allow them to be "unconstructed" there.
#[cfg_attr(
    not(all(target_os = "linux", feature = "fingerprint")),
    allow(dead_code)
)]
#[derive(Debug)]
pub enum Outcome {
    /// A finger matched an enrolled print.
    Match,
    /// A finger was read but did not match (or the user gave up / it timed out).
    NoMatch,
    /// Verification couldn't run at all — no `fingerprint` feature, no reader /
    /// `fprintd` / enrolled finger, `PolicyKit` denied (e.g. an inactive/SSH
    /// session), or a D-Bus error. Carries an operator-facing reason.
    Unavailable(String),
}

#[cfg(all(target_os = "linux", feature = "fingerprint"))]
pub use imp::verify;

#[cfg(all(target_os = "linux", feature = "fingerprint"))]
mod imp {
    use std::time::Duration;

    use futures_util::StreamExt as _;

    use super::Outcome;

    /// Max wall-clock to wait for a swipe before giving up (→ `NoMatch`).
    const VERIFY_TIMEOUT: Duration = Duration::from_secs(30);

    #[zbus::proxy(
        interface = "net.reactivated.Fprint.Manager",
        default_service = "net.reactivated.Fprint",
        default_path = "/net/reactivated/Fprint/Manager"
    )]
    trait FprintManager {
        fn get_default_device(&self) -> zbus::Result<zbus::zvariant::OwnedObjectPath>;
    }

    #[zbus::proxy(
        interface = "net.reactivated.Fprint.Device",
        default_service = "net.reactivated.Fprint"
    )]
    trait FprintDevice {
        /// `""` claims the device for the calling user (`PolicyKit`-gated).
        fn claim(&self, username: &str) -> zbus::Result<()>;
        /// `"any"` verifies against any enrolled finger.
        fn verify_start(&self, finger_name: &str) -> zbus::Result<()>;
        fn verify_stop(&self) -> zbus::Result<()>;
        fn release(&self) -> zbus::Result<()>;

        #[zbus(signal)]
        fn verify_status(&self, result: String, done: bool) -> zbus::Result<()>;
    }

    /// Verify a finger against the user's enrolled prints. Any D-Bus / setup
    /// failure (no device, no enrolled finger, `PolicyKit` denial) surfaces as
    /// [`Outcome::Unavailable`]; only a read that doesn't match (or a timeout) is
    /// [`Outcome::NoMatch`].
    pub async fn verify() -> Outcome {
        match run().await {
            Ok(outcome) => outcome,
            Err(e) => Outcome::Unavailable(e.to_string()),
        }
    }

    async fn run() -> zbus::Result<Outcome> {
        let conn = zbus::Connection::system().await?;
        let manager = FprintManagerProxy::new(&conn).await?;
        let device_path = manager.get_default_device().await?;
        let device = FprintDeviceProxy::builder(&conn)
            .path(device_path)?
            .build()
            .await?;
        device.claim("").await?;
        // Release the device whatever the verify result.
        let result = verify_on(&device).await;
        let _ = device.release().await;
        result
    }

    async fn verify_on(device: &FprintDeviceProxy<'_>) -> zbus::Result<Outcome> {
        // Subscribe before VerifyStart so the first status can't be missed.
        let mut status = device.receive_verify_status().await?;
        device.verify_start("any").await?;
        let waited = tokio::time::timeout(VERIFY_TIMEOUT, async {
            while let Some(signal) = status.next().await {
                let args = signal.args()?;
                if args.done {
                    let outcome = if args.result == "verify-match" {
                        Outcome::Match
                    } else {
                        Outcome::NoMatch
                    };
                    // Pin the error type for inference.
                    return Ok::<Outcome, zbus::Error>(outcome);
                }
                // Intermediate retries (verify-retry-scan, swipe-too-short, …):
                // fprintd keeps the session open, so keep waiting.
            }
            Ok(Outcome::NoMatch)
        })
        .await;
        let _ = device.verify_stop().await;
        // Timeout elapsed → no match; otherwise propagate the inner result.
        waited.unwrap_or(Ok(Outcome::NoMatch))
    }
}

#[cfg(not(all(target_os = "linux", feature = "fingerprint")))]
pub async fn verify() -> Outcome {
    Outcome::Unavailable("agent built without the `fingerprint` feature".to_owned())
}

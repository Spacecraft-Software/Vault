<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Changelog

All notable changes to Vault are documented here. Dates are ISO 8601 UTC per
the Spacecraft Software Standard §12. Vault is pre-1.0; versions in the `0.x`
range may break in any release.

## [Unreleased]

### Added

- M0 scaffolding: Cargo workspace, eight member crates (`vault-core`,
  `vault-api`, `vault-store`, `vault-agent`, `vault-ipc`, `vault-cli`,
  `vault-tui`, `vault-theme`).
- `vault --version` emits the Standard §13.2 attribution block.
- Posture files at repo root: `README.md`, `NOTICE.md`, `CONTRIBUTING.md`,
  `LICENSE`, `CREDITS.md`, `CHANGELOG.md`.
- `PRD.md` — full product requirements document.
- CI configuration: `fmt`, `clippy -D warnings`, `cargo audit`, `cargo deny`.
- **M2 — login + sync against Vaultwarden.**
  - `vault-core::login::master_password_hash` — base64 `PBKDF2-SHA-256(master_key, password, 1)` for `/identity/connect/token`.
  - `vault-api` — `BitwardenClient` over `reqwest` + `rustls`, with `prelogin`,
    `login_password`, and `sync` methods. `BaseUrls` accommodates both
    Bitwarden's hosted split (`api.bitwarden.com` + `identity.bitwarden.com`)
    and Vaultwarden's single-origin `/api` + `/identity` deployment.
    Two-factor detection on `400` with `TwoFactorProviders[2]` surfaces a
    typed `TwoFactorRequired` error.
  - `vault-store` — `VaultCache` with serde JSON envelope on disk and an
    encrypted `payload` field (Vault `EncString` over the raw `/sync`
    response). Writes go through an atomic `NamedTempFile::persist` rename.
  - **Tests** — `vault-api::tests::parsing` (7) covers wire-shape decoding;
    `vault-store::tests::cache` (4) covers the encrypted persistence
    round-trip; `vault-api::tests::login_sync` is the full wiremock
    integration test, kept `#[ignore]` pending a clean test-binary linker
    environment (see file preamble — library and `--bin vault` build fine).
  - `docs/m2-vaultwarden.md` — recipe for the real Vaultwarden-in-a-container
    manual gate.
- **M1 — offline export decrypt.** `vault-core` now ships:
  - `EncString` (Bitwarden type 2: AES-256-CBC + HMAC-SHA-256, Encrypt-then-MAC
    with constant-time verification; legacy types 0/1 explicitly rejected).
  - `kdf::{KdfType, KdfParams}` and `derive_master_key` covering
    PBKDF2-SHA-256 and Argon2id (with Bitwarden's SHA-256 salt preprocessing).
  - `stretch_master_key` — HKDF-SHA-256 expansion of a 32-byte master key
    into a 64-byte `(enc, mac)` pair using the official `info="enc"` /
    `info="mac"` labels.
  - `EncryptedExport` — parser and decryptor for password-protected Bitwarden
    `.json` exports, validating the password against `encKeyValidation_DO_NOT_EDIT`
    before touching the data payload.
  - 9 integration tests covering round-trip, tampering detection, both KDFs,
    wrong-password rejection, and envelope-shape validation.

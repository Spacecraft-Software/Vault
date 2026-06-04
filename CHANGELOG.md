<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Changelog

All notable changes to Vault are documented here. Dates are ISO 8601 UTC per
the Spacecraft Software Standard §12. Vault is pre-1.0; versions in the `0.x`
range may break in any release.

## [Unreleased]

### Added

- **M4 (slice 4) — `--json` on the lifecycle verbs + a real `vault sync`.**
  Closes the two remaining M4 items.
  - `unlock`, `lock`, `sync`, and `stop-agent` now take `--json`. They stay
    **silent on success in human mode** (unchanged — existing pipelines keep
    working); under `--json` each emits a small envelope: `{"unlocked":true}`,
    `{"locked":true}`, `{"stopped":true}`, and for sync
    `{"synced":true,"items":N,"last_sync":"…"}`.
  - `vault sync` now actually re-pulls `/sync` over the unlock-time session and
    replaces the in-memory ciphers, folder map, and `last_sync` stamp (it was an
    M3 stub that only checked the unlocked flag). The agent answers a successful
    re-sync with a fresh `Status` snapshot, so `--json` can report the new item
    count. Parity with `unlock`: only the in-memory vault is refreshed — the
    agent still doesn't write the on-disk `vault-store` cache. Known limitation:
    a `sync` long after `unlock` can `401` once the access token expires (no
    refresh-token flow yet in M4); it surfaces as `IpcError::Network`, same as
    `add`/`edit`/`remove`.
  - The `/sync` → `(ciphers, folders)` decode is factored out of
    `perform_unlock` into a shared `unlock::ciphers_and_folders`, now the single
    spine of both `unlock` and `resync`. Tests: two direct unit tests on that
    function (typed-view decode + malformed-folder skipping); the CLI's
    `cmd_simple` was retired in favour of `cmd_ack` (Ok-only acks) and a
    dedicated `cmd_sync`.

- **M4 (slice 3) — `vault add` + `vault edit`.** The two remaining write verbs,
  the inverse of the read path: caller-supplied plaintext fields are encrypted
  **inside the agent** (the user key never leaves it) and `POST`/`PUT` to the
  server. Login (`--type login`) and secure note (`--type note`) are supported.
  - `vault add <name> [--type login|note] [--username U] [--uri URL]
    [--folder F] [--notes N] [--generate[=LEN]] [--json]`. The password is read
    from stdin or generated locally with `--generate` (printed back so the user
    has it); no `--password` flag, so secrets never enter argv / shell history.
  - `vault edit <selector> [--name|--username|--uri|--folder|--notes ...]
    [--password (stdin)] [--generate[=LEN]] [--json]`. Only the flags you pass
    change; `edit` re-encrypts just those fields onto a clone of the original
    encrypted cipher, so everything it doesn't individually edit — secondary
    URIs, custom fields, organization membership — survives verbatim. `--uri`
    replaces the primary URI and keeps the rest. Folder is resolved by id or
    case-insensitive name.
  - New `vault_core::Cipher::from_plain` (the encryption inverse of `decrypt`),
    `vault_api::BitwardenClient::{create_cipher, update_cipher}` (`POST`/`PUT
    /api/ciphers`, camelCase request body with a `secureNote` marker on type 2),
    `Request::Add` / `Request::Edit` and `Response::Saved { id, name }`, and the
    agent's `add_cipher` / `edit_cipher` (with folder name→id resolution). Tests:
    3 `from_plain` round-trips (`vault-core`); `resolve_folder` and two
    `apply_cipher_edits` cases proving a secondary URI survives an edit (agent);
    and `#[ignore]`d wiremock create/update + secure-note-marker tests (api).

  (`add` + `edit` complete the write verbs; `--json` on the lifecycle verbs and
  the real `vault sync` landed in slice 4 above. M4 feature work is complete —
  the remaining M4 gate is the end-to-end `add → list/get → edit → get → remove`
  run against a real Vaultwarden per `docs/m2-vaultwarden.md`.)

### Fixed

- **`vault-agent` clippy debt from M4 slice 4 (the stale-artifact gremlin,
  again).** A fresh full compile surfaced three findings a warm clippy cache had
  masked at commit time: an `unused_import` (`Error as IpcError` in `server.rs`,
  now only referenced from the test module, so moved there) and two
  `redundant_pub_crate` hits (`unlock::ciphers_and_folders` / `now_iso` are
  `pub` inside a private module, not `pub(crate)`). No behaviour change — purely
  the lints CI's cold compile would have failed on.

- **CI is green for the first time (M0–M3 had been red on every push).** Four
  jobs were failing independently of the code's behaviour:
  - **`clippy -D warnings`** — the workspace lints enable `clippy::pedantic` +
    `clippy::nursery` and deny `unwrap`/`expect`/`panic`, but clippy had never
    run to completion locally (a stale-artifact issue), so the debt was never
    seen. Resolved across every crate: `# Errors` / `# Panics` doc sections,
    `const fn`, `#[must_use]`, let-chains for collapsible `if`s, `map_or`,
    `sort_by_key`, derived `Default`, `Send`/`Sync` bounds on the transport
    generics (`future_not_send`), and justified `#[allow]`s on the
    infallible-HMAC/RNG `expect`s and the civil-calendar casts in
    `vault-agent::unlock`.
  - **`vault --version`** now actually emits the §13.2 attribution block. clap
    only surfaces `after_help` on `--help`, so the block was missing from
    `--version`; it now rides in `long_version` (mirrored in `vault-agent`).
  - **rustfmt** — `cargo fmt --all` applied.
  - **cargo-deny** — two policy decisions, called out explicitly: (1) allow
    `CDLA-Permissive-2.0` (webpki-roots ≥ 1.0 ships Mozilla's CA bundle under
    it — a permissive *data* licence, GPL-compatible, no copyleft on the
    linking program); (2) mark the eight `vault-*` crates `publish = false` and
    set `allow-wildcard-paths = true` so intra-workspace `path` deps stop
    tripping the wildcard ban. A `clippy.toml` permits `unwrap`/`expect`/`panic`
    in tests only.

### Added

- **M4 (slice 2) — `vault remove`.** Soft-deletes a cipher via
  `DELETE /api/ciphers/{id}` and drops it from the in-memory cache. CLI:
  `vault remove <selector> [-f|--force] [--json]`. The selector matches
  `Cipher.id` exactly first, then falls back to a case-insensitive
  decrypted-name match; if a name resolves to more than one cipher the agent
  refuses with `AmbiguousItem` (CLI exit 10) and prints the matching ids so
  the caller can retry with the explicit UUID. Interactive callers must
  re-type the selector to confirm; non-TTY stdin requires `--force`.
  `vault-agent::Vault` now owns the authenticated `BitwardenClient`
  (replacing the dead-code `access_token` field) so future M4 verbs reuse
  one session. New `IpcError::AmbiguousItem { name, ids }` variant; new
  `Response::Removed { id, name }`. Three new tests:
  `resolve_cipher_matches_by_id_then_name`,
  `resolve_cipher_rejects_ambiguous_name` (agent), and an `#[ignore]`d
  wiremock test `delete_cipher_sends_authorized_delete` (api) that asserts
  the `Bearer` header and surfaces 404 as `ServerStatus`.
- **M4 (slice 1) — `vault generate`.** Pure-local password generator with no
  agent or server interaction. `vault-core::generate::generate_password`
  takes a `GenerateOptions` (length + per-class toggles for lowercase,
  uppercase, digits, symbols) and returns a `Zeroizing<String>`. Sampling
  uses OS `getrandom` with 64-bit rejection sampling to avoid modulo bias;
  output is seeded with one character from each enabled class then
  Fisher–Yates shuffled. CLI verb `vault generate [--length N] [--symbols]
  [--no-lowercase] [--no-uppercase] [--no-digits] [--json]`. 8 integration
  tests in `crates/vault-core/tests/generate.rs`.
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

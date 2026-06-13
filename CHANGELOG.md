<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Changelog

All notable changes to Vault are documented here. Dates are ISO 8601 UTC per
the Spacecraft Software Standard §12. Vault is pre-1.0; versions in the `0.x`
range may break in any release.

## [Unreleased]

### Added

- **`vault config` + `vault purge` (PRD §7.1).** A persistent, typed config
  file and the two remaining settings/maintenance verbs.
  - **Config file** at `$XDG_CONFIG_HOME/vault/config.toml`, modeled as a
    *known-key registry*: `vault config set <key> <value>` validates the key
    and parses the value to its type (a typo or non-numeric value is rejected,
    not silently kept), `vault config unset <key>` clears it, and
    `vault config get` with no key lists every known key with its effective
    value (`--json` on all three). Writes are atomic (tempfile + rename).
    Recognised keys this release: `clipboard.clear_secs` and
    `agent.idle_lock_secs` (both `u64`, `0` disables).
  - **Wired into auto-spawn.** When the CLI starts the agent, it sources those
    two knobs from the config and passes them as launch flags — so a saved
    `clipboard.clear_secs` finally has a persistent home instead of being
    flag/env-only. On the auto-spawn path the config value populates the agent
    flag (winning over `$VAULT_CLIPBOARD_CLEAR_SECS`); a manually launched
    agent is unaffected, and a malformed config is reported and skipped rather
    than blocking the spawn.
  - **`vault purge`** drops a running agent's in-memory keys (best-effort
    `Lock`, never auto-spawning) and removes the on-disk item cache
    (`$XDG_DATA_HOME/vault`). Confirmation-gated like `remove` (`--force` to
    skip; required when stdin isn't a TTY); an absent cache is success.
  - CLI-only slice — no protocol, agent, or TUI changes; the agent still
    receives knobs as the launch flags it already accepted. New `toml`
    dependency (MIT/Apache, within the `deny.toml` allow-list).
  - Tests: config registry units (set/get/unset round-trips, unknown-key and
    bad-value rejection, `0` accepted, `KNOWN_KEYS` reachable by all three
    ops, TOML serde round-trip) and a pure `agent_args` test for the
    config→launch-flags mapping (both set / one set / none).

- **Clipboard hardening — clear-on-lock sweep, backend trait, OSC52 fallback,
  configurable interval.** Closes the secret-can-outlive-the-agent limitation
  tracked since the M5 copy slice, and delivers PRD §7.5 in its
  architecturally honest shape.
  - **Clear-on-lock sweep.** The agent remembers the last value it copied
    (`Zeroizing`, dropped once a timer clears it) and `lock()` now sweeps it
    off the clipboard — covering `vault lock`, `Quit`/`stop-agent`,
    idle-lock, and the new **SIGTERM handler** (PRD §7.3: the agent locks,
    sweeps, removes its socket, and exits on SIGTERM). The sweep keeps the
    only-if-still-ours rule: a newer copy by the user is never clobbered.
  - **Backend trait (PRD §7.5).** New `vault-agent/src/clipboard.rs` defines
    a `Backend` trait (`arboard` is the one system implementation; detection
    unchanged) so tests inject a fake clipboard — the sweep logic is now
    exercised end-to-end on headless CI — and a config-selected backend can
    slot in later. `Status` gains a serde-defaulted `clipboard_backend`
    field (`"arboard"` / absent) so clients can see what they're talking to;
    old-agent frames still decode (regression-tested).
  - **OSC52 fallback (client-side, by design).** OSC52 copies by escaping to
    the user's *terminal* — something the detached agent fundamentally cannot
    do, so PRD §7.5's SSH/tmux fallback lives in the TUI: when the agent
    declines with the new typed `Error::ClipboardUnavailable`, the TUI
    fetches the value (id-targeted `Get` — the one path where the secret
    crosses the local UDS, same as `vault get`) and emits the OSC52 sequence
    itself, with tmux DCS-passthrough wrapping when `$TMUX` is set
    (`set-clipboard on` required). The TUI runs its own 30 s timed clear
    (OSC52 `!` payload) while it lives, and sweeps on quit; a generated
    password falls back without any `Get` since it's already local.
  - **Configurable interval.** `vault-agent --clipboard-clear-secs N` (then
    `$VAULT_CLIPBOARD_CLEAR_SECS`, then 30; `0` disables) sets the agent's
    default; `Request::Copy`/`CopyText` still override per call. The new
    `Response::Copied { clear_after_secs }` reports the *effective* window,
    so the TUI's toast now shows the agent's real interval instead of a
    hardcoded 30. The future `vault config` file maps onto the same knob.
  - Tests: fake-backend units for sweep-on-lock, never-clobber-newer-copy,
    and timer/sweep marker interplay; `Status` backend-name reporting;
    interval-resolution precedence; OSC52 sequence/clear/tmux-wrapping
    units; and the old-agent `Status` decode regression.

- **M5 (slice 5) — CLI agent auto-spawn + headless feature gate.** The two
  non-TUI M5 items, closing out the milestone.
  - **Auto-spawn (PRD §7.3).** Any `vault` verb now starts `vault-agent`
    itself when the socket is dead (missing file or stale, connection-refused
    socket — other errors, e.g. permissions, still surface directly). The CLI
    locates the agent via `$VAULT_AGENT_BIN`, then a `vault-agent` sibling of
    the `vault` binary, then `$PATH`; starts it in its own process group
    (`--socket` passed explicitly, stdin/stdout null, stderr appended to
    `agent.log` beside the socket in the 0700 runtime dir); and poll-connects
    until the agent accepts (2 s deadline, 25 ms interval), reusing the first
    accepted stream. Opt out per-call with the global `--no-auto-spawn`;
    `stop-agent` never spawns (stopping a dead agent shouldn't start one).
    New `vault-cli/src/spawn.rs` module; the old "start the daemon with
    `vault-agent &`" hint remains only on the no-spawn paths.
  - **Headless gate (PRD G6).** The `vault` bin now carries
    `required-features = ["cli"]`, making the documented server install
    literal: `cargo install --path crates/vault-cli --no-default-features
    --features cli` (pair with `cargo install --path crates/vault-agent
    --no-default-features` to drop the clipboard's X11/Wayland tree). A new
    CI `headless` job builds both combos so the gate can't rot. README's
    Status and headless sections updated to match reality.
  - Known limitation: two racing CLI invocations can each spawn an agent; the
    second bind steals the socket path (the listener removes a pre-existing
    socket file) and the first agent is orphaned until its idle lock. Benign
    for the single-user posture; a flock around spawn is a possible follow-up.
  - Tests: binary-resolution precedence (override > sibling > `$PATH`,
    empty override ignored), dead-socket error classification, and poll-loop
    behavior (picks up a late listener; gives up at the deadline).

- **M5 (slice 4) — TUI mutations: `a` add, `e` edit, `d` delete (confirm).**
  PRD §7.2's Mutation row goes live, completing the daily-driver loop (browse
  → search → reveal/copy → mutate) without falling back to the CLI. Pure TUI
  slice: the agent's M4 write paths (`Request::Add` / `Edit` / `Remove`) are
  driven as-is — no protocol changes, no agent changes, no new dependencies.
  - **Add (`a`).** A centered form overlay with a Type row (login ⇄ secure
    note, toggled with Space/←/→) over Name / User / Pass / URI / Folder /
    Notes (notes expose only Name / Folder / Notes). Tab/↓ and Shift-Tab/↑
    cycle fields (wrapping); Enter validates (name required) and submits;
    Esc discards. **Ctrl+G in the Pass field** fills it with a fresh
    default-options password (PRD's "generate into the active field" story).
    Values typed under one type survive a toggle, but hidden login fields
    never leak into a secure-note submit.
  - **Edit (`e`).** Same form, prefilled with the metadata the list already
    has (name / username / folder); type is fixed. Submit diffs against the
    prefill: untouched fields ride as "unchanged" on the wire (so an edit
    never re-encrypts a password it didn't see), a cleared field submits
    empty. The selected row's exact cipher id is the selector, so duplicate
    names can't mislead it. An edit with no changes is rejected in-form.
  - **Delete (`d`).** A small confirm overlay (`Delete 'name'? y/N`);
    `y`/Enter sends `Request::Remove` with the exact id, `n`/Esc backs out.
  - On success the vault reloads and a toast reports `saved '…'` /
    `deleted '…'`; on any error the form stays open so nothing typed is lost.
    Opening any mutation overlay re-masks a revealed secret. The unfocused
    Pass field renders masked; form secrets are redacted in `Debug`
    (`FormState` / `FormSubmit`).
  - Known deviation (tracked): PRD §7.2's full CUA bindings
    (Ctrl+C/X/V/Z/S/F) and bracketed paste in text inputs are deferred —
    fields accept typed input only this slice.
  - Tests: 11 new `vault-tui` units (form open/prefill/gating, focus wrap,
    type-toggle value preservation, Ctrl+G targeting, submit diff/validation,
    note-residue exclusion, confirm gating/take/cancel, overlay re-masking,
    `Debug` redaction) plus `TestBackend` smokes for the form overlay
    (masked unfocused Pass) and the confirm overlay.

- **M5 (slice 3) — TUI search, generator overlay, and `:` command line.** The
  three previewed keys go live: `/` filters the item list as you type, `g`
  opens a password-generator overlay, and `:` opens a small vim-style command
  line.
  - **Search (`/`).** Live, case-insensitive substring match on item name and
    username, composed on top of the active folder filter. Enter accepts the
    query (filter stays, shown in the `Items (n) /query` pane title), Esc in
    search mode drops it, and Esc in normal mode peels an active filter back
    before quitting. Every query edit re-anchors the selection and re-masks any
    revealed secret. Arrow keys still move the selection mid-search.
  - **Generator (`g`).** A centered overlay over the browser showing a freshly
    generated password (`vault-core`'s `generate_password`, same engine as
    `vault generate`): `g`/`r` regenerate, `+`/`-` adjust length (clamped
    8–128, Bitwarden's ceiling), `s` toggles symbols, `c` copies, `Esc` closes.
    The password lives in a `GeneratorState` (zeroised on drop, redacted in
    `Debug`).
  - **Copying a generated password** uses a new `Request::CopyText { text,
    clear_after_secs }`: the value rides the local UDS once (exactly like
    `Unlock`'s password already does), and the agent writes it to its own
    clipboard with the same 30-second auto-clear machinery as `Request::Copy`.
    Requires an unlocked agent; headless (`--no-default-features`) builds
    decline it cleanly.
  - **Command line (`:`).** Deliberately tiny vocabulary: `q`/`quit`,
    `r`/`refresh`, `sync` (agent re-pulls `/sync`, list reloads), `lock` (agent
    drops keys, screen flips to the Locked banner). Unknown commands toast the
    vocabulary. The status bar echoes the line being edited (`/query▌` /
    `:cmd▌`) ahead of toasts and hints.
  - Tests: `vault-tui` adds search/compose/re-anchor, command-buffer, and
    generator (defaults, regenerate, clamp, symbols, `Debug`-redaction) units
    plus `TestBackend` smokes for the query title/status echo, command echo,
    and generator overlay; `vault-agent`'s locked-session test now covers
    `CopyText`-while-locked. No new dependencies.

- **M5 (slice 2) — TUI reveal + clipboard copy.** The detail pane is no longer
  secret-free: `Space` reveals the selected login's password on demand and
  `c` / `u` / `o` copy the password / username / URI to the clipboard, with a
  status-bar toast (`copied password · clears in 30s`) and a 30-second
  auto-clear. Copy/reveal act only when the item list is focused.
  - **Clipboard lives in the agent**, not the TUI. A new `Request::Copy { id,
    name, field, clear_after_secs }` has the agent decrypt the field, place it on
    its own clipboard (`arboard`, `wayland-data-control`), and schedule the
    clear — so the secret never crosses the socket on the copy path, the copy
    survives the TUI quitting, and a future `vault get --copy` becomes possible.
    The auto-clear task only wipes the clipboard if it still holds what we wrote
    (or can't read it back, failing safe), leaving anything the user copied since
    untouched. Behind a default-on `clipboard` feature on `vault-agent`; a
    `--no-default-features` headless build drops the X11/Wayland tree and answers
    `Copy` with a clean "not compiled in" error.
  - **Reveal uses `Request::Get`**, which gains an `id: Option<String>` field.
    The TUI targets the *exact* selected cipher id, closing a real footgun:
    `get_item` matched by name only, so a duplicate item name could reveal/copy
    the wrong item. Name remains the fallback selector and error label; the CLI
    passes `id: None` (unchanged behavior). Revealed plaintext is held in a
    `RevealedSecret` newtype (zeroised on drop, redacted in `Debug`) and
    re-masked on any navigation.
  - Tests: `vault-agent` gains an id-targeting-among-duplicate-names regression
    test and a pure `should_clear_clipboard` unit; `vault-tui` adds reveal /
    re-mask / toast / `Debug`-redaction units and `TestBackend` smokes for the
    masked-by-default, revealed, and toast states.
  - Supply-chain: `arboard` pulls `error-code` (`BSL-1.0`, via Windows-only
    `clipboard-win`) — added to `deny.toml`'s allow-list (FSF-confirmed
    GPL-compatible). No new advisories (`cargo deny check advisories` clean).
  - Known limitation: on `Quit` / `stop-agent` a pending auto-clear task dies
    with the runtime, so a just-copied secret can linger on the clipboard until
    overwritten (notably under `wayland-data-control`'s serving process). A
    clear-on-shutdown sweep is a tracked follow-up.

- **M5 (slice 1) — `vault-tui` skeleton (read-only browser).** The TUI stub is
  now a real cruxpass-style three-pane interface (`ratatui` + `crossterm`):
  **left** folder list, **center** filterable item list, **right** item detail,
  with a status bar. It is just another UDS client of the agent — the user key
  never crosses into it — and drives only the existing `Request::Status` +
  `Request::List`, so no IPC change.
  - Requires a pre-unlocked agent; a locked or absent agent shows a centered
    banner (`Locked` / `No agent`). `r` refreshes (re-runs Status + List).
  - Keys: `q`/`Esc`/`Ctrl+C` quit, `j`/`k` + arrows move, `Tab`/`h`/`l` switch
    pane focus. Folder selection filters the item list (`All` / `Unfiled` /
    named folders, derived from the entries). The status bar previews the
    `/ c u o g :` keys as coming-soon so the layout is final.
  - Detail is **read-only and secret-free** this slice: it shows only the
    non-secret `ListEntry` metadata (name, type, username, folder, id) the agent
    already returned — reveal/copy (which need `Request::Get`) land with the copy
    slice. Terminal teardown is RAII + a panic hook, so a panic never leaves the
    terminal in raw mode. `vault-tui --version` carries the §13.2 block.
  - New modules `app` (state + pure nav/filter logic, 6 unit tests), `ui`
    (rendering + a `#RRGGBB`→`Color` theme helper over `vault_theme::steelbore`,
    2 `TestBackend` render smoke tests), and `client` (UDS request helper).
  - Supply-chain: `ratatui`'s tree adds two informational advisories with no fix
    short of dropping ratatui — **RUSTSEC-2024-0436** (`paste`, unmaintained
    build-time proc-macro) and **RUSTSEC-2026-0002** (`lru` 0.12.5, unsound
    `IterMut`, transitive). `paste` is ignored in `deny.toml`; the
    `rustsec/audit-check` CI job ignores both (it fails on any advisory, unlike
    `cargo deny`) and gains `checks: write` so it can post its check-run
    annotations. Both documented with revisit notes.

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

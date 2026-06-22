<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Changelog

All notable changes to Vault are documented here. Dates are ISO 8601 UTC per
the Spacecraft Software Standard §12. Vault is pre-1.0; versions in the `0.x`
range may break in any release.

## [Unreleased]

### Security

- **Interactive secret prompts no longer echo to the terminal.** `vault login`
  / `vault unlock` printed the **master password in clear text** as it was
  typed (visible on screen and in scrollback); the PIN, the `add`/`edit` login
  password, and the card number/CVV and identity SSN/passport/license prompts
  had the same flaw. The CLI now disables terminal `ECHO` for the duration of
  every interactive secret read (a `NoEcho` RAII guard over `rustix::termios`,
  restored on drop — including on error/panic; no new dependency, no `unsafe`).
  Interactive entry now also **submits on Enter** (the master-password path
  previously read until EOF, so a typed password sat until `Ctrl-D`). Piped /
  redirected input is unchanged — `pass show | vault login` still reads the
  whole stream — and non-secret prompts (the register server picker, account
  email, the ephemeral authenticator code) still echo by design.

- **Bumped `quinn-proto` 0.11.14 → 0.11.15 (RUSTSEC-2026-0185).** A remote
  memory-exhaustion (DoS) advisory in `quinn-proto`'s out-of-order stream
  reassembly, published 2026-06-22. `quinn-proto` is a phantom `Cargo.lock`
  entry — an unenabled QUIC/HTTP3 path of `reqwest`; Vault speaks HTTP/2 only,
  so it never enters the build graph and the flaw is unreachable — but
  `cargo audit` scans the lockfile literally, so the patched release is pulled
  in to keep the supply-chain gate green.

### Added

- **EncString fuzz soak passed (PRD §11.4 / RELEASING.md gate #1).** A ≥ 24 h
  libFuzzer soak of the `EncString` type-2 parser completed with **0 findings**:
  8,874,210,317 executions over 86,401 s (~102.7 k exec/s), coverage flat at 312
  blocks, exit 0, `fuzz/artifacts/` empty. The verbatim run is captured in
  `docs/fuzzing-report.md`. First of the v0.1 operational gates cleared; the tag
  still waits on the live PQC handshake and the daily-driver attestation.

- **REUSE compliance (Standard §4.3) + CI gate.** Added `LICENSES/GPL-3.0-or-later.txt`
  and a `REUSE.toml` (a `path="**"` annotation supplying copyright + license in
  bulk, mirroring `construct/`), so every file carries license + copyright info
  and `reuse lint` passes (77/77 files, GPL-3.0-or-later only). A new `REUSE lint`
  CI job enforces it. Satisfies the §5.2 posture requirement for a `LICENSES/`
  directory.

- **`justfile` dev gates.** Recipes mirroring CI exactly — `just fmt` / `clippy`
  (fresh-isolated `-D warnings`, the only form that matches the runner) / `test`
  / `headless` / `version-gate` / `deny` / `audit`, with `just ci` running the
  full set, plus `just fuzz [secs]` and `just pqc`. Encodes the commands from
  `.github/workflows/ci.yml` so they can't drift and are one keystroke.

- **`RELEASING.md` + v0.1 status reconcile.** A maintainer checklist for cutting
  the `v0.1.0` tag (operational gates → mechanical version bump / CHANGELOG date
  / signed tag), and PRD §11–§12 annotated with each criterion's status. Docs
  only — no version bump or tag yet (those wait on the operational gates).

- **Scrolling detail pane.** The detail pane now scrolls to keep the focused
  field visible — the granular identity view is ~18 fields and could overflow a
  shorter terminal. Reuses the form's `scroll_offset`; only the detail-focused
  view scrolls (browsing is unchanged).

- **Granular identity field selectors.** 16 new `--field` selectors expose every
  identity field individually — `identity-{title,first-name,middle-name,
  last-name,username,company,ssn,passport,license,address1,address2,address3,
  city,state,postal,country}` — alongside the existing composed `identity-name`
  / `identity-address`. `vault get … --field identity-ssn` now works, and the
  TUI identity detail pane shows the full granular set so per-field reveal/copy
  reaches every field (SSN/passport/license masked, revealed on demand like the
  card CVV). Same proto → agent → CLI → TUI shape as the `card-*` selectors.

- **TUI per-field reveal/copy in the detail pane.** The detail pane is now
  focusable (`Tab` cycles folders → items → detail): with it focused, `j`/`k`
  move a field cursor and `Space`/`c` reveal/copy the **selected** field — so the
  **card CVV** (and any non-primary field) can finally be revealed and copied,
  not just the item's primary field. Masked fields (card number/CVV) still fetch
  only on reveal. Item-list `Space`/`c` keep hitting the primary field. Cards and
  identities get the field cursor; logins keep their `c`/`u`/`o`/`t` keys.

- **TUI form scrolling + full identity editing.** The add/edit form overlay now
  **scrolls** (a viewport that keeps the focused row visible; the keybind footer
  stays fixed, with a `↕` cue when there's more). This retires the curated
  10-field identity limit: the TUI identity form now edits the **full 18-field
  set**, including the SSN/passport/license secrets (masked while unfocused, like
  the card number/CVV; redacted in any `Debug`). Pure `vault-tui` — the
  `IdentityWrite` backend already carried all the fields.

- **`card-cardholder` field selector.** `vault get <card> --field card-cardholder`
  now returns the cardholder name, and the TUI detail pane shows a `Holder` line
  — which also lets the TUI card **edit** form prefill the cardholder (it
  previously started blank, as there was no read selector). Closes the
  card edit-prefill gap from the card-write / TUI-card slices.

- **`mlock` the user keys (no swap exposure).** The agent's unwrapped user keys
  (`user_enc`/`user_mac`) are now wrapped in a `SealedKey` newtype that boxes the
  bytes for a stable address and `mlock`s their page(s) so they can't be paged to
  a swap file, completing the agent memory-hygiene hardening (core dumps + ptrace
  already covered). Surgical (only the key pages, never the whole process → no
  `RLIMIT_MEMLOCK`/OOM risk) via the safe `region` crate, keeping
  `#![forbid(unsafe_code)]`; best-effort (a refused lock logs nothing and the key
  is still zeroized). `SealedKey` derefs to `[u8; 32]`, so the encrypt/decrypt
  call sites are unchanged; it zeroizes while still locked, then unlocks, on drop.

- **Agent anti-leak hardening (core dumps + ptrace).** On startup the agent now
  disables core dumps and marks itself non-dumpable (which also blocks same-user
  ptrace), so the in-memory user key / refresh token can't leak to a core file
  or a debugger. Done via the `secmem-proc` crate (audited `rustix` syscalls,
  keeps the agent's `#![forbid(unsafe_code)]`); best-effort — a sandbox that
  restricts `setrlimit` logs a warning and the agent keeps running. PRD §12 M7
  hardening groundwork. (`mlock`/no-swap remains a tracked follow-up.)

- **Post-quantum transport (`pqc` feature, off by default).** A GPL-clean hybrid
  **X25519MLKEM768** key-exchange group is added to the rustls client config, so
  a TLS 1.3 handshake negotiates a post-quantum-secure secret when the server
  offers it (silent classical fallback otherwise). The classical half reuses
  ring's X25519; the PQ half is RustCrypto `ml-kem` (Apache-2.0/MIT) — *not*
  aws-lc-rs, whose OpenSSL-licensed AWS-LC is GPL-incompatible. Build with
  `cargo build -p vault-agent --features pqc`; see `docs/pqc.md`. Satisfies the
  PRD §12 M7 "PQC transport feature flag" item (`vault-api/src/pqc.rs`, client
  role only). Tests cover the ML-KEM client kx round-trip + the hybrid layout.

- **`EncString` parser fuzz harness.** A cargo-fuzz / libFuzzer target
  (`fuzz/fuzz_targets/enc_string_parse.rs`) for the security-critical Bitwarden
  "type 2" parser — feeds arbitrary input to `EncString::parse` and asserts the
  parse → serialize → parse round-trip is stable. Lives in a standalone `fuzz/`
  workspace (nightly + sanitizer only), so the CI gates are untouched; run with
  `cargo +nightly fuzz run enc_string_parse` (see `docs/fuzzing.md`). Groundwork
  toward the PRD §11.4 / M7 `v0.1` gate (the ≥ 24 h soak is a maintainer step).

- **TUI identity create/edit (curated).** The `vault-tui` add/edit form (`a`/`e`)
  now composes identity (type 4) items — the **Type** row cycles `login → secure
  note → card → identity`. To fit the non-scrolling overlay it edits a curated
  10-field subset (title, first/last name, email, phone, address1, city, state,
  postal code, country); the long-tail fields and the SSN/passport/license
  secrets stay CLI-only. On edit, email/phone prefill from the detail pane (the
  composite Person/Address lines can't be split back, so those start blank =
  leave unchanged). Builds the existing `IdentityWrite` on `Request::Add`/`Edit`
  — no backend change. With this, **all four cipher types are editable from both
  front-ends.** Tests: identity add carries the curated fields, identity edit
  prefill/diff, 4-way type-toggle cycle.

- **Create/edit identity ciphers.** `vault add … --type identity` and `vault
  edit` now build/update identity (type 4) items — the last cipher type to get a
  write path. The 15 non-secret fields (title, names, username, company, email,
  phone, address1–3, city, state, postal code, country) are flags; the three
  sensitive fields — **SSN, passport, license** — are prompted on the controlling
  terminal when their bool flag (`--ssn`/`--passport`/`--license`) is set (never
  argv). The identity username is `--identity-username` (the bare `--username` is
  the login field). Editing identity fields on a non-identity item is rejected.
  - `vault-core`: `from_plain` emits an `Identity` for type 4. `vault-ipc`: a
    typed `IdentityWrite` (ssn/passport/license as zeroized `Vec<u8>`, redacted
    `Debug`) on `Request::Add`/`Edit` (serde-defaulted). `vault-agent`:
    `add_cipher` builds a `PlainIdentity`; `apply_cipher_edits` sets only the
    given identity fields. Tests: `from_plain`→`decrypt` identity round-trip;
    `apply_cipher_edits` identity partial-update; `IdentityWrite` transport +
    `Debug`-redaction.
  - This unblocks **identity TUI editing** (the next follow-up) — the backend it
    needed now exists.

- **TUI card create/edit.** The `vault-tui` add/edit form (`a`/`e`) now composes
  card (type 3) items, not just logins and secure notes. The **Type** row cycles
  `login → secure note → card`; the card rows are cardholder/brand/number/expiry
  (one `MM/YYYY` field, split on submit)/CVV, with number and CVV masked while
  unfocused. On edit, brand/expiry prefill from the detail pane's on-select fetch
  and secrets start blank (blank = leave unchanged). Builds the existing
  `CardWrite` payload on `Request::Add`/`Edit` — no backend change. Identity TUI
  editing stays pending (no identity write path yet). Tests: card add carries
  split expiry + redacts secrets, card edit prefill/diff, `parse_expiry`.

- **Create/edit card ciphers.** `vault add … --type card` and `vault edit`
  now build/update card (type 3) items: cardholder/brand/expiry via flags, the
  **number and CVV prompted on the controlling terminal** (`/dev/tty`, never
  argv — so they don't leak to shell history / `ps`). `--expiry` takes
  `MM/YYYY` or `MM/YY`; on edit, `--number`/`--code` re-prompt those secrets.
  Editing card fields on a non-card item is rejected.
  - `vault-core`: `from_plain` emits a `Card` for type 3. `vault-ipc`: a typed
    `CardWrite` (secrets as zeroized `Vec<u8>`, redacted `Debug`) on
    `Request::Add`/`Edit` (serde-defaulted). `vault-agent`: `add_cipher` builds
    a `PlainCard`; `apply_cipher_edits` sets only the given card fields (others
    preserved).
  - Identity create/edit remains the tracked follow-up (read-only for now).
    Tests: `from_plain`→`decrypt` card round-trip; `apply_cipher_edits` card
    partial-update; `CardWrite` transport + `Debug`-redaction; CLI `split_expiry`.

- **TUI card/identity detail render.** Selecting a card or identity in
  `vault-tui` now shows its fields in the detail pane: card brand/expiry with a
  masked number (`Space` reveals it, re-masked on navigation) and masked CVV;
  identity name/email/phone/address. `c` copies the primary field per type (card
  number / identity email / login password); `Space` reveals the primary secret
  (card number / login password). Non-sensitive fields are fetched on select via
  the existing `Request::Get`; the card number/CVV are fetched **only on reveal**
  — no card secret enters the TUI until asked. No proto/agent/core change
  (reuses the PR #23 `Field` selectors). This completes card/identity support
  end-to-end (CLI + TUI). Tests: `primary_secret_field`/`primary_copy_field`
  units + `TestBackend` renders for card (masked number, revealed) and identity.

- **Card & identity cipher types (read, CLI).** `vault-core` now models card
  (type 3) and identity (type 4) ciphers — full field sets, decrypted into
  `PlainCard`/`PlainIdentity` (sensitive fields zeroized on drop) via new
  `DecryptOptions { card, identity }`. New `Field` selectors —
  `card-number`/`card-brand`/`card-expiry`/`card-code` and
  `identity-name`/`identity-email`/`identity-phone`/`identity-address` — make
  them readable: `vault get <item> --field card-number`. The agent composes the
  derived ones (`card-expiry` → `MM/YYYY`; `identity-name`/`-address` joined).
  Rendering them in the TUI detail pane is the next slice (the list path only
  carries name/username today). Tests: vault-core card/identity decrypt;
  vault-agent `get_item` card-number/expiry + `NoSuchField`; vault-ipc `Field`
  round-trip. No new deps.

- **Live TOTP codes from login ciphers.** A login's stored `totp` field (an
  `otpauth://totp/…` URI or a bare base32 secret) now yields the **current RFC
  6238 code** rather than the raw secret: `vault get <item> --field totp` prints
  it, and the TUI's new `t` key copies it. The code is generated in the agent,
  so the secret never crosses the socket. New `vault-core::totp` module
  (HOTP/dynamic-truncation, hand-rolled base32, otpauth parsing; SHA1 default +
  SHA256/SHA512) behind the one new dep `sha1`. RFC 6238 vector + base32 + parse
  unit tests; an agent test that `Field::Totp` returns a 6-digit code (not the
  secret). `Field::Totp` / `FieldArg::Totp` already existed — only the value
  changed and the `t` key was added.

- **Interactive TOTP two-factor auth.** A 2FA-enabled account is no longer a
  dead end on the password grant: on `Error::TwoFactorRequired`, prompt for the
  authenticator code and resubmit the token grant with it.
  - `vault-api`: `login_password` gains `two_factor: Option<&TwoFactor>` and
    appends `twoFactorToken`/`twoFactorProvider`/`twoFactorRemember`; a wrong
    code re-challenges so the caller re-prompts.
  - `vault-ipc`: `TwoFactorCode` + serde-defaulted `two_factor` on
    `Request::Unlock` (forward-compatible). `vault-agent` threads it into the
    password grant (provider `0` = authenticator).
  - `vault-cli`: `vault login`/`unlock` resubmit on a challenge, reading the
    code from the **controlling terminal** (`/dev/tty`) so it works even with
    the password piped to stdin; `--totp` / `$BW_TOTP` supply it non-
    interactively. `vault-tui`: an "Authenticator code" step in the unlock
    screen (stashes the password, resubmits with the code).
  - Scope: the authenticator/TOTP provider only; other providers (email, Duo,
    WebAuthn) and "remember this device" are future work. An API key still
    bypasses 2FA entirely.
  - Tests: `vault-api` wiremock challenge→resubmit; `vault-ipc` transport
    round-trip; `vault-tui` `begin_2fa`/request-with-code units.

- **`tui.vim` — vim jump motions in the TUI.** Opt-in (`vault config set tui.vim
  true`): on top of the default `hjkl`, the browser gains `gg` (top), `G`
  (bottom), and `Ctrl-d`/`Ctrl-u` (half-page; a fixed step — the pure-render
  `App` has no viewport height). Because `g` becomes the `gg` prefix in vim
  mode, the generator overlay moves from `g` to `Ctrl-g`; non-vim mode is
  unchanged (`g` opens the generator). Read by `vault-tui` directly (not relayed
  to the agent). New `App` motions (`move_top`/`move_bottom`/`page_up`/
  `page_down`, reusing the focus-aware re-masking `move_*` pattern) + a `gg`
  prefix state machine. Completes the PRD §7.1 config registry. Tested in
  `vault-config` (round-trip / reject / not-an-agent-flag) and `vault-tui` (jump
  + clamp + empty-list no-op + the `gg` arm/take sequence).

- **`ui.reduced_motion` config key (reserved).** Completes the PRD §7.1 config
  registry with the accessibility preference to suppress animated TUI elements.
  The TUI has no animations yet (it's fully event-driven — no spinner, no
  lock-countdown, no blink), so the key is **inert groundwork**: `vault-config`
  records/validates it and `vault-tui` populates an `App.reduced_motion` flag
  from it, ready for a future spinner / lock-countdown to honor without
  re-plumbing. It's a TUI-rendering preference, read by the TUI directly (not
  relayed to the agent). Tested in `vault-config` (round-trip, rejects
  non-booleans, never emitted as an agent flag).

- **TUI About overlay.** `vault-tui` gains a read-only About screen (open with
  `?` or `:about`, dismiss with `Esc`/`q`) showing the version, maintainer,
  copyright/license, and canonical URL — rendered from the same
  `ATTRIBUTION`/`PKG_VERSION` constants as `vault-tui --version`, so it can't
  drift. This was the last unfilled v0.1 success criterion that the Standard
  §13.2 block appears "in `--version`, `--help`, README, **and the TUI About
  screen**" (PRD §14). New `InputMode::About` + `render_about` (modeled on the
  generator overlay); a `TestBackend` test asserts the §13.2 content reaches the
  screen.

- **`clipboard.backend` selection.** New config key choosing how the TUI's copy
  keys reach a clipboard: `auto` (default — native `arboard`, else the TUI falls
  back to OSC52), `arboard` (force native; warns if unavailable), or `osc52`
  (the agent declines so the TUI copies through the terminal via an OSC52
  escape — for SSH/tmux, so copies land on the *local* machine). The agent
  can't emit OSC52 itself (no terminal); `osc52` just makes it step aside for
  the TUI's existing client-side path.
  - `clipboard::BackendChoice` + `select()` (wrapping the existing `detect()`);
    a `--clipboard-backend` flag (defined unconditionally so a headless agent
    accepts it as a no-op) flowing from the config like the other keys.
    `vault status` reports `osc52` even with no native backend held.
  - Tests: `vault-config` validation/round-trip + `agent_args` emission;
    `BackendChoice` `as_str`/default, `select(osc52)` is `None` (CI-safe), and a
    `Status` test for the `osc52`-mode label.

- **Scheduled background sync.** New `sync.interval_secs` config key: while
  unlocked, the agent re-pulls `/sync` on that cadence (a `tokio` interval task,
  `server::scheduled_sync_loop`), refreshing the in-memory vault and the
  encrypted on-disk cache so it never drifts from the server and an offline/PIN
  unlock later reads fresh data — no manual `vault sync`. `0`/unset disables.
  - Reuses `AgentState::resync` wholesale; best-effort — a `Locked` / `Offline`
    / network result is logged and skipped. It deliberately does **not**
    `touch()`, so background syncs never defer the idle-lock countdown.
  - Flows config → auto-spawn flag (`--sync-interval-secs`) like
    `idle_lock_secs`; takes effect on the next agent spawn. `last_sync` (already
    in `vault status`) surfaces freshness — no protocol change.
  - Tests: `vault-config` get/set/unset + `agent_args` flag emission; an agent
    invariant test that a locked `resync` is a clean `Locked` no-op and doesn't
    move `last_activity`.

- **Session resume across agent restart (opt-in, Linux).** With the new
  `agent.session_keyring` config key, an unlock mirrors the user key into the
  Linux **kernel session keyring** (kernel memory — never on disk, never
  swapped, possessor-gated, evicted on logout). A restarted agent (crash,
  `SIGTERM`, `stop-agent` + auto-spawn) reads it back and resumes **unlocked
  without the master password**, bounded by the idle-lock TTL: the keyring entry
  carries a kernel timeout (refreshed on activity, throttled), so a dead agent's
  session self-expires.
  - Lock semantics split: explicit `vault lock` and idle-lock **clear** the
    keyring (durably locked); `stop-agent`/`SIGTERM`/crash leave it so the next
    agent resumes. `AgentState::lock` (in-memory wipe) vs the new
    `lock_and_clear_session`.
  - New `crates/vault-agent/src/session.rs` over the pure-Rust `linux-keyutils`
    crate (`[target.'cfg(target_os = "linux")']`, MIT/Apache-2.0); a no-op stub
    elsewhere. `main.rs` attempts resume at startup via the existing
    `unlock::load_cache` + `vault_from_user_key` path.
  - `vault config set agent.session_keyring true` (flows to the auto-spawned
    agent as `--session-keyring`, mirroring `idle_lock_secs`).
  - This is the sole, **default-off** carve-out to PRD §7.3 / G4 ("master key
    never resident outside the agent process"); documented in PRD §7.3. Off, the
    key never leaves the process. Linux-only — a no-op everywhere else.
  - Tests: `SessionBlob` serde round-trip (cross-platform) + a keyring
    store/load/clear round-trip that skips gracefully where no keyring exists;
    `vault-config` `agent.session_keyring` get/set/unset + `agent_args` flag
    emission.

- **Bitwarden personal API-key authentication (2FA accounts).** A new auth path
  that uses the OAuth2 `client_credentials` grant, which is *not* 2FA-challenged
  — so an account with two-factor auth enabled can finally authenticate without
  an interactive TOTP prompt (Vault has no TOTP entry). The API key authenticates
  the *session* only; the `Key` it returns is still wrapped under the stretched
  master key, so **the master password is still required at every unlock** to
  decrypt the vault.
  - `vault login --api-key`: reads `$BW_CLIENTID` / `$BW_CLIENTSECRET` (matching
    the official `bw` CLI), else prompts, then reads the master password. On
    success the agent authenticates via `client_credentials` and **persists the
    key** (0600 `apikey.json` in the account data dir) so plain `vault unlock`
    (and the TUI unlock) auto-reuse it — no 2FA, no re-supplying creds.
  - `vault apikey status` / `vault apikey forget` manage the stored key (status
    echoes only the non-secret `client_id`; forget falls back to the password
    grant).
  - `vault-api`: `BitwardenClient::login_api_key` (`grant_type=client_credentials`,
    `scope=api`). `vault-store`: `ApiKeyCreds` + `save`/`load`/`delete_apikey_to_dir`
    (atomic, 0600, custom `Debug` that redacts the secret). `vault-ipc`: optional
    `api_key` on `Request::Unlock` (serde-defaulted, forward-compatible) plus
    `ApiKeyStatus` / `ApiKeyForget` verbs and an `ApiKeyStatus` response (never
    carries the secret). `vault-agent`: grant selection (request creds → persisted
    key → password) with persistence on enrollment, and `ensure_online` now falls
    back to API-key re-auth — so a PIN/offline session of an API-key account can
    still go online for `sync`/edits even when the grant issued no refresh token.
  - The key is protected at rest by filesystem permissions (0600) only: it must
    be readable *before* unlock (it's used during auth), so it can't be wrapped
    under the user key — the same trust level as the stored refresh token.
  - Tests: `vault-api` wiremock for the `client_credentials` form + a bad-key
    `ServerStatus`; `vault-store` round-trip / delete / `NotFound` / 0600-mode /
    Debug-redaction units; `vault-ipc` transport round-trips (`api_key` present
    + absent-decodes-to-`None`, `ApiKeyStatus`). No new external dependencies.

- **TUI in-place unlock.** When the agent is locked, `vault-tui` no longer
  dead-ends at a "run `vault unlock`" banner — it shows an interactive unlock
  prompt for the registered account: type the master password, or `Tab` to a
  PIN when one is enrolled, and drop straight into the browser. Reuses the
  readline `TextInput` (secret masked with `•`) and the existing
  `Unlock`/`UnlockPin` requests — no protocol or agent changes; failed unlocks
  show the error (incl. `BadPin { attempts_remaining }` / `PinLockedOut`) and
  clear the field.
  - To read the account (server/email/device_id) — which a *locked* agent
    doesn't report — `config.rs` was extracted from `vault-cli` into a shared
    **`vault-config`** crate, now used by both the CLI and the TUI (single
    source of truth for `config.toml`; the agent still doesn't read config).
  - Tests: `vault-config`'s units moved with it; new `vault-tui` units for
    `UnlockState::request` (password vs PIN), `toggle_pin` (no-op without
    enrollment, clears on switch), `unlock_failed`, and a `TestBackend` smoke
    that the unlock screen shows the account, masks the secret, and offers the
    `Tab` hint only when a PIN is enrolled. No new external dependencies.

- **Token persistence + refresh.** The OAuth2 refresh token is now kept and
  reused, so a cache/PIN/offline session can become fully capable and a
  long-lived session survives access-token expiry.
  - `vault-api`: `BitwardenClient` keeps the `refresh_token` from
    `login_password`, exposes it (`refresh_token()`), and can be seeded with one
    (`with_refresh_token`). New `refresh()` runs `grant_type=refresh_token`. The
    four server ops (`sync`/`create`/`update`/`delete`) route through one
    `send_with_auth` helper that, on a `401` with a refresh token held,
    refreshes once and retries.
  - The refresh token is persisted **encrypted under the user key** in the cache
    (`refresh_token` envelope field) on online unlock + every `sync`, and
    recovered into the in-memory session on a cache/PIN unlock.
  - New `Vault::ensure_online`: a token-less session (offline / PIN) **lazily
    upgrades** to online on its first `sync`/`add`/`edit`/`remove` by building a
    client from the stored refresh token and refreshing — so PIN unlock stays
    fast/offline but server ops "just work" when the network is up. A genuinely
    offline box (or no stored refresh token) still returns `Error::Offline`.
  - Tests: store refresh-token round-trip; `ensure_online` returns `Offline`
    without a client/token and `Ok` with a live client; refresh-token recovery
    from the cache on offline unlock. No new dependencies.

- **PIN unlock.** Unlock the vault with a short PIN instead of the master
  password (like the Bitwarden extension/desktop), built on the encrypted cache.
  - `vault pin set` (requires an unlocked agent) encrypts the user key under a
    key derived from the PIN — same KDF/stretch/`EncString` crypto as the
    master path, PIN as the secret, email as salt — and stores it as
    `pin_protected_user_key` in the cache (envelope schema 3). `vault pin
    disable` forgets it; `vault pin status` reports enabled + attempts left.
  - `vault unlock --pin` recovers the user key from the cache with the PIN and
    builds a **read-only** session (no token — `sync`/`add`/`edit`/`remove`
    return `Error::Offline`, like an offline unlock). Plain `vault unlock`
    stays master-password.
  - **Lockout:** wrong PINs are counted in the cache (so the limit survives an
    agent restart); the 5th wrong PIN wipes `pin_protected_user_key` and
    returns `PinLockedOut` — re-enable after a master-password unlock. Wrong
    PINs before that return `BadPin { attempts_remaining }`. New typed errors
    `BadPin` / `PinLockedOut` / `PinNotSet` (CLI exit codes 12/13/14). PIN must
    be ≥ 4 characters (validated client-side).
  - The cache→vault recovery core is shared between the offline-master and PIN
    paths (`recover_user_key` + `vault_from_user_key`); the attempt/lockout
    logic is a pure `pin_attempt` over an in-memory cache, with a thin
    disk-backed `unlock_pin` wrapper.
  - Tests: store pin-field round-trip; pure `pin_attempt` lifecycle (recover →
    reset counter → 5-strike lockout + key wipe → stays locked), `PinNotSet`
    with no enrollment, and `pin_protect_user_key` ↔ `recover_user_key`
    round-trip. No new dependencies.
  - Out of scope (tracked): TUI PIN entry; a PIN/offline session syncing once
    token persistence lands; Bitwarden's "require master password on restart"
    (memory-only pin key) mode.

- **Encrypted-cache persistence + offline unlock.** The agent now writes its
  vault to disk and can unlock without the network — the substrate for the
  upcoming **PIN unlock** (and useful on its own).
  - On an online `unlock` (and every `sync`), the agent persists
    `$XDG_DATA_HOME/vault/<account>/cache.json` (`<account>` = sanitized
    `host_email`): the `/sync` response encrypted under the user key, plus the
    `protected_user_key` (the login token `Key` — the user key encrypted under
    the master-stretched key, safe at rest) and the account `kdf` params.
    `vault-store` was already built for this but had never been wired in;
    `VaultCache` is now schema 2 (new fields are serde-defaulted, so any older
    file still loads).
  - **Offline unlock:** when a live login fails with a network error and a
    cache exists, `unlock` falls back to the cache — re-derives the master key
    locally from the cached KDF params, decrypts the `protected_user_key` (the
    EncString MAC check detects a wrong password → `BadPassword`), and loads
    ciphers from the encrypted payload. Bad password / 2FA still propagate (no
    fallback). Unlock now survives restart and works without connectivity once
    you've unlocked online once.
  - An offline session has **no access token**, so `Vault.client` is `None` and
    sync / add / edit / remove return the new typed `Error::Offline`
    ("unlock again while online…", CLI exit code 11). Read paths (status /
    list / get / copy / TUI browse) work fully from cache. (Local mutations
    don't re-persist the cache yet, so it can lag edits until the next
    `sync` — tracked.)
  - Tests: `KdfParams` serde round-trip; `VaultCache` protected-key + kdf
    round-trip and legacy-v1 load; a pure `unlock_from_cache` recovery +
    wrong-password rejection; `account_dir_name` sanitization; and the
    offline-session `Error::Offline` gating. No new dependencies.

- **TUI text-input editing — readline keys + bracketed paste (PRD §7.2).** The
  `/` search, `:` command line, and every add/edit form field were
  append/backspace-only `String`s with no cursor and no paste. They now share a
  `TextInput { buf, cursor }` with real line editing:
  - Cursor movement `←`/`→`/`Home`/`End` (+ `Ctrl+A`/`Ctrl+E`), `Delete` at the
    cursor, and insert anywhere — fix a mid-word typo without deleting back to it.
  - Kill/yank into a shared kill-ring: `Ctrl+W` (word back), `Ctrl+U` (to start),
    `Ctrl+K` (to end), `Ctrl+Y` (yank).
  - **Bracketed paste** (`EnableBracketedPaste` + `Event::Paste`): paste a value
    from the system clipboard — including over SSH/tmux — at the cursor;
    newlines are stripped (every input is single-line).
  - `Ctrl+S` submits the add/edit form (PRD §7.2 *save*). On the form's Type
    row `←`/`→`/`Space` still toggle login⇄note; cursor keys edit only in text
    fields. The caret renders where edits land (`gi▌t`), not just at the end.
  - **`Ctrl+C` remains the global quit** — a deliberate deviation from §7.2's
    literal `Ctrl+C`=copy: there's no selection model, and quit-safety/muscle
    memory win. Deferred (tracked): selection + `Ctrl+C`/`X`/`V`/`Z`
    copy/cut/paste/undo, and reading the agent clipboard back for paste.
  - TUI-only — no protocol, agent, CLI, or dependency changes (crossterm 0.28
    already exposes the paste API). Tests: `TextInput` units (insert/delete at
    cursor, nav clamping, kills return removed text, paste at cursor, UTF-8
    boundary safety), kill→yank round-trip, paste-into-focused-field,
    search-edit re-anchor, and a mid-string caret `TestBackend` smoke.

- **`vault register` + `vault login` — account profile (PRD §7.1).** The last
  two unimplemented verbs, as an account-profile flow (not the Bitwarden
  personal API-key model, which stays a tracked follow-up).
  - **`register`** records the account — server, email (lower-cased), and a
    freshly minted stable `device_id` — into a new `[account]` table in
    `config.toml`. No agent or network (a light `http(s)://` check is the only
    validation; real errors surface at first `login`). Re-registering keeps the
    existing `device_id`.
  - **`login`** authenticates against the registered account (master password →
    `Request::Unlock`) and ends on a sync summary
    (`logged in as <email> · <n> items · synced <ts>`, or `--json`). It
    auto-spawns the agent, so a cold `vault login` brings everything up.
  - **`unlock`** now resolves `server`/`email` from the profile too, so its
    flags (and `$VAULT_SERVER`/`$VAULT_EMAIL`) are optional once registered;
    precedence is explicit flag/env → profile → error. `login` and `unlock`
    share one `Request::Unlock` — the difference is resolution and `login`'s
    verbose, status-backed success.
  - **Stable device id.** `Request::Unlock` gains a serde-defaulted
    `device_id: Option<String>`; the agent uses it as the Bitwarden
    `deviceIdentifier` instead of minting a fresh UUID each unlock, so the
    account stops accumulating a new device per session. Old `Unlock` frames
    without the field still decode (regression-tested).
  - Tests: `[account]` round-trip + "no empty table until set" + device-id
    mint/preserve + email lower-casing; `resolve_account` precedence
    (flag → profile → error); the `Unlock` device-id round-trip and
    old-frame-decode regression. New `uuid` dep on `vault-cli` (already in the
    workspace tree).

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

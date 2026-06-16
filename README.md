<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Vault

> Terminal-native Bitwarden client — cruxpass-style TUI and rbw-style CLI on a
> shared Rust engine.

Vault is a single-user Bitwarden client built in Rust. It ships two
front-ends — a full-screen TUI and a scriptable CLI — coordinated by a
long-lived agent daemon that holds the decrypted master key in locked,
zeroizable memory. Vault works against Bitwarden's hosted service and against
self-hosted [Vaultwarden](https://github.com/dani-garcia/vaultwarden).

The full product requirements live in [`PRD.md`](./PRD.md).

## Status

Pre-alpha, M5. The read and write paths are wired end-to-end against a live
agent: `status` / `unlock` / `lock` / `sync` / `list` / `get` / `add` /
`edit` / `remove` / `generate` / `stop-agent` on the CLI (with `--json`
everywhere), and a three-pane `vault-tui` with search, reveal/copy
(agent-side clipboard, 30 s auto-clear), a generator overlay, a `:` command
line, add/edit/delete, and an About overlay (`?` / `:about`). The CLI
auto-starts the agent when needed, and
once you've unlocked online at least once, `unlock` also works **offline**
from an encrypted local cache (read/copy from cache; sync and edits need the
network). See [PRD §12](./PRD.md#12-milestones) for the roadmap (M0 → v0.1)
and [`CHANGELOG.md`](./CHANGELOG.md) for per-slice detail.

## Build

```sh
cargo build --release
./target/release/vault --version
```

Headless install (no TUI dependencies; the agent additionally drops the
clipboard's X11/Wayland tree):

```sh
cargo install --path crates/vault-cli --no-default-features --features cli
cargo install --path crates/vault-agent --no-default-features
```

The CLI auto-starts `vault-agent` when the socket is dead: it looks for a
sibling of the `vault` binary, then `$PATH` (override with
`$VAULT_AGENT_BIN`; opt out per-call with `--no-auto-spawn`). A spawned
agent logs to `agent.log` beside the socket.

The security-critical `EncString` parser has a cargo-fuzz harness under `fuzz/`
(a standalone workspace, run on nightly) — see [`docs/fuzzing.md`](docs/fuzzing.md).

An optional **post-quantum transport** (`--features pqc`) prefers the hybrid
X25519MLKEM768 key exchange on the HTTPS client, off by default — see
[`docs/pqc.md`](docs/pqc.md).

The agent hardens itself at startup: it **disables core dumps and ptrace** (so
the in-memory user key can't leak to a core file or a debugger) and **`mlock`s
the user-key pages** so they're never swapped to disk — on top of the `0600`
socket and zeroized key buffers.

## Getting started

```sh
vault register --server https://vault.example.org --email me@example.org
vault login      # master password → authenticate + confirm a sync
vault list       # browse; server/email come from the registered profile
```

`register` records the account (server, email, and a stable device id) in the
config file; `login` and `unlock` then resolve those from the profile, so their
`--server`/`--email` flags (and `$VAULT_SERVER`/`$VAULT_EMAIL`) are optional
once registered. `login` is the first-time "authenticate and verify sync";
`unlock` is the routine "hand the agent my key again".

If the account has two-factor auth, `login`/`unlock` prompt for your
**authenticator (TOTP) code** after the password (read from the controlling
terminal, so it works even with the password piped in); supply it up front with
`--totp 123456` or `$BW_TOTP` for scripts. The TUI shows an "Authenticator code"
step in its unlock screen. An [API key](#api-key-login-2fa-accounts) skips the
2FA prompt entirely; only the authenticator provider is supported so far.

### TOTP codes

If a login stores a TOTP secret, Vault generates the **live one-time code** on
demand — the stored secret stays in the agent; only the short code crosses out:

```sh
vault get github --field totp     # -> 123456 (rolls over every 30 s)
```

In the TUI, press `t` to copy the current code for the selected item. Standard
authenticator secrets are supported (`otpauth://totp/…` URIs or a bare base32
secret; SHA1/SHA256/SHA512).

### Cards & identities

Card (type 3) and identity (type 4) ciphers are readable from the CLI via
`--field`:

```sh
vault get visa --field card-number     # also: card-cardholder, card-brand, card-expiry, card-code
vault get me   --field identity-email  # also: identity-name, identity-phone, identity-address
```

In the TUI, selecting a card or identity shows its fields in the detail pane:
card holder/brand/expiry with the number and CVV masked; identity
person/email/phone/address. With the item list focused, `Space` reveals the
primary secret and `c` copies the primary field (card number / identity email /
login password). **`Tab` into the detail pane** to navigate fields with `j`/`k`
and reveal (`Space`) or copy (`c`) the **selected** field — including the card
CVV. Masked values (number, CVV) are fetched only on reveal, so no card secret
enters the TUI until you ask.

Create a card with `vault add … --type card` — the non-secret fields are flags;
the number and CVV are prompted on the terminal (never argv, so they don't leak
to shell history / `ps`):

```sh
vault add "My Visa" --type card --brand Visa --expiry 04/2030
#   Card number: …
#   CVV (leave empty for none): …
vault edit "My Visa" --expiry 05/2031 --code   # --code re-prompts the CVV
```

`--expiry` accepts `MM/YYYY` or `MM/YY`. Editing card fields on a non-card item
is rejected.

Create an identity with `vault add … --type identity` — the non-secret fields
are flags; SSN, passport, and license numbers are prompted on the terminal when
you pass the matching bool flag (never argv):

```sh
vault add "Jane Doe" --type identity --first-name Jane --last-name Doe \
  --email jane@example.org --city Amber --ssn
#   SSN / national id: …
vault edit "Jane Doe" --city "New Amber" --passport   # --passport prompts it
```

(The login username is `--username`; the identity's own username field is
`--identity-username`.) Editing identity fields on a non-identity item is
rejected.

The TUI can also create and edit cards and identities: press `a` and cycle the
**Type** row with `Space` (`login → secure note → card → identity`), or `e` on a
selected item. The card's number and CVV mask while unfocused; on edit they start
blank (blank = leave unchanged), and the brand/expiry prefill from the detail
pane. The identity form edits the **full field set** — including the
SSN/passport/license secrets (masked, like the card number) — and the form
**scrolls** when the field list is taller than the overlay (the keybind footer
stays put).

### PIN unlock

For quick access without re-typing the master password, enroll a PIN (after an
online unlock) and unlock with it:

```sh
vault pin set            # prompts for a PIN (≥ 4 chars)
vault unlock --pin       # prompts for the PIN; unlocks from the local cache
vault pin status         # enrolled? attempts remaining?
vault pin disable        # forget the PIN
```

The TUI unlocks **in place**: when the agent is locked, `vault-tui` shows an
unlock prompt for your registered account (master password, or `Tab` to a PIN
when one is enrolled) instead of sending you back to the CLI.

A PIN session reads from the encrypted cache, and — once the network is
reachable — transparently goes online for `sync` and edits by refreshing a
stored token (no master password needed); only a genuinely offline box stays
read-only. Five wrong PINs disable the PIN and require a master-password unlock
— bounding brute-force of a short secret.

### API-key login (2FA accounts)

If your account has two-factor auth enabled, the password grant is rejected
with a 2FA challenge that Vault can't answer interactively. Generate a
**personal API key** in the web vault (Settings → Security → Keys → *View API
Key*) and log in with it — the `client_credentials` grant skips the 2FA prompt:

```sh
BW_CLIENTID=user.xxxx BW_CLIENTSECRET=… vault login --api-key
# or, interactively (prompts for client_id / client_secret), then:
#   Master password: …
```

The API key authenticates the *session* only — **you still enter your master
password** to decrypt the vault; the key just gets you past 2FA. On success the
agent stores the key (`apikey.json`, `0600`, in the account data dir), so plain
`vault unlock` and the TUI unlock reuse it automatically — no further 2FA, no
re-entering the key. A stored key also lets a PIN/offline session go back online
for `sync` and edits.

```sh
vault apikey status      # configured? (shows the non-secret client_id)
vault apikey forget      # delete the stored key; logins revert to the password grant
```

The key is protected at rest by filesystem permissions (`0600`) only: it must
be usable *before* the vault is unlocked, so it can't be encrypted under your
key — the same trust level as the stored refresh token or an SSH private key.

### Stay unlocked across restarts (Linux, opt-in)

By default the agent holds the key only in its own memory, so any restart
(crash, `stop-agent`, logout) means a fresh unlock. On Linux you can opt into
resuming a session across an agent restart:

```sh
vault config set agent.session_keyring true
```

With this on, an unlock also mirrors the key into the Linux **kernel session
keyring** (kernel memory, never on disk, never swapped, evicted on logout). A
restarted agent reads it back and comes up unlocked — but only within the
idle-lock window (`agent.idle_lock_secs`): the keyring entry self-expires, so a
dead agent's session doesn't linger. An explicit `vault lock` (or idle-lock)
forgets it and forces a full unlock; a plain `stop-agent`/`SIGTERM` leaves it so
the next auto-spawn resumes. This is an opt-in relaxation of Vault's "key never
leaves the agent" posture (PRD §7.3); it's off by default and a no-op on
non-Linux.

## Configuration

Persistent settings live at `$XDG_CONFIG_HOME/vault/config.toml`, managed with
`vault config`:

```sh
vault config get                          # list every known key + value
vault config set clipboard.clear_secs 45  # validated; writes config.toml
vault config set agent.idle_lock_secs 600
vault config set sync.interval_secs 300    # background sync every 5 min
vault config unset clipboard.clear_secs
```

Recognised keys: `clipboard.clear_secs` (auto-clear window, `0` disables),
`clipboard.backend` (`auto`/`arboard`/`osc52`; see below),
`agent.idle_lock_secs` (idle-lock timeout, `0` disables),
`agent.session_keyring` (resume across restarts; see above),
`sync.interval_secs` (background `/sync` interval while unlocked, `0` disables),
`ui.reduced_motion` (suppress animated TUI elements — **reserved**: the TUI has
no animations yet, so this records the preference for when a spinner /
lock-countdown lands), and `tui.vim` (vim motions; see below). When the CLI
auto-starts the agent, the agent-side keys populate its launch flags (changes
apply on the next agent spawn); `ui.reduced_motion` and `tui.vim` are read by
`vault-tui` directly. Wipe the on-disk item cache (and drop a running agent's
keys) with `vault purge`.

With `tui.vim` set, `vault-tui` adds vim jump motions on top of the default
`hjkl` navigation: `gg` to the top, `G` to the bottom, and `Ctrl-d`/`Ctrl-u` for
a half-page. Because `g` becomes the `gg` prefix, the password generator moves
from `g` to `Ctrl-g` while vim mode is on (with it off, `g` opens the generator
as before).

With `sync.interval_secs` set, the agent re-pulls `/sync` on that cadence while
unlocked — keeping the in-memory vault and offline cache fresh without a manual
`vault sync`. It's best-effort (a locked, offline, or failed sync is skipped)
and never defers the idle-lock countdown.

`clipboard.backend` picks how the TUI's copy keys reach a clipboard:

- `auto` (default) — the agent uses its native backend (`arboard`: Wayland /
  X11 / macOS); if none is reachable it declines and the TUI falls back to
  OSC52.
- `arboard` — force the native backend (warns if unavailable).
- `osc52` — the agent never copies; the TUI writes to the clipboard through the
  terminal via an OSC52 escape. Use this **over SSH/tmux** so copies land on
  your *local* machine (needs a terminal that supports OSC52; inside tmux,
  `set-clipboard on`). The agent itself can't emit OSC52 — it's a daemon with no
  terminal — so this just makes it step aside for the TUI.

## Repository layout

```
vault/
├── crates/
│   ├── vault-core/      crypto, vault model, KDF, EncString
│   ├── vault-api/       Bitwarden REST + identity
│   ├── vault-store/     local encrypted cache, sync state
│   ├── vault-agent/     daemon, UDS, master-key custody
│   ├── vault-ipc/       client ↔ agent CBOR protocol
│   ├── vault-cli/       `vault` binary
│   ├── vault-tui/       `vault-tui` binary (ratatui)
│   └── vault-theme/     Steelbore palette tokens
├── docs/                deeper design notes
├── CHANGELOG.md
├── CONTRIBUTING.md
├── CREDITS.md
├── LICENSE
├── NOTICE.md
├── PRD.md
└── README.md
```

## Project Posture

Spacecraft Software is a **personal hobby project**. Most subprojects —
including Vault — are developed at hobby pace and shaped around the
maintainer's own use case, not a general audience. Selected subprojects (e.g.,
**Anvil-SSH**) are intentionally designed for general use and say so
explicitly in their own README.

- **No warranty, no liability.** See [`NOTICE.md`](./NOTICE.md).
- **Contributions are welcome but not guaranteed.** See [`CONTRIBUTING.md`](./CONTRIBUTING.md).
- **Forking is encouraged.** GPL-3.0-or-later is there for exactly that.

## Standards conformance

Vault follows the Spacecraft Software Standard v1.12. In particular:

- **§3** Memory-safety-first — Rust, `#![forbid(unsafe_code)]` on every library crate.
- **§4** GPL-3.0-or-later with SPDX headers on every source file.
- **§5** Personal/Hobby posture; required posture files at repo root.
- **§6.3** All commits cryptographically signed (Ed25519 SSH).
- **§7** Privacy, Freedom, Autonomy — no telemetry, no analytics, no auto-update pings.
- **§9** Steelbore palette (Void Navy `#000027`, Molten Amber `#D98E32`).
- **§12** ISO 8601 UTC timestamps throughout.
- **§13.2** Attribution block surfaced via `--version`, `--help`, README, and TUI About.

## Credits

See [`CREDITS.md`](./CREDITS.md). Vault stands on the shoulders of
[Bitwarden](https://bitwarden.com/) (protocol/spec),
[rbw](https://github.com/doy/rbw) (CLI shape, MIT, Daniel Frank), and
[cruxpass](https://github.com/AryanpurTech/cruxpass) (TUI flow,
AryanpurTech).

---

**Maintainer:** Mohamed Hammad &lt;Mohamed.Hammad@SpacecraftSoftware.org&gt;
**License:** GPL-3.0-or-later
**Website:** <https://Vault.SpacecraftSoftware.org/>

*--- Forged in Spacecraft Software ---*

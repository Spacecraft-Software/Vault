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
line, and add/edit/delete. The CLI auto-starts the agent when needed, and
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

## Configuration

Persistent settings live at `$XDG_CONFIG_HOME/vault/config.toml`, managed with
`vault config`:

```sh
vault config get                          # list every known key + value
vault config set clipboard.clear_secs 45  # validated; writes config.toml
vault config set agent.idle_lock_secs 600
vault config unset clipboard.clear_secs
```

Recognised keys: `clipboard.clear_secs` (auto-clear window, `0` disables) and
`agent.idle_lock_secs` (idle-lock timeout, `0` disables). When the CLI
auto-starts the agent, these populate its launch flags. Wipe the on-disk item
cache (and drop a running agent's keys) with `vault purge`.

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

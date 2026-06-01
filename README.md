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

Pre-alpha — M0 scaffolding only. The `vault` binary builds and emits the
Standard §13.2 attribution block via `--version`; nothing else is wired up
yet. See [PRD §12](./PRD.md#12-milestones) for the roadmap (M0 → v0.1).

## Build

```sh
cargo build --release
./target/release/vault --version
```

Headless install (no TUI dependencies) — once the feature gate lands in M5:

```sh
cargo install --path crates/vault-cli --no-default-features --features cli
```

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

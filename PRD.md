<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Vault — Product Requirements Document

| Field          | Value                                                     |
| -------------- | --------------------------------------------------------- |
| Project        | Vault                                                     |
| Repository     | <https://github.com/Spacecraft-Software/Vault>            |
| Subdomain      | <https://Vault.SpacecraftSoftware.org/>                   |
| Maintainer     | Mohamed Hammad — `Mohamed.Hammad@SpacecraftSoftware.org`  |
| License        | GPL-3.0-or-later                                          |
| Posture        | Personal / Hobby (Standard §5)                            |
| Standard       | The Spacecraft Software Standard v1.12                    |
| Document state | Draft v0.1                                                |
| Last updated   | 2026-06-16                                                |

## 1. Summary

Vault is a terminal-native [Bitwarden](https://bitwarden.com/) client for Linux,
macOS, and BSD. It exposes two coordinated front-ends sharing a single Rust
engine:

- A full-screen **TUI** modelled on the look-and-feel of
  [cruxpass](https://github.com/AryanpurTech/cruxpass) — three-pane layout,
  fast keyboard navigation, modal flows.
- A scriptable **CLI** modelled on
  [rbw](https://github.com/doy/rbw) — flat verbs, JSON output, headless install,
  no TUI dependency.

Both are backed by a long-lived agent daemon that holds the decrypted master
key in locked, zeroizable memory. Vault works against Bitwarden's hosted
service and against self-hosted [Vaultwarden](https://github.com/dani-garcia/vaultwarden).

## 2. Background and motivation

The existing terminal Bitwarden surface is fragmented:

- The official Bitwarden CLI (`bw`) is Node-based, slow to start, and not
  ergonomic for daily TUI use.
- `rbw` is excellent for scripting but ships no interactive front-end.
- `cruxpass` is a polished TUI, but its storage backend is its own format —
  not Bitwarden.

Vault closes the gap: cruxpass-class interactive UX over the Bitwarden
protocol, with a clean CLI siblng for automation. A single Rust workspace
keeps the crypto, sync, and storage code consolidated and auditable.

## 3. Goals

| #   | Goal                                                                                              |
| --- | ------------------------------------------------------------------------------------------------- |
| G1  | Fully functional Bitwarden client offline once initially synced.                                  |
| G2  | TUI usable as a daily driver; sub-100 ms perceived latency on local operations.                   |
| G3  | CLI achieves practical parity with `rbw`'s read+write surface and accepts/emits JSON everywhere.  |
| G4  | Master key never resident outside the agent process; locked on idle, signal, or explicit `lock`. (Opt-in carve-out: §7.3 `session_keyring`.) |
| G5  | Works against both `bitwarden.com` and self-hosted Vaultwarden, including cert pinning.           |
| G6  | Headless install (`--no-default-features --features cli`) ships a single binary, no TUI deps.     |
| G7  | Conformance with the Spacecraft Software Standard (§3 priority hierarchy, §4 license, §5 posture, §6.3 signed commits, §12 timestamps, §13 attribution). |

## 4. Non-goals (v0.1)

- Mobile, browser, or GUI front-ends.
- Bitwarden Send, organization administration, emergency access, or premium-only features (TOTP code generation is in-scope; YubiKey/U2F flows are not).
- Cross-vault import beyond Bitwarden's own encrypted JSON export.
- Multi-account juggling in a single agent process (one account per agent socket).
- Telemetry, crash reporting, auto-update pings — see §10 PFA.

## 5. Target users

| Persona              | Description                                                                                  |
| -------------------- | -------------------------------------------------------------------------------------------- |
| **Terminal native**  | Lives in tmux/Zellij/Helix/Vim. Wants a TUI that obeys their muscle memory.                  |
| **Script author**    | Wraps secrets into shell/Nushell/Ion pipelines. Needs predictable JSON, exit codes, and `--field` extraction. |
| **Self-host operator** | Runs Vaultwarden on their LAN. Needs custom CA pinning and full offline operation.         |
| **Security-aware power user** | Wants zeroized buffers, mlocked keys, no swap exposure, signed releases.            |

## 6. User stories

### Authentication & lifecycle

- As a new user I can run `vault register` then `vault login` and end up with a working sync.
- As a returning user I can run `vault unlock`, type my master password once, and have my key cached in the agent for a configurable TTL.
- As a security-aware user I can run `vault lock` (or `:lock` in the TUI) and be confident the key is wiped from memory.
- As an automation author I can detect agent state programmatically (`vault status --json`).

### Reading

- As a CLI user I can run `vault get github.com --field password` and pipe the result into another tool.
- As a TUI user I can press `/`, type a fuzzy query, hit `Enter`, and see the matching entry's detail pane.
- As a TUI user I can press `c` to copy the password to clipboard with a 30-second auto-clear.

### Writing

- As any user I can add (`add`), edit (`edit`), and remove (`remove`) login items, secure notes, and cards.
- As a CLI user I can pipe JSON into `vault add --json` and have it merged into the next sync.
- As a TUI user I can press `g` to generate a password against my configured policy and have it pre-filled into the active field.

### Sync & offline

- As a user on a plane I can browse, search, and copy from my last-synced vault.
- As a user back online I can `vault sync` and resolve any conflict surfaced by the server (last-writer-wins with a local rescue copy).

## 7. Functional requirements

### 7.1 CLI surface

Verbs are flat, matching `rbw`'s muscle memory; flags follow the Spacecraft
Software CLI Standard (SFRS v1.0.0).

| Command                                      | Purpose                                       |
| -------------------------------------------- | --------------------------------------------- |
| `vault register`                             | First-time API key registration               |
| `vault login`                                | Authenticate against server                   |
| `vault unlock` / `vault lock`                | Manage agent key state                        |
| `vault status`                               | Report agent + sync state                     |
| `vault sync`                                 | Pull from server                              |
| `vault list [--folder F] [--fields …]`       | List entries                                  |
| `vault get <name> [--full] [--field F]`      | Fetch entry / specific field                  |
| `vault add` / `vault edit` / `vault remove`  | Mutate entries                                |
| `vault generate [--length N] [--symbols]`    | Password generation                           |
| `vault purge`                                | Wipe local cache                              |
| `vault config get`/`set`/`unset`             | Settings                                      |
| `vault stop-agent`                           | Kill the daemon                               |

**Standard-mandated flags on every subcommand:**
`--json`, `--format json|jsonl|yaml|csv`, `--no-color`/`NO_COLOR`,
`--absolute-time`, `--version`, `--help`. Errors go to `stderr` as a structured
envelope; exit codes documented in `docs/exit_codes.md`.

### 7.2 TUI surface

| Element              | Behaviour                                                                                |
| -------------------- | ---------------------------------------------------------------------------------------- |
| **Layout**           | Left: folder/collection tree. Center: filterable item list. Right: item detail with reveal-on-demand fields. Status bar bottom. |
| **Search**           | `/` opens a fuzzy query against name + URI + username.                                   |
| **Copy**             | `c` copies password, `u` copies username, `o` opens URI. Clipboard clears in 30 s (configurable). |
| **Mutation**         | `a` add, `e` edit, `d` delete (confirm), `g` generate.                                   |
| **Command palette**  | `:` opens a Vim-style palette (`:sync`, `:lock`, `:theme reload`, …).                    |
| **Bindings**         | Full CUA in every text input (`Ctrl+C`/`X`/`V`/`Z`/`S`/`F`); opt-in Vim layer via `set vim` config. |
| **Theme**            | Default Steelbore theme (Void Navy `#000027` background, Molten Amber `#D98E32` foreground) from Standard §9. User themes loadable via path. |
| **Library**          | `ratatui` + `crossterm`. No cursive (license tree hygiene).                              |

### 7.3 Agent

- Long-lived process per user; one Unix domain socket per account.
- Holds: unwrapped master key, derived item-encryption keys, current sync revision.
- Locks on: idle timeout (default 15 min, configurable), `vault lock`, `SIGTERM`, screen-lock dbus signal where available.
- Auto-spawned by any client on first use; never run as root; socket mode `0600`.
- **Session resume (opt-in, Linux).** With `agent.session_keyring` enabled, the
  unwrapped user key may *also* reside in the Linux kernel **session keyring** —
  kernel memory, never on disk, never swapped, possessor-gated, evicted on
  logout — so a restarted agent (crash / `SIGTERM` / `stop-agent` + auto-spawn)
  resumes unlocked without the master password, bounded by the idle-lock TTL
  (the keyring entry carries a kernel timeout). Explicit `vault lock` and
  idle-lock clear it; `SIGTERM`/`stop-agent` leave it for resume. This is the
  sole, default-off carve-out to G4's "master key never resident outside the
  agent process"; off, the key never leaves the process.

- **Fingerprint unlock (opt-in, Linux).** An extension of the same carve-out:
  with `agent.fingerprint_unlock` (requires `session_keyring`, the off-by-default
  `fingerprint` feature, and the system `fprintd`), the agent **gates the keyring
  resume behind a verified fingerprint** instead of resuming silently — idle-lock
  then zeroises the in-memory key but *keeps* the keyring entry so a touch
  re-unlocks (lifetime `agent.fingerprint_ttl_secs`), while manual `vault lock`
  still clears it. The biometric is verified in the agent (D-Bus), and enrollment
  is OS-level (`fprintd-enroll`) — Vault stores no template. **Posture:** because
  the keyring entry is possessor-gated, a fingerprint adds *user-presence and
  convenience*, **not** cryptographic strength beyond `session_keyring`; it is
  strictly weaker than a master-password unlock. Default off. See
  `docs/fingerprint.md`.

### 7.4 Storage

- Vault items persisted as Bitwarden-format ciphertext (AES-256-CBC + HMAC-SHA256) under `$XDG_DATA_HOME/vault/`.
- Metadata (sync revision, folder tree, item index) encrypted-at-rest with a key derived from the master key.
- Cache rebuilds idempotently from a fresh `vault sync`; corruption is recoverable, not fatal.

### 7.5 Clipboard

- Backend trait with implementations for: `wl-clipboard` (Wayland), `xclip`/`xsel` (X11), OSC 52 (SSH/tmux fallback), macOS `pbcopy`.
- Detected at runtime; first-available wins. Override via `clipboard.backend` config key.

## 8. Non-functional requirements

### 8.1 Security

| Requirement                                                                                          |
| ---------------------------------------------------------------------------------------------------- |
| Master key resides only in `vault-agent`; `mlock`'d page, never swapped, `zeroize`'d on drop.        |
| KDF: PBKDF2-SHA256 **and** Argon2id supported; auto-detected from account; never silently downgrade. |
| Item encryption parser: constant-time HMAC verification, fuzzed in CI.                               |
| TLS: rustls + system roots; optional pinning by SPKI hash for self-hosted Vaultwarden.               |
| PQC: feature-flagged X25519+ML-KEM hybrid transport via rustls hybrid groups. Roadmap in `docs/pqc.md`. |
| Supply chain: `cargo audit` + `cargo deny` on every CI run; lockfile committed.                      |
| All release commits signed (Ed25519 SSH) per Standard §6.3.                                          |

### 8.2 Performance

| Target                                          | Budget                                       |
| ----------------------------------------------- | -------------------------------------------- |
| `vault get` against warm agent                  | < 50 ms end-to-end (incl. process spawn)     |
| TUI keystroke → screen update                   | < 16 ms (60 Hz target)                       |
| Full sync of a 1 000-item vault                 | < 5 s on a residential connection            |
| Cold start `vault-tui` to first frame           | < 200 ms                                     |

### 8.3 Accessibility (Standard §11)

- Reduced-motion config option (disables lock-countdown animation, spinner).
- High-contrast theme variant.
- Screen-reader-friendly mode disables decorative borders and emits semantic field labels.

### 8.4 Compatibility

- Linux (glibc + musl), macOS 13+, FreeBSD. Windows is best-effort, not gated.
- POSIX shell + Nushell + Ion + PowerShell 7+ tested for completions.
- Rust edition 2024, MSRV pinned to the last stable.

## 9. Architecture

```
┌──────────────┐   UDS    ┌─────────────────┐    HTTPS    ┌────────────────┐
│  vault (CLI) │ ───────► │   vault-agent   │ ──────────► │ Bitwarden /    │
│  vault-tui   │ ◄─────── │ (master key,    │ ◄────────── │ Vaultwarden    │
└──────────────┘  CBOR    │  decrypted TTL) │             └────────────────┘
                          │                 │
                          │  vault-store    │
                          │  (encrypted     │
                          │  cache on disk) │
                          └─────────────────┘
```

### 9.1 Workspace layout

```
vault/
├── crates/
│   ├── vault-core/      # crypto, vault model, KDF, EncString
│   ├── vault-api/       # Bitwarden REST + identity
│   ├── vault-store/     # local encrypted cache, sync state
│   ├── vault-agent/     # daemon, UDS, master-key custody
│   ├── vault-ipc/       # client ↔ agent CBOR over UDS
│   ├── vault-cli/       # `vault` binary
│   ├── vault-tui/       # `vault-tui` binary (ratatui)
│   └── vault-theme/     # Steelbore theme tokens
├── docs/
├── references/          # cruxpass/ rbw/ vendored as read-only refs
├── CHANGELOG.md
├── CONTRIBUTING.md
├── CREDITS.md
├── LICENSE
├── NOTICE.md
├── PRD.md
├── README.md
└── Cargo.toml
```

## 10. Privacy, Freedom, Autonomy (Standard §7)

- **No tracking.** Zero telemetry, no analytics, no crash reporters, no auto-update pings. Network traffic exists only against the user-configured Bitwarden or Vaultwarden server.
- **Minimal permissions.** Clipboard access requested lazily on first copy. `--offline` disables all network IO.
- **Local-first.** Once an initial sync has succeeded, the vault is fully usable without network. `vault sync` is explicit; opt-in scheduled sync available via cron-style config.

## 11. Success metrics

Vault is "v0.1 done" when:

1. A user can install (`cargo install vault`), `register`, `login`, `sync`, and reach `vault get` end-to-end against both bitwarden.com and a Vaultwarden test container. — **✅ capability complete** (CLI flow + `docs/m2-vaultwarden.md`); the final live confirmation against both servers is a maintainer step.
2. The TUI sustains daily-driver use for the maintainer for two consecutive weeks without a blocker. — **⏳ operational** (maintainer attestation pending).
3. `cargo audit`, `cargo deny`, `cargo fmt --check`, `clippy -D warnings`, and the integration suite pass on every PR. — **✅ done** (CI enforces all five on every PR).
4. Fuzz harness for the EncString parser has run ≥ 24 h with no findings. — **⏳ harness built** (`fuzz/`, `docs/fuzzing.md`); the ≥ 24 h soak is pending.
5. README, NOTICE, CONTRIBUTING, CREDITS, and CHANGELOG are present and accurate; §13.2 attribution block appears in `--version`, `--help` footer, README, and TUI About screen. — **✅ done**.

**Status (2026-06-16): code complete.** Remaining for the `v0.1.0` tag are the
operational gates above — the two-week daily-driver (2), the ≥ 24 h fuzz soak
(4), and a live PQC handshake test (§12 M7) — after which the tag is cut per
[`RELEASING.md`](RELEASING.md).

## 12. Milestones

| Phase | Deliverable                                                                                          | Gate                                                                | Status |
| ----- | ---------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- | ------ |
| M0    | Workspace skeleton, posture files, CI (fmt/clippy/audit/deny), signed commits verified               | Empty `vault --version` returns Standard §13.2 attribution block    | ✅ |
| M1    | `vault-core` + `vault-store`: parse Bitwarden export JSON, decrypt offline                           | Round-trip an exported vault locally                                | ✅ |
| M2    | `vault-api`: login + sync against Vaultwarden in a test container                                    | `vault sync` populates encrypted cache                              | ✅ |
| M3    | `vault-agent` + IPC + `vault unlock` / `lock` / `get` / `list`                                       | `rbw` parity for read paths                                         | ✅ |
| M4    | CLI write paths (`add` / `edit` / `remove` / `generate`) with `--json` on every command              | Scripts drive Vault end-to-end                                      | ✅ |
| M5    | `vault-tui` MVP: list / detail / search / copy / generate                                            | Daily-driver usable in a terminal                                   | ✅ |
| M6    | Vim layer, theme loader, accessibility toggles                                                       | §8 / §9.1 / §11 boxes ticked                                        | ◑ vim + accessibility toggles done; runtime theme loader not implemented (out of scope for v0.1 — the palette ships as `vault-theme` tokens) |
| M7    | PQC transport feature flag, hardening pass, EncString fuzz harness                                   | `v0.1` tag                                                          | ◑ PQC flag ✅ / hardening (core dumps + ptrace + mlock) ✅ / fuzz harness ✅; `v0.1` tag pending the operational gates in §11 |

## 13. Risks and open questions

| Risk                                                                                                    | Mitigation                                                                                          |
| ------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| Bitwarden official Rust SDK is AGPL/BSL — incompatible with GPL-3.0-or-later when linked.               | Re-implement wire format from public spec; use MIT-licensed `rbw` as a reading reference, not a dependency. |
| Clipboard story is fragmented across Wayland / X11 / SSH / tmux / macOS.                                | Trait-based backend with runtime detection; OSC 52 fallback is always available.                    |
| Sibling `bwtui` at the umbrella may signal scope overlap.                                               | Investigate before tagging v0.1; absorb, archive, or document the distinction.                      |
| Bitwarden may roll a vault-level PQC wrap before our transport flag lands.                              | Track upstream in `docs/pqc.md`; design `vault-core` so wrap algorithms are pluggable.              |
| KDF auto-detection edge cases (very old accounts, mid-migration accounts).                              | Conservative detection; refuse and surface a clear error rather than guess.                         |

## 14. References

- [The Spacecraft Software Standard v1.12](https://github.com/Spacecraft-Software/Standard)
- [Bitwarden — Security whitepaper](https://bitwarden.com/help/bitwarden-security-white-paper/)
- [Vaultwarden](https://github.com/dani-garcia/vaultwarden)
- [rbw](https://github.com/doy/rbw) — CLI reference shape, MIT-licensed
- [cruxpass](https://github.com/AryanpurTech/cruxpass) — TUI flow reference
- [ratatui](https://github.com/ratatui-org/ratatui)

## 15. Attribution (Standard §13.2)

Vault is part of the Spacecraft Software ecosystem. Maintainer: Mohamed Hammad
(`Mohamed.Hammad@SpacecraftSoftware.org`). Issues, source, and releases at
<https://github.com/Spacecraft-Software/Vault>. Canonical project page:
<https://Vault.SpacecraftSoftware.org/>.

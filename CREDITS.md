<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# CREDITS

Vault stands on substantial third-party work. This file is the inbound
counterpart to the Spacecraft Software Standard §13.2 outbound attribution
block: §13.2 tells consumers who maintains Vault; this document tells
consumers whose work Vault stands on. See Standard §13.3.

Routine package-manager dependencies whose `LICENSE` files are surfaced
mechanically via Cargo are **not** listed here; their license metadata travels
with the binary. Only works whose ideas or implementation form a substantial
conceptual basis for Vault appear below.

## Bitwarden — protocol and specification

| Field      | Value                                                                  |
| ---------- | ---------------------------------------------------------------------- |
| Name       | Bitwarden                                                              |
| Author(s)  | Bitwarden, Inc.                                                        |
| License    | Bitwarden's clients are mostly GPL-3.0; the official Rust SDK includes AGPL-3.0 and Business Source License components. Vault does **not** link or vendor the official SDK. |
| Source URL | <https://bitwarden.com/help/bitwarden-security-white-paper/>           |
| Scope      | The Bitwarden protocol — REST endpoints, identity flow, EncString format, KDF parameters — that Vault speaks. Re-implemented from the public security whitepaper and protocol documentation. |

## rbw — CLI shape and reference behaviour

| Field      | Value                                                                  |
| ---------- | ---------------------------------------------------------------------- |
| Name       | rbw                                                                    |
| Author(s)  | Daniel Frank and contributors                                          |
| License    | MIT                                                                    |
| Source URL | <https://github.com/doy/rbw>                                           |
| Scope      | Vault's CLI verb set, agent-process design, and several integration choices were studied from rbw. rbw's MIT license permits reading and re-implementing; no rbw source code is vendored or linked. |

## cruxpass — TUI layout and flow

| Field      | Value                                                                  |
| ---------- | ---------------------------------------------------------------------- |
| Name       | cruxpass                                                               |
| Author(s)  | AryanpurTech                                                           |
| License    | Reference repository — see upstream                                    |
| Source URL | <https://github.com/AryanpurTech/cruxpass>                             |
| Scope      | Vault's TUI three-pane layout, modal flows, and keyboard ergonomics are modelled on cruxpass's interaction design. No source is vendored. |

## ratatui — terminal UI framework

| Field      | Value                                                                  |
| ---------- | ---------------------------------------------------------------------- |
| Name       | ratatui                                                                |
| Author(s)  | The Ratatui Developers                                                 |
| License    | MIT                                                                    |
| Source URL | <https://github.com/ratatui-org/ratatui>                               |
| Scope      | Used as the rendering substrate for `vault-tui`. Listed here because the TUI's structure is shaped by ratatui's widget and layout primitives, beyond routine dependency use. |

## EFF large wordlist — passphrase generation

| Field      | Value                                                                  |
| ---------- | ---------------------------------------------------------------------- |
| Name       | EFF Large Wordlist for Passphrases                                     |
| Author(s)  | Electronic Frontier Foundation                                         |
| License    | CC-BY-3.0                                                              |
| Source URL | <https://www.eff.org/dice>                                             |
| Scope      | The 7776-word diceware list embedded at `crates/vault-core/src/wordlist.rs`, used by `generate_passphrase`. Verbatim EFF word data (regenerated from the EFF source via `crates/vault-core/tools/gen_wordlist.sh`); declared CC-BY-3.0 in `REUSE.toml` per Standard §4.2. |

## The Spacecraft Software Standard

| Field      | Value                                                                  |
| ---------- | ---------------------------------------------------------------------- |
| Name       | The Spacecraft Software Standard                                       |
| Author(s)  | Mohamed Hammad & Spacecraft Software                                   |
| License    | GPL-3.0-or-later                                                       |
| Source URL | <https://Standard.SpacecraftSoftware.org/>                             |
| Scope      | Vault conforms to v1.12 of the Standard for naming, licensing, posture, attribution, signed commits, and dates/times.                                |

---

*--- Forged in Spacecraft Software ---*

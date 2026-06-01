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

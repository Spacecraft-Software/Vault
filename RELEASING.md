<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Releasing Vault

Vault's posture is **Personal / Hobby** (Standard §5): no SLA, no semver promise,
and `0.x` may break in any release. This checklist is a maintainer aid for
cutting a tag, not a contract.

All code-side work for `v0.1` has landed (see `CHANGELOG.md` `[Unreleased]`). The
remaining `v0.1` success metrics (PRD §11) are **operational** — run them, then
do the mechanical cut below.

## 1. Operational gates (run before tagging `v0.1.0`)

- [ ] **EncString fuzz soak** — ≥ 24 h with no findings (PRD §11.4):
      `cargo +nightly fuzz run enc_string_parse -- -max_total_time=86400`
      (see `docs/fuzzing.md`). Any reproducer under `fuzz/artifacts/` blocks the
      tag until fixed.
- [ ] **Live PQC handshake** — build with PQC and confirm an X25519MLKEM768
      handshake against a PQC-enabled endpoint:
      `cargo build -p vault-agent --features pqc` (see `docs/pqc.md`).
- [ ] **End-to-end** (PRD §11.1) — `register` / `login` / `sync` / `get` against
      both bitwarden.com and a Vaultwarden container (`docs/m2-vaultwarden.md`).
- [ ] **Daily-driver** (PRD §11.2) — two consecutive weeks of maintainer use with
      no blocker.

## 2. Cut the release (mechanical)

- [ ] Bump the version once: `[workspace.package] version` in the root
      `Cargo.toml` (`0.0.1` → `0.1.0`); all crates inherit it. Commit the updated
      `Cargo.lock`.
- [ ] `CHANGELOG.md`: rename `## [Unreleased]` → `## [0.1.0] - <YYYY-MM-DD>`
      (ISO 8601 UTC, Standard §12) and open a fresh empty `[Unreleased]`.
- [ ] Run the CI-exact gates locally and confirm green:
      `cargo fmt --all -- --check`;
      `rm -rf target/clippy && RUSTFLAGS="-D warnings" CARGO_TARGET_DIR=target/clippy cargo clippy --workspace --all-targets --all-features -- -D warnings`;
      `RUSTFLAGS="-D warnings" cargo test --workspace --all-targets`;
      `cargo deny check`;
      `cargo build -p vault-cli --no-default-features --features cli` and
      `cargo build -p vault-agent --no-default-features`.
- [ ] `vault --version` shows `0.1.0` and the Standard §13.2 attribution block
      (the CI `version-gate` mirror).
- [ ] Refresh `projects/PROJECTS.md` (the umbrella status tracker): status,
      `Last Updated`, milestone — per `projects/CLAUDE.md` editing rules.
- [ ] Commit (signed, Ed25519 — Standard §6.3), open the PR, merge when green.
- [ ] On the merge commit, create a **signed annotated tag** and push it:
      `git tag -s v0.1.0 -m "Vault v0.1.0"` then `git push origin v0.1.0`.
      Confirm the tag shows "Verified" (signing key registered on GitHub).

## Notes

- Every commit and the tag must be cryptographically signed and show "Verified"
  (Standard §6.3). Never `--no-verify` / `--no-gpg-sign`.
- The `fuzz/` crate is a standalone workspace (nightly + sanitizer) and is not a
  CI gate; the soak above is the manual equivalent.

# SPDX-License-Identifier: GPL-3.0-or-later
#
# Developer gate recipes mirroring CI (.github/workflows/ci.yml). Run `just ci`
# before pushing; it runs the same checks the runner does. The toolchain is
# pinned by rust-toolchain.toml (1.95.0), so these match CI exactly.

# List the recipes.
default:
    @just --list

# rustfmt check (CI: rustfmt job).
fmt:
    cargo fmt --all -- --check

# Apply formatting.
fmt-fix:
    cargo fmt --all

# Clippy, CI-exact: a fresh isolated target dir + -D warnings (a warm cache false-greens).
clippy:
    rm -rf target/clippy
    RUSTFLAGS="-D warnings" CARGO_TARGET_DIR=target/clippy cargo clippy --workspace --all-targets --all-features -- -D warnings

# Tests (CI: test job; RUSTFLAGS=-D warnings, as the workflow sets globally).
test:
    RUSTFLAGS="-D warnings" cargo test --workspace --all-targets

# Live HTTP integration tests (#[ignore]d by default; needs network / Vaultwarden — docs/m2-vaultwarden.md).
test-live:
    cargo test -- --ignored

# Headless builds (CI: headless job): CLI without the TUI, agent without the clipboard tree.
headless:
    cargo build -p vault-cli --no-default-features --features cli
    cargo build -p vault-agent --no-default-features

# `vault --version` carries the Standard §13.2 attribution block (CI: version-gate job).
version-gate:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build --bin vault --release
    out=$(./target/release/vault --version)
    grep -q "Mohamed Hammad <Mohamed.Hammad@SpacecraftSoftware.org>" <<<"$out"
    grep -q "GPL-3.0-or-later" <<<"$out"
    grep -q "https://Vault.SpacecraftSoftware.org/" <<<"$out"
    echo "version-gate: ok"

# Supply-chain: licenses/bans/advisories/sources (CI: cargo-deny job).
deny:
    cargo deny check

# Vulnerability advisories; --ignore mirrors CI's audit job (.github/workflows/ci.yml). Needs cargo-audit.
audit:
    cargo audit --ignore RUSTSEC-2024-0436 --ignore RUSTSEC-2026-0002

# REUSE/SPDX licensing lint (CI: REUSE job). Needs reuse (`uvx reuse lint` or `pipx install reuse`).
reuse:
    reuse lint

# EncString fuzz harness (nightly; docs/fuzzing.md). Smoke by default; the v0.1 gate is `just fuzz 86400`.
fuzz seconds="30":
    cd fuzz && cargo +nightly fuzz run enc_string_parse -- -max_total_time={{seconds}}

# Build the post-quantum transport feature (docs/pqc.md) and run its tests.
pqc:
    cargo build -p vault-agent --features pqc
    cargo test -p vault-api --features pqc

# Everything the CI runner checks, in order. Run before pushing.
ci: fmt clippy test headless version-gate deny audit reuse

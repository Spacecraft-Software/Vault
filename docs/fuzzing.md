<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Fuzzing the `EncString` parser

Vault fuzzes its security-critical Bitwarden "type 2" `EncString` parser
(`crates/vault-core/src/enc_string.rs`) with [`cargo-fuzz`] / libFuzzer. The
parser base64-decodes attacker-influenceable cache and `/sync` strings into
IV / ciphertext / MAC, so it must never panic and must round-trip cleanly. PRD
§11.4 requires this harness to run **≥ 24 h with no findings** as part of the
`v0.1` tag gate (§12 M7).

## Layout

The harness is a **standalone workspace** under `fuzz/`, deliberately kept out of
the main workspace (the root `Cargo.toml` lists explicit `members` and also
`exclude = ["fuzz"]`, and `fuzz/Cargo.toml` carries its own empty `[workspace]`).
That isolation matters: cargo-fuzz needs a nightly toolchain and a sanitizer
runtime, so the repo's CI gates (`fmt` / `clippy -D warnings` / `test` / `deny` /
headless builds) never try to build it. The fuzz target is also the one place
`#![no_main]` and libFuzzer's internal `unsafe` live — outside the workspace's
`#![forbid(unsafe_code)]`.

- `fuzz/Cargo.toml` — the `vault-fuzz` package.
- `fuzz/fuzz_targets/enc_string_parse.rs` — the target: parse arbitrary input,
  and on success assert the parse → serialize → parse round-trip is stable.

## Prerequisites

```sh
rustup toolchain install nightly
cargo install cargo-fuzz      # provides `cargo fuzz` (libFuzzer driver)
```

## Run

```sh
# from the repo root
cargo +nightly fuzz run enc_string_parse
```

Seed the corpus with a real example so libFuzzer starts from valid structure
(optional but speeds up coverage):

```sh
mkdir -p fuzz/corpus/enc_string_parse
printf '2.%s|%s|%s' \
  "$(head -c16 /dev/zero | base64)" \
  "$(head -c16 /dev/zero | base64)" \
  "$(head -c32 /dev/zero | base64)" \
  > fuzz/corpus/enc_string_parse/seed
```

### The §11.4 soak

```sh
# 24 hours (86400 s); findings are written under fuzz/artifacts/
cargo +nightly fuzz run enc_string_parse -- -max_total_time=86400
```

A crash or assertion failure drops a reproducer in
`fuzz/artifacts/enc_string_parse/`; replay it with
`cargo +nightly fuzz run enc_string_parse fuzz/artifacts/enc_string_parse/<file>`.
The `corpus/`, `artifacts/`, `target/`, and `coverage/` directories are
git-ignored.

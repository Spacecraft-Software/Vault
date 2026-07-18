<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Contributing to Vault

Thank you for your interest. Please read this document before opening an
issue or pull request — it sets honest expectations for both sides so no
one's time is wasted.

## Project Stance

Vault is a subproject of **Spacecraft Software**, a personal hobby project. It
is shaped around the maintainer's own use case and developed at hobby pace.

This is **not** a community-driven project, but external input is welcome
and appreciated within the bounds set out below.

## What Is Welcome

- **Bug reports** — clear, reproducible, with environment details (OS, kernel,
  Rust toolchain version, shell, server type — bitwarden.com vs Vaultwarden,
  relevant config). For security-sensitive bugs see *Reporting Security Issues*
  below.
- **Suggestions** — features, refactors, naming proposals (must conform to
  Spacecraft Software Standard §2 — aerospace / sci-fi / AI naming), design
  feedback.
- **Pull requests** — small, focused, and aligned with the Spacecraft Software
  Standard and Vault's PRD.
- **Documentation fixes** — typos, inaccuracies, broken links, clarifications,
  translations.
- **Test coverage improvements** — almost always merge-worthy.

## What Is Not Guaranteed

- **PR acceptance.** Direction, scope, and quality bar are set by the
  maintainer alone. A submitted contribution is not a guaranteed merge, even
  if it is correct, well-written, and passes CI. If a PR is not accepted, that
  is a judgment of fit, not of the work.
- **Response time.** This is a hobby project. Expect responses on the order of
  days to weeks, not hours.
- **Roadmap influence.** Suggestions may inform direction but do not override
  the maintainer's plans documented in [`PRD.md`](./PRD.md).
- **API stability for in-progress work.** Pre-1.0 versions may break in any
  release.

## Before Opening a PR

1. **Open an issue first** for non-trivial changes. Discuss the design before
   writing code.
2. **Read the Spacecraft Software Standard** and the Vault [`PRD.md`](./PRD.md).
   Memory safety → performance → hardened security, in that order. Rust where
   viable. POSIX-compliant CLI. GPL-3.0-or-later with SPDX headers on every
   source file.
3. **Match the CLI Standard** (v1.0.0) for anything touching `vault-cli`.
4. **Run the full test suite locally.** PRs that don't pass CI will not be
   reviewed.
5. **Use the project's preferred toolchain.** Format with `rustfmt`, lint with
   `clippy -- -D warnings`, and run `cargo audit` for any added dependency.
6. **Sign-off your commits** (`git commit -s`) under the
   [Developer Certificate of Origin](https://developercertificate.org/).
7. **Cryptographically sign your commits** — Spacecraft Software Standard §6.3
   requires every commit to a Spacecraft Software remote to be signed and show
   "Verified" on GitHub. Ed25519 SSH signing is the current default.

## Security-Sensitive Areas

Vault handles credential material. Extra care is expected in:

- Anything touching the master key, KDF, or EncString parsing (`vault-core`).
- The agent's IPC boundary (`vault-ipc`, `vault-agent`).
- Clipboard handling.
- Network code (`vault-api`).

Changes in these areas should include unit tests; non-trivial changes should
include integration tests and, where applicable, fuzz harness updates.

## Commit Style

- Conventional Commits prefix (`feat:`, `fix:`, `docs:`, `refactor:`,
  `test:`, `chore:`, `perf:`, `build:`, `ci:`).
- Subject ≤ 72 characters, imperative mood ("add" not "added").
- Body wrapped at 72 columns; explain *why*, not just *what*.
- Reference issues by number (`Closes #42`).

## Forking

If your needs diverge from the maintainer's, or you want to take Vault in a
different direction, **fork it**. That is exactly what GPL-3.0-or-later is
for. The only constraints are those imposed by the license itself: keep the
source open and under a compatible license, preserve copyright notices, and
pass the same freedoms downstream.

## Reporting Security Issues

For security-sensitive bugs, do **not** open a public issue. Email
&lt;Mohamed.Hammad@SpacecraftSoftware.org&gt; with details. PGP key available on
request.

A coordinated-disclosure window of 90 days from acknowledgment is the default;
this can be shortened or lengthened by mutual agreement.

## License of Contributions

By submitting a contribution, you agree that it will be licensed under
**GPL-3.0-or-later**, the same terms as the project. Contributions that cannot
be licensed under GPL-3.0-or-later cannot be accepted.

You retain copyright in your contributions; no CLA is required.

---

**Maintainer:** Mohamed Hammad &lt;Mohamed.Hammad@SpacecraftSoftware.org&gt;
**License:** GPL-3.0-or-later
**Website:** <https://Vault.SpacecraftSoftware.org/>

*--- Forged in Spacecraft Software ---*

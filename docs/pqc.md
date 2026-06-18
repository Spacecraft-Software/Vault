<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Post-quantum transport (`pqc` feature)

Vault can negotiate a **post-quantum-secure TLS 1.3 handshake** with the
Bitwarden / Vaultwarden server using the hybrid **X25519MLKEM768** key-exchange
group. It is **off by default** and enabled with the `pqc` cargo feature.

```sh
# build the agent with PQC preferred on its HTTPS client
cargo build -p vault-agent --features pqc
# (vault-api exposes the underlying feature: `--features vault-api/pqc`)
```

When enabled, the client offers X25519MLKEM768 first and the classical groups
(X25519, P-256, P-384) as fallback. If the server doesn't support PQC — most
don't yet — the handshake silently falls back to a classical group, so enabling
the feature is safe. PQC is TLS 1.3 only.

## Live handshake test

The unit tests in `crates/vault-api/src/pqc.rs` exercise only our half of the
exchange (KEM round-trip, share/secret layout, config ordering). The
`live_handshake_negotiates_x25519mlkem768` test is the interop gate: it drives a
real TLS 1.3 handshake with [`client_config`] against Cloudflare's PQC research
host (`pq.cloudflareresearch.com`) and asserts the *negotiated* key-exchange
group is X25519MLKEM768 — proving the wire construction interoperates with an
independent server. It is `#[ignore]`d (needs network); run it with:

```sh
cargo test -p vault-api --features pqc -- --ignored live_handshake
```

## Why we hand-roll it (and don't use aws-lc-rs)

rustls only ships X25519MLKEM768 through its **aws-lc-rs** provider. aws-lc-rs
bundles AWS-LC, whose license tree includes **OpenSSL-licensed** code — which is
**GPL-incompatible**. Vault is GPL-3.0-or-later (Standard §4), so aws-lc-rs is
not an option, and our `deny.toml` allow-list would reject it.

Instead, `crates/vault-api/src/pqc.rs` builds the hybrid group from
**GPL-compatible** parts:

- **classical half** — ring's audited X25519 (`rustls::crypto::ring::kx_group::X25519`),
  reused as-is;
- **post-quantum half** — RustCrypto's [`ml-kem`] (`MlKem768`), Apache-2.0/MIT.

The two are composed into a `rustls::crypto::SupportedKxGroup` and injected via
reqwest's `use_preconfigured_tls`. Only the **client** role is implemented.

## Wire construction

Per `draft-ietf-tls-ecdhe-mlkem` (X25519MLKEM768), the post-quantum element
comes first in every share and in the derived secret:

| | bytes | layout |
|---|---|---|
| client share | 1216 | `ek_ML-KEM-768 (1184) ‖ x25519_pub (32)` |
| server share | 1120 | `ct (1088) ‖ x25519_pub (32)` |
| shared secret | 64 | `ss_ML-KEM (32) ‖ ss_X25519 (32)` |

The client generates an ML-KEM keypair (keeping the decapsulation key) plus an
X25519 ephemeral, sends `ek ‖ x25519_pub`, then on the server's reply
X25519-DHs the classical part, decapsulates the ML-KEM ciphertext, and
concatenates the two secrets (PQ first). This mirrors rustls's own
(crate-private) `aws_lc_rs::pq::hybrid` layout.

## Status (PRD §12 M7)

This satisfies the M7 "PQC transport feature flag" item, and the live handshake
gate is now met (see above — `live_handshake_negotiates_x25519mlkem768` confirms
X25519MLKEM768 against Cloudflare). The ≥ 24 h EncString fuzz soak is also done
(`docs/fuzzing-report.md`). Still pending for the `v0.1` tag: the §11.2 two-week
daily-driver attestation.

[`ml-kem`]: https://crates.io/crates/ml-kem

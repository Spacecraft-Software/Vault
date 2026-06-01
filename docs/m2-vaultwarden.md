<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# M2 manual gate — login + sync against a Vaultwarden container

The library tests in `vault-api/tests/parsing.rs` and
`vault-store/tests/cache.rs` cover the wire-shape decoding and the encrypted
disk-cache round-trip. The HTTP integration test in
`vault-api/tests/login_sync.rs` covers the full live path against a wiremock
origin; CI runs it via `cargo test -- --ignored`. This document is the manual
recipe for verifying the *real* M2 gate against an actual Vaultwarden
server — sufficient to demonstrate "vault sync populates encrypted cache" end
to end.

## 1. Start Vaultwarden in a container

```sh
podman run --rm --name vw -d \
    -p 8080:80 \
    -e SIGNUPS_ALLOWED=true \
    -e DISABLE_ADMIN_TOKEN=true \
    docker.io/vaultwarden/server:latest
```

Same command with `docker` if podman isn't available. The server now listens
on `http://localhost:8080`.

## 2. Register a test account

Either through the web UI at `http://localhost:8080` (Create Account → use
`vault-m2@example.org`, password `m2-gate-test`), or via the Bitwarden CLI:

```sh
bw config server http://localhost:8080
bw register vault-m2@example.org m2-gate-test --name vault-m2
```

Add at least one item to the vault so `/api/sync` has something to return.

## 3. Drive Vault's API client from a tiny harness

Until `vault login` and `vault sync` are wired in M3 (they need the agent for
key custody), the library APIs are driven directly. Save this as
`examples/m2_smoke.rs` under `crates/vault-api/` if you want to keep it:

```rust
use uuid::Uuid;
use vault_api::{BaseUrls, BitwardenClient};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let urls = BaseUrls::self_hosted("http://localhost:8080")?;
    let mut client = BitwardenClient::new(urls, Uuid::new_v4(), "vault-m2")?;
    let pre = client.prelogin("vault-m2@example.org").await?;
    let params = pre.into_kdf_params()?;
    client
        .login_password(
            "vault-m2@example.org",
            b"m2-gate-test",
            params,
        )
        .await?;
    let sync = client.sync().await?;
    eprintln!("ciphers: {}, folders: {}", sync.cipher_count(), sync.folder_count());
    Ok(())
}
```

Then:

```sh
cargo run -p vault-api --example m2_smoke
```

Expected output: `ciphers: 1, folders: 0` (or whatever you added in step 2).

## 4. Persist to the encrypted cache

Extend the harness — or follow `tests/login_sync.rs` — to call
`VaultCache::set_payload` and `save_to_dir`, then re-read with
`load_from_dir` + `load_payload`. The same KDF + HKDF used to derive the
keys must be supplied at load time; this approximation will be replaced in
M3 by the user symmetric key the agent holds.

## 5. Tear down

```sh
podman stop vw   # (or `docker stop vw`)
```

## Notes

- Vaultwarden defaults to PBKDF2 today. Test the Argon2id branch by
  registering through the official Bitwarden CLI with `--kdf 1
  --kdf-iter 3 --kdf-memory 65536 --kdf-parallelism 4`, or by editing the
  user row in the Vaultwarden SQLite DB directly.
- Two-factor authentication is **not** implemented in M2. The account you
  use here must not have 2FA enabled.
- `SIGNUPS_ALLOWED=true` is a test-only convenience; do not run a
  production Vaultwarden that way.

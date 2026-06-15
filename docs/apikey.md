<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Manual gate — API-key login against a 2FA account

`vault login --api-key` is exercised in unit/wiremock tests
(`vault-api/tests/login_sync.rs`, `vault-store/tests/cache.rs`,
`vault-ipc/tests/transport.rs`), but the end-to-end "skips the 2FA prompt" claim
can only be verified against a real Bitwarden / Vaultwarden account with
two-factor auth enabled and a personal API key. This is the manual recipe.

> The API key is one way past 2FA; the other is the **interactive
> authenticator prompt** — `vault login` (no `--api-key`) prompts for a TOTP
> code (or takes `--totp` / `$BW_TOTP`). Use the API key when you want
> unattended logins; use the prompt when you'd rather not store a key.

## Prerequisites

- A Bitwarden (hosted) or Vaultwarden account **with 2FA enabled**.
- A personal API key for that account: web vault → **Settings → Security →
  Keys → View API Key** → gives `client_id` (`user.<uuid>`) and `client_secret`.
- A `vault` + `vault-agent` build on `PATH` (`cargo build`).

## Recipe

```sh
# 1. Register the account profile (server + email + a stable device id). No network.
vault register --server https://vault.example.org --email me@example.org

# 2. Confirm the password grant is 2FA-blocked (this is the gap the API key closes).
vault login
#   Master password: …
#   -> error: two-factor authentication required … (expected: no TOTP entry)

# 3. Log in with the API key — the client_credentials grant skips 2FA.
BW_CLIENTID=user.xxxx BW_CLIENTSECRET=… vault login --api-key
#   Master password: …            <- still required, to DECRYPT the vault
#   -> authenticated; sync ok      (no 2FA prompt)
vault list                         # browse decrypted names

# 4. The key was persisted (0600). A routine unlock reuses it — no 2FA, no key re-entry.
vault apikey status                # -> api key: configured (user.xxxx)
ls -l "${XDG_DATA_HOME:-$HOME/.local/share}/vault"/*/apikey.json   # -> -rw------- (0600)
vault lock
vault unlock                       # master password only -> unlocks, no 2FA
vault-tui                          # locked screen -> type master password -> browser

# 5. (Optional) PIN/offline -> online still works for an API-key account.
vault pin set                      # enroll a PIN
vault lock && vault unlock --pin   # read-only PIN session
vault sync                         # ensure_online re-auths via the stored API key

# 6. Forget the key -> logins revert to the password grant (2FA-blocked again).
vault apikey forget                # -> api key forgotten
vault apikey status                # -> api key: not configured
vault login                        # -> two-factor authentication required (back to step 2)
```

## What each step proves

- **Step 2 vs 3:** the password grant 2FA-fails while the API key authenticates
  cleanly — the API key *is* the second factor.
- **Step 3:** the master password is still prompted and required; the API key
  does not replace it (it only obtains the token).
- **Step 4:** the key is persisted `0600` and auto-reused by `unlock` / the TUI.
- **Step 5:** a token-less (PIN/offline) session can still go online because
  `ensure_online` re-authenticates with the stored key.
- **Step 6:** `forget` removes the key and auth falls back to the password grant.

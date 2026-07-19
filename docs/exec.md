<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# `vault exec` — inject secrets as env vars at launch

Run a command with env vars resolved from vault items at launch time, instead
of exporting API keys into your shell for the session (`export
ANTHROPIC_API_KEY=…`) where they sit in shell history, `env`, and
`/proc/<pid>/environ` for as long as the shell lives.

```sh
vault exec -- claude
vault exec --profile llm-agents -- opencode
```

Each configured env var is resolved with one `Get` against the agent and
injected only into the child process's environment — never into the invoking
shell, and never written to disk in plaintext.

## Configure a profile

Mappings live in `[exec.profiles.<name>]` in `config.toml`, edited via `vault
config exec` (no manual TOML editing needed):

```sh
vault config exec set ANTHROPIC_API_KEY "Anthropic API Key"
vault config exec set --profile llm-agents ANTHROPIC_API_KEY "Anthropic API Key"
vault config exec set --profile llm-agents BRAVE_API_KEY "Brave Search API Key#custom:api_key"

vault config exec list                # every profile
vault config exec list default        # one profile
vault config exec unset BRAVE_API_KEY  # drops the profile once its last var is gone
```

`--profile` defaults to `default` on both `exec` and `config exec` when
omitted. Give each LLM agent its own vault item (`Anthropic API Key (Claude
Code)`, `OpenAI API Key (Codex)`, …) so keys can be rotated or revoked
independently — that's the point of routing through Vault instead of one
shared shell export.

## Item-spec grammar

The right-hand side of each mapping is `<item name>` or `<item
name>#<field>`:

| Spec                          | Resolves to                              |
|--------------------------------|-------------------------------------------|
| `Anthropic API Key`            | the item's password field (the default)   |
| `Item#username`                | the item's username field                 |
| `Item#notes`                   | the item's notes field                    |
| `Item#totp`                    | a freshly generated TOTP code              |
| `Item#custom:api_key`          | the custom field named `api_key` (case-insensitive) |

Use a custom field when the key doesn't naturally live in the password slot —
e.g. an item that also stores an org id in the password field and the API key
in a custom field.

## Failure is closed, not partial

`vault exec` resolves every mapped var *before* launching the child. If any
item is missing, a field is absent, or a name matches more than one item, the
command aborts with a clear error and the child never starts — you never get
a half-populated environment silently missing one key.

## What this does and doesn't protect against

Once injected, the values are ordinary env vars in the child process: visible
to that process, to anything it in turn execs, and — for other processes
running as the same user — via `/proc/<pid>/environ` for the child's
lifetime. That's inherent to how OS environment variables work, the same as
`envchain`, `direnv exec`, or `vaultenv`; `vault exec` isn't a secret-holding
channel once a value crosses into the child's environment. What it *does*
give you over a shell `export`:

- The secret is resolved fresh at launch, not left sitting in the invoking
  shell's environment (or its history) for the rest of the session.
- Nothing is written to disk in plaintext — it's decrypted in the agent and
  crosses the local UDS socket only as far as this one process.
- Per-agent items mean revoking or rotating one key doesn't require touching
  the others.

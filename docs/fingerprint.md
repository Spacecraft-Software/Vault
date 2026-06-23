<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Fingerprint unlock (`fingerprint` feature, Linux)

Re-unlock Vault with a fingerprint touch instead of re-typing the master
password. Off by default; Linux + `fprintd` only.

## What it is — and what it is **not**

Fingerprint unlock **gates the resume of a key that already lives in the kernel
session keyring** (`agent.session_keyring`). A fingerprint yields only
*match / no-match*, never key material, so this is **not** a PIN-style at-rest
wrap and gives **no cryptographic protection** beyond `session_keyring`:

- The keyring entry is **possessor-gated, not fingerprint-gated** — any process
  in your login session can read it directly, bypassing Vault and the
  fingerprint. So fingerprint unlock is **convenience + user-presence**, no
  stronger than `session_keyring`, and **weaker than a master-password unlock**
  (which derives the key fresh and never persists it).
- Real biometric-gated-at-rest protection would need TPM2/FIDO2 hardware
  sealing — out of scope here.

This is the same default-off PRD §7.3 / G4 carve-out as `session_keyring`, plus
a biometric gate on resume. Leave it off (the default) and nothing changes.

## How it behaves

With `agent.fingerprint_unlock` on (requires `agent.session_keyring`):

- The agent **does not silently auto-resume** on restart / after idle-lock — it
  stays locked until a verified touch.
- **Idle-lock** zeroises the in-memory key but **keeps** the keyring entry, so a
  touch re-unlocks after an idle timeout. The entry's lifetime is
  `agent.fingerprint_ttl_secs` (`0` = until logout / manual lock).
- **Manual `vault lock`** still clears the keyring — a fingerprint cannot bypass
  an explicit lock; the master password is required afterwards.
- The agent verifies the finger **itself** (D-Bus → `fprintd`), so a client
  can't bypass it by talking to the socket.

## Setup

```sh
# 1. Build/install an agent with the feature (Linux):
cargo install --path crates/vault-agent --features fingerprint --force

# 2. Enroll a finger at the OS level (Vault never stores templates):
fprintd-enroll

# 3. Enable the keyring store + the fingerprint gate:
vault config set agent.session_keyring true
vault config set agent.fingerprint_unlock true
# Optional: how long a touch can re-unlock after the last unlock (seconds);
# 0 = until logout / manual lock.
vault config set agent.fingerprint_ttl_secs 7200
```

(The CLI auto-spawns the agent with `--session-keyring --fingerprint-unlock
--fingerprint-ttl-secs …` from these keys. A custom systemd unit must pass the
same flags.)

## Use

```sh
vault unlock              # first unlock of the session: master password (+ 2FA)
# … later, after a restart or idle-lock:
vault unlock --fingerprint   # touch the sensor → unlocked
```

In `vault-tui`, the unlock screen offers a **fingerprint** mode (cycle with
`Tab` when enabled): press `Enter`, then touch the sensor.

## When it falls back

`vault unlock --fingerprint` (and the TUI mode) report **"unavailable"** and you
use the master password (or PIN) instead when:

- the agent was built without the `fingerprint` feature, or it's not Linux;
- there's no reader / `fprintd` / enrolled finger, or the session isn't active
  (e.g. SSH — PolicyKit denies);
- no resumable keyring session remains (TTL elapsed, logout, manual lock, or
  `session_keyring` is off).

A finger that's read but doesn't match reports **"fingerprint not recognized"**.

// SPDX-License-Identifier: GPL-3.0-or-later

//! User configuration — the typed `config.toml` behind `vault config`.
//!
//! A small, *known-key* registry: every setting is a dotted key
//! (`clipboard.clear_secs`) backed by a field on [`Config`]. `config set`
//! validates the key and parses the value to the field's type, so a typo or a
//! non-numeric value is rejected at write time rather than silently ignored by
//! whatever would have consumed it. The file lives at
//! `$XDG_CONFIG_HOME/vault/config.toml`; a missing file reads as defaults.
//!
//! Only the CLI reads this today — it sources the agent's launch flags from it
//! during auto-spawn (see `crate::spawn`). The registry is shaped to grow into
//! the rest of PRD §7.1's keys without disturbing callers.

use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Every recognised config key, in display order. `config get` with no key
/// lists exactly these; `set`/`get`/`unset` reject anything not here.
pub const KNOWN_KEYS: &[&str] = &["clipboard.clear_secs", "agent.idle_lock_secs"];

/// The full user configuration. Every field is optional — absence means "use
/// the consumer's own default" — so the on-disk file only carries what the
/// user has explicitly set.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Clipboard settings.
    pub clipboard: ClipboardCfg,
    /// Agent settings.
    pub agent: AgentCfg,
    /// Registered account profile (written by `vault register`). Skipped from
    /// the file until something is set, so an unregistered config carries no
    /// empty `[account]` table.
    #[serde(skip_serializing_if = "AccountCfg::is_empty")]
    pub account: AccountCfg,
}

/// `[clipboard]` table.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClipboardCfg {
    /// Seconds before a copied secret is auto-cleared; `0` disables.
    pub clear_secs: Option<u64>,
}

/// `[agent]` table.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AgentCfg {
    /// Idle-lock timeout in seconds; `0` disables auto-lock.
    pub idle_lock_secs: Option<u64>,
}

/// `[account]` table — the registered account, written by `vault register`
/// and read by `login`/`unlock` to default `server`/`email`/`device_id`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AccountCfg {
    /// Server origin (`https://vault.example.org`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    /// Account email (lower-cased on write).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Stable per-account device identifier (uuid v4), minted once at register
    /// time so the agent stops registering a fresh device each unlock.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
}

impl AccountCfg {
    /// Whether no account field is set (drives skipping the table on write).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.server.is_none() && self.email.is_none() && self.device_id.is_none()
    }
}

impl Config {
    /// Effective `clipboard.clear_secs`, if set.
    #[must_use]
    pub const fn clipboard_clear_secs(&self) -> Option<u64> {
        self.clipboard.clear_secs
    }

    /// Effective `agent.idle_lock_secs`, if set.
    #[must_use]
    pub const fn idle_lock_secs(&self) -> Option<u64> {
        self.agent.idle_lock_secs
    }

    /// The registered account profile.
    #[must_use]
    pub const fn account(&self) -> &AccountCfg {
        &self.account
    }

    /// Record the account `server` + `email`, lower-casing the email and
    /// minting a `device_id` once (a pre-existing id is preserved so the
    /// account keeps its identity across re-registration).
    pub fn set_account(&mut self, server: &str, email: &str) {
        self.account.server = Some(server.to_owned());
        self.account.email = Some(email.trim().to_lowercase());
        if self.account.device_id.is_none() {
            self.account.device_id = Some(uuid::Uuid::new_v4().to_string());
        }
    }

    /// Current value of `key` as a display string, `None` when unset. Errors
    /// (as the offending key) when `key` is not recognised.
    pub fn get(&self, key: &str) -> Result<Option<String>, String> {
        match key {
            "clipboard.clear_secs" => Ok(self.clipboard.clear_secs.map(|v| v.to_string())),
            "agent.idle_lock_secs" => Ok(self.agent.idle_lock_secs.map(|v| v.to_string())),
            other => Err(other.to_owned()),
        }
    }

    /// Parse `raw` and store it under `key`.
    ///
    /// # Errors
    ///
    /// Returns a user-facing message when `key` is unrecognised or `raw`
    /// doesn't parse as the key's type.
    pub fn set(&mut self, key: &str, raw: &str) -> Result<(), String> {
        match key {
            "clipboard.clear_secs" => {
                self.clipboard.clear_secs = Some(parse_u64(key, raw)?);
                Ok(())
            }
            "agent.idle_lock_secs" => {
                self.agent.idle_lock_secs = Some(parse_u64(key, raw)?);
                Ok(())
            }
            other => Err(unknown_key(other)),
        }
    }

    /// Clear `key`.
    ///
    /// # Errors
    ///
    /// Returns a user-facing message when `key` is unrecognised.
    pub fn unset(&mut self, key: &str) -> Result<(), String> {
        match key {
            "clipboard.clear_secs" => {
                self.clipboard.clear_secs = None;
                Ok(())
            }
            "agent.idle_lock_secs" => {
                self.agent.idle_lock_secs = None;
                Ok(())
            }
            other => Err(unknown_key(other)),
        }
    }
}

/// `key=value` agent launch flags for the keys the config sets, in
/// `KNOWN_KEYS` order. Consumed by auto-spawn; unset keys contribute nothing,
/// leaving the agent's own env/default precedence intact.
#[must_use]
pub fn agent_args(cfg: &Config) -> Vec<OsString> {
    let mut args = Vec::new();
    if let Some(secs) = cfg.clipboard_clear_secs() {
        args.push(OsString::from("--clipboard-clear-secs"));
        args.push(OsString::from(secs.to_string()));
    }
    if let Some(secs) = cfg.idle_lock_secs() {
        args.push(OsString::from("--idle-lock-secs"));
        args.push(OsString::from(secs.to_string()));
    }
    args
}

fn parse_u64(key: &str, raw: &str) -> Result<u64, String> {
    raw.parse::<u64>()
        .map_err(|_| format!("{key}: expected a non-negative integer, got '{raw}'"))
}

fn unknown_key(key: &str) -> String {
    format!(
        "unknown config key '{key}' (known: {})",
        KNOWN_KEYS.join(", ")
    )
}

/// Path to the config file: `$XDG_CONFIG_HOME/vault/config.toml`.
#[must_use]
pub fn config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("vault").join("config.toml"))
}

/// Load the config, treating an absent file as defaults.
///
/// # Errors
///
/// Returns a user-facing message when the config dir can't be located, the
/// file can't be read (other than not-found), or the TOML is malformed.
pub fn load() -> Result<Config, String> {
    let path = config_path().ok_or("could not locate the config directory")?;
    match std::fs::read_to_string(&path) {
        Ok(text) => toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// Persist `cfg` atomically (tempfile + rename), creating the config dir.
///
/// # Errors
///
/// Returns a user-facing message when the path can't be located, the directory
/// can't be created, or the write fails.
pub fn save(cfg: &Config) -> Result<PathBuf, String> {
    let path = config_path().ok_or("could not locate the config directory")?;
    let parent = path.parent().ok_or("config path has no parent directory")?;
    std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    let text = toml::to_string_pretty(cfg).map_err(|e| format!("serialise config: {e}"))?;

    // Atomic replace so a crash mid-write never truncates the file (mirrors
    // vault-store::write_atomic).
    let tmp = tempfile::NamedTempFile::new_in(parent).map_err(|e| format!("tempfile: {e}"))?;
    {
        let mut f = tmp.as_file();
        f.write_all(text.as_bytes())
            .and_then(|()| f.flush())
            .map_err(|e| format!("write config: {e}"))?;
    }
    tmp.persist(&path)
        .map_err(|e| format!("{}: {}", path.display(), e.error))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_then_get_round_trips_both_keys() {
        let mut c = Config::default();
        c.set("clipboard.clear_secs", "45").expect("set");
        c.set("agent.idle_lock_secs", "600").expect("set");
        assert_eq!(
            c.get("clipboard.clear_secs").unwrap().as_deref(),
            Some("45")
        );
        assert_eq!(
            c.get("agent.idle_lock_secs").unwrap().as_deref(),
            Some("600")
        );
        assert_eq!(c.clipboard_clear_secs(), Some(45));
        assert_eq!(c.idle_lock_secs(), Some(600));
    }

    #[test]
    fn get_unset_key_is_none_not_error() {
        let c = Config::default();
        assert_eq!(c.get("clipboard.clear_secs"), Ok(None));
    }

    #[test]
    fn set_rejects_unknown_key_and_bad_value() {
        let mut c = Config::default();
        assert!(c.set("bogus.key", "1").is_err());
        let err = c.set("clipboard.clear_secs", "not-a-number").unwrap_err();
        assert!(err.contains("clipboard.clear_secs"), "{err}");
        // The bad set left the field untouched.
        assert_eq!(c.clipboard_clear_secs(), None);
    }

    #[test]
    fn unset_clears_a_set_key_and_rejects_unknown() {
        let mut c = Config::default();
        c.set("clipboard.clear_secs", "45").expect("set");
        c.unset("clipboard.clear_secs").expect("unset");
        assert_eq!(c.clipboard_clear_secs(), None);
        assert!(c.unset("nope.nope").is_err());
    }

    #[test]
    fn zero_is_a_valid_disabling_value() {
        let mut c = Config::default();
        c.set("clipboard.clear_secs", "0").expect("set");
        assert_eq!(c.clipboard_clear_secs(), Some(0));
    }

    #[test]
    fn known_keys_are_all_reachable_by_get_set_unset() {
        for key in KNOWN_KEYS {
            let mut c = Config::default();
            assert!(c.get(key).is_ok(), "get missing {key}");
            assert!(c.set(key, "1").is_ok(), "set missing {key}");
            assert!(c.unset(key).is_ok(), "unset missing {key}");
        }
    }

    #[test]
    fn toml_round_trips_through_serde() {
        let mut c = Config::default();
        c.set("clipboard.clear_secs", "45").expect("set");
        let text = toml::to_string_pretty(&c).expect("serialise");
        let back: Config = toml::from_str(&text).expect("parse");
        assert_eq!(back, c);
    }

    #[test]
    fn set_account_lowercases_email_and_mints_device_id_once() {
        let mut c = Config::default();
        c.set_account("https://vault.example.org", "Me@Example.org");
        assert_eq!(
            c.account().server.as_deref(),
            Some("https://vault.example.org")
        );
        assert_eq!(c.account().email.as_deref(), Some("me@example.org"));
        let id = c.account().device_id.clone().expect("device_id minted");
        // Re-registering a different server/email keeps the same device id.
        c.set_account("https://other.example.org", "Other@Example.org");
        assert_eq!(c.account().device_id.as_deref(), Some(id.as_str()));
        assert_eq!(c.account().email.as_deref(), Some("other@example.org"));
    }

    #[test]
    fn account_round_trips_and_absent_until_set() {
        // A config with nothing set must not emit an [account] table.
        let empty = toml::to_string_pretty(&Config::default()).expect("serialise");
        assert!(
            !empty.contains("[account]"),
            "empty config grew [account]:\n{empty}"
        );

        let mut c = Config::default();
        c.set_account("https://vault.example.org", "me@example.org");
        let text = toml::to_string_pretty(&c).expect("serialise");
        assert!(text.contains("[account]"), "account table missing:\n{text}");
        let back: Config = toml::from_str(&text).expect("parse");
        assert_eq!(back.account(), c.account());
    }

    #[test]
    fn agent_args_emits_only_set_keys_in_order() {
        let mut c = Config::default();
        assert!(agent_args(&c).is_empty(), "nothing set → no flags");

        c.set("agent.idle_lock_secs", "600").expect("set");
        assert_eq!(
            agent_args(&c),
            vec![OsString::from("--idle-lock-secs"), OsString::from("600")]
        );

        c.set("clipboard.clear_secs", "45").expect("set");
        assert_eq!(
            agent_args(&c),
            vec![
                OsString::from("--clipboard-clear-secs"),
                OsString::from("45"),
                OsString::from("--idle-lock-secs"),
                OsString::from("600"),
            ]
        );
    }
}

// SPDX-License-Identifier: GPL-3.0-or-later

//! Item-spec grammar for `vault exec` / `vault config exec`.
//!
//! An `[exec.profiles.*]` mapping stores `ENV_VAR = "<item spec>"`. The spec
//! names a vault item and, optionally, which field to pull the value from:
//! `<item name>` (defaults to the password field) or `<item name>#<field>`
//! where `<field>` is `password`/`username`/`notes`/`totp`/`custom:<name>`.
//! This module only parses that string into a [`vault_ipc::proto::Field`]
//! selector — resolving it against the agent is `cmd_exec`'s job.

use vault_ipc::proto::Field;

/// A parsed item spec: which item, and which of its fields.
#[derive(Debug, PartialEq, Eq)]
pub struct FieldSpec {
    /// Item name (decrypted form), matched like every other CLI selector.
    pub name: String,
    /// Which field to pull the value from.
    pub field: Field,
}

/// Parse an item spec (`"<item name>"` or `"<item name>#<field>"`).
///
/// # Errors
///
/// Returns a user-facing message when the item name is empty or the field
/// keyword after `#` isn't one of `password`/`username`/`notes`/`totp`/
/// `custom:<name>`.
pub fn parse_item_spec(raw: &str) -> Result<FieldSpec, String> {
    let (name, field_str) = match raw.split_once('#') {
        Some((name, field_str)) => (name.trim(), Some(field_str.trim())),
        None => (raw.trim(), None),
    };
    if name.is_empty() {
        return Err(format!("empty item name in exec spec '{raw}'"));
    }
    let field = field_str.map_or(Ok(Field::Password), parse_field)?;
    Ok(FieldSpec {
        name: name.to_owned(),
        field,
    })
}

fn parse_field(spec: &str) -> Result<Field, String> {
    let lower = spec.to_ascii_lowercase();
    match lower.as_str() {
        "password" => Ok(Field::Password),
        "username" => Ok(Field::Username),
        "notes" => Ok(Field::Notes),
        "totp" => Ok(Field::Totp),
        _ if lower.starts_with("custom:") => {
            let custom_name = spec["custom:".len()..].trim();
            if custom_name.is_empty() {
                Err("custom field spec must include a name, e.g. 'custom:api_key'".to_owned())
            } else {
                Ok(Field::Custom(custom_name.to_owned()))
            }
        }
        _ => Err(format!(
            "unknown exec field '{spec}' (expected password/username/notes/totp/custom:<name>)"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_name_defaults_to_password() {
        let spec = parse_item_spec("Anthropic API Key").expect("parse");
        assert_eq!(spec.name, "Anthropic API Key");
        assert_eq!(spec.field, Field::Password);
    }

    #[test]
    fn explicit_field_keywords_parse() {
        assert_eq!(
            parse_item_spec("Item#username").expect("parse").field,
            Field::Username
        );
        assert_eq!(
            parse_item_spec("Item#notes").expect("parse").field,
            Field::Notes
        );
        assert_eq!(
            parse_item_spec("Item#totp").expect("parse").field,
            Field::Totp
        );
        // Case-insensitive keyword matching.
        assert_eq!(
            parse_item_spec("Item#PASSWORD").expect("parse").field,
            Field::Password
        );
    }

    #[test]
    fn custom_field_preserves_name_case() {
        let spec = parse_item_spec("Brave Search#custom:API_Key").expect("parse");
        assert_eq!(spec.field, Field::Custom("API_Key".to_owned()));
    }

    #[test]
    fn whitespace_around_name_and_field_is_trimmed() {
        let spec = parse_item_spec("  Item Name  #  username  ").expect("parse");
        assert_eq!(spec.name, "Item Name");
        assert_eq!(spec.field, Field::Username);
    }

    #[test]
    fn rejects_empty_name_and_unknown_field() {
        assert!(parse_item_spec("#password").is_err());
        assert!(parse_item_spec("Item#bogus").is_err());
        assert!(parse_item_spec("Item#custom:").is_err());
    }
}

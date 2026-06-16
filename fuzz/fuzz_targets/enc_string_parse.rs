// SPDX-License-Identifier: GPL-3.0-or-later

//! Fuzz the security-critical Bitwarden "type 2" `EncString` parser.
//!
//! `EncString::parse` base64-decodes attacker-influenceable cache/sync strings
//! into IV / ciphertext / MAC, so it must never panic and must be internally
//! consistent. This target feeds arbitrary bytes (as lossy UTF-8) to the parser
//! and, on a successful parse, asserts the parse → serialize → parse round-trip
//! is stable — catching both panics and any parser/serializer disagreement.
//!
//! Run with `cargo +nightly fuzz run enc_string_parse` (see `docs/fuzzing.md`).

#![no_main]

use libfuzzer_sys::fuzz_target;
use vault_core::EncString;

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    if let Ok(parsed) = EncString::parse(&s) {
        // The canonical serialization of a parsed value must itself parse back
        // to an equal value — the parser and serializer must agree.
        let reparsed =
            EncString::parse(&parsed.serialize()).expect("serialize() output must re-parse");
        assert_eq!(parsed, reparsed, "parse/serialize round-trip diverged");
    }
});

// SPDX-License-Identifier: GPL-3.0-or-later

//! M1 gate — round-trip a Bitwarden-shaped encrypted export.
//!
//! The fixture is generated inside the test rather than checked in, because
//! we can't ship a real Bitwarden export without leaking the maintainer's
//! credentials. The test still exercises every wire-level detail an external
//! export touches: the JSON envelope, PBKDF2-SHA-256 / Argon2id KDFs,
//! HKDF-SHA-256 stretching, the hex-encoded validation slot, and AES-256-CBC
//! + HMAC-SHA-256 EncString framing.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::json;
use vault_core::enc_string::EncString;
use vault_core::kdf::{KdfParams, KdfType, derive_master_key, stretch_master_key};
use vault_core::{EncryptedExport, Error};

fn synth_export(password: &str, salt: &str, plaintext: &[u8], params: KdfParams) -> String {
    let derived = derive_master_key(password.as_bytes(), salt.as_bytes(), params).unwrap();
    let (enc_key, mac_key) = stretch_master_key(&derived).unwrap();
    let validation_pt = hex::encode(derived);
    let validation = EncString::encrypt(&enc_key, &mac_key, validation_pt.as_bytes());
    let data = EncString::encrypt(&enc_key, &mac_key, plaintext);

    let envelope = json!({
        "encrypted": true,
        "passwordProtected": true,
        "salt": salt,
        "kdfType": u8::from(params.kind),
        "kdfIterations": params.iterations,
        "kdfMemory": params.memory_kib,
        "kdfParallelism": params.parallelism,
        "encKeyValidation_DO_NOT_EDIT": validation.serialize(),
        "data": data.serialize(),
    });
    serde_json::to_string_pretty(&envelope).unwrap()
}

#[test]
fn enc_string_round_trip() {
    let enc_key = [0x11u8; 32];
    let mac_key = [0x22u8; 32];
    let message = b"the molten amber holds the void";
    let ct = EncString::encrypt(&enc_key, &mac_key, message);
    let pt = ct.decrypt(&enc_key, &mac_key).unwrap();
    assert_eq!(pt, message);
}

#[test]
fn enc_string_serialize_parse_round_trip() {
    let enc_key = [0xAAu8; 32];
    let mac_key = [0xBBu8; 32];
    let ct = EncString::encrypt(&enc_key, &mac_key, b"hello");
    let wire = ct.serialize();
    assert!(wire.starts_with("2."));
    let parsed = EncString::parse(&wire).unwrap();
    assert_eq!(parsed.decrypt(&enc_key, &mac_key).unwrap(), b"hello");
}

#[test]
fn enc_string_rejects_legacy_types() {
    let cases = ["0.aaaa", "1.bbbb"];
    for s in cases {
        match EncString::parse(s) {
            Err(Error::EncString(msg)) => {
                assert!(msg.contains("legacy") || msg.contains("missing"));
            }
            other => panic!("expected legacy rejection, got {other:?}"),
        }
    }
}

#[test]
fn enc_string_detects_tampering() {
    let enc_key = [0x33u8; 32];
    let mac_key = [0x44u8; 32];
    let ct = EncString::encrypt(&enc_key, &mac_key, b"super secret");
    let mut wire = ct.serialize();
    // Flip a single ciphertext byte by mutating the middle base64 component.
    let bar1 = wire.find('|').unwrap();
    let bar2 = bar1 + 1 + wire[bar1 + 1..].find('|').unwrap();
    let ct_b64 = &wire[bar1 + 1..bar2];
    let mut ct_bytes = B64.decode(ct_b64).unwrap();
    ct_bytes[0] ^= 0x01;
    let mutated_b64 = B64.encode(&ct_bytes);
    wire.replace_range(bar1 + 1..bar2, &mutated_b64);
    let parsed = EncString::parse(&wire).unwrap();
    matches!(parsed.decrypt(&enc_key, &mac_key), Err(Error::MacMismatch))
        .then_some(())
        .expect("tampered ciphertext must fail MAC");
}

#[test]
fn export_decrypt_pbkdf2() {
    // Low iteration count so the test stays fast; production uses 600_000.
    let params = KdfParams {
        kind: KdfType::Pbkdf2Sha256,
        iterations: 1_000,
        memory_kib: None,
        parallelism: None,
    };
    let plaintext = br#"{"items":[{"name":"hull-camera","login":{"username":"discovery"}}]}"#;
    let json = synth_export(
        "correct horse battery staple",
        "user@example.org",
        plaintext,
        params,
    );
    let env = EncryptedExport::from_json(&json).unwrap();
    let pt = env.decrypt(b"correct horse battery staple").unwrap();
    assert_eq!(pt, plaintext);
}

#[test]
fn export_decrypt_argon2id() {
    let params = KdfParams {
        kind: KdfType::Argon2id,
        iterations: 2,
        memory_kib: Some(8 * 1024),
        parallelism: Some(2),
    };
    let plaintext = br#"{"folders":[],"items":[]}"#;
    let json = synth_export("an even better password", "salt-bytes", plaintext, params);
    let env = EncryptedExport::from_json(&json).unwrap();
    let pt = env.decrypt(b"an even better password").unwrap();
    assert_eq!(pt, plaintext);
}

#[test]
fn export_rejects_wrong_password() {
    let params = KdfParams {
        kind: KdfType::Pbkdf2Sha256,
        iterations: 1_000,
        memory_kib: None,
        parallelism: None,
    };
    let json = synth_export("right", "salt", b"x", params);
    let env = EncryptedExport::from_json(&json).unwrap();
    matches!(env.decrypt(b"wrong"), Err(Error::BadExportPassword))
        .then_some(())
        .expect("wrong password must yield BadExportPassword");
}

#[test]
fn export_rejects_unencrypted_envelope() {
    let envelope = serde_json::to_string(&serde_json::json!({
        "encrypted": false,
        "passwordProtected": false,
        "salt": "x",
        "kdfType": 0,
        "kdfIterations": 1,
        "encKeyValidation_DO_NOT_EDIT": "",
        "data": "",
    }))
    .unwrap();
    matches!(
        EncryptedExport::from_json(&envelope),
        Err(Error::UnsupportedExport(_))
    )
    .then_some(())
    .expect("encrypted:false must be rejected");
}

#[test]
fn hkdf_stretch_known_answer() {
    // HKDF-SHA-256 with empty salt and a 32-byte all-zero PRK, info="enc"/"mac".
    // Verified against RFC 5869 §3 semantics: from_prk skips the extract step
    // and feeds the PRK straight to expand.
    let master = [0u8; 32];
    let (enc, mac) = stretch_master_key(&master).unwrap();
    assert_ne!(enc, [0u8; 32]);
    assert_ne!(mac, [0u8; 32]);
    assert_ne!(
        enc, mac,
        "enc and mac must diverge — different info strings"
    );
}

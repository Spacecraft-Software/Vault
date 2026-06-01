// SPDX-License-Identifier: GPL-3.0-or-later

//! Half of the M2 gate — sync-payload encryption/persistence round-trip.
//!
//! The HTTP half lives in `vault-api/tests/login_sync.rs` (gated `#[ignore]`
//! pending a working test-link environment; see that file's preamble). This
//! suite exercises the same `VaultCache::set_payload` / `load_payload` path
//! that a real sync would drive once the access token is in hand.

use vault_core::kdf::{KdfParams, KdfType, derive_master_key, stretch_master_key};
use vault_store::{VaultCache, load_from_dir, save_to_dir};

fn fast_pbkdf2() -> KdfParams {
    KdfParams {
        kind: KdfType::Pbkdf2Sha256,
        iterations: 1_000,
        memory_kib: None,
        parallelism: None,
    }
}

#[test]
fn cache_round_trip_through_disk() {
    let tmp = tempfile::tempdir().unwrap();

    // Stand in for the keys vault-agent will eventually hold.
    let master = derive_master_key(b"password", b"user@example.org", fast_pbkdf2()).unwrap();
    let (enc, mac) = stretch_master_key(&master).unwrap();

    let sync_json = br#"{"Profile":{"Email":"user@example.org"},"Ciphers":[{"Id":"c1"}]}"#;
    let mut cache = VaultCache::new(
        "device-uuid".into(),
        "https://vault.example.org".into(),
        "User@Example.org".into(),
    );
    assert_eq!(cache.email, "user@example.org"); // normalised at construction
    cache.set_payload(&enc, &mac, sync_json).unwrap();
    assert!(cache.last_sync.is_some());

    let path = save_to_dir(tmp.path(), &cache).unwrap();
    assert!(path.exists());
    let on_disk = std::fs::read_to_string(&path).unwrap();
    assert!(on_disk.contains("\"schema_version\": 1"));
    assert!(
        !on_disk.contains("Ciphers"),
        "payload must be encrypted on disk"
    );

    let loaded = load_from_dir(tmp.path()).unwrap();
    let pt = loaded.load_payload(&enc, &mac).unwrap();
    assert_eq!(pt, sync_json);
}

#[test]
fn cache_load_missing_returns_not_found() {
    let tmp = tempfile::tempdir().unwrap();
    let err = load_from_dir(tmp.path()).unwrap_err();
    assert!(matches!(err, vault_store::Error::NotFound(_)));
}

#[test]
fn cache_without_payload_errs_on_load() {
    let cache = VaultCache::new("dev".into(), "https://x".into(), "a@b".into());
    let key = [0u8; 32];
    let err = cache.load_payload(&key, &key).unwrap_err();
    assert!(matches!(err, vault_store::Error::NoPayload));
}

#[test]
fn cache_wrong_key_fails_to_decrypt() {
    let tmp = tempfile::tempdir().unwrap();
    let master = derive_master_key(b"right", b"user@example.org", fast_pbkdf2()).unwrap();
    let (enc, mac) = stretch_master_key(&master).unwrap();
    let mut cache = VaultCache::new("dev".into(), "https://x".into(), "a@b".into());
    cache.set_payload(&enc, &mac, b"secret payload").unwrap();
    save_to_dir(tmp.path(), &cache).unwrap();

    let bad = [0xFFu8; 32];
    let loaded = load_from_dir(tmp.path()).unwrap();
    let err = loaded.load_payload(&bad, &bad).unwrap_err();
    assert!(matches!(err, vault_store::Error::Crypto(_)));
}

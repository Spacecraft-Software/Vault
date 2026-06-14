// SPDX-License-Identifier: GPL-3.0-or-later

//! Half of the M2 gate — sync-payload encryption/persistence round-trip.
//!
//! The HTTP half lives in `vault-api/tests/login_sync.rs` (gated `#[ignore]`
//! pending a working test-link environment; see that file's preamble). This
//! suite exercises the same `VaultCache::set_payload` / `load_payload` path
//! that a real sync would drive once the access token is in hand.

use vault_core::kdf::{KdfParams, KdfType, derive_master_key, stretch_master_key};
use vault_store::{VaultCache, load_from_dir, save_to_dir};

const fn fast_pbkdf2() -> KdfParams {
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
        "User@Example.org",
    );
    assert_eq!(cache.email, "user@example.org"); // normalised at construction
    cache.set_payload(&enc, &mac, sync_json).unwrap();
    assert!(cache.last_sync.is_some());

    let path = save_to_dir(tmp.path(), &cache).unwrap();
    assert!(path.exists());
    let on_disk = std::fs::read_to_string(&path).unwrap();
    assert!(on_disk.contains("\"schema_version\": 2"));
    assert!(
        !on_disk.contains("Ciphers"),
        "payload must be encrypted on disk"
    );

    let loaded = load_from_dir(tmp.path()).unwrap();
    let pt = loaded.load_payload(&enc, &mac).unwrap();
    assert_eq!(pt, sync_json);
}

#[test]
fn protected_user_key_and_kdf_round_trip() {
    let tmp = tempfile::tempdir().unwrap();
    let mut cache = VaultCache::new("dev".into(), "https://x".into(), "a@b");
    cache.protected_user_key = Some("2.aaa|bbb|ccc".into());
    cache.kdf = Some(fast_pbkdf2());
    save_to_dir(tmp.path(), &cache).unwrap();

    let loaded = load_from_dir(tmp.path()).unwrap();
    assert_eq!(loaded.protected_user_key.as_deref(), Some("2.aaa|bbb|ccc"));
    assert_eq!(loaded.kdf, Some(fast_pbkdf2()));
}

/// A schema-1 cache (no `protected_user_key` / `kdf`) must still deserialize —
/// the new fields are serde-defaulted.
#[test]
fn legacy_v1_cache_still_loads() {
    let tmp = tempfile::tempdir().unwrap();
    let v1 = r#"{
        "schema_version": 1,
        "device_id": "dev",
        "server": "https://x",
        "email": "a@b",
        "last_sync": null,
        "payload": null
    }"#;
    std::fs::write(tmp.path().join("cache.json"), v1).unwrap();
    let loaded = load_from_dir(tmp.path()).unwrap();
    assert_eq!(loaded.email, "a@b");
    assert_eq!(loaded.protected_user_key, None);
    assert_eq!(loaded.kdf, None);
}

#[test]
fn cache_load_missing_returns_not_found() {
    let tmp = tempfile::tempdir().unwrap();
    let err = load_from_dir(tmp.path()).unwrap_err();
    assert!(matches!(err, vault_store::Error::NotFound(_)));
}

#[test]
fn cache_without_payload_errs_on_load() {
    let cache = VaultCache::new("dev".into(), "https://x".into(), "a@b");
    let key = [0u8; 32];
    let err = cache.load_payload(&key, &key).unwrap_err();
    assert!(matches!(err, vault_store::Error::NoPayload));
}

#[test]
fn cache_wrong_key_fails_to_decrypt() {
    let tmp = tempfile::tempdir().unwrap();
    let master = derive_master_key(b"right", b"user@example.org", fast_pbkdf2()).unwrap();
    let (enc, mac) = stretch_master_key(&master).unwrap();
    let mut cache = VaultCache::new("dev".into(), "https://x".into(), "a@b");
    cache.set_payload(&enc, &mac, b"secret payload").unwrap();
    save_to_dir(tmp.path(), &cache).unwrap();

    let bad = [0xFFu8; 32];
    let loaded = load_from_dir(tmp.path()).unwrap();
    let err = loaded.load_payload(&bad, &bad).unwrap_err();
    assert!(matches!(err, vault_store::Error::Crypto(_)));
}

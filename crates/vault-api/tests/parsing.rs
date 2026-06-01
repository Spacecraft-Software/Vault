// SPDX-License-Identifier: GPL-3.0-or-later

//! Pure-parse tests for the API wire shapes. These do **not** touch
//! `reqwest`'s linker dependencies (ring, hyper-rustls) and therefore link
//! cleanly even when ring's static-lib propagation is broken on the host —
//! see `tests/login_sync.rs` for the full-stack wiremock variant.

use vault_api::identity::{PreloginResponse, TokenResponse};
use vault_api::sync::SyncResponse;
use vault_api::{BaseUrls, Error};

#[test]
fn prelogin_pbkdf2_decodes() {
    let json = r#"{"kdf":0,"kdfIterations":600000,"kdfMemory":null,"kdfParallelism":null}"#;
    let pre: PreloginResponse = serde_json::from_str(json).unwrap();
    let params = pre.into_kdf_params().unwrap();
    assert_eq!(params.iterations, 600_000);
    assert!(params.memory_kib.is_none());
}

#[test]
fn prelogin_argon2id_decodes() {
    let json = r#"{"kdf":1,"kdfIterations":3,"kdfMemory":65536,"kdfParallelism":4}"#;
    let pre: PreloginResponse = serde_json::from_str(json).unwrap();
    let params = pre.into_kdf_params().unwrap();
    assert_eq!(params.iterations, 3);
    assert_eq!(params.memory_kib, Some(65_536));
    assert_eq!(params.parallelism, Some(4));
}

#[test]
fn token_response_minimal_decodes() {
    let json = r#"{
        "access_token":"abc",
        "expires_in":3600,
        "token_type":"Bearer",
        "refresh_token":"def",
        "Key":"2.iv|ct|mac"
    }"#;
    let t: TokenResponse = serde_json::from_str(json).unwrap();
    assert_eq!(t.access_token, "abc");
    assert_eq!(t.refresh_token.as_deref(), Some("def"));
    assert_eq!(t.key.as_deref(), Some("2.iv|ct|mac"));
}

#[test]
fn sync_response_counts() {
    let json = r#"{
        "Profile": {},
        "Folders": [{"Id":"f1"}, {"Id":"f2"}],
        "Collections": [],
        "Ciphers": [{"Id":"c1"}, {"Id":"c2"}, {"Id":"c3"}],
        "Domains": {},
        "Sends": []
    }"#;
    let s: SyncResponse = serde_json::from_str(json).unwrap();
    assert_eq!(s.cipher_count(), 3);
    assert_eq!(s.folder_count(), 2);
}

#[test]
fn base_urls_self_hosted_appends_paths() {
    let u = BaseUrls::self_hosted("https://vault.example.org").unwrap();
    assert_eq!(u.api.as_str(), "https://vault.example.org/api/");
    assert_eq!(u.identity.as_str(), "https://vault.example.org/identity/");
}

#[test]
fn base_urls_self_hosted_keeps_path_prefix() {
    // Reverse-proxied deployments often serve under a subpath.
    let u = BaseUrls::self_hosted("https://example.org/vw").unwrap();
    assert_eq!(u.api.as_str(), "https://example.org/vw/api/");
    assert_eq!(u.identity.as_str(), "https://example.org/vw/identity/");
}

#[test]
fn base_urls_rejects_garbage() {
    matches!(BaseUrls::self_hosted("not a url"), Err(Error::BaseUrl(_)))
        .then_some(())
        .expect("garbage URL must be rejected");
}

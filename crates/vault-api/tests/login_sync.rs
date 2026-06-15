// SPDX-License-Identifier: GPL-3.0-or-later

//! M2 gate — full login → sync → cache round-trip against a wiremock server.
//!
//! The test stands up a wiremock origin that emulates the three Vaultwarden
//! endpoints Vault needs: `/identity/accounts/prelogin`,
//! `/identity/connect/token`, and `/api/sync`. The client runs through the
//! real KDF, real master-password hashing, real HTTP transport (HTTP, not
//! TLS, since wiremock binds plaintext) and real JSON decode paths. The only
//! thing mocked is the server.
//!
//! **Why `#[ignore]`?**
//! This test links `reqwest` + `rustls` + `ring` into a test binary. On the
//! maintainer's current dev host the cargo / `links =` propagation drops
//! `-l static=ring_core_0_17_14_` from the test-binary link line, leaving
//! ring's asm-only symbols (`x25519_sc_mask`, `OPENSSL_cpuid_setup`, …)
//! undefined at link time. The library code is unaffected — `cargo check`
//! and `cargo build --workspace` succeed; only `--test login_sync` fails to
//! link. CI runs on a clean toolchain where this isn't an issue and will
//! re-enable the test via `cargo test -- --ignored`.
//!
//! Run locally with:
//!
//! ```sh
//! cargo test -p vault-api --test login_sync -- --ignored --nocapture
//! ```

// Test-support helpers below use `unwrap()` on infallible calls (writing to a
// `String`, etc.); a panic there fails the test, which is the intent.
#![allow(clippy::unwrap_used)]

use std::fmt::Write as _;
use std::path::Path;

use serde_json::json;
use uuid::Uuid;
use wiremock::matchers::{body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use vault_api::{BaseUrls, BitwardenClient};
use vault_core::EncString;
use vault_core::kdf::{KdfParams, KdfType, derive_master_key, stretch_master_key};
use vault_core::login::master_password_hash;
use vault_store::VaultCache;

const EMAIL: &str = "discovery@example.org";
const PASSWORD: &str = "open the pod bay doors";
const KDF_ITERS: u32 = 1_000; // fast for tests; real accounts use 600_000+

const fn pbkdf2_params() -> KdfParams {
    KdfParams {
        kind: KdfType::Pbkdf2Sha256,
        iterations: KDF_ITERS,
        memory_kib: None,
        parallelism: None,
    }
}

#[tokio::test]
#[ignore = "links ring into a test binary; see file preamble"]
async fn login_sync_cache_round_trip() {
    let server = MockServer::start().await;
    let urls = BaseUrls::self_hosted(&server.uri()).expect("self_hosted parses");

    // Pre-compute what the client *will* send so we can assert on it.
    let derived = derive_master_key(
        PASSWORD.as_bytes(),
        EMAIL.to_lowercase().as_bytes(),
        pbkdf2_params(),
    )
    .unwrap();
    let expected_hash = master_password_hash(&derived, PASSWORD.as_bytes()).unwrap();

    // --- /identity/accounts/prelogin -----------------------------------
    Mock::given(method("POST"))
        .and(path("/identity/accounts/prelogin"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kdf": 0,
            "kdfIterations": KDF_ITERS,
            "kdfMemory": null,
            "kdfParallelism": null
        })))
        .mount(&server)
        .await;

    // --- /identity/connect/token ---------------------------------------
    // wiremock's matchers are AND'd: this assertion fires only if the
    // form-encoded body contains the expected hash, asserting the client
    // computed the master-password hash correctly.
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(body_string_contains("grant_type=password"))
        .and(body_string_contains(urlencoded(&expected_hash)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "test-access-token",
            "expires_in": 3600,
            "token_type": "Bearer",
            "refresh_token": "test-refresh-token",
            "Key": "2.dGVzdA==|dGVzdA==|dGVzdA==",
            "PrivateKey": null
        })))
        .mount(&server)
        .await;

    // --- /api/sync ------------------------------------------------------
    let sync_body = json!({
        "Profile": { "Id": "user-id-1", "Email": EMAIL },
        "Folders": [
            { "Id": "folder-1", "Name": "2.iv==|ct==|mac==" }
        ],
        "Collections": [],
        "Ciphers": [
            { "Id": "cipher-1", "Type": 1, "Name": "2.iv==|ct==|mac==" },
            { "Id": "cipher-2", "Type": 1, "Name": "2.iv==|ct==|mac==" }
        ],
        "Domains": {},
        "Sends": []
    });
    Mock::given(method("GET"))
        .and(path("/api/sync"))
        .and(header("Authorization", "Bearer test-access-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sync_body))
        .mount(&server)
        .await;

    // --- Drive the real client -----------------------------------------
    let device_id = Uuid::new_v4();
    let mut client = BitwardenClient::new(urls.clone(), device_id, "vault-test").unwrap();
    let prelogin = client.prelogin(EMAIL).await.unwrap();
    let params = prelogin.into_kdf_params().unwrap();
    let token = client
        .login_password(EMAIL, PASSWORD.as_bytes(), params, None)
        .await
        .unwrap();
    assert_eq!(token.access_token, "test-access-token");
    assert!(client.is_authenticated());

    let sync = client.sync().await.unwrap();
    assert_eq!(sync.cipher_count(), 2);
    assert_eq!(sync.folder_count(), 1);

    // --- Persist to vault-store encrypted cache -------------------------
    let tmp = tempfile::tempdir().unwrap();
    let dir: &Path = tmp.path();

    // M2 stores under a key derived from the export-style stretch of the
    // master key. M3 will replace this with the agent-held user key.
    let (enc_key, mac_key) = stretch_master_key(&derived).unwrap();

    let sync_bytes = serde_json::to_vec(&sync).unwrap();
    let mut cache = VaultCache::new(device_id.to_string(), server.uri(), EMAIL);
    cache.set_payload(&enc_key, &mac_key, &sync_bytes).unwrap();
    let cache_path = vault_store::save_to_dir(dir, &cache).unwrap();
    assert!(cache_path.exists(), "cache.json must exist on disk");

    // --- Reload from disk and verify equality --------------------------
    let reloaded = vault_store::load_from_dir(dir).unwrap();
    assert_eq!(reloaded.email, EMAIL.to_lowercase());
    assert!(reloaded.last_sync.is_some());
    let pt = reloaded.load_payload(&enc_key, &mac_key).unwrap();
    let pt_json: serde_json::Value = serde_json::from_slice(&pt).unwrap();
    assert_eq!(pt_json["Ciphers"].as_array().unwrap().len(), 2);
    assert_eq!(pt_json["Folders"].as_array().unwrap().len(), 1);
}

#[tokio::test]
#[ignore = "links ring into a test binary; see file preamble"]
async fn wrong_password_surfaces_server_status() {
    let server = MockServer::start().await;
    let urls = BaseUrls::self_hosted(&server.uri()).unwrap();

    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_grant",
            "error_description": "username or password is incorrect"
        })))
        .mount(&server)
        .await;

    let mut client = BitwardenClient::new(urls, Uuid::new_v4(), "vault-test").unwrap();
    let err = client
        .login_password(EMAIL, b"wrong", pbkdf2_params(), None)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        vault_api::Error::ServerStatus { status: 400, .. }
    ));
}

#[tokio::test]
#[ignore = "links ring into a test binary; see file preamble"]
async fn delete_cipher_sends_authorized_delete() {
    let server = MockServer::start().await;
    let urls = BaseUrls::self_hosted(&server.uri()).unwrap();

    // Stand up a token mock so we can prime the client with an access token.
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "del-test-token",
            "expires_in": 3600,
            "token_type": "Bearer",
            "refresh_token": "del-test-refresh",
            "Key": "2.dGVzdA==|dGVzdA==|dGVzdA==",
            "PrivateKey": null
        })))
        .mount(&server)
        .await;

    let cipher_id = "11111111-2222-3333-4444-555555555555";
    Mock::given(method("DELETE"))
        .and(path(format!("/api/ciphers/{cipher_id}")))
        .and(header("Authorization", "Bearer del-test-token"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let mut client = BitwardenClient::new(urls, Uuid::new_v4(), "vault-test").unwrap();
    // Prime token via login_password (uses the token mock above).
    client
        .login_password(EMAIL, PASSWORD.as_bytes(), pbkdf2_params(), None)
        .await
        .unwrap();

    client.delete_cipher(cipher_id).await.unwrap();

    // 404 should surface as ServerStatus.
    Mock::given(method("DELETE"))
        .and(path("/api/ciphers/does-not-exist"))
        .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
        .mount(&server)
        .await;
    let err = client.delete_cipher("does-not-exist").await.unwrap_err();
    assert!(matches!(
        err,
        vault_api::Error::ServerStatus { status: 404, .. }
    ));
}

#[tokio::test]
#[ignore = "links ring into a test binary; see file preamble"]
async fn create_and_update_cipher_send_authorized_requests() {
    let server = MockServer::start().await;
    let urls = BaseUrls::self_hosted(&server.uri()).unwrap();

    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "write-test-token",
            "expires_in": 3600,
            "token_type": "Bearer",
            "Key": "2.dGVzdA==|dGVzdA==|dGVzdA==",
        })))
        .mount(&server)
        .await;

    // An encrypted, type-2 EncString name — the body must carry it verbatim.
    let enc = [0x11u8; 32];
    let mac = [0x22u8; 32];
    let name = EncString::encrypt(&enc, &mac, b"GitHub").serialize();
    let cipher = vault_core::Cipher {
        cipher_type: 1,
        name: Some(name),
        ..vault_core::Cipher::default()
    };

    let new_id = "aaaa1111-bbbb-2222-cccc-333333333333";
    Mock::given(method("POST"))
        .and(path("/api/ciphers"))
        .and(header("Authorization", "Bearer write-test-token"))
        .and(body_string_contains("\"name\":\"2."))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "Id": new_id })))
        .mount(&server)
        .await;

    let cipher_id = "44445555-6666-7777-8888-999999999999";
    Mock::given(method("PUT"))
        .and(path(format!("/api/ciphers/{cipher_id}")))
        .and(header("Authorization", "Bearer write-test-token"))
        .and(body_string_contains("\"name\":\"2."))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "Id": cipher_id })))
        .mount(&server)
        .await;

    let mut client = BitwardenClient::new(urls, Uuid::new_v4(), "vault-test").unwrap();
    client
        .login_password(EMAIL, PASSWORD.as_bytes(), pbkdf2_params(), None)
        .await
        .unwrap();

    let got_id = client.create_cipher(&cipher).await.unwrap();
    assert_eq!(got_id, new_id, "create returns the server-assigned id");

    client.update_cipher(cipher_id, &cipher).await.unwrap();

    // Unknown id on PUT surfaces as ServerStatus.
    Mock::given(method("PUT"))
        .and(path("/api/ciphers/nope"))
        .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
        .mount(&server)
        .await;
    let err = client.update_cipher("nope", &cipher).await.unwrap_err();
    assert!(matches!(
        err,
        vault_api::Error::ServerStatus { status: 404, .. }
    ));
}

#[tokio::test]
#[ignore = "links ring into a test binary; see file preamble"]
async fn create_secure_note_carries_securenote_marker() {
    let server = MockServer::start().await;
    let urls = BaseUrls::self_hosted(&server.uri()).unwrap();

    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "note-token",
            "expires_in": 3600,
            "token_type": "Bearer",
            "Key": "2.dGVzdA==|dGVzdA==|dGVzdA==",
        })))
        .mount(&server)
        .await;

    let enc = [0x33u8; 32];
    let mac = [0x44u8; 32];
    let note = vault_core::Cipher {
        cipher_type: 2,
        name: Some(EncString::encrypt(&enc, &mac, b"My note").serialize()),
        ..vault_core::Cipher::default()
    };

    // Type-2 bodies must carry the `secureNote` marker (and no `login`).
    Mock::given(method("POST"))
        .and(path("/api/ciphers"))
        .and(body_string_contains("\"secureNote\""))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "Id": "note-id-1" })))
        .mount(&server)
        .await;

    let mut client = BitwardenClient::new(urls, Uuid::new_v4(), "vault-test").unwrap();
    client
        .login_password(EMAIL, PASSWORD.as_bytes(), pbkdf2_params(), None)
        .await
        .unwrap();

    let id = client.create_cipher(&note).await.unwrap();
    assert_eq!(id, "note-id-1");
}

#[tokio::test]
#[ignore = "links ring into a test binary; see file preamble"]
async fn login_api_key_posts_client_credentials_grant() {
    let server = MockServer::start().await;
    let urls = BaseUrls::self_hosted(&server.uri()).unwrap();

    // The body must carry the client_credentials grant + the API-key creds.
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(body_string_contains("grant_type=client_credentials"))
        .and(body_string_contains("client_id=user.abc123"))
        .and(body_string_contains("client_secret=s3cr3t"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "apikey-token",
            "expires_in": 3600,
            "token_type": "Bearer",
            "Key": "2.dGVzdA==|dGVzdA==|dGVzdA==",
        })))
        .mount(&server)
        .await;

    let mut client = BitwardenClient::new(urls, Uuid::new_v4(), "vault-test").unwrap();
    let token = client
        .login_api_key("user.abc123", b"s3cr3t")
        .await
        .unwrap();
    assert_eq!(token.access_token, "apikey-token");
    assert!(token.key.is_some(), "client_credentials still returns Key");
    assert!(client.is_authenticated());
}

#[tokio::test]
#[ignore = "links ring into a test binary; see file preamble"]
async fn login_api_key_bad_key_surfaces_server_status() {
    let server = MockServer::start().await;
    let urls = BaseUrls::self_hosted(&server.uri()).unwrap();

    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_client"
        })))
        .mount(&server)
        .await;

    let mut client = BitwardenClient::new(urls, Uuid::new_v4(), "vault-test").unwrap();
    let err = client
        .login_api_key("user.abc123", b"wrong")
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        vault_api::Error::ServerStatus { status: 400, .. }
    ));
}

#[tokio::test]
#[ignore = "links ring into a test binary; see file preamble"]
async fn login_password_two_factor_challenge_then_resubmit() {
    let server = MockServer::start().await;
    let urls = BaseUrls::self_hosted(&server.uri()).unwrap();

    // First attempt → 400 with the 2FA-required shape. `up_to_n_times(1)` so it
    // matches only the first request; the coded resubmit falls through to the
    // success mock below.
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(body_string_contains("grant_type=password"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "TwoFactorProviders": [0],
            "TwoFactorProviders2": { "0": {} }
        })))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Resubmit carrying the authenticator code → 200 + token.
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(body_string_contains("twoFactorToken=123456"))
        .and(body_string_contains("twoFactorProvider=0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "tfa-token",
            "expires_in": 3600,
            "token_type": "Bearer",
            "Key": "2.dGVzdA==|dGVzdA==|dGVzdA==",
        })))
        .mount(&server)
        .await;

    let mut client = BitwardenClient::new(urls, Uuid::new_v4(), "vault-test").unwrap();
    let err = client
        .login_password(EMAIL, PASSWORD.as_bytes(), pbkdf2_params(), None)
        .await
        .unwrap_err();
    assert!(
        matches!(err, vault_api::Error::TwoFactorRequired(_)),
        "first attempt must 2FA-challenge: {err:?}"
    );

    let tf = vault_api::TwoFactor {
        provider: 0,
        token: "123456".to_owned(),
        remember: false,
    };
    let token = client
        .login_password(EMAIL, PASSWORD.as_bytes(), pbkdf2_params(), Some(&tf))
        .await
        .unwrap();
    assert_eq!(token.access_token, "tfa-token");
    assert!(client.is_authenticated());
}

fn urlencoded(s: &str) -> String {
    // wiremock body_string_contains needs the literal bytes that appear in
    // the form-encoded request body. reqwest's serde_urlencoded percent-
    // encodes `+`, `/`, `=` etc.
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            b' ' => out.push('+'),
            _ => {
                out.push('%');
                write!(out, "{b:02X}").unwrap();
            }
        }
    }
    out
}

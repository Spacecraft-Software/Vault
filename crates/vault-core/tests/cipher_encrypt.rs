// SPDX-License-Identifier: GPL-3.0-or-later

//! `Cipher::from_plain` → `Cipher::decrypt` round-trips: the encryption path
//! used by `vault add` / `vault edit` is the exact inverse of the read path.

use vault_core::cipher::{Cipher, DecryptOptions, PlainCipher};

#[test]
fn from_plain_then_decrypt_round_trips_login() {
    let enc = [0x11u8; 32];
    let mac = [0x22u8; 32];
    let plain = PlainCipher {
        id: "id-1".into(),
        cipher_type: 1,
        folder_id: Some("folder-1".into()),
        name: Some("GitHub".into()),
        notes: Some("a note".into()),
        username: Some("alice".into()),
        password: Some("hunter2".into()),
        totp: Some("otpauth://totp/x".into()),
        primary_uri: Some("https://github.com".into()),
    };

    let cipher = Cipher::from_plain(&plain, &enc, &mac);
    assert_eq!(cipher.cipher_type, 1);
    assert_eq!(cipher.id, "id-1");
    assert_eq!(cipher.folder_id.as_deref(), Some("folder-1"));
    // Every value field is a type-2 EncString, not plaintext.
    assert!(cipher.name.as_deref().unwrap().starts_with("2."));
    assert!(cipher.login.as_ref().unwrap().password.is_some());

    let back = cipher.decrypt(&enc, &mac, DecryptOptions::all()).unwrap();
    assert_eq!(back.name.as_deref(), Some("GitHub"));
    assert_eq!(back.notes.as_deref(), Some("a note"));
    assert_eq!(back.username.as_deref(), Some("alice"));
    assert_eq!(back.password.as_deref(), Some("hunter2"));
    assert_eq!(back.totp.as_deref(), Some("otpauth://totp/x"));
    assert_eq!(back.primary_uri.as_deref(), Some("https://github.com"));
}

#[test]
fn from_plain_secure_note_has_no_login_object() {
    let enc = [1u8; 32];
    let mac = [2u8; 32];
    let plain = PlainCipher {
        id: String::new(),
        cipher_type: 2,
        folder_id: None,
        name: Some("My note".into()),
        notes: Some("secret text".into()),
        username: None,
        password: None,
        totp: None,
        primary_uri: None,
    };

    let cipher = Cipher::from_plain(&plain, &enc, &mac);
    assert!(cipher.login.is_none(), "secure notes carry no login object");
    let back = cipher.decrypt(&enc, &mac, DecryptOptions::all()).unwrap();
    assert_eq!(back.name.as_deref(), Some("My note"));
    assert_eq!(back.notes.as_deref(), Some("secret text"));
}

#[test]
fn from_plain_omits_absent_login_fields() {
    let enc = [3u8; 32];
    let mac = [4u8; 32];
    let plain = PlainCipher {
        id: String::new(),
        cipher_type: 1,
        folder_id: None,
        name: Some("partial".into()),
        notes: None,
        username: Some("bob".into()),
        password: None,
        totp: None,
        primary_uri: None,
    };

    let cipher = Cipher::from_plain(&plain, &enc, &mac);
    let login = cipher.login.as_ref().unwrap();
    assert!(login.username.is_some());
    assert!(login.password.is_none());
    assert!(login.totp.is_none());
    assert!(login.uris.is_none());
    assert!(cipher.notes.is_none());
}

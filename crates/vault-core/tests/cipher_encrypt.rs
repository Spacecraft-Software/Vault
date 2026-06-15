// SPDX-License-Identifier: GPL-3.0-or-later

//! `Cipher::from_plain` → `Cipher::decrypt` round-trips: the encryption path
//! used by `vault add` / `vault edit` is the exact inverse of the read path.

use vault_core::cipher::{Card, Cipher, DecryptOptions, Identity, PlainCipher};
use vault_core::enc_string::EncString;

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
        card: None,
        identity: None,
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
        card: None,
        identity: None,
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
        card: None,
        identity: None,
    };

    let cipher = Cipher::from_plain(&plain, &enc, &mac);
    let login = cipher.login.as_ref().unwrap();
    assert!(login.username.is_some());
    assert!(login.password.is_none());
    assert!(login.totp.is_none());
    assert!(login.uris.is_none());
    assert!(cipher.notes.is_none());
}

#[test]
fn decrypt_card_fields() {
    let enc = [0x33u8; 32];
    let mac = [0x44u8; 32];
    let e = |s: &str| Some(EncString::encrypt(&enc, &mac, s.as_bytes()).serialize());
    let cipher = Cipher {
        id: "card-1".into(),
        cipher_type: 3,
        name: Some(EncString::encrypt(&enc, &mac, b"Visa").serialize()),
        card: Some(Card {
            cardholder_name: e("Alice Example"),
            brand: e("Visa"),
            number: e("4111111111111111"),
            exp_month: e("4"),
            exp_year: e("2030"),
            code: e("123"),
        }),
        ..Cipher::default()
    };

    let plain = cipher
        .decrypt(
            &enc,
            &mac,
            DecryptOptions {
                card: true,
                ..DecryptOptions::default()
            },
        )
        .unwrap();
    let card = plain.card.as_ref().expect("card decrypted");
    assert_eq!(card.number.as_deref(), Some("4111111111111111"));
    assert_eq!(card.code.as_deref(), Some("123"));
    assert_eq!(card.brand.as_deref(), Some("Visa"));
    assert_eq!(card.exp_month.as_deref(), Some("4"));
    // Not asked for → identity stays None even if absent.
    assert!(plain.identity.is_none());
}

#[test]
fn decrypt_identity_fields() {
    let enc = [0x55u8; 32];
    let mac = [0x66u8; 32];
    let e = |s: &str| Some(EncString::encrypt(&enc, &mac, s.as_bytes()).serialize());
    let cipher = Cipher {
        id: "id-1".into(),
        cipher_type: 4,
        identity: Some(Identity {
            first_name: e("Alice"),
            last_name: e("Example"),
            email: e("alice@example.org"),
            phone: e("+1 555 0100"),
            address1: e("1 Void Navy Way"),
            city: e("Amber"),
            ..Identity::default()
        }),
        ..Cipher::default()
    };

    let plain = cipher
        .decrypt(
            &enc,
            &mac,
            DecryptOptions {
                identity: true,
                ..DecryptOptions::default()
            },
        )
        .unwrap();
    let id = plain.identity.as_ref().expect("identity decrypted");
    assert_eq!(id.first_name.as_deref(), Some("Alice"));
    assert_eq!(id.last_name.as_deref(), Some("Example"));
    assert_eq!(id.email.as_deref(), Some("alice@example.org"));
    assert_eq!(id.phone.as_deref(), Some("+1 555 0100"));
    assert_eq!(id.address1.as_deref(), Some("1 Void Navy Way"));
    assert_eq!(id.ssn, None);
    assert!(plain.card.is_none());
}

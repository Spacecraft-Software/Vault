// SPDX-License-Identifier: GPL-3.0-or-later

//! Round-trip tests for the length-prefixed CBOR transport.

use tokio::io::{AsyncWriteExt, duplex};

use vault_ipc::proto::{Error as IpcError, Field, ListEntry, Request, Response, Status};
use vault_ipc::transport::{MAX_FRAME, read_frame, write_frame};

#[tokio::test]
async fn ping_round_trip() {
    let (mut a, mut b) = duplex(64 * 1024);
    write_frame(&mut a, &Request::Ping).await.unwrap();
    let got: Request = read_frame(&mut b).await.unwrap();
    assert!(matches!(got, Request::Ping));
}

#[tokio::test]
async fn unlock_round_trip_preserves_password_bytes() {
    let (mut a, mut b) = duplex(64 * 1024);
    let pw = b"correct horse battery staple\x00\x01\xff".to_vec();
    let req = Request::Unlock {
        server: "https://vault.example.org".into(),
        email: "user@example.org".into(),
        password: pw.clone(),
        device_id: Some("11111111-2222-3333-4444-555555555555".into()),
    };
    write_frame(&mut a, &req).await.unwrap();
    let got: Request = read_frame(&mut b).await.unwrap();
    match got {
        Request::Unlock {
            server,
            email,
            password,
            device_id,
        } => {
            assert_eq!(server, "https://vault.example.org");
            assert_eq!(email, "user@example.org");
            assert_eq!(password, pw);
            assert_eq!(
                device_id.as_deref(),
                Some("11111111-2222-3333-4444-555555555555")
            );
        }
        other => panic!("expected Unlock, got {other:?}"),
    }
}

/// An `Unlock` frame from a client built before `device_id` existed must still
/// decode — the field is serde-defaulted, the protocol's forward-compat rule
/// for added optional fields.
#[tokio::test]
async fn unlock_without_device_id_field_still_decodes() {
    #[derive(serde::Serialize)]
    #[serde(tag = "op", content = "args", rename_all = "snake_case")]
    enum OldRequest {
        Unlock {
            server: String,
            email: String,
            password: Vec<u8>,
        },
    }
    let (mut a, mut b) = duplex(64 * 1024);
    let old = OldRequest::Unlock {
        server: "https://vault.example.org".into(),
        email: "user@example.org".into(),
        password: b"pw".to_vec(),
    };
    write_frame(&mut a, &old).await.unwrap();
    let got: Request = read_frame(&mut b).await.unwrap();
    match got {
        Request::Unlock { device_id, .. } => assert_eq!(device_id, None, "absent → None"),
        other => panic!("expected Unlock, got {other:?}"),
    }
}

#[tokio::test]
async fn list_response_round_trip() {
    let (mut a, mut b) = duplex(64 * 1024);
    let entries = vec![
        ListEntry {
            id: "01".into(),
            name: "github.com".into(),
            cipher_type: 1,
            username: Some("alice".into()),
            folder: Some("work".into()),
        },
        ListEntry {
            id: "02".into(),
            name: "secret-note".into(),
            cipher_type: 2,
            username: None,
            folder: None,
        },
    ];
    write_frame(&mut a, &Response::List(entries.clone()))
        .await
        .unwrap();
    let got: Response = read_frame(&mut b).await.unwrap();
    match got {
        Response::List(v) => {
            assert_eq!(v.len(), 2);
            assert_eq!(v[0].name, "github.com");
            assert_eq!(v[0].username.as_deref(), Some("alice"));
            assert_eq!(v[1].cipher_type, 2);
        }
        other => panic!("expected Response::List, got {other:?}"),
    }
}

#[tokio::test]
async fn error_response_round_trip() {
    let (mut a, mut b) = duplex(8 * 1024);
    let cases = [
        IpcError::Locked,
        IpcError::BadPassword,
        IpcError::TwoFactorRequired,
        IpcError::NoSuchItem("github.com".into()),
        IpcError::NoSuchField {
            item: "github.com".into(),
            field: "totp".into(),
        },
        IpcError::Network("DNS".into()),
        IpcError::Decrypt("MAC mismatch".into()),
        IpcError::Internal("bug".into()),
    ];
    for original in cases {
        write_frame(&mut a, &Response::Error(original.clone()))
            .await
            .unwrap();
        let got: Response = read_frame(&mut b).await.unwrap();
        match got {
            Response::Error(e) => assert_eq!(e.to_string(), original.to_string()),
            other => panic!("expected Response::Error, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn status_round_trip_preserves_optionals() {
    let (mut a, mut b) = duplex(8 * 1024);
    let s = Status {
        unlocked: true,
        server: Some("https://vault.example.org".into()),
        email: Some("alice@example.org".into()),
        items: Some(42),
        last_sync: Some("2026-06-01T00:00:00Z".into()),
        agent_version: "0.0.1".into(),
        clipboard_backend: Some("arboard".into()),
    };
    write_frame(&mut a, &Response::Status(s.clone()))
        .await
        .unwrap();
    let got: Response = read_frame(&mut b).await.unwrap();
    match got {
        Response::Status(got) => {
            assert!(got.unlocked);
            assert_eq!(got.items, Some(42));
            assert_eq!(got.agent_version, "0.0.1");
            assert_eq!(got.clipboard_backend.as_deref(), Some("arboard"));
        }
        other => panic!("expected Status, got {other:?}"),
    }
}

/// A `Status` frame from an agent built before `clipboard_backend` existed
/// must still decode — the field is serde-defaulted, which is the protocol's
/// stated forward-compat strategy for added optional fields.
#[tokio::test]
async fn status_without_clipboard_backend_field_still_decodes() {
    // Hand-build the CBOR an old agent would send: the externally-tagged
    // Status response whose struct lacks the new field entirely.
    #[derive(serde::Serialize)]
    struct OldStatus {
        unlocked: bool,
        server: Option<String>,
        email: Option<String>,
        items: Option<usize>,
        last_sync: Option<String>,
        agent_version: String,
    }
    #[derive(serde::Serialize)]
    #[serde(tag = "kind", content = "data", rename_all = "snake_case")]
    enum OldResponse {
        Status(OldStatus),
    }

    let (mut a, mut b) = duplex(8 * 1024);
    let old = OldResponse::Status(OldStatus {
        unlocked: false,
        server: None,
        email: None,
        items: None,
        last_sync: None,
        agent_version: "0.0.0".into(),
    });
    write_frame(&mut a, &old).await.unwrap();
    let got: Response = read_frame(&mut b).await.unwrap();
    match got {
        Response::Status(got) => {
            assert_eq!(got.clipboard_backend, None, "defaults when absent");
            assert_eq!(got.agent_version, "0.0.0");
        }
        other => panic!("expected Status, got {other:?}"),
    }
}

#[tokio::test]
async fn get_request_defaults_to_password() {
    let (mut a, mut b) = duplex(8 * 1024);
    let req = Request::Get {
        id: None,
        name: "github.com".into(),
        field: None,
    };
    write_frame(&mut a, &req).await.unwrap();
    let got: Request = read_frame(&mut b).await.unwrap();
    match got {
        Request::Get { id, name, field } => {
            assert_eq!(id, None);
            assert_eq!(name, "github.com");
            assert_eq!(field.unwrap_or_default(), Field::Password);
        }
        other => panic!("expected Get, got {other:?}"),
    }
}

#[tokio::test]
async fn oversized_length_prefix_is_rejected() {
    // Forge a frame whose declared length exceeds MAX_FRAME — read_frame
    // must reject without allocating gigabytes.
    let (mut a, mut b) = duplex(64);
    let len = MAX_FRAME + 1;
    a.write_all(&len.to_be_bytes()).await.unwrap();
    a.flush().await.unwrap();
    drop(a);
    let res: std::io::Result<Request> = read_frame(&mut b).await;
    assert!(res.is_err(), "oversized length must error");
}

#[tokio::test]
async fn short_read_returns_unexpected_eof() {
    let (a, mut b) = duplex(64);
    drop(a); // immediate EOF
    let res: std::io::Result<Request> = read_frame(&mut b).await;
    assert!(res.is_err(), "EOF must surface as an error");
}

#[tokio::test]
async fn multiple_frames_on_one_stream() {
    let (mut a, mut b) = duplex(64 * 1024);
    write_frame(&mut a, &Request::Ping).await.unwrap();
    write_frame(&mut a, &Request::Lock).await.unwrap();
    write_frame(&mut a, &Request::Quit).await.unwrap();
    assert!(matches!(
        read_frame::<_, Request>(&mut b).await.unwrap(),
        Request::Ping
    ));
    assert!(matches!(
        read_frame::<_, Request>(&mut b).await.unwrap(),
        Request::Lock
    ));
    assert!(matches!(
        read_frame::<_, Request>(&mut b).await.unwrap(),
        Request::Quit
    ));
}

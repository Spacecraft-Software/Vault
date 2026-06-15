// SPDX-License-Identifier: GPL-3.0-or-later

//! UDS server — one tokio task per accepted connection.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;

use vault_ipc::proto::{Request, Response};
use vault_ipc::{read_frame, write_frame};

use crate::state::AgentState;
use crate::unlock::perform_unlock;

/// Bind the listener at `path` with mode 0700 on the parent dir and 0600 on
/// the socket itself, then run the accept loop until shutdown is signalled.
pub async fn run(path: PathBuf, state: Arc<Mutex<AgentState>>) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        let perms = std::fs::Permissions::from_mode(0o700);
        std::fs::set_permissions(parent, perms)?;
    }
    // If a stale socket from a previous run is in the way, remove it. We
    // don't probe whether it's live — the connect() side will error if it is.
    let _ = std::fs::remove_file(&path);

    let listener = UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;

    eprintln!("vault-agent: listening on {}", path.display());

    loop {
        // Check the shutdown flag in between accepts.
        if state.lock().await.shutdown_requested {
            break;
        }

        let accept = listener.accept().await;
        match accept {
            Ok((stream, _addr)) => {
                let s = state.clone();
                tokio::spawn(handle_conn(stream, s));
            }
            Err(e) => {
                eprintln!("vault-agent: accept error: {e}");
            }
        }
    }

    let _ = std::fs::remove_file(&path);
    Ok(())
}

async fn handle_conn(stream: UnixStream, state: Arc<Mutex<AgentState>>) {
    let (mut rd, mut wr) = stream.into_split();
    loop {
        // Read one request per iteration; close on any framing error.
        let req: Request = match read_frame(&mut rd).await {
            Ok(r) => r,
            Err(_) => return,
        };
        let resp = dispatch(req, &state).await;
        if write_frame(&mut wr, &resp).await.is_err() {
            return;
        }
    }
}

#[allow(clippy::too_many_lines)] // flat one-arm-per-request protocol dispatch reads best in one place
async fn dispatch(req: Request, state: &Arc<Mutex<AgentState>>) -> Response {
    match req {
        Request::Ping | Request::Status => {
            let s = state.lock().await;
            Response::Status(s.status_snapshot())
        }
        Request::Unlock {
            server,
            email,
            password,
            device_id,
            api_key,
        } => {
            // Wrap the password so it is zeroised on drop no matter how
            // perform_unlock fares; deref coercion hands it to the API as &[u8].
            let password = zeroize::Zeroizing::new(password);
            let unlock_res = perform_unlock(
                &server,
                &email,
                &password,
                device_id.as_deref(),
                api_key.as_ref(),
            )
            .await;
            match unlock_res {
                Ok(vault) => {
                    let mut s = state.lock().await;
                    s.vault = Some(vault);
                    s.persist_session();
                    s.touch();
                    Response::Ok
                }
                Err(e) => Response::Error(e),
            }
        }
        Request::UnlockPin { server, email, pin } => {
            let pin = zeroize::Zeroizing::new(pin);
            // PIN unlock is offline (cache only) and synchronous; run it, then
            // install the resulting read-only vault.
            match crate::unlock::unlock_pin(&server, &email, &pin) {
                Ok(vault) => {
                    let mut s = state.lock().await;
                    s.vault = Some(vault);
                    s.persist_session();
                    s.touch();
                    Response::Ok
                }
                Err(e) => Response::Error(e),
            }
        }
        Request::PinSet { pin } => {
            let pin = zeroize::Zeroizing::new(pin);
            let mut s = state.lock().await;
            let res = s.pin_enroll(&pin);
            s.touch();
            drop(s);
            match res {
                Ok(()) => Response::Ok,
                Err(e) => Response::Error(e),
            }
        }
        Request::PinDisable { server, email } => {
            match crate::unlock::pin_disable(&server, &email) {
                Ok(()) => Response::Ok,
                Err(e) => Response::Error(e),
            }
        }
        Request::PinStatus { server, email } => {
            Response::PinStatus(crate::unlock::pin_status(&server, &email))
        }
        Request::ApiKeyStatus { server, email } => {
            Response::ApiKeyStatus(crate::unlock::apikey_status(&server, &email))
        }
        Request::ApiKeyForget { server, email } => {
            match crate::unlock::apikey_forget(&server, &email) {
                Ok(()) => Response::Ok,
                Err(e) => Response::Error(e),
            }
        }
        Request::Lock => {
            let mut s = state.lock().await;
            // Explicit lock: also forget any persisted keyring session.
            s.lock_and_clear_session();
            s.touch();
            Response::Ok
        }
        Request::Sync => {
            // Re-pull /sync over the unlock-time session and refresh the
            // in-memory cache. Hold the mutex across the network call (as with
            // Remove) — single-user / single-agent, so a coarse lock is fine.
            let mut s = state.lock().await;
            let res = s.resync().await;
            s.touch();
            let resp = match res {
                Ok(()) => Response::Status(s.status_snapshot()),
                Err(e) => Response::Error(e),
            };
            drop(s);
            resp
        }
        Request::List => {
            let mut s = state.lock().await;
            let res = s.list_entries();
            s.touch();
            drop(s);
            match res {
                Ok(items) => Response::List(items),
                Err(e) => Response::Error(e),
            }
        }
        Request::Get { id, name, field } => {
            let mut s = state.lock().await;
            let f = field.unwrap_or_default();
            let res = s.get_item(id.as_deref(), &name, f);
            s.touch();
            drop(s);
            match res {
                Ok(item) => Response::Item(item),
                Err(e) => Response::Error(e),
            }
        }
        #[cfg(feature = "clipboard")]
        Request::Copy {
            id,
            name,
            field,
            clear_after_secs,
        } => {
            let f = field.unwrap_or_default();
            let mut s = state.lock().await;
            // Decrypt the field, then hand it straight to the agent's own
            // clipboard. `item` zeroises its copy on drop; `value` is the copy
            // the clear task carries so it knows what to wipe.
            let outcome = match s.get_item(id.as_deref(), &name, f) {
                Ok(item) => {
                    let value = zeroize::Zeroizing::new(item.value.clone());
                    s.clipboard_set(&value).map(|()| value)
                }
                Err(e) => Err(e),
            };
            let secs = clear_after_secs.unwrap_or(s.clipboard_clear_secs);
            s.touch();
            drop(s);
            match outcome {
                Ok(value) => {
                    schedule_clipboard_clear(state.clone(), value, secs);
                    Response::Copied(vault_ipc::proto::Copied {
                        clear_after_secs: secs,
                    })
                }
                Err(e) => Response::Error(e),
            }
        }
        #[cfg(not(feature = "clipboard"))]
        Request::Copy { .. } => Response::Error(vault_ipc::proto::Error::ClipboardUnavailable),
        #[cfg(feature = "clipboard")]
        Request::CopyText {
            text,
            clear_after_secs,
        } => {
            // The wrapper zeroises the inbound bytes no matter which way the
            // arm exits; `value` is the copy the clear task carries.
            let text = zeroize::Zeroizing::new(text);
            let mut s = state.lock().await;
            let outcome = if s.is_unlocked() {
                std::str::from_utf8(&text)
                    .map_err(|e| {
                        vault_ipc::proto::Error::Internal(format!(
                            "copy text is not valid UTF-8: {e}"
                        ))
                    })
                    .and_then(|v| {
                        let value = zeroize::Zeroizing::new(v.to_owned());
                        s.clipboard_set(&value).map(|()| value)
                    })
            } else {
                Err(vault_ipc::proto::Error::Locked)
            };
            let secs = clear_after_secs.unwrap_or(s.clipboard_clear_secs);
            s.touch();
            drop(s);
            match outcome {
                Ok(value) => {
                    schedule_clipboard_clear(state.clone(), value, secs);
                    Response::Copied(vault_ipc::proto::Copied {
                        clear_after_secs: secs,
                    })
                }
                Err(e) => Response::Error(e),
            }
        }
        #[cfg(not(feature = "clipboard"))]
        Request::CopyText { .. } => Response::Error(vault_ipc::proto::Error::ClipboardUnavailable),
        Request::Remove { selector } => {
            // Hold the agent mutex across the network call. Vault is
            // single-user / single-agent, so request concurrency is low and
            // a coarse lock keeps the cache + server in lock-step.
            let mut s = state.lock().await;
            let res = s.remove_cipher(&selector).await;
            s.touch();
            drop(s);
            match res {
                Ok(removed) => Response::Removed(removed),
                Err(e) => Response::Error(e),
            }
        }
        Request::Add {
            name,
            cipher_type,
            folder,
            notes,
            username,
            password,
            totp,
            uri,
        } => {
            let w = crate::state::CipherWrite {
                name: Some(name),
                folder,
                notes,
                username,
                password,
                totp,
                uri,
            };
            let mut s = state.lock().await;
            let res = s.add_cipher(cipher_type, w).await;
            s.touch();
            drop(s);
            match res {
                Ok(saved) => Response::Saved(saved),
                Err(e) => Response::Error(e),
            }
        }
        Request::Edit {
            selector,
            name,
            folder,
            notes,
            username,
            password,
            totp,
            uri,
        } => {
            let w = crate::state::CipherWrite {
                name,
                folder,
                notes,
                username,
                password,
                totp,
                uri,
            };
            let mut s = state.lock().await;
            let res = s.edit_cipher(&selector, w).await;
            s.touch();
            drop(s);
            match res {
                Ok(saved) => Response::Saved(saved),
                Err(e) => Response::Error(e),
            }
        }
        Request::Quit => {
            let mut s = state.lock().await;
            s.lock();
            s.shutdown_requested = true;
            Response::Ok
        }
    }
}

/// Spawn a one-shot task that wipes the clipboard after `secs` (the effective
/// interval — the caller already applied the agent default), but only if it
/// still holds the value we copied. `0` disables the auto-clear. The task
/// carries the secret so the clear survives the requesting client quitting;
/// if the *agent* goes down first, `AgentState::lock`'s sweep covers it.
#[cfg(feature = "clipboard")]
fn schedule_clipboard_clear(
    state: Arc<Mutex<AgentState>>,
    value: zeroize::Zeroizing<String>,
    secs: u64,
) {
    use tokio::time::{Duration, sleep};
    if secs == 0 {
        return;
    }
    tokio::spawn(async move {
        sleep(Duration::from_secs(secs)).await;
        let mut s = state.lock().await;
        s.clipboard_clear_if_ours(&value);
    });
}

/// Optional periodic idle-lock task — caller spawns it after `run` starts.
pub async fn idle_lock_loop(state: Arc<Mutex<AgentState>>) {
    use tokio::time::{Duration, sleep};
    loop {
        sleep(Duration::from_secs(15)).await;
        let mut s = state.lock().await;
        if s.idle_lock_due() {
            // Idle-lock is a security event: forget the keyring session too.
            s.lock_and_clear_session();
            eprintln!("vault-agent: idle-lock triggered");
        }
        if s.shutdown_requested {
            break;
        }
    }
}

/// Optional periodic background-sync task — caller spawns it after `run` starts
/// when `sync_interval_secs > 0`. Every interval, if the agent is unlocked it
/// re-pulls `/sync` via [`AgentState::resync`], refreshing the in-memory vault
/// and the on-disk cache. Best effort: a `Locked` (agent locked) / `Offline` /
/// network result is logged and skipped, never disturbing the session. It
/// deliberately does **not** `touch()` — a background sync must not defer the
/// idle-lock countdown.
pub async fn scheduled_sync_loop(state: Arc<Mutex<AgentState>>) {
    use tokio::time::{Duration, sleep};
    // Fixed for the agent's life (config changes apply on the next spawn).
    let interval = {
        let s = state.lock().await;
        s.sync_interval_secs
    };
    if interval == 0 {
        return;
    }
    loop {
        sleep(Duration::from_secs(interval)).await;
        let mut s = state.lock().await;
        if s.shutdown_requested {
            break;
        }
        if s.is_unlocked()
            && let Err(e) = s.resync().await
        {
            eprintln!("vault-agent: scheduled sync skipped: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UnixStream;
    use vault_ipc::proto::{Error as IpcError, Field, Request, Response};

    /// End-to-end smoke: bind the listener at a tempdir socket, drive
    /// Status → Lock → Get (while locked) → Quit, and confirm clean shutdown.
    #[tokio::test(flavor = "current_thread")]
    async fn server_handles_locked_session() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.sock");
        let state = Arc::new(Mutex::new(AgentState::new(900)));

        let server_state = state.clone();
        let server_path = path.clone();
        let handle = tokio::spawn(async move { run(server_path, server_state).await });

        // Spin until the listener is up — at most a handful of yields.
        for _ in 0..50 {
            if UnixStream::connect(&path).await.is_ok() {
                break;
            }
            tokio::task::yield_now().await;
        }

        // One connection: Status, then Get-while-locked, then Quit.
        let mut stream = UnixStream::connect(&path).await.expect("connect");
        let (mut rd, mut wr) = stream.split();

        write_frame(&mut wr, &Request::Status).await.unwrap();
        let resp: Response = read_frame(&mut rd).await.unwrap();
        match resp {
            Response::Status(s) => {
                assert!(!s.unlocked);
                assert_eq!(s.agent_version, env!("CARGO_PKG_VERSION"));
            }
            other => panic!("expected Status, got {other:?}"),
        }

        write_frame(
            &mut wr,
            &Request::Get {
                id: None,
                name: "github.com".into(),
                field: Some(Field::Password),
            },
        )
        .await
        .unwrap();
        let resp: Response = read_frame(&mut rd).await.unwrap();
        assert!(matches!(resp, Response::Error(IpcError::Locked)));

        // Copy-while-locked exercises the new dispatch arm. It must decline with
        // an error before ever touching the clipboard (so it's deterministic on
        // a headless CI box). With the clipboard feature it's `Locked`; without
        // it's the "not compiled in" internal error — either way an error.
        write_frame(
            &mut wr,
            &Request::Copy {
                id: None,
                name: "github.com".into(),
                field: Some(Field::Password),
                clear_after_secs: Some(0),
            },
        )
        .await
        .unwrap();
        let resp: Response = read_frame(&mut rd).await.unwrap();
        assert!(matches!(resp, Response::Error(_)));

        // CopyText-while-locked must likewise decline before touching the
        // clipboard (Locked with the feature, "not compiled in" without).
        write_frame(
            &mut wr,
            &Request::CopyText {
                text: b"generated-password".to_vec(),
                clear_after_secs: Some(0),
            },
        )
        .await
        .unwrap();
        let resp: Response = read_frame(&mut rd).await.unwrap();
        assert!(matches!(resp, Response::Error(_)));

        write_frame(&mut wr, &Request::Quit).await.unwrap();
        let resp: Response = read_frame(&mut rd).await.unwrap();
        assert!(matches!(resp, Response::Ok));

        // After Quit, drop the connection so the server's accept loop can
        // observe the shutdown flag on its next iteration.
        drop(stream);
        // Kick the accept loop by opening one more connection; the loop
        // checks the flag right before `.accept()`.
        let _ = UnixStream::connect(&path).await;

        // The accept loop should exit within a few ms; give it a small budget.
        tokio::time::timeout(std::time::Duration::from_secs(2), handle)
            .await
            .expect("server task exited")
            .expect("join")
            .expect("run returned");

        // Socket file removed on clean shutdown.
        assert!(!path.exists());
    }
}

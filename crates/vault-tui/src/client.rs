// SPDX-License-Identifier: GPL-3.0-or-later

//! Minimal UDS client — one request per fresh connection.
//!
//! Mirrors `vault-cli`'s `connect` / `exchange`: the TUI is just another agent
//! client and never holds the user key. Slice 1 drives only [`Request::Status`]
//! and [`Request::List`]; later slices add `Get` (copy) over the same path.

use std::path::Path;

use tokio::net::UnixStream;

use vault_ipc::proto::{Request, Response};
use vault_ipc::{read_frame, write_frame};

/// Open a fresh connection to the agent at `socket`, send `req`, and read one
/// framed [`Response`].
///
/// # Errors
///
/// Returns an error if the socket can't be reached (agent not running) or the
/// request/response framing fails.
pub async fn request(socket: &Path, req: &Request) -> anyhow::Result<Response> {
    let mut stream = UnixStream::connect(socket)
        .await
        .map_err(|e| anyhow::anyhow!("could not connect to agent at {}: {e}", socket.display()))?;
    let (mut rd, mut wr) = stream.split();
    write_frame(&mut wr, req)
        .await
        .map_err(|e| anyhow::anyhow!("send failed: {e}"))?;
    let resp = read_frame::<_, Response>(&mut rd)
        .await
        .map_err(|e| anyhow::anyhow!("receive failed: {e}"))?;
    Ok(resp)
}

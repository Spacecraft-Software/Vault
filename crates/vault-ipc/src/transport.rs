// SPDX-License-Identifier: GPL-3.0-or-later

//! Length-prefixed CBOR framing over an async byte stream.

use std::io;

use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Hard upper bound on a single frame — 16 MiB. Sane for vault payloads;
/// also prevents a malicious peer from forcing us to allocate gigabytes.
pub const MAX_FRAME: u32 = 16 * 1024 * 1024;

/// Encode `msg` to CBOR, prefix with a 4-byte big-endian length, write.
///
/// # Errors
///
/// Returns [`io::Error`] if `msg` fails to serialise, if the encoded body
/// exceeds [`MAX_FRAME`] (or `u32`), or if writing to `stream` fails.
pub async fn write_frame<W, T>(stream: &mut W, msg: &T) -> io::Result<()>
where
    W: AsyncWriteExt + Unpin + Send,
    T: Serialize + Sync,
{
    let mut body = Vec::with_capacity(256);
    ciborium::ser::into_writer(msg, &mut body)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let len = u32::try_from(body.len()).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "frame too large for u32 length")
    })?;
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame exceeds MAX_FRAME",
        ));
    }
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(&body).await?;
    stream.flush().await?;
    Ok(())
}

/// Read a 4-byte length, then read that many bytes, then CBOR-decode.
///
/// # Errors
///
/// Returns [`io::Error`] on EOF / short read, if the declared length exceeds
/// [`MAX_FRAME`], or if the body fails to CBOR-decode into `T`.
pub async fn read_frame<R, T>(stream: &mut R) -> io::Result<T>
where
    R: AsyncReadExt + Unpin + Send,
    T: DeserializeOwned,
{
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes);
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame length exceeds MAX_FRAME",
        ));
    }
    let mut body = vec![0u8; len as usize];
    stream.read_exact(&mut body).await?;
    ciborium::de::from_reader(&body[..])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

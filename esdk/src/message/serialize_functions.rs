// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//! Low-level byte read/write primitives for message serialization.
//!
//! The `raw` writer parameter on every `read_*` function tees the consumed
//! bytes into a mirror buffer so callers can reconstruct the exact raw header
//! bytes used for authentication and signing.

use super::{Error, ser_err};
use crate::error::{Kind, err_with_cause};
use crate::shapes::{Sink, Source, Tee};
use std::io::Write;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[track_caller]
fn ser_io(e: std::io::Error) -> Error {
    match e.kind() {
        std::io::ErrorKind::UnexpectedEof => {
            err_with_cause(Kind::Serialization, "unexpected end of data", e)
        }
        _ => err_with_cause(Kind::Io, "a reader or writer failed", e),
    }
}

/// Read up to `buf.len()` bytes; returns the number actually read (may be < len on EOF).
pub(crate) async fn read_up_to(this: &mut dyn Source, buf: &mut [u8]) -> Result<usize, Error> {
    let mut curr: usize = 0;
    loop {
        match this.read(&mut buf[curr..]).await {
            Ok(0) => {
                return Ok(curr);
            }
            Ok(n) => {
                curr += n;
                if curr == buf.len() {
                    return Ok(curr);
                }
            }
            Err(e) => return Err(ser_io(e)),
        }
    }
}

/// Like `read_up_to`, but `first` is a one-byte peek already consumed by the caller.
pub(crate) async fn read_up_to_peek(
    this: &mut dyn Source,
    buf: &mut [u8],
    first: Option<u8>,
) -> Result<usize, Error> {
    if buf.is_empty() {
        return Ok(0);
    }
    match first {
        Some(f) => {
            buf[0] = f;
            read_up_to(this, &mut buf[1..]).await.map(|n| n + 1)
        }
        None => read_up_to(this, buf).await,
    }
}

#[track_caller]
fn ser_utf8(item: std::string::FromUtf8Error) -> Error {
    err_with_cause(Kind::Serialization, "UTF-8 decode error", item)
}

pub(crate) fn write_bytes(w: &mut dyn Write, data: &[u8]) -> Result<(), Error> {
    w.write_all(data).map_err(ser_io)?;
    Ok(())
}

/// Write `data` to an output stream.
pub(crate) async fn write_to_sink(w: &mut dyn Sink, data: &[u8]) -> Result<(), Error> {
    w.write_all(data).await.map_err(ser_io)
}

/// Flush an output stream.
pub(crate) async fn flush_sink(w: &mut dyn Sink) -> Result<(), Error> {
    w.flush().await.map_err(ser_io)
}

// Big-endian fixed-width writers.
pub(crate) fn write_u8(w: &mut dyn Write, data: u8) -> Result<(), Error> {
    write_bytes(w, &data.to_be_bytes())
}
pub(crate) fn write_u16(w: &mut dyn Write, data: u16) -> Result<(), Error> {
    write_bytes(w, &data.to_be_bytes())
}
pub(crate) fn write_u32(w: &mut dyn Write, data: u32) -> Result<(), Error> {
    write_bytes(w, &data.to_be_bytes())
}

/// Read exactly `buf.len()` bytes and mirror them into `raw`.
pub(crate) async fn read_bytes(
    r: &mut dyn Source,
    buf: &mut [u8],
    raw: &mut Tee,
) -> Result<(), Error> {
    r.read_exact(buf).await.map_err(ser_io)?;
    write_bytes(raw, buf)
}

/// Read exactly `length` bytes into a fresh Vec.
pub(crate) async fn read_vec(
    r: &mut dyn Source,
    length: usize,
    raw: &mut Tee,
) -> Result<Vec<u8>, Error> {
    let mut result = vec![0; length];
    read_bytes(r, &mut result, raw).await?;
    Ok(result)
}

// Big-endian fixed-width readers. Each mirrors the consumed bytes into `raw`.
pub(crate) async fn read_u8(r: &mut dyn Source, raw: &mut Tee) -> Result<u8, Error> {
    let mut result = [0u8; 1];
    read_bytes(r, &mut result, raw).await?;
    Ok(result[0])
}

/// Read one byte, returning `Ok(None)` on clean EOF. Does NOT mirror into a
/// raw buffer (used for streaming peek).
pub(crate) async fn read_opt_u8(r: &mut dyn Source) -> Result<Option<u8>, Error> {
    let mut result = [0u8; 1];
    match r.read_exact(&mut result).await {
        Ok(_) => Ok(Some(result[0])),
        Err(e) => match e.kind() {
            std::io::ErrorKind::UnexpectedEof => Ok(None),
            _ => Err(ser_io(e)),
        },
    }
}

pub(crate) async fn read_u16(r: &mut dyn Source, raw: &mut Tee) -> Result<u16, Error> {
    let mut result = [0u8; 2];
    read_bytes(r, &mut result, raw).await?;
    Ok(u16::from_be_bytes(result))
}
pub(crate) async fn read_u32(r: &mut dyn Source, raw: &mut Tee) -> Result<u32, Error> {
    let mut result = [0u8; 4];
    read_bytes(r, &mut result, raw).await?;
    Ok(u32::from_be_bytes(result))
}
pub(crate) async fn read_u64(r: &mut dyn Source, raw: &mut Tee) -> Result<u64, Error> {
    let mut result = [0u8; 8];
    read_bytes(r, &mut result, raw).await?;
    Ok(u64::from_be_bytes(result))
}

/// Read a `UInt16` length prefix followed by that many bytes.
pub(crate) async fn read_seq_u16(r: &mut dyn Source, raw: &mut Tee) -> Result<Vec<u8>, Error> {
    let len = read_u16(r, raw).await?;
    read_vec(r, usize::from(len), raw).await
}

/// Read a `UInt32` length prefix followed by that many bytes into `data`,
/// rejecting lengths above `bound`.
pub(crate) async fn read_seq_u32_bounded(
    r: &mut dyn Source,
    bound: u32,
    msg: &str,
    data: &mut Vec<u8>,
    raw: &mut Tee,
) -> Result<(), Error> {
    let len = read_u32(r, raw).await?;
    if len > bound {
        return ser_err(msg);
    }
    let Ok(len_usize) = usize::try_from(len) else {
        return ser_err("length too large for platform");
    };
    data.resize(len_usize, 0);
    read_bytes(r, &mut data[..], raw).await
}

/// Read a `UInt64` length prefix followed by that many bytes, rejecting lengths
/// above `bound`.
pub(crate) async fn read_seq_u64_bounded(
    r: &mut dyn Source,
    bound: u64,
    msg: &str,
    raw: &mut Tee,
) -> Result<Vec<u8>, Error> {
    let len = read_u64(r, raw).await?;
    if len > bound {
        return ser_err(msg);
    }
    let Ok(len_usize) = usize::try_from(len) else {
        return ser_err("length too large for platform");
    };
    read_vec(r, len_usize, raw).await
}

/// Read a UInt16-prefixed UTF-8 string.
pub(crate) async fn read_str_u16(r: &mut dyn Source, raw: &mut Tee) -> Result<String, Error> {
    let len = read_u16(r, raw).await?;
    let result = read_vec(r, usize::from(len), raw).await?;
    let result = String::from_utf8(result).map_err(ser_utf8)?;
    Ok(result)
}

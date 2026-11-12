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
use vstd::prelude::*;

verus! {

/// The big-endian value of two bytes.
pub(crate) open spec fn spec_be_u16(b: [u8; 2]) -> int {
    b[0] as int * 256 + b[1] as int
}

/// The big-endian value of four bytes.
pub(crate) open spec fn spec_be_u32(b: [u8; 4]) -> int {
    b[0] as int * 16_777_216 + b[1] as int * 65_536 + b[2] as int * 256 + b[3] as int
}

/// The big-endian value of eight bytes.
pub(crate) open spec fn spec_be_u64(b: [u8; 8]) -> int {
    b[0] as int * 72_057_594_037_927_936 + b[1] as int * 281_474_976_710_656
        + b[2] as int * 1_099_511_627_776 + b[3] as int * 4_294_967_296
        + b[4] as int * 16_777_216 + b[5] as int * 65_536 + b[6] as int * 256
        + b[7] as int
}

/// Decode a big-endian `u16`.
pub(crate) fn be_u16(b: [u8; 2]) -> (r: u16)
    ensures
        r as int == spec_be_u16(b),
{
    u16::from(b[0]) * 256 + u16::from(b[1])
}

/// Decode a big-endian `u32`.
pub(crate) fn be_u32(b: [u8; 4]) -> (r: u32)
    ensures
        r as int == spec_be_u32(b),
{
    u32::from(b[0]) * 16_777_216 + u32::from(b[1]) * 65_536 + u32::from(b[2]) * 256
        + u32::from(b[3])
}

/// Decode a big-endian `u64`.
pub(crate) fn be_u64(b: [u8; 8]) -> (r: u64)
    ensures
        r as int == spec_be_u64(b),
{
    u64::from(b[0]) * 72_057_594_037_927_936 + u64::from(b[1]) * 281_474_976_710_656
        + u64::from(b[2]) * 1_099_511_627_776 + u64::from(b[3]) * 4_294_967_296
        + u64::from(b[4]) * 16_777_216 + u64::from(b[5]) * 65_536 + u64::from(b[6]) * 256
        + u64::from(b[7])
}

/// The most bytes `read_into_vec` adds to its buffer per read (1 MiB).
/// 1 MiB matches serde's (Rust serialization library's) up-front allocation.
/// But this value is arbitrary and we can change it at any time.
pub(crate) const READ_CHUNK: usize = 1_048_576;

/// The end of the next chunk when `start` of `length` bytes have been read:
/// at most `READ_CHUNK` past `start`, and never past `length`.
pub(crate) fn next_chunk_end(start: usize, length: usize) -> (end: usize)
    requires
        start < length,
    ensures
        start < end <= length,
        end - start <= READ_CHUNK,
{
    let remaining = length - start;
    if remaining < READ_CHUNK {
        length
    } else {
        start + READ_CHUNK
    }
}

/// The outcome of checking a length prefix against a bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LenCheck {
    /// The length is within the bound and fits in a `usize`.
    Ok(usize),
    /// The length is above the bound.
    OverBound,
    /// The length is within the bound but does not fit in a `usize`.
    TooLargeForPlatform,
}

/// Check a `u32` length prefix against `bound` and convert it to `usize`.
pub(crate) fn bounded_len_u32(len: u32, bound: u32) -> (r: LenCheck)
    ensures
        (r is Ok) <==> (len <= bound && len as int <= usize::MAX as int),
        (r is OverBound) <==> len > bound,
        (r is TooLargeForPlatform) <==> (len <= bound && len as int > usize::MAX as int),
        r matches LenCheck::Ok(n) ==> n as int == len as int,
{
    if len > bound {
        LenCheck::OverBound
    } else {
        match usize::try_from(len) {
            Ok(n) => LenCheck::Ok(n),
            Err(_) => LenCheck::TooLargeForPlatform,
        }
    }
}

/// Check a `u64` length prefix against `bound` and convert it to `usize`.
pub(crate) fn bounded_len_u64(len: u64, bound: u64) -> (r: LenCheck)
    ensures
        (r is Ok) <==> (len <= bound && len as int <= usize::MAX as int),
        (r is OverBound) <==> len > bound,
        (r is TooLargeForPlatform) <==> (len <= bound && len as int > usize::MAX as int),
        r matches LenCheck::Ok(n) ==> n as int == len as int,
{
    if len > bound {
        LenCheck::OverBound
    } else {
        match usize::try_from(len) {
            Ok(n) => LenCheck::Ok(n),
            Err(_) => LenCheck::TooLargeForPlatform,
        }
    }
}

} // verus!

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

/// Replace `data` with the next `length` bytes of `r`.
/// `data` grows as bytes arrive,
/// so a length read from a message can't make decrypt allocate more than the message holds.
pub(crate) async fn read_into_vec(
    r: &mut dyn Source,
    length: usize,
    data: &mut Vec<u8>,
    raw: &mut Tee,
) -> Result<(), Error> {
    data.clear();
    while data.len() < length {
        let start = data.len();
        // The loop guard `data.len() < length` discharges `next_chunk_end`'s `start < length`.
        let end = next_chunk_end(start, length);
        data.resize(end, 0);
        read_bytes(r, &mut data[start..end], raw).await?;
    }
    Ok(())
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
    Ok(be_u16(result))
}
pub(crate) async fn read_u32(r: &mut dyn Source, raw: &mut Tee) -> Result<u32, Error> {
    let mut result = [0u8; 4];
    read_bytes(r, &mut result, raw).await?;
    Ok(be_u32(result))
}
pub(crate) async fn read_u64(r: &mut dyn Source, raw: &mut Tee) -> Result<u64, Error> {
    let mut result = [0u8; 8];
    read_bytes(r, &mut result, raw).await?;
    Ok(be_u64(result))
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
    let len_usize = match bounded_len_u32(read_u32(r, raw).await?, bound) {
        LenCheck::Ok(n) => n,
        LenCheck::OverBound => return ser_err(msg),
        LenCheck::TooLargeForPlatform => return ser_err("length too large for platform"),
    };
    read_into_vec(r, len_usize, data, raw).await
}

/// Read a `UInt64` length prefix followed by that many bytes, rejecting lengths
/// above `bound`.
pub(crate) async fn read_seq_u64_bounded(
    r: &mut dyn Source,
    bound: u64,
    msg: &str,
    raw: &mut Tee,
) -> Result<Vec<u8>, Error> {
    let len_usize = match bounded_len_u64(read_u64(r, raw).await?, bound) {
        LenCheck::Ok(n) => n,
        LenCheck::OverBound => return ser_err(msg),
        LenCheck::TooLargeForPlatform => return ser_err("length too large for platform"),
    };
    let mut data = Vec::new();
    read_into_vec(r, len_usize, &mut data, raw).await?;
    Ok(data)
}

/// Read a UInt16-prefixed UTF-8 string.
pub(crate) async fn read_str_u16(r: &mut dyn Source, raw: &mut Tee) -> Result<String, Error> {
    let len = read_u16(r, raw).await?;
    let result = read_vec(r, usize::from(len), raw).await?;
    let result = String::from_utf8(result).map_err(ser_utf8)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed-seed linear congruential generator for reproducible sample values.
    fn lcg(state: &mut u64) -> u64 {
        *state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        *state
    }

    #[test]
    fn be_u16_matches_from_be_bytes_for_every_value() {
        for v in 0..=u16::MAX {
            let b = v.to_be_bytes();
            assert_eq!(be_u16(b), u16::from_be_bytes(b));
        }
    }

    #[test]
    fn be_u32_matches_from_be_bytes() {
        let mut samples = vec![
            0,
            1,
            0xFF,
            0x100,
            0xFFFF,
            0x1_0000,
            0x00FF_FFFF,
            0x8000_0000,
            u32::MAX,
        ];
        let mut state = 1;
        for _ in 0..4096 {
            samples.push((lcg(&mut state) >> 32).try_into().unwrap());
        }
        for v in samples {
            let b = v.to_be_bytes();
            assert_eq!(be_u32(b), u32::from_be_bytes(b));
        }
    }

    #[test]
    fn be_u64_matches_from_be_bytes() {
        let mut samples = vec![
            0,
            1,
            0xFF,
            0xFFFF_FFFF,
            0x1_0000_0000,
            0x8000_0000_0000_0000,
            u64::MAX,
        ];
        let mut state = 2;
        for _ in 0..4096 {
            samples.push(lcg(&mut state));
        }
        for v in samples {
            let b = v.to_be_bytes();
            assert_eq!(be_u64(b), u64::from_be_bytes(b));
        }
    }

    #[test]
    fn next_chunk_end_matches_min_step() {
        let cases = [
            (0, 1),
            (0, READ_CHUNK - 1),
            (0, READ_CHUNK),
            (0, READ_CHUNK + 1),
            (READ_CHUNK, 2 * READ_CHUNK + 7),
            (5, 6),
            (usize::MAX - 1, usize::MAX),
            (0, usize::MAX),
            (usize::MAX - READ_CHUNK - 1, usize::MAX),
        ];
        for (start, length) in cases {
            assert_eq!(
                next_chunk_end(start, length),
                start + READ_CHUNK.min(length - start),
                "start={start} length={length}"
            );
        }
    }

    /// The check `read_seq_u32_bounded` and `read_seq_u64_bounded` made before `bounded_len_*`.
    fn old_check<T: Copy + PartialOrd>(len: T, bound: T) -> LenCheck
    where
        usize: TryFrom<T>,
    {
        if len > bound {
            return LenCheck::OverBound;
        }
        usize::try_from(len).map_or(LenCheck::TooLargeForPlatform, LenCheck::Ok)
    }

    #[test]
    fn bounded_len_matches_old_check() {
        let vals32 = [0, 1, 255, 65_535, 1_048_576, u32::MAX - 1, u32::MAX];
        for len in vals32 {
            for bound in vals32 {
                assert_eq!(bounded_len_u32(len, bound), old_check(len, bound));
            }
        }
        let vals64 = [0, 1, 65_535, u64::from(u32::MAX), u64::MAX - 1, u64::MAX];
        for len in vals64 {
            for bound in vals64 {
                assert_eq!(bounded_len_u64(len, bound), old_check(len, bound));
            }
        }
    }
}

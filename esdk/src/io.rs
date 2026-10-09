// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Adapters that let a synchronous [`std::io::Read`] or [`std::io::Write`]
//! be passed to [`encrypt_stream`](crate::encrypt_stream) and [`decrypt_stream`](crate::decrypt_stream).
//!
//! ```no_run
//! # async fn example(input: aws_esdk::EncryptStreamInput) -> Result<(), Box<dyn std::error::Error>> {
//! use aws_esdk::io::{SyncReader, SyncWriter};
//!
//! let plaintext = std::fs::File::open("plaintext.txt")?;
//! let ciphertext = std::fs::File::create("ciphertext.bin")?;
//! aws_esdk::encrypt_stream(SyncReader::new(plaintext), SyncWriter::new(ciphertext), &input).await?;
//! # Ok(())
//! # }
//! ```
//!
//! Each read or write runs on the calling thread and blocks it until it completes.
//! On a tokio runtime, a slow reader or writer holds a worker thread for that time.
//! For files and sockets on a runtime, prefer the tokio types (`tokio::fs::File`, `tokio::net::TcpStream`),
//! or run the whole call inside [`tokio::task::spawn_blocking`].

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A synchronous [`std::io::Read`] as a tokio [`AsyncRead`].
///
/// Each poll reads synchronously, blocking the calling thread; see the [module docs](self).
#[derive(Debug)]
pub struct SyncReader<R>(R);

impl<R> SyncReader<R> {
    /// Wrap `reader`.
    pub const fn new(reader: R) -> Self {
        Self(reader)
    }

    /// The wrapped reader.
    pub fn into_inner(self) -> R {
        self.0
    }
}

impl<R: std::io::Read + Unpin> AsyncRead for SyncReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let n = self.get_mut().0.read(buf.initialize_unfilled())?;
        buf.advance(n);
        Poll::Ready(Ok(()))
    }
}

/// A synchronous [`std::io::Write`] as a tokio [`AsyncWrite`].
///
/// Each poll writes synchronously, blocking the calling thread; see the [module docs](self).
/// Shutting it down flushes it.
#[derive(Debug)]
pub struct SyncWriter<W>(W);

impl<W> SyncWriter<W> {
    /// Wrap `writer`.
    pub const fn new(writer: W) -> Self {
        Self(writer)
    }

    /// The wrapped writer.
    pub fn into_inner(self) -> W {
        self.0
    }
}

impl<W: std::io::Write + Unpin> AsyncWrite for SyncWriter<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Ready(self.get_mut().0.write(buf))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(self.get_mut().0.flush())
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(self.get_mut().0.flush())
    }
}

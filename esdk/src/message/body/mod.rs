// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//! Message body encryption and decryption.

pub(crate) mod body_aad;
mod body_decrypt;
mod body_encrypt;

pub(crate) use body_aad::*;
pub(crate) use body_decrypt::*;
pub(crate) use body_encrypt::*;

use crate::error::Error;
use crate::error::{Kind, err};
use aws_crypto_mpl::types::AlgorithmSuite;
use aws_mpl_primitives::AesGcm;

pub(crate) fn get_alg_suite(info: &AlgorithmSuite) -> Result<AesGcm, Error> {
    match info.encryption_key_length() {
        16 => Ok(AesGcm::Aes128Gcm),
        24 => Ok(AesGcm::Aes192Gcm),
        32 => Ok(AesGcm::Aes256Gcm),
        other => Err(err(
            Kind::Internal,
            format!("unsupported AES-GCM key length {other} in algorithm suite"),
        )),
    }
}

/// Bytes of frames processed between yields to the async runtime,
/// so a large message does not hold one worker thread for its whole duration.
/// 64 KiB of AES-GCM takes well under 100 microseconds.
pub(crate) const BYTES_PER_YIELD: usize = 64 * 1024;

/// Yields to the async runtime once every [`BYTES_PER_YIELD`] bytes of frames.
/// A frame is never split, so a frame longer than that yields once per frame.
pub(crate) struct FrameYielder {
    frame_length: usize,
    since_yield: usize,
}

impl FrameYielder {
    pub(crate) const fn new(frame_length: usize) -> Self {
        Self {
            frame_length,
            since_yield: 0,
        }
    }

    /// Call once per frame, before processing it.
    pub(crate) async fn next_frame(&mut self) {
        self.since_yield = self.since_yield.saturating_add(self.frame_length);
        if self.since_yield >= BYTES_PER_YIELD {
            self.since_yield = 0;
            tokio::task::yield_now().await;
        }
    }
}

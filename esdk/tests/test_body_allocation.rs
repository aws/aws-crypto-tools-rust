// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Decrypt must size its body buffers by the bytes it reads, not by the
//! lengths the message declares.
//!
//! The OS hands out zeroed memory lazily, so a huge `vec![0; n]` usually
//! succeeds and the bug goes unnoticed. While decrypt runs, this binary's
//! allocator refuses any allocation above `LIMIT`. A decrypt that reserves a
//! declared length then aborts with "memory allocation of N bytes failed".

#[allow(clippy::duplicate_mod)]
mod fixtures;
mod test_helpers;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use test_helpers::*;

/// Decrypt reads a body 1 MiB at a time, so it never needs more than this here.
const LIMIT: usize = 4 << 20;

thread_local! {
    static LIMITED: Cell<bool> = const { Cell::new(false) };
}

struct LimitedAllocator;

impl LimitedAllocator {
    fn allows(size: usize) -> bool {
        size <= LIMIT || !LIMITED.try_with(Cell::get).unwrap_or(false)
    }
}

unsafe impl GlobalAlloc for LimitedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if !Self::allows(layout.size()) {
            return std::ptr::null_mut();
        }
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if !Self::allows(layout.size()) {
            return std::ptr::null_mut();
        }
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if !Self::allows(new_size) {
            return std::ptr::null_mut();
        }
        unsafe { System.realloc(ptr, layout, new_size) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: LimitedAllocator = LimitedAllocator;

/// Run `decrypt` with the limit on. `#[tokio::test]` runs the whole future on
/// the test's thread, so the limit covers every allocation decrypt makes.
async fn limited<T>(decrypt: impl Future<Output = T>) -> T {
    LIMITED.set(true);
    let out = decrypt.await;
    LIMITED.set(false);
    out
}

// The header sets 128 MiB frames; the message is a few hundred bytes.
#[tokio::test]
async fn decrypt_does_not_reserve_the_frame_length() {
    let ct = encrypt_with_frame_length(b"hello", 128 << 20).await;
    let keyring = test_keyring().await;
    let client = aws_esdk::Client::default();

    let out = limited(client.decrypt().ciphertext(&ct).keyring(keyring).send()).await;

    assert_eq!(out.unwrap().plaintext(), b"hello");
}

// "hello" fits in the final frame, which has its own length. Replace it with
// a regular frame, which is read at the full frame length, cut off after its IV.
#[tokio::test]
async fn truncated_regular_frame_does_not_reserve_the_frame_length() {
    let ct = encrypt_with_frame_length(b"hello", 128 << 20).await;
    let final_frame_start = [ENDFRAME_MARKER, 1u32.to_be_bytes()].concat();
    let header_len = ct.windows(8).position(|w| w == final_frame_start).unwrap();
    let mut bad = ct[..header_len].to_vec();
    bad.extend_from_slice(&1u32.to_be_bytes());
    bad.extend_from_slice(&[0u8; IV_LEN]);
    bad.extend_from_slice(&[0u8; 64]);
    let keyring = test_keyring().await;
    let client = aws_esdk::Client::default();

    let out = limited(client.decrypt().ciphertext(&bad).keyring(keyring).send()).await;

    assert!(out.is_err());
}

// The content length is set to the largest value allowed (2^36 - 32), but the
// body is still the real one, a few KiB long.
#[tokio::test]
async fn nonframed_content_length_is_not_reserved() {
    for version in [Version::V1, Version::V2] {
        let mut ct = external_nonframed_ct(version).to_vec();
        let length_at = parse_external_nonframed_body(&ct, version).body_start + IV_LEN;
        ct[length_at..length_at + 8].copy_from_slice(&0x000F_FFFF_FFE0u64.to_be_bytes());

        let out = limited(try_decrypt_external_nonframed(version, &ct)).await;

        assert!(out.is_err(), "{version:?}");
    }
}

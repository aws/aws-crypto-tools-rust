// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Decrypt must allocate memory for the bytes that a message holds, not for the lengths that it declares.
//! Each test decrypts a short message that declares a much larger length.
//! The test must fail if decrypt allocates the declared length.
//!
//! With the default allocator, a decrypt that allocates the declared length could still pass:
//! a huge `vec![0; n]` usually succeeds, because the OS supplies the memory only when something writes to it.
//! So this file installs an allocator that refuses large allocations while decrypt runs:
//! 1. `#[global_allocator]` makes `LimitedAllocator` handle every allocation in this file's test binary,
//!    including the ones that decrypt makes inside `aws_esdk`.
//! 2. `LimitedAllocator` refuses any allocation over `MAX_ALLOCATION` while `LIMIT_ON` is true on the thread that asks for it.
//! 3. Each test runs decrypt inside `with_limit`, which sets `LIMIT_ON` to true until decrypt finishes.
//!    `#[tokio::test]` runs a test and its decrypt on one thread, so decrypt's allocations see `LIMIT_ON` as true.
//! 4. A refused allocation makes Rust print "memory allocation of N bytes failed" and abort the test binary.
//!
//! The limit is off while a test builds its message, because encrypt allocates the whole frame length.

#[allow(clippy::duplicate_mod)]
mod fixtures;
mod test_helpers;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use test_helpers::*;

// Decrypt grows its buffers 1 MiB at a time, so it needs less than this for these messages.
const MAX_ALLOCATION: usize = 4 << 20;

// The largest nonframed content length that decrypt accepts.
// Decrypt rejects any larger length before it allocates, so a larger value would test nothing.
const LARGEST_CONTENT_LENGTH: u64 = 0x000F_FFFF_FFE0;

// Each thread has its own LIMIT_ON, so one test's limit can't refuse another test's encrypt.
// The tests run at the same time on separate threads.
thread_local! {
    static LIMIT_ON: Cell<bool> = const { Cell::new(false) };
}

struct LimitedAllocator;

unsafe impl GlobalAlloc for LimitedAllocator {
    // GlobalAlloc's default alloc_zeroed and realloc both call alloc,
    // so the limit also covers `vec![0; n]` and a growing Vec.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.size() > MAX_ALLOCATION && LIMIT_ON.get() {
            return std::ptr::null_mut();
        }
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: LimitedAllocator = LimitedAllocator;

async fn with_limit<T>(decrypt: impl Future<Output = T>) -> T {
    LIMIT_ON.set(true);
    let out = decrypt.await;
    LIMIT_ON.set(false);
    out
}

#[tokio::test]
async fn decrypt_does_not_allocate_the_frame_length() {
    let ct = encrypt_with_frame_length(b"hello", 128 << 20).await;
    let keyring = test_keyring().await;
    let client = aws_esdk::Client::default();

    let out = with_limit(client.decrypt().ciphertext(&ct).keyring(keyring).send()).await;

    assert_eq!(out.unwrap().plaintext(), b"hello");
}

// Decrypt reads a final frame at the length stored in the frame, but a regular frame at the header's frame length.
// "hello" fits in one final frame, so this test replaces it with a regular frame.
// That frame holds 64 bytes, not the 128 MiB that the header declares.
#[tokio::test]
async fn truncated_regular_frame_does_not_allocate_the_frame_length() {
    let ct = encrypt_with_frame_length(b"hello", 128 << 20).await;
    let final_frame_start = [ENDFRAME_MARKER, 1u32.to_be_bytes()].concat();
    let header_len = ct.windows(8).position(|w| w == final_frame_start).unwrap();
    let mut bad = ct[..header_len].to_vec();
    bad.extend_from_slice(&1u32.to_be_bytes());
    bad.extend_from_slice(&[0u8; IV_LEN]);
    bad.extend_from_slice(&[0u8; 64]);
    let keyring = test_keyring().await;
    let client = aws_esdk::Client::default();

    let out = with_limit(client.decrypt().ciphertext(&bad).keyring(keyring).send()).await;

    assert!(out.is_err());
}

// The message declares about 64 GiB of content but holds only its real 10 KiB body.
#[tokio::test]
async fn nonframed_content_length_is_not_allocated() {
    for version in [Version::V1, Version::V2] {
        let mut ct = external_nonframed_ct(version).to_vec();
        let length_at = parse_external_nonframed_body(&ct, version).body_start + IV_LEN;
        ct[length_at..length_at + 8].copy_from_slice(&LARGEST_CONTENT_LENGTH.to_be_bytes());

        let out = with_limit(try_decrypt_external_nonframed(version, &ct)).await;

        assert!(out.is_err(), "{version:?}");
    }
}

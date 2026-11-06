// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[allow(clippy::duplicate_mod)]
mod fixtures;
mod test_helpers;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use test_helpers::*;

// Decrypt grows its body buffers 1 MiB at a time, so these messages need less than this.
const LIMIT: usize = 4 << 20;

const LARGEST_CONTENT_LENGTH: u64 = 0x000F_FFFF_FFE0;

// LIMITED is per thread.
// #[tokio::test] runs the whole test on one thread, so the limit applies to decrypt.
// A multi_thread runtime would run decrypt on other threads, where the limit is off.
thread_local! {
    static LIMITED: Cell<bool> = const { Cell::new(false) };
}

// A huge zeroed allocation usually succeeds:
// the OS maps its pages only when something writes to them.
// So a decrypt that allocates the length that the message declares could still pass these tests.
// While decrypt runs, this allocator refuses anything over LIMIT.
// Such a decrypt then aborts with "memory allocation of N bytes failed".
struct LimitedAllocator;

unsafe impl GlobalAlloc for LimitedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.size() > LIMIT && LIMITED.get() {
            return std::ptr::null_mut();
        }
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: LimitedAllocator = LimitedAllocator;

async fn limited<T>(decrypt: impl Future<Output = T>) -> T {
    LIMITED.set(true);
    let out = decrypt.await;
    LIMITED.set(false);
    out
}

#[tokio::test]
async fn decrypt_does_not_reserve_the_frame_length() {
    let ct = encrypt_with_frame_length(b"hello", 128 << 20).await;
    let keyring = test_keyring().await;
    let client = aws_esdk::Client::default();

    let out = limited(client.decrypt().ciphertext(&ct).keyring(keyring).send()).await;

    assert_eq!(out.unwrap().plaintext(), b"hello");
}

// "hello" fits in one final frame, which stores its own content length.
// Decrypt reads a regular frame at the header's frame length, so swap in a regular frame.
// Its content is 64 bytes, not the 128 MiB that the header sets.
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

// The message declares about 64 GiB of content but holds only its real 10 KiB body.
#[tokio::test]
async fn nonframed_content_length_is_not_reserved() {
    for version in [Version::V1, Version::V2] {
        let mut ct = external_nonframed_ct(version).to_vec();
        let length_at = parse_external_nonframed_body(&ct, version).body_start + IV_LEN;
        ct[length_at..length_at + 8].copy_from_slice(&LARGEST_CONTENT_LENGTH.to_be_bytes());

        let out = limited(try_decrypt_external_nonframed(version, &ct)).await;

        assert!(out.is_err(), "{version:?}");
    }
}

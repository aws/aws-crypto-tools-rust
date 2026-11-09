// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! A message gives lengths for its body: a frame length in the header, or a content length for a nonframed body.
//! These lengths can be far bigger than the message itself.
//! Decrypt must not make a buffer of that length before it reads the bytes.
//! Each test below decrypts a short message that gives a much bigger length.
//!
//! Checking what decrypt returns isn't enough.
//! A request for a huge buffer often succeeds, because the OS supplies memory only when a program writes to it.
//! So decrypt could make the huge buffer and still return the right result.
//!
//! This file replaces Rust's default allocator with one that refuses anything over 4 MiB (`ALLOCATION_CAP`).
//! If decrypt asks for a huge buffer, the tests stop with "memory allocation of N bytes failed".
//! Each file in `tests/` builds into its own program, so this allocator affects only these tests.

#[allow(clippy::duplicate_mod)]
mod fixtures;
mod test_helpers;

use std::alloc::{GlobalAlloc, Layout, System};
use test_helpers::*;

// Decrypt grows its buffers 1 MiB at a time, so it needs less than this for these messages.
const ALLOCATION_CAP: usize = 4 << 20;

struct CappedAllocator;

unsafe impl GlobalAlloc for CappedAllocator {
    // GlobalAlloc's default alloc_zeroed and realloc both call alloc,
    // so the cap also covers `vec![0; n]` and a growing Vec.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.size() > ALLOCATION_CAP {
            return std::ptr::null_mut();
        }
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: CappedAllocator = CappedAllocator;

// The output of `encrypt_with_frame_length(b"hello", 128 << 20)`, saved to a file.
// Encrypting here would fail: encrypt allocates the whole 128 MiB frame, and CappedAllocator refuses that.
const HELLO_128_MIB_FRAMES: &[u8] =
    include_bytes!("fixtures_binary/v2_framed_hello_128mib_frames.bin");

// The largest nonframed content length that decrypt accepts.
// Decrypt rejects any larger length before it allocates, so a larger value would test nothing.
const LARGEST_CONTENT_LENGTH: u64 = 0x000F_FFFF_FFE0;

#[tokio::test]
async fn decrypt_does_not_allocate_the_frame_length() {
    let keyring = test_keyring().await;
    let client = aws_esdk::Client::default();

    let out = client
        .decrypt()
        .ciphertext(HELLO_128_MIB_FRAMES)
        .keyring(keyring)
        .send()
        .await;

    assert_eq!(out.unwrap().plaintext(), b"hello");
}

// Decrypt reads a final frame at the length stored in the frame, but a regular frame at the header's frame length.
// "hello" fits in one final frame, so this test replaces it with a regular frame.
// That frame holds 64 bytes, not the 128 MiB that the header declares.
#[tokio::test]
async fn truncated_regular_frame_does_not_allocate_the_frame_length() {
    let ct = HELLO_128_MIB_FRAMES;
    let final_frame_start = [ENDFRAME_MARKER, 1u32.to_be_bytes()].concat();
    let header_len = ct.windows(8).position(|w| w == final_frame_start).unwrap();
    let mut bad = ct[..header_len].to_vec();
    bad.extend_from_slice(&1u32.to_be_bytes());
    bad.extend_from_slice(&[0u8; IV_LEN]);
    bad.extend_from_slice(&[0u8; 64]);
    let keyring = test_keyring().await;
    let client = aws_esdk::Client::default();

    let out = client
        .decrypt()
        .ciphertext(&bad)
        .keyring(keyring)
        .send()
        .await;

    assert!(out.is_err());
}

// The message declares about 64 GiB of content but holds only its real 10 KiB body.
#[tokio::test]
async fn nonframed_content_length_is_not_allocated() {
    for version in [Version::V1, Version::V2] {
        let mut ct = external_nonframed_ct(version).to_vec();
        let length_at = parse_external_nonframed_body(&ct, version).body_start + IV_LEN;
        ct[length_at..length_at + 8].copy_from_slice(&LARGEST_CONTENT_LENGTH.to_be_bytes());

        let out = try_decrypt_external_nonframed(version, &ct).await;

        assert!(out.is_err(), "{version:?}");
    }
}

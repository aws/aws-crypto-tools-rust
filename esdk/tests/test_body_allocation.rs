// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Decrypt must size its body buffers by the bytes it reads, not by the
//! lengths the header and body declare.

#[allow(clippy::duplicate_mod)]
mod fixtures;
mod test_helpers;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use test_helpers::*;

/// Refuse any single allocation above this, so a regression cannot take the host down.
const REFUSE_ABOVE: usize = 256 << 20;

static TRACKING: AtomicBool = AtomicBool::new(false);
static LARGEST: AtomicUsize = AtomicUsize::new(0);
// Tests in this binary share LARGEST, so run them one at a time.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Counting;

impl Counting {
    fn record(size: usize) -> bool {
        if TRACKING.load(Ordering::Relaxed) {
            LARGEST.fetch_max(size, Ordering::Relaxed);
        }
        size <= REFUSE_ABOVE
    }
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if !Self::record(layout.size()) {
            return std::ptr::null_mut();
        }
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if !Self::record(layout.size()) {
            return std::ptr::null_mut();
        }
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if !Self::record(new_size) {
            return std::ptr::null_mut();
        }
        unsafe { System.realloc(ptr, layout, new_size) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

fn start_tracking() {
    LARGEST.store(0, Ordering::Relaxed);
    TRACKING.store(true, Ordering::Relaxed);
}

fn stop_tracking() -> usize {
    TRACKING.store(false, Ordering::Relaxed);
    LARGEST.load(Ordering::Relaxed)
}

// The message is a few hundred bytes; its header claims 128 MiB frames.
// Encrypt still reserves the full frame (the caller chose that size), so the
// frame length stays under REFUSE_ABOVE / 2 to keep encrypt below the refusal cap.
#[tokio::test(flavor = "multi_thread")]
async fn decrypt_does_not_reserve_header_frame_length() {
    let _guard = SERIAL.lock().await;
    let frame_length: u32 = 128 << 20;
    let ct = encrypt_with_frame_length(b"hello", frame_length).await;
    assert!(ct.len() < 1024, "ciphertext is {} bytes", ct.len());

    let keyring = test_keyring().await;
    let client = aws_esdk::Client::default();
    start_tracking();
    let out = client
        .decrypt()
        .ciphertext(&ct)
        .keyring(keyring)
        .send()
        .await;
    let largest = stop_tracking();
    assert_eq!(out.unwrap().plaintext(), b"hello");
    assert!(
        largest < 1 << 20,
        "decrypt of a {}-byte message made a {largest}-byte allocation",
        ct.len()
    );
}

// A truncated regular frame must fail before the full frame is reserved.
#[tokio::test(flavor = "multi_thread")]
async fn truncated_regular_frame_does_not_reserve_frame_length() {
    let _guard = SERIAL.lock().await;
    let frame_length: u32 = 128 << 20;
    let ct = encrypt_with_frame_length(b"hello", frame_length).await;
    // Replace the body with a regular frame (sequence number 1) that stops after the IV.
    let final_frame_start = [ENDFRAME_MARKER, 1u32.to_be_bytes()].concat();
    let header_len = ct.windows(8).position(|w| w == final_frame_start).unwrap();
    let mut bad = ct[..header_len].to_vec();
    bad.extend_from_slice(&1u32.to_be_bytes());
    bad.extend_from_slice(&[0u8; IV_LEN]);
    bad.extend_from_slice(&[0u8; 64]);

    let keyring = test_keyring().await;
    let client = aws_esdk::Client::default();
    start_tracking();
    let out = client
        .decrypt()
        .ciphertext(&bad)
        .keyring(keyring)
        .send()
        .await;
    let largest = stop_tracking();
    assert!(out.is_err());
    assert!(
        largest < 4 << 20,
        "truncated message made a {largest}-byte allocation"
    );
}

// A nonframed message whose content length claims the largest value allowed
// (2^36 - 32), but which carries only its real body, must fail with an error.
#[tokio::test(flavor = "multi_thread")]
async fn nonframed_large_content_length_fails_without_reserving_it() {
    let _guard = SERIAL.lock().await;
    for version in [Version::V1, Version::V2] {
        let mut ct = external_nonframed_ct(version).to_vec();
        let body = parse_external_nonframed_body(&ct, version);
        let len_at = body.body_start + IV_LEN;
        ct[len_at..len_at + 8].copy_from_slice(&0x000F_FFFF_FFE0u64.to_be_bytes());

        start_tracking();
        let res = try_decrypt_external_nonframed(version, &ct).await;
        let largest = stop_tracking();

        assert!(res.is_err(), "{version:?}: truncated body must fail");
        assert!(
            largest < 4 << 20,
            "{version:?}: largest allocation was {largest} bytes"
        );
    }
}

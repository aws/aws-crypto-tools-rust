// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Resource behavior: repeated encrypt/decrypt round trips (including keyring
//! construction) must not grow live heap memory. A counting global allocator
//! tracks live bytes; this file is its own test binary so the allocator is
//! scoped to this test.

#[allow(clippy::duplicate_mod)]
mod fixtures;
mod test_helpers;

use aws_esdk::*;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering};

static LIVE_BYTES: AtomicIsize = AtomicIsize::new(0);

struct CountingAllocator;

fn layout_size(layout: Layout) -> isize {
    // Layout guarantees size <= isize::MAX.
    isize::try_from(layout.size()).unwrap_or(isize::MAX)
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            LIVE_BYTES.fetch_add(layout_size(layout), Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            LIVE_BYTES.fetch_add(layout_size(layout), Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        LIVE_BYTES.fetch_sub(layout_size(layout), Ordering::Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_ptr = unsafe { System.realloc(ptr, layout, new_size) };
        if !new_ptr.is_null() {
            LIVE_BYTES.fetch_sub(layout_size(layout), Ordering::Relaxed);
            LIVE_BYTES.fetch_add(
                isize::try_from(new_size).unwrap_or(isize::MAX),
                Ordering::Relaxed,
            );
        }
        new_ptr
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

const WARMUP_ITERS: usize = 20;
const MEASURED_ITERS: usize = 200;
/// Bound on live-heap growth over the measured iterations. A leak of even one
/// 64 KiB plaintext or ciphertext buffer per iteration would exceed this by
/// more than an order of magnitude.
const MAX_GROWTH_BYTES: isize = 512 * 1024;

async fn round_trip(plaintext: &[u8]) {
    // Fresh keyring per iteration so keyring construction is measured too.
    let keyring = test_helpers::test_keyring().await;
    let out = encrypt(&EncryptInput::with_legacy_keyring(
        plaintext,
        EncryptionContext::new(),
        keyring.clone(),
    ))
    .await
    .unwrap();
    let dec = decrypt(&DecryptInput::with_legacy_keyring(
        &out.ciphertext,
        EncryptionContext::new(),
        keyring,
    ))
    .await
    .unwrap();
    assert_eq!(dec.plaintext, plaintext);
}

#[test]
fn no_live_memory_growth_over_repeated_round_trips() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let plaintext = vec![0xA5u8; 64 * 1024];

    for _ in 0..WARMUP_ITERS {
        rt.block_on(round_trip(&plaintext));
    }
    let baseline = LIVE_BYTES.load(Ordering::Relaxed);
    assert!(
        baseline > 0,
        "counting allocator must observe live allocations"
    );

    for _ in 0..MEASURED_ITERS {
        rt.block_on(round_trip(&plaintext));
    }
    let after = LIVE_BYTES.load(Ordering::Relaxed);

    let growth = after - baseline;
    assert!(
        growth < MAX_GROWTH_BYTES,
        "live heap grew by {growth} bytes over {MEASURED_ITERS} round trips (limit {MAX_GROWTH_BYTES})"
    );
}

// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Repeated encrypt/decrypt round trips must not grow live heap memory,
//! measured by a counting global allocator.
//!
//! Local because it measures this process's live heap through a global
//! allocator — an implementation-internal property that never appears on the
//! wire, so the cross-language interop vectors cannot observe it.

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

// Only `alloc` and `dealloc` are instrumented. The default `GlobalAlloc`
// `alloc_zeroed` and `realloc` are defined in terms of these two, so every
// allocation the binary makes is counted and balanced through them.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            LIVE_BYTES.fetch_add(layout_size(layout), Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        LIVE_BYTES.fetch_sub(layout_size(layout), Ordering::Relaxed);
    }
}

// Each file under tests/ builds as its own binary, so this allocator serves
// only this test.
#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

const WARMUP_ITERS: usize = 20;
const MEASURED_ITERS: usize = 200;
/// A leak of one 64 KiB buffer per iteration would exceed this bound by more
/// than an order of magnitude.
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
    // A current-thread runtime keeps every allocation on this thread, so the
    // live-byte counter is read at a quiescent point with no worker-thread
    // allocations racing the measurement.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let plaintext = vec![0xA5u8; 64 * 1024];

    // Warm up so one-time allocations are counted before the baseline.
    for _ in 0..WARMUP_ITERS {
        rt.block_on(round_trip(&plaintext));
    }
    let baseline = LIVE_BYTES.load(Ordering::Relaxed);
    assert!(
        baseline > 0,
        "counting allocator must observe live allocations"
    );

    // Live bytes after the measured iterations must stay near the baseline.
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

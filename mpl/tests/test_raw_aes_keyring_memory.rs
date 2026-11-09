// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! A message can list up to 65,535 encrypted data keys, and none of them has to be for this keyring.
//! So the raw AES keyring's decrypt must use memory in proportion to that count.
//! A copy of the whole list for each key would grow with the square of the count instead.
//!
//! This file replaces Rust's default allocator with one that counts the bytes in use.
//! The test decrypts 2,048 keys for another keyring and checks how far that count rises.
//! Each file in `tests/` builds into its own program, so this allocator affects only this test.

use aws_crypto_mpl::Error;
use aws_crypto_mpl::keyring::RawAesKeyring;
use aws_crypto_mpl::types::{
    AesWrappingAlg, AlgorithmSuiteId, DecryptionMaterials, EncryptedDataKey, EncryptionContext,
    EsdkAlgorithmSuiteId,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

static IN_USE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

struct CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    // GlobalAlloc's default alloc_zeroed and realloc call alloc and dealloc,
    // so these two methods see every allocation.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            let in_use = IN_USE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(in_use, Ordering::Relaxed);
        }
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        IN_USE.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

const EDK_COUNT: usize = 2048;

// A copy of the whole list for each of the 2,048 keys takes about 300 MB.
const MAX_GROWTH: usize = 32 << 20;

#[tokio::test]
async fn on_decrypt_memory_grows_with_the_edk_count() {
    let keyring = RawAesKeyring::builder()
        .key_namespace("this keyring")
        .key_name("key")
        .wrapping_key(vec![0; 32])
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()
        .unwrap();
    let materials = DecryptionMaterials::builder()
        .algorithm_suite_id(AlgorithmSuiteId::Esdk(
            EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf,
        ))
        .set_encryption_context(Some(EncryptionContext::new()))
        .build()
        .unwrap();
    let edks: Vec<EncryptedDataKey> = (0..EDK_COUNT)
        .map(|_| {
            EncryptedDataKey::builder()
                .key_provider_id("another keyring")
                .key_provider_info(vec![0])
                .ciphertext(vec![0])
                .build()
                .unwrap()
        })
        .collect();

    let before = IN_USE.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);
    let err = keyring
        .on_decrypt()
        .materials(materials)
        .set_encrypted_data_keys(Some(edks))
        .send()
        .await
        .expect_err("no key is for this keyring");
    let growth = PEAK.load(Ordering::Relaxed) - before;

    assert!(
        growth < MAX_GROWTH,
        "decrypt of {EDK_COUNT} keys used {growth} more bytes"
    );
    // The returned error still lists every key.
    let Error::NoMatchingDataKey(e) = &err else {
        panic!("{err:?}");
    };
    assert_eq!(e.encrypted_data_keys().len(), EDK_COUNT);
}

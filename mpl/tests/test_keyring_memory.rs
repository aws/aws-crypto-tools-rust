// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! A message can list up to 65,535 encrypted data keys, and none of them has to be for the keyring that decrypts it.
//! Each test checks that a keyring's decrypt uses memory in step with the number of keys.
//! This file replaces Rust's default allocator with one that counts each thread's bytes in use.

use aws_crypto_mpl::Error;
use aws_crypto_mpl::keyring::{OnDecryptFluentBuilder, RawAesKeyring};
use aws_crypto_mpl::types::{
    AesWrappingAlg, AlgorithmSuiteId, DecryptionMaterials, EncryptedDataKey, EncryptionContext,
    EsdkAlgorithmSuiteId,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

// `#[tokio::test]` runs each test on one thread.
// So with one count per thread, each test counts only its own allocations, and the tests can run at the same time.
thread_local! {
    static IN_USE: Cell<usize> = const { Cell::new(0) };
    static PEAK: Cell<usize> = const { Cell::new(0) };
}

struct CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    // GlobalAlloc's default alloc_zeroed and realloc call alloc and dealloc,
    // so these two methods see every allocation.
    // try_with skips counting while a thread is exiting and its locals are gone.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            let _ = IN_USE.try_with(|in_use| {
                in_use.set(in_use.get() + layout.size());
                let _ = PEAK.try_with(|peak| peak.set(peak.get().max(in_use.get())));
            });
        }
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // A thread can free memory that another thread allocated, which would take its count below zero.
        let _ = IN_USE.try_with(|in_use| in_use.set(in_use.get().saturating_sub(layout.size())));
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

async fn assert_memory_grows_with_the_edk_count(on_decrypt: impl Fn() -> OnDecryptFluentBuilder) {
    let small = growth(on_decrypt(), 512).await;
    let large = growth(on_decrypt(), 2048).await;
    // 2,048 keys is 4x 512 keys, so memory in step with the number of keys rises about 4x.
    // A Vec can hold up to 2x the memory it needs, so the limit is 8x.
    assert!(
        large < 8 * small,
        "512 keys used {small} bytes, but 2,048 keys used {large}"
    );
}

/// The most memory that this thread had in use during the call, above what it had before.
async fn growth(on_decrypt: OnDecryptFluentBuilder, edk_count: usize) -> usize {
    let materials = DecryptionMaterials::builder()
        .algorithm_suite_id(AlgorithmSuiteId::Esdk(
            EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf,
        ))
        .set_encryption_context(Some(EncryptionContext::new()))
        .build()
        .unwrap();
    let edks: Vec<EncryptedDataKey> = (0..edk_count)
        .map(|_| {
            EncryptedDataKey::builder()
                .key_provider_id("another keyring")
                .key_provider_info(vec![0])
                .ciphertext(vec![0])
                .build()
                .unwrap()
        })
        .collect();

    let before = IN_USE.get();
    PEAK.set(before);
    let err = on_decrypt
        .materials(materials)
        .set_encrypted_data_keys(Some(edks))
        .send()
        .await
        .expect_err("no key is for this keyring");
    let growth = PEAK.get() - before;

    // The returned error lists every key.
    let Error::NoMatchingDataKey(e) = &err else {
        panic!("{err:?}");
    };
    assert_eq!(e.encrypted_data_keys().len(), edk_count);
    growth
}

#[tokio::test]
async fn raw_aes_keyring() {
    let keyring = RawAesKeyring::builder()
        .key_namespace("this keyring")
        .key_name("key")
        .wrapping_key(vec![0; 32])
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()
        .unwrap();
    assert_memory_grows_with_the_edk_count(|| keyring.on_decrypt()).await;
}

#[cfg(all(feature = "kms", feature = "ddb"))]
#[tokio::test]
async fn hierarchical_keyring() {
    use aws_crypto_mpl::key_store::DynamoDbKeyStore;
    use aws_crypto_mpl::key_store::types::KmsConfiguration;
    use aws_crypto_mpl::keyring::HierarchicalKeyring;
    use aws_sdk_dynamodb::config::BehaviorVersion;
    use std::time::Duration;

    // Every key is for another keyring, so decrypt never calls the key store, KMS or DynamoDB.
    let kms = aws_sdk_kms::Client::from_conf(
        aws_sdk_kms::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .build(),
    );
    let ddb = aws_sdk_dynamodb::Client::from_conf(
        aws_sdk_dynamodb::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .build(),
    );
    let key_store = DynamoDbKeyStore::builder()
        .ddb_table_name("table")
        .kms_configuration(KmsConfiguration::kms_key_arn(
            "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
        ))
        .logical_key_store_name("table")
        .kms_client(kms)
        .ddb_client(ddb)
        .build()
        .await
        .unwrap();
    let keyring = HierarchicalKeyring::builder()
        .key_store(key_store)
        .ttl(Duration::from_secs(600))
        .branch_key_id("branch key")
        .build()
        .await
        .unwrap();
    assert_memory_grows_with_the_edk_count(|| keyring.on_decrypt()).await;
}

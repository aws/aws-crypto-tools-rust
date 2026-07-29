// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Encrypt/decrypt round trips run concurrently across threads.
//!
//! Two messages with the same message ID get the same data key and the same
//! frame IVs. Repeating an AES-GCM key+IV pair breaks it: plaintext can be
//! recovered and messages forged. So the test asserts IDs stay unique even
//! when many threads encrypt at once.
//!
//! Local to exercise the native client's RNG under real threads.

#[allow(clippy::duplicate_mod)]
mod fixtures;
mod test_helpers;

use aws_esdk::*;
use aws_mpl_legacy::commitment::EsdkCommitmentPolicy;
use aws_mpl_legacy::suites::EsdkAlgorithmSuiteId;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

const THREADS: usize = 8;
const ITERS_PER_THREAD: usize = 24;

/// V2 header: version (1) + algorithm suite id (2) + message id (32).
fn v2_message_id(ct: &[u8]) -> Vec<u8> {
    assert_eq!(ct[0], 0x02, "expected a V2 message");
    ct[3..35].to_vec()
}

/// V1 header: version (1) + type (1) + algorithm suite id (2) + message id (16).
fn v1_message_id(ct: &[u8]) -> Vec<u8> {
    assert_eq!(ct[0], 0x01, "expected a V1 message");
    ct[4..20].to_vec()
}

/// Run `THREADS` OS threads, each doing `ITERS_PER_THREAD` encrypt + decrypt
/// round trips. Returns every message ID produced across all threads.
fn concurrent_round_trips(
    suite: Option<EsdkAlgorithmSuiteId>,
    policy: EsdkCommitmentPolicy,
    extract_id: fn(&[u8]) -> Vec<u8>,
) -> Vec<Vec<u8>> {
    let ids: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));

    // Each thread runs its own runtime and keyring.
    let handles: Vec<_> = (0..THREADS)
        .map(|t| {
            let ids = Arc::clone(&ids);
            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(1)
                    .enable_all()
                    .build()
                    .unwrap();
                rt.block_on(async {
                    let keyring = test_helpers::test_keyring().await;
                    for i in 0..ITERS_PER_THREAD {
                        // Encrypt and record the message ID from the header.
                        let plaintext = format!("thread {t} message {i}").into_bytes();
                        let mut enc_input = EncryptInput::with_legacy_keyring(
                            &plaintext,
                            EncryptionContext::new(),
                            keyring.clone(),
                        );
                        enc_input.algorithm_suite_id = suite;
                        enc_input.commitment_policy = policy;
                        let out = encrypt(&enc_input).await.unwrap();
                        ids.lock().unwrap().push(extract_id(&out.ciphertext));

                        // Decrypt and verify the round trip.
                        let mut dec_input = DecryptInput::with_legacy_keyring(
                            &out.ciphertext,
                            EncryptionContext::new(),
                            keyring.clone(),
                        );
                        dec_input.commitment_policy = policy;
                        let dec = decrypt(&dec_input).await.unwrap();
                        assert_eq!(
                            dec.plaintext, plaintext,
                            "round trip must return the plaintext"
                        );
                    }
                });
            })
        })
        .collect();

    for h in handles {
        h.join().expect("worker thread must not panic");
    }

    Arc::try_unwrap(ids).unwrap().into_inner().unwrap()
}

#[test]
fn concurrent_v2_round_trips_and_unique_message_ids() {
    // Default committing suite produces V2 messages.
    let ids = concurrent_round_trips(
        None,
        EsdkCommitmentPolicy::RequireEncryptRequireDecrypt,
        v2_message_id,
    );

    assert_eq!(ids.len(), THREADS * ITERS_PER_THREAD);
    for id in &ids {
        assert_eq!(id.len(), 32, "V2 message ID must be 32 bytes");
    }
    let unique: HashSet<&Vec<u8>> = ids.iter().collect();
    assert_eq!(
        unique.len(),
        ids.len(),
        "message IDs must be unique across concurrent encrypts"
    );
}

#[test]
fn concurrent_v1_round_trips_and_unique_message_ids() {
    // A non-committing suite produces V1 messages.
    let ids = concurrent_round_trips(
        Some(EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256),
        EsdkCommitmentPolicy::ForbidEncryptAllowDecrypt,
        v1_message_id,
    );

    assert_eq!(ids.len(), THREADS * ITERS_PER_THREAD);
    for id in &ids {
        assert_eq!(id.len(), 16, "V1 message ID must be 16 bytes");
    }
    let unique: HashSet<&Vec<u8>> = ids.iter().collect();
    assert_eq!(
        unique.len(),
        ids.len(),
        "message IDs must be unique across concurrent encrypts"
    );
}

// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for decrypt.md sections: #output, #algorithm-suite, #authenticated-data, #security-considerations

#[allow(clippy::duplicate_mod)]
mod fixtures;
mod test_helpers;

use aws_esdk::*;
use fixtures::*;
use std::num::NonZeroU32;
use test_helpers::*;

#[tokio::test(flavor = "multi_thread")]
async fn test_decrypt_output_includes_encryption_context() {
    let keyring = test_keyring().await;
    let ec = small_encryption_context(SmallEncryptionContextVariation::AB);
    let ct = Client::default()
        .encrypt()
        .plaintext(b"ec test")
        .encryption_context(ec.clone())
        .keyring(keyring.clone())
        .send()
        .await
        .unwrap()
        .ciphertext;

    let result = Client::default()
        .decrypt()
        .ciphertext(&ct)
        .encryption_context(ec.clone())
        .keyring(keyring.clone())
        .send()
        .await
        .unwrap();
    for (k, v) in ec.iter() {
        //= spec/client-apis/decrypt.md#output
        //= type=test
        //# - Decrypt operation output MUST include an [encryption context](#encryption-context) value.
        assert_eq!(result.encryption_context.get(k).unwrap(), v);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_decrypt_output_includes_algorithm_suite() {
    let keyring = test_keyring().await;
    let suite = AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey;
    let ct = Client::default()
        .encrypt()
        .plaintext(b"suite test")
        .keyring(keyring.clone())
        .algorithm_suite_id(suite)
        .send()
        .await
        .unwrap()
        .ciphertext;

    let result = Client::default()
        .decrypt()
        .ciphertext(&ct)
        .keyring(keyring.clone())
        .send()
        .await
        .unwrap();
    //= spec/client-apis/decrypt.md#output
    //= type=test
    //# - Decrypt operation output MUST include an [algorithm suite](#algorithm-suite) value.
    //
    //= spec/client-apis/decrypt.md#algorithm-suite
    //= type=test
    //= reason=Output suite matches a supported ESDK suite (AlgAes256GcmHkdfSha512CommitKey)
    //# This algorithm suite MUST be [supported for the ESDK](../framework/algorithm-suites.md#supported-algorithm-suites-enum).
    assert_eq!(result.algorithm_suite_id, suite);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_decrypt_no_unauthenticated_data_released() {
    // Non-signing suite so the per-frame auth tag is the integrity layer under test:
    // tampering it makes the body plaintext unauthenticated (on-point for this requirement,
    // unlike tampering the post-authentication signature).
    let keyring = test_keyring().await;
    let pt = vec![0xABu8; 20];
    let valid_ct = Client::default()
        .encrypt()
        .plaintext(&pt)
        .keyring(keyring.clone())
        .algorithm_suite_id(AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey)
        .frame_length(NonZeroU32::new(10).unwrap())
        .send()
        .await
        .unwrap()
        .ciphertext;

    // Tamper the first regular frame's auth tag: [seq_num(4)][IV(12)][content(10)][tag(16)].
    let body_start = find_body_start(&valid_ct, 10).expect("must find body");
    let tag_end = body_start + 4 + IV_LEN + 10 + TAG_LEN - 1;
    let mut tampered_ct = valid_ct.clone();
    tampered_ct[tag_end] ^= 0xFF;

    //= spec/client-apis/decrypt.md#authenticated-data
    //= type=test
    //= reason=Untampered ct decrypts; tampered body auth tag → Cryptographic error with no DecryptOutput, so unauthenticated plaintext is never released
    //# This operation MUST NOT release any unauthenticated plaintext or unauthenticated associated data.
    assert!(
        Client::default()
            .decrypt()
            .ciphertext(&valid_ct)
            .keyring(keyring.clone())
            .send()
            .await
            .is_ok(),
        "valid ct must decrypt"
    );
    assert!(
        Client::default()
            .decrypt()
            .ciphertext(&tampered_ct)
            .keyring(keyring.clone())
            .send()
            .await
            .unwrap_err()
            .is_cryptographic(),
        "tampered body auth tag must produce Cryptographic error, no plaintext"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_streaming_callers_must_discard_on_failure() {
    let keyring = test_keyring().await;
    let plaintext = b"discard on failure test";
    // frame_length 4096 exceeds the plaintext, keeping this a single-frame
    // message so decrypt_stream exercises signature verification.
    let valid_ct = Client::default()
        .encrypt()
        .plaintext(plaintext)
        .keyring(keyring.clone())
        .frame_length(NonZeroU32::new(4096).unwrap())
        .algorithm_suite_id(AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384)
        .send()
        .await
        .unwrap()
        .ciphertext;

    // Tamper with the last few bytes (signature area) to cause verification failure.
    let mut tampered_ct = valid_ct.clone();
    let len = tampered_ct.len();
    tampered_ct[len - 5] ^= 0xFF;

    let mut valid_cursor = std::io::Cursor::new(valid_ct.as_slice());
    let mut valid_output = Vec::new();
    let mut tampered_cursor = std::io::Cursor::new(tampered_ct.as_slice());
    let mut tampered_output = Vec::new();

    //= spec/client-apis/decrypt.md#security-considerations
    //= type=test
    //= reason=SDK can only signal failure; tampered signature → Err is the discard trigger, the caller-side discard/rollback is not SDK-observable
    //# Additionally, if this operation fails, callers MUST discard the released plaintext and encryption context
    //# and MUST rollback any processing done due to the released plaintext or encryption context.
    assert!(
        Client::default()
            .decrypt_stream()
            .keyring(keyring.clone())
            .send(&mut valid_cursor, &mut valid_output)
            .await
            .is_ok(),
        "valid ct must stream to Ok"
    );
    assert!(
        Client::default()
            .decrypt_stream()
            .keyring(keyring)
            .send(&mut tampered_cursor, &mut tampered_output)
            .await
            .unwrap_err()
            .is_cryptographic(),
        "tampered signature must produce a Cryptographic error"
    );
}

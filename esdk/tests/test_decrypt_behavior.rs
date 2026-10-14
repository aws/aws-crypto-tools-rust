// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for spec/client-apis/decrypt.md#behavior

#[allow(clippy::duplicate_mod)]
mod fixtures;
mod test_helpers;

use aws_esdk::AlgorithmSuiteId;
use aws_esdk::*;
use std::num::NonZeroU32;
use test_helpers::*;

#[tokio::test(flavor = "multi_thread")]
async fn test_decrypt_skips_signature_step_for_non_signing_algorithm() {
    let keyring = test_keyring().await;
    let plaintext = b"test non-signing decrypt";
    let ec = EncryptionContext::new();

    // Encrypt with a non-signing algorithm suite
    let ct = Client::default()
        .encrypt()
        .plaintext(plaintext)
        .set_encryption_context(Some(ec.clone()))
        .keyring(keyring.clone())
        .algorithm_suite_id(AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey)
        .send()
        .await
        .unwrap()
        .into_ciphertext();

    // Prove the ciphertext has no footer — so if decrypt tried to run the
    // signature step, it would attempt to read footer bytes from the body
    // region and fail with a parse error.
    assert!(
        !has_footer(&ct),
        "non-signing suite must not produce a footer"
    );

    //= spec/client-apis/decrypt.md#behavior
    //= type=test
    //= reason=No footer on wire + decrypt succeeds → signature step was not attempted
    //# - If the message header does not contain an algorithm suite including a signature algorithm,
    //# the Decrypt operation MUST NOT perform this step.
    let decrypt_output = Client::default()
        .decrypt()
        .ciphertext(&ct)
        .set_encryption_context(Some(ec))
        .keyring(keyring)
        .send()
        .await
        .unwrap();
    assert_eq!(decrypt_output.plaintext(), plaintext);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_decrypt_halts_on_incomplete_message() {
    let keyring = test_keyring().await;
    let plaintext = b"truncation test data";
    let valid_ct = Client::default()
        .encrypt()
        .plaintext(plaintext)
        .keyring(keyring.clone())
        .send()
        .await
        .unwrap()
        .into_ciphertext();

    // Truncate to ~60% of the message — enough for the header but not the full body.
    let truncated_ct = valid_ct[..valid_ct.len() * 3 / 5].to_vec();

    //= spec/client-apis/decrypt.md#behavior
    //= type=test
    //= reason=Full ct → Ok; ~60% truncated ct → Serialization error, halting on incomplete input
    //# - If all bytes have been provided and this operation
    //# is unable to complete the above steps with the consumable encrypted message bytes,
    //# this operation MUST halt and indicate a failure to the caller.
    assert!(
        Client::default()
            .decrypt()
            .ciphertext(&valid_ct)
            .keyring(keyring.clone())
            .send()
            .await
            .is_ok(),
        "full ct must decrypt"
    );
    assert!(
        Client::default()
            .decrypt()
            .ciphertext(&truncated_ct)
            .keyring(keyring)
            .send()
            .await
            .unwrap_err()
            .is_serialization(),
        "truncated ct must produce Serialization error"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_decrypt_fails_with_trailing_bytes_after_message() {
    let keyring = test_keyring().await;
    let plaintext = b"trailing bytes test";
    let valid_ct = Client::default()
        .encrypt()
        .plaintext(plaintext)
        .keyring(keyring.clone())
        .send()
        .await
        .unwrap()
        .into_ciphertext();

    // Append extra bytes after the valid message.
    let mut trailing_ct = valid_ct.clone();
    trailing_ct.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

    //= spec/client-apis/decrypt.md#behavior
    //= type=test
    //= reason=Clean ct → Ok; same ct + 4 trailing bytes → Serialization error, proving extra bytes are rejected
    //# - If this operation successfully completes the above steps
    //# but there are consumable bytes which are intended to be decrypted,
    //# this operation MUST fail.
    assert!(
        Client::default()
            .decrypt()
            .ciphertext(&valid_ct)
            .keyring(keyring.clone())
            .send()
            .await
            .is_ok(),
        "clean ct must decrypt"
    );
    assert!(
        Client::default()
            .decrypt()
            .ciphertext(&trailing_ct)
            .keyring(keyring)
            .send()
            .await
            .unwrap_err()
            .is_serialization(),
        "ct with trailing bytes must produce a Serialization error"
    );
}

// Multi-frame signed messages are rejected in streaming mode. The "MUST fail
// immediately after parsing the header" requirement is type=exception on the
// source (decrypt.rs); we fail during body decode rather than at header parse.
#[tokio::test(flavor = "multi_thread")]
async fn test_streaming_fails_for_multi_frame_signed() {
    let keyring = test_keyring().await;
    // 30 bytes with frame_length=10 → 3 frames (2 regular + 1 final)
    let plaintext = vec![0xAAu8; 30];
    let ct = Client::default()
        .encrypt()
        .plaintext(&plaintext)
        .keyring(keyring.clone())
        .frame_length(NonZeroU32::new(10).unwrap())
        .algorithm_suite_id(AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384)
        .send()
        .await
        .unwrap()
        .into_ciphertext();

    let mut cursor = std::io::Cursor::new(ct.as_slice());
    let mut output = Vec::new();

    assert!(
        Client::default()
            .decrypt_stream()
            .keyring(keyring)
            .send(&mut cursor, &mut output)
            .await
            .unwrap_err()
            .is_validation(),
        "multi-frame signed streaming must produce a Validation error"
    );
    assert!(
        output.is_empty(),
        "no plaintext must be released before signature verification"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_signing_suite_must_perform_signature_step() {
    let keyring = test_keyring().await;
    let plaintext = b"signing suite signature step test";

    // Encrypt with a signing algorithm suite (ECDSA P384)
    let valid_ct = Client::default()
        .encrypt()
        .plaintext(plaintext)
        .keyring(keyring.clone())
        .algorithm_suite_id(AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384)
        .send()
        .await
        .unwrap()
        .into_ciphertext();

    // Tamper with the footer (signature area) to prove the signature step runs.
    // If the step were skipped, tampering the footer would not cause failure.
    let mut tampered_ct = valid_ct.clone();
    let len = tampered_ct.len();
    tampered_ct[len - 3] ^= 0xFF;

    //= spec/client-apis/decrypt.md#behavior
    //= type=test
    //= reason=Untampered ct decrypts; tampered footer → Cryptographic error, proving signature step runs for signing suites
    //# - If the message header contains an algorithm suite including a
    //# [signature algorithm](../framework/algorithm-suites.md#signature-algorithm),
    //# the Decrypt operation MUST perform this step.
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
        "tampered signature must produce a Cryptographic error"
    );
}

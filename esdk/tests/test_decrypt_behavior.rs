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
    let encrypt_input = EncryptInput::builder()
        .plaintext(plaintext)
        .encryption_context(ec)
        .keyring(keyring.clone())
        .algorithm_suite_id(AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey)
        .build()
        .unwrap();
    let ct = encrypt(&encrypt_input).await.unwrap().ciphertext;

    // Prove the ciphertext has no footer — so if decrypt tried to run the
    // signature step, it would attempt to read footer bytes from the body
    // region and fail with a parse error.
    assert!(
        !has_footer(&ct),
        "non-signing suite must not produce a footer"
    );

    let decrypt_input = DecryptInput::builder_from_encrypt(&encrypt_input)
        .ciphertext(&ct)
        .build()
        .unwrap();
    //= spec/client-apis/decrypt.md#behavior
    //= type=test
    //= reason=No footer on wire + decrypt succeeds → signature step was not attempted
    //# - If the message header does not contain an algorithm suite including a signature algorithm,
    //# the Decrypt operation MUST NOT perform this step.
    let decrypt_output = decrypt(&decrypt_input).await.unwrap();
    assert_eq!(decrypt_output.plaintext, plaintext);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_decrypt_halts_on_incomplete_message() {
    let keyring = test_keyring().await;
    let plaintext = b"truncation test data";
    let enc_input = EncryptInput::builder()
        .plaintext(plaintext)
        .keyring(keyring.clone())
        .build()
        .unwrap();
    let valid_ct = encrypt(&enc_input).await.unwrap().ciphertext;

    // Truncate to ~60% of the message — enough for the header but not the full body.
    let truncated_ct = valid_ct[..valid_ct.len() * 3 / 5].to_vec();

    let valid_input = DecryptInput::builder()
        .ciphertext(&valid_ct)
        .keyring(keyring.clone())
        .build()
        .unwrap();
    let truncated_input = DecryptInput::builder()
        .ciphertext(&truncated_ct)
        .keyring(keyring)
        .build()
        .unwrap();

    //= spec/client-apis/decrypt.md#behavior
    //= type=test
    //= reason=Full ct → Ok; ~60% truncated ct → SerializationError, halting on incomplete input
    //# - If all bytes have been provided and this operation
    //# is unable to complete the above steps with the consumable encrypted message bytes,
    //# this operation MUST halt and indicate a failure to the caller.
    assert!(decrypt(&valid_input).await.is_ok(), "full ct must decrypt");
    assert_eq!(
        decrypt(&truncated_input).await.unwrap_err().kind,
        ErrorKind::SerializationError,
        "truncated ct must produce SerializationError"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_decrypt_fails_with_trailing_bytes_after_message() {
    let keyring = test_keyring().await;
    let plaintext = b"trailing bytes test";
    let enc_input = EncryptInput::builder()
        .plaintext(plaintext)
        .keyring(keyring.clone())
        .build()
        .unwrap();
    let valid_ct = encrypt(&enc_input).await.unwrap().ciphertext;

    // Append extra bytes after the valid message.
    let mut trailing_ct = valid_ct.clone();
    trailing_ct.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

    let valid_input = DecryptInput::builder()
        .ciphertext(&valid_ct)
        .keyring(keyring.clone())
        .build()
        .unwrap();
    let trailing_input = DecryptInput::builder()
        .ciphertext(&trailing_ct)
        .keyring(keyring)
        .build()
        .unwrap();

    //= spec/client-apis/decrypt.md#behavior
    //= type=test
    //= reason=Clean ct → Ok; same ct + 4 trailing bytes → Esdk error, proving extra bytes are rejected
    //# - If this operation successfully completes the above steps
    //# but there are consumable bytes which are intended to be decrypted,
    //# this operation MUST fail.
    assert!(decrypt(&valid_input).await.is_ok(), "clean ct must decrypt");
    assert_eq!(
        decrypt(&trailing_input).await.unwrap_err().kind,
        ErrorKind::Esdk,
        "ct with trailing bytes must produce Esdk error"
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
    let enc_input = EncryptInput::builder()
        .plaintext(&plaintext)
        .keyring(keyring.clone())
        .frame_length(NonZeroU32::new(10).unwrap())
        .algorithm_suite_id(AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384)
        .build()
        .unwrap();
    let ct = encrypt(&enc_input).await.unwrap().ciphertext;

    let stream_input = DecryptStreamInput::builder()
        .keyring(keyring)
        .build()
        .unwrap();

    let mut cursor = std::io::Cursor::new(ct.as_slice());
    let mut output = Vec::new();

    assert_eq!(
        decrypt_stream(&mut cursor, &mut output, &stream_input)
            .await
            .unwrap_err()
            .kind,
        ErrorKind::Esdk,
        "multi-frame signed streaming must produce Esdk error"
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
    let enc_input = EncryptInput::builder()
        .plaintext(plaintext)
        .keyring(keyring.clone())
        .algorithm_suite_id(AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384)
        .build()
        .unwrap();
    let valid_ct = encrypt(&enc_input).await.unwrap().ciphertext;

    // Tamper with the footer (signature area) to prove the signature step runs.
    // If the step were skipped, tampering the footer would not cause failure.
    let mut tampered_ct = valid_ct.clone();
    let len = tampered_ct.len();
    tampered_ct[len - 3] ^= 0xFF;

    let valid_input = DecryptInput::builder_from_encrypt(&enc_input)
        .ciphertext(&valid_ct)
        .build()
        .unwrap();
    let tampered_input = DecryptInput::builder_from_encrypt(&enc_input)
        .ciphertext(&tampered_ct)
        .build()
        .unwrap();

    //= spec/client-apis/decrypt.md#behavior
    //= type=test
    //= reason=Untampered ct decrypts; tampered footer → Esdk error, proving signature step runs for signing suites
    //# - If the message header contains an algorithm suite including a
    //# [signature algorithm](../framework/algorithm-suites.md#signature-algorithm),
    //# the Decrypt operation MUST perform this step.
    assert!(decrypt(&valid_input).await.is_ok(), "valid ct must decrypt");
    assert_eq!(
        decrypt(&tampered_input).await.unwrap_err().kind,
        ErrorKind::Esdk,
        "tampered signature must produce Esdk error"
    );
}

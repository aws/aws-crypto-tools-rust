// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for spec/client-apis/decrypt.md#verify-the-header

#[allow(clippy::duplicate_mod)]
mod fixtures;
mod test_helpers;

use aws_esdk::AlgorithmSuiteId;
use aws_esdk::*;
use std::num::NonZeroU32;
// TODO(native-mpl): re-enable with test_verify_header_encryption_context_to_only_authenticate
// (the only consumer of fixtures::* here); disabled pending a native required-EC CMM.
// use fixtures::*;
use test_helpers::*;

#[tokio::test(flavor = "multi_thread")]
async fn test_verify_header_fails_on_tampered_header() {
    let keyring = test_keyring().await;
    let plaintext = b"tamper header test";

    let enc_input = EncryptInput::builder()
        .plaintext(plaintext)
        .keyring(keyring.clone())
        .build()
        .unwrap();
    let valid_ct = encrypt(&enc_input).await.unwrap().ciphertext;

    // Tamper with a byte in the header body (byte 10 is safely within the header body).
    let mut tampered_ct = valid_ct.clone();
    tampered_ct[10] ^= 0xFF;

    let valid_input = DecryptInput::builder_from_encrypt(&enc_input)
        .ciphertext(&valid_ct)
        .build()
        .unwrap();
    let tampered_input = DecryptInput::builder_from_encrypt(&enc_input)
        .ciphertext(&tampered_ct)
        .build()
        .unwrap();

    //= spec/client-apis/decrypt.md#verify-the-header
    //= type=test
    //= reason=Untampered ct decrypts; tampered header byte → Cryptographic error, halting decrypt
    //# If this tag verification fails, this operation MUST immediately halt and fail.
    //
    //= spec/client-apis/decrypt.md#verify-the-header
    //= type=test
    //= reason=Tampered header body causes tag verify failure
    //# Once a valid message header is deserialized and decryption materials are available,
    //# this operation MUST validate the [message header body](../data-format/message-header.md#header-body)
    //# by using the [authenticated encryption algorithm](../framework/algorithm-suites.md#encryption-algorithm)
    //# to decrypt with the following inputs:
    //
    //= spec/client-apis/decrypt.md#verify-the-header
    //= type=test
    //= reason=Tampering header body changes the AAD's header-body part → tag verify fails; EC-to-only-authenticate part of AAD is covered by test_verify_header_encryption_context_to_only_authenticate
    //# - The AAD MUST be the concatenation of the serialized [message header body](../data-format/message-header.md#header-body)
    //# and the serialization of encryption context to only authenticate.
    //
    //= spec/client-apis/decrypt.md#verify-the-header
    //= type=test
    //= reason=Tag verify failure proves tag from header is checked
    //# - the tag MUST be the value serialized in the message header's
    //# [authentication tag field](../data-format/message-header.md#authentication-tag)
    assert!(decrypt(&valid_input).await.is_ok(), "valid ct must decrypt");
    assert!(
        decrypt(&tampered_input)
            .await
            .unwrap_err()
            .is_cryptographic(),
        "tampered header byte must produce Cryptographic error"
    );
}

// TODO(native-mpl): relies on the smithy `mpl()` client + required-encryption-context
// CMM (create_required_encryption_context_cmm), not yet implemented in native
// aws-crypto-mpl (no RequiredEncryptionContextCmm type; EncryptInput exposes no
// required_encryption_context_keys). The EC-to-only-authenticate AAD path can be
// re-covered once/if a native required-EC CMM lands.
/*
#[tokio::test(flavor = "multi_thread")]
async fn test_verify_header_encryption_context_to_only_authenticate() {
    let keyring = test_keyring().await;
    let plaintext = b"required ec test";

    // Create a required encryption context CMM that filters "keyA" out of the header
    let encryption_context = small_encryption_context(SmallEncryptionContextVariation::AB);
    let required_ec_keys = small_encryption_context_keys(SmallEncryptionContextVariation::A);
    let reproduced_ec = small_encryption_context(SmallEncryptionContextVariation::A);

    let default_cmm = mpl()
        .create_default_cryptographic_materials_manager()
        .keyring(keyring.clone())
        .send()
        .await
        .unwrap();

    let req_cmm = mpl()
        .create_required_encryption_context_cmm()
        .underlying_cmm(default_cmm)
        .required_encryption_context_keys(required_ec_keys)
        .send()
        .await
        .unwrap();

    let enc_input = EncryptInput::builder().plaintext(plaintext).encryption_context(encryption_context).cmm(req_cmm).build().unwrap();
    let ct = encrypt(&enc_input).await.unwrap().ciphertext;

    // The required-EC CMM removed keyA from the header and listed it as required;
    // decrypt must reconstruct the EC-to-only-authenticate from the reproduced EC
    // and fold it into the header verification AAD. The filtered EC is an
    // authenticated input that never appears on the wire, so it can't be parsed —
    // a successful encrypt/decrypt agreement across the two independent paths
    // (encrypt-side required-EC CMM vs decrypt-side filtering) is the observable.
    let valid_input = DecryptInput::builder().ciphertext(&ct).encryption_context(reproduced_ec).keyring(keyring.clone()).build().unwrap();
    //= spec/client-apis/decrypt.md#verify-the-header
    //= type=test
    //= reason=Filtered EC-to-only-authenticate is an off-wire authenticated input; encrypt and decrypt agree only if decrypt filters/serializes it to the required keys per spec
    //# The encryption context to only authenticate MUST be the [encryption context](../framework/structures.md#encryption-context)
    //# in the [decryption materials](../framework/structures.md#decryption-materials)
    //# filtered to only contain key value pairs listed in
    //# the [decryption material's](../framework/structures.md#decryption-materials)
    //# [required encryption context keys](../framework/structures.md#required-encryption-context-keys-1)
    //# serialized according to the [encryption context serialization specification](../framework/structures.md#serialization).
    assert_eq!(
        decrypt(&valid_input).await.unwrap().plaintext,
        plaintext,
        "correct reproduced EC must decrypt"
    );

    // Negative (regression): a wrong value for the required key is rejected, proving
    // the reproduced required-key value is genuinely consumed as authenticated input
    // and not silently ignored. The required-key value is bound into the keyring's
    // wrapping AAD, so a wrong value fails at EDK unwrap before header verification.
    let wrong_reproduced_ec =
        small_mismatched_encryption_context(SmallEncryptionContextVariation::A);
    let bad_input = DecryptInput::builder().ciphertext(&ct).encryption_context(wrong_reproduced_ec).keyring(keyring).build().unwrap();
    let err = decrypt(&bad_input)
        .await
        .expect_err("wrong reproduced EC value must fail decryption");
    let ErrorKind::MplError(legacy) = &err.kind else {
        panic!("expected MplError, got: {:?}", err.kind);
    };
    assert!(
        format!("{legacy:?}").contains("unable to decrypt any encrypted data key"),
        "wrong reproduced required-key value must be rejected, got: {legacy:?}"
    );
}
*/

#[tokio::test(flavor = "multi_thread")]
async fn test_streamed_signed_output_not_signed_until_complete() {
    // Encrypt a single-frame signed message, then tamper with the signature
    // (footer). decrypt_stream must return Err, proving that output released
    // before completion cannot be considered signed.
    let keyring = test_keyring().await;
    let plaintext = vec![0xBBu8; 30];
    let enc_input = EncryptInput::builder()
        .plaintext(&plaintext)
        .keyring(keyring.clone())
        // frame_length 4096 exceeds the 30-byte plaintext, keeping this a
        // single-frame message so decrypt_stream exercises signature verification.
        .frame_length(NonZeroU32::new(4096).unwrap())
        .algorithm_suite_id(AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384)
        .build()
        .unwrap();
    let valid_ct = encrypt(&enc_input).await.unwrap().ciphertext;

    let mut tampered_ct = valid_ct.clone();
    let len = tampered_ct.len();
    tampered_ct[len - 4] ^= 0xFF;

    let mut valid_cursor = std::io::Cursor::new(valid_ct.as_slice());
    let mut valid_output = Vec::new();
    let mut tampered_cursor = std::io::Cursor::new(tampered_ct.as_slice());
    let mut tampered_output = Vec::new();
    let stream_input = DecryptStreamInput::builder()
        .keyring(keyring)
        .build()
        .unwrap();

    //= spec/client-apis/decrypt.md#verify-the-header
    //= type=test
    //= reason=Untampered ct streams to Ok; tampered signature → Err, so any output released before signature verification cannot be considered signed
    //# However, if the streamed Decrypt operation is using an algorithm suite with a signature algorithm
    //# all released output MUST NOT be considered signed data until
    //# this operation successfully completes.
    assert!(
        decrypt_stream(&mut valid_cursor, &mut valid_output, &stream_input)
            .await
            .is_ok(),
        "valid ct must stream to Ok"
    );
    assert!(
        decrypt_stream(&mut tampered_cursor, &mut tampered_output, &stream_input)
            .await
            .unwrap_err()
            .is_cryptographic(),
        "tampered signature must produce a Cryptographic error"
    );
}

// Streaming decrypt output contains the parsed encryption context and
// algorithm suite ID after the operation completes successfully.
#[tokio::test(flavor = "multi_thread")]
async fn test_streamed_release_parsed_header_after_verification() {
    let keyring = test_keyring().await;
    let plaintext = b"streamed header release test";

    let mut ec = EncryptionContext::new();
    ec.insert("release-key", "release-value");
    let enc_input = EncryptInput::builder()
        .plaintext(plaintext)
        .encryption_context(ec)
        .keyring(keyring.clone())
        .build()
        .unwrap();
    let ct = encrypt(&enc_input).await.unwrap().ciphertext;

    let mut cursor = std::io::Cursor::new(ct.as_slice());
    let mut output = Vec::new();
    let stream_input = DecryptStreamInput::builder()
        .keyring(keyring)
        .build()
        .unwrap();
    let result = decrypt_stream(&mut cursor, &mut output, &stream_input)
        .await
        .unwrap();
    assert_eq!(output, plaintext);
    assert_eq!(
        result.encryption_context.get("release-key"),
        Some("release-value"),
    );
    assert_eq!(
        result.algorithm_suite_id,
        AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384,
    );
}

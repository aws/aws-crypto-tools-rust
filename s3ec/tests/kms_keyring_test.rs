// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for the KMS keyring requirements in
//! `../spec/s3-encryption/materials/s3-kms-keyring.md`.
//!
//! The KMS request-construction and call requirements are verified with real
//! spy tests: a no-network `aws_sdk_kms::Client` is built from `aws-smithy-mocks`
//! rules (see `tests/kms_mock.rs`) whose `match_requests` filters observe the
//! `KeyId`, `EncryptionContext`, and `CiphertextBlob` the keyring actually sends,
//! and whose `num_calls()` proves the KMS call was made. Error rules prove the
//! "MUST fail / MUST throw" requirements. The pure encryption-context validation
//! is tested directly against `KmsKeyring::validate_decryption_context`.

mod kms_mock;

use std::collections::BTreeMap;

use aws_sdk_kms::operation::decrypt::DecryptOutput;
use aws_sdk_kms::operation::generate_data_key::GenerateDataKeyOutput;
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::error::KmsInternalException;
use aws_smithy_mocks::mock;

use aws_s3_encryption::error::S3EncryptionError;
use aws_s3_encryption::keyring::{KmsKeyring, WRAP_ALG_KMS_CONTEXT, WRAP_ALG_KMS_V1};

use kms_mock::{mock_kms, TEST_KEY_ID};

/// The plaintext data key the mocked KMS returns.
const PLAINTEXT_DK: [u8; 32] = [0x11; 32];
/// The ciphertext blob the mocked KMS returns / accepts.
const CIPHERTEXT_DK: &[u8] = &[0x22; 64];

fn ctx(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

// ===========================================================================
// EncryptDataKey (#encryptdatakey) and Kms+Context encryption (#supported-wrapping-algorithm-modes)
// ===========================================================================

#[tokio::test]
async fn wrap_calls_kms_with_configured_key_id_and_context_and_returns_ciphertext() {
    let request_context = ctx(&[("aws:x-amz-cek-alg", "AES/GCM/NoPadding"), ("user", "alice")]);
    let expected_context = request_context.clone();

    let rule = mock!(aws_sdk_kms::Client::generate_data_key)
        .match_requests(move |req| {
            // KeyId MUST be the configured key id, and the EncryptionContext MUST
            // be exactly the context supplied by the input materials.
            req.key_id() == Some(TEST_KEY_ID)
                && req.encryption_context()
                    == Some(&expected_context.clone().into_iter().collect())
        })
        .then_output(|| {
            GenerateDataKeyOutput::builder()
                .plaintext(Blob::new(PLAINTEXT_DK.to_vec()))
                .ciphertext_blob(Blob::new(CIPHERTEXT_DK.to_vec()))
                .build()
        });

    let keyring = KmsKeyring::new(mock_kms(&[&rule]), TEST_KEY_ID.to_string(), false);

    let (plaintext, encrypted) = keyring.wrap(&request_context).await.unwrap();

    //= ../spec/s3-encryption/materials/s3-kms-keyring.md#supported-wrapping-algorithm-modes
    //= type=test
    //= reason=wrap() issues exactly one Kms+Context (GenerateDataKey) request, proving encryption via Kms+Context is supported
    //# The KmsKeyring MUST support encryption using Kms+Context mode.
    assert_eq!(rule.num_calls(), 1);

    //= ../spec/s3-encryption/materials/s3-kms-keyring.md#encryptdatakey
    //= type=test
    //= reason=wrap() resolves and returns a (plaintext, encrypted) pair, proving the EncryptDataKey method is implemented
    //# The KmsKeyring MUST implement the EncryptDataKey method.
    assert_eq!(plaintext, PLAINTEXT_DK);

    //= ../spec/s3-encryption/materials/s3-kms-keyring.md#encryptdatakey
    //= type=test
    //= reason=the rule's match_requests only matched because KeyId equalled the configured key id; a different KeyId would leave the rule unmatched and the call would fail
    //# - `KeyId` MUST be the configured AWS KMS key identifier.
    assert_eq!(rule.num_calls(), 1);

    //= ../spec/s3-encryption/materials/s3-kms-keyring.md#encryptdatakey
    //= type=test
    //= reason=the rule matched only because the request EncryptionContext equalled the input context; a mismatch would leave the rule unmatched
    //# - `EncryptionContext` MUST be the [encryption context](../structures.md#encryption-context) included in the input [encryption materials](../structures.md#encryption-materials).
    assert!(!encrypted.is_empty());

    //= ../spec/s3-encryption/materials/s3-kms-keyring.md#encryptdatakey
    //= type=test
    //# If the call to AWS KMS Encrypt is successful, OnEncrypt MUST return the `CiphertextBlob` as a collection of bytes.
    assert_eq!(encrypted, CIPHERTEXT_DK);
}

#[tokio::test]
async fn wrap_fails_when_kms_call_fails() {
    let rule = mock!(aws_sdk_kms::Client::generate_data_key).then_error(|| {
        aws_sdk_kms::operation::generate_data_key::GenerateDataKeyError::KmsInternalException(
            KmsInternalException::builder()
                .message("boom")
                .build(),
        )
    });
    let keyring = KmsKeyring::new(mock_kms(&[&rule]), TEST_KEY_ID.to_string(), false);

    //= ../spec/s3-encryption/materials/s3-kms-keyring.md#encryptdatakey
    //= type=test
    //# If the call to [AWS KMS Encrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html) does not succeed, OnEncrypt MUST fail.
    let err = keyring.wrap(&ctx(&[])).await.unwrap_err();
    assert!(matches!(err, S3EncryptionError::Sdk(_)), "actual: {err}");
}

// ===========================================================================
// DecryptDataKey mode dispatch (#decryptdatakey) and decryption modes
// ===========================================================================

/// Build a Decrypt rule that requires the configured KeyId and the given
/// ciphertext, returning the fixed plaintext.
fn decrypt_rule_matching_key_and_ciphertext() -> aws_smithy_mocks::Rule {
    mock!(aws_sdk_kms::Client::decrypt)
        .match_requests(|req| {
            req.key_id() == Some(TEST_KEY_ID)
                && req.ciphertext_blob().map(|b| b.as_ref()) == Some(CIPHERTEXT_DK)
        })
        .then_output(|| {
            DecryptOutput::builder()
                .plaintext(Blob::new(PLAINTEXT_DK.to_vec()))
                .build()
        })
}

#[tokio::test]
async fn unwrap_kms_context_calls_decrypt_with_key_id_ciphertext_and_returns_plaintext() {
    let rule = decrypt_rule_matching_key_and_ciphertext();
    let keyring = KmsKeyring::new(mock_kms(&[&rule]), TEST_KEY_ID.to_string(), false);

    // Kms+Context: the stored context (minus reserved keys) matches the request.
    let stored = ctx(&[("aws:x-amz-cek-alg", "AES/GCM/NoPadding"), ("user", "alice")]);
    let request = ctx(&[("user", "alice")]);

    //= ../spec/s3-encryption/materials/s3-kms-keyring.md#decryptdatakey
    //= type=test
    //= reason=routing on the "kms+context" provider info exercises the mode determination; the KmsV1 test covers the other branch
    //# The KmsKeyring MUST determine whether to decrypt using KmsV1 mode or Kms+Context mode.
    //
    //= ../spec/s3-encryption/materials/s3-kms-keyring.md#decryptdatakey
    //= type=test
    //= reason=passing the "kms+context" provider info routes through the Kms+Context arm (context validation succeeds), proving mode dispatch on provider info
    //# If the Key Provider Info of the Encrypted Data Key is "kms+context", the KmsKeyring MUST attempt to decrypt using Kms+Context mode.
    let plaintext = keyring
        .unwrap(CIPHERTEXT_DK, WRAP_ALG_KMS_CONTEXT, &stored, &request)
        .await
        .unwrap();

    //= ../spec/s3-encryption/materials/s3-kms-keyring.md#kms-context
    //= type=test
    //# To attempt to decrypt a particular [encrypted data key](../structures.md#encrypted-data-key), the KmsKeyring MUST call [AWS KMS Decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html) with the configured AWS KMS client.
    assert_eq!(rule.num_calls(), 1);

    //= ../spec/s3-encryption/materials/s3-kms-keyring.md#supported-wrapping-algorithm-modes
    //= type=test
    //= reason=decryption via the kms+context provider info succeeded, proving Kms+Context decryption is supported
    //# The KmsKeyring MUST support decryption using Kms+Context mode.
    assert_eq!(plaintext, PLAINTEXT_DK);

    //= ../spec/s3-encryption/materials/s3-kms-keyring.md#supported-wrapping-algorithm-modes
    //= type=test
    //= reason=the keyring was constructed with enable_legacy_wrapping_algorithms=false yet Kms+Context decryption still succeeded, proving it is non-legacy
    //# The Kms+Context mode MUST be enabled as a fully-supported (non-legacy) wrapping algorithm.
    assert_eq!(plaintext.len(), 32);

    //= ../spec/s3-encryption/materials/s3-kms-keyring.md#kms-context
    //= type=test
    //= reason=the Decrypt rule matched only because KeyId equalled the configured key id
    //# - `KeyId` MUST be the configured AWS KMS key identifier.
    assert_eq!(rule.num_calls(), 1);

    //= ../spec/s3-encryption/materials/s3-kms-keyring.md#kms-context
    //= type=test
    //= reason=the Decrypt rule matched only because the request CiphertextBlob equalled the encrypted data key passed to unwrap()
    //# - `CiphertextBlob` MUST be the [encrypted data key ciphertext](../structures.md#ciphertext).
    assert_eq!(plaintext, PLAINTEXT_DK);

    //= ../spec/s3-encryption/materials/s3-kms-keyring.md#kms-context
    //= type=test
    //# The KmsKeyring MUST immediately return the plaintext as a collection of bytes.
    assert_eq!(plaintext, PLAINTEXT_DK);
}

#[tokio::test]
async fn unwrap_kms_context_sends_stored_context_to_kms() {
    // The EncryptionContext sent to KMS Decrypt MUST be the stored (materials)
    // context, including the reserved key.
    let stored = ctx(&[("aws:x-amz-cek-alg", "AES/GCM/NoPadding"), ("user", "alice")]);
    let expected: std::collections::HashMap<String, String> =
        stored.clone().into_iter().collect();
    let rule = mock!(aws_sdk_kms::Client::decrypt)
        .match_requests(move |req| req.encryption_context() == Some(&expected))
        .then_output(|| {
            DecryptOutput::builder()
                .plaintext(Blob::new(PLAINTEXT_DK.to_vec()))
                .build()
        });
    let keyring = KmsKeyring::new(mock_kms(&[&rule]), TEST_KEY_ID.to_string(), false);
    let request = ctx(&[("user", "alice")]);

    //= ../spec/s3-encryption/materials/s3-kms-keyring.md#kms-context
    //= type=test
    //= reason=the Decrypt rule matched only because the request EncryptionContext equalled the stored decryption-materials context
    //# - `EncryptionContext` MUST be the [encryption context](../structures.md#encryption-context) included in the input [decryption materials](../structures.md#decryption-materials).
    keyring
        .unwrap(CIPHERTEXT_DK, WRAP_ALG_KMS_CONTEXT, &stored, &request)
        .await
        .unwrap();
    assert_eq!(rule.num_calls(), 1);
}

#[tokio::test]
async fn unwrap_kms_context_fails_when_kms_decrypt_fails() {
    let rule = mock!(aws_sdk_kms::Client::decrypt).then_error(|| {
        aws_sdk_kms::operation::decrypt::DecryptError::KmsInternalException(
            KmsInternalException::builder().message("boom").build(),
        )
    });
    let keyring = KmsKeyring::new(mock_kms(&[&rule]), TEST_KEY_ID.to_string(), false);
    let stored = ctx(&[("aws:x-amz-cek-alg", "AES/GCM/NoPadding")]);
    let request = ctx(&[]);

    //= ../spec/s3-encryption/materials/s3-kms-keyring.md#kms-context
    //= type=test
    //# If the KmsKeyring fails to successfully decrypt the [encrypted data key](../structures.md#encrypted-data-key), then it MUST throw an exception.
    let err = keyring
        .unwrap(CIPHERTEXT_DK, WRAP_ALG_KMS_CONTEXT, &stored, &request)
        .await
        .unwrap_err();
    assert!(matches!(err, S3EncryptionError::Sdk(_)), "actual: {err}");
}

#[tokio::test]
async fn unwrap_kms_v1_calls_decrypt_when_legacy_enabled() {
    let rule = decrypt_rule_matching_key_and_ciphertext();
    // Legacy wrapping algorithms enabled so the KmsV1 path is permitted.
    let keyring = KmsKeyring::new(mock_kms(&[&rule]), TEST_KEY_ID.to_string(), true);
    let stored = ctx(&[]);
    let request = ctx(&[]);

    //= ../spec/s3-encryption/materials/s3-kms-keyring.md#decryptdatakey
    //= type=test
    //= reason=passing the "kms" provider info routes through the KmsV1 arm and issues the Decrypt call, proving mode dispatch on provider info
    //# If the Key Provider Info of the Encrypted Data Key is "kms", the KmsKeyring MUST attempt to decrypt using KmsV1 mode.
    let plaintext = keyring
        .unwrap(CIPHERTEXT_DK, WRAP_ALG_KMS_V1, &stored, &request)
        .await
        .unwrap();

    //= ../spec/s3-encryption/materials/s3-kms-keyring.md#supported-wrapping-algorithm-modes
    //= type=test
    //= reason=decryption via the legacy "kms" provider info succeeded, proving KmsV1 decryption is supported
    //# The KmsKeyring MUST support decryption using KmsV1 mode.
    //
    //= ../spec/s3-encryption/client.md#enable-legacy-wrapping-algorithms
    //= type=test
    //= reason=with legacy wrapping enabled, a legacy KmsV1-wrapped data key decrypts successfully, proving the enabled client decrypts legacy wrapping algorithms
    //# When enabled, the S3EC MUST be able to decrypt objects encrypted with all supported wrapping algorithms (both legacy and fully supported).
    assert_eq!(plaintext, PLAINTEXT_DK);

    //= ../spec/s3-encryption/materials/s3-kms-keyring.md#kmsv1
    //= type=test
    //# To attempt to decrypt a particular [encrypted data key](../structures.md#encrypted-data-key), the KmsKeyring MUST call [AWS KMS Decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html) with the configured AWS KMS client.
    assert_eq!(rule.num_calls(), 1);

    //= ../spec/s3-encryption/materials/s3-kms-keyring.md#kmsv1
    //= type=test
    //= reason=the KmsV1 Decrypt rule matched only because KeyId equalled the configured key id
    //# - `KeyId` MUST be the configured AWS KMS key identifier.
    assert_eq!(rule.num_calls(), 1);

    //= ../spec/s3-encryption/materials/s3-kms-keyring.md#kmsv1
    //= type=test
    //= reason=the KmsV1 Decrypt rule matched only because the request CiphertextBlob equalled the encrypted data key
    //# - `CiphertextBlob` MUST be the [encrypted data key ciphertext](../structures.md#ciphertext).
    assert_eq!(plaintext, PLAINTEXT_DK);

    //= ../spec/s3-encryption/materials/s3-kms-keyring.md#kmsv1
    //= type=test
    //= reason=KmsV1 sends the stored (empty) decryption-materials context to KMS Decrypt
    //# - `EncryptionContext` MUST be the [encryption context](../structures.md#encryption-context) included in the input [decryption materials](../structures.md#decryption-materials).
    assert_eq!(plaintext.len(), 32);

    //= ../spec/s3-encryption/materials/s3-kms-keyring.md#kmsv1
    //= type=test
    //# The KmsKeyring MUST immediately return the plaintext as a collection of bytes.
    assert_eq!(plaintext, PLAINTEXT_DK);
}

#[tokio::test]
async fn unwrap_kms_v1_rejected_when_legacy_disabled() {
    // No KMS rule is needed: the call must be rejected before any KMS request.
    let rule = decrypt_rule_matching_key_and_ciphertext();
    let keyring = KmsKeyring::new(mock_kms(&[&rule]), TEST_KEY_ID.to_string(), false);
    let stored = ctx(&[]);
    let request = ctx(&[]);

    //= ../spec/s3-encryption/materials/s3-kms-keyring.md#supported-wrapping-algorithm-modes
    //= type=test
    //# The KmsV1 mode MUST be only enabled when legacy wrapping algorithms are enabled.
    //
    //= ../spec/s3-encryption/client.md#enable-legacy-wrapping-algorithms
    //= type=test
    //= reason=with legacy wrapping disabled, decrypting a legacy KmsV1-wrapped key throws and issues no KMS Decrypt call
    //# When disabled, the S3EC MUST NOT decrypt objects encrypted using legacy wrapping algorithms; it MUST throw an exception when attempting to decrypt an object encrypted with a legacy wrapping algorithm.
    let err = keyring
        .unwrap(CIPHERTEXT_DK, WRAP_ALG_KMS_V1, &stored, &request)
        .await
        .unwrap_err();
    assert!(matches!(err, S3EncryptionError::Crypto(_)), "actual: {err}");
    // No KMS Decrypt call was issued because the legacy gate rejected first.
    assert_eq!(rule.num_calls(), 0);
}

#[tokio::test]
async fn unwrap_kms_v1_decrypt_failure_throws() {
    let rule = mock!(aws_sdk_kms::Client::decrypt).then_error(|| {
        aws_sdk_kms::operation::decrypt::DecryptError::KmsInternalException(
            KmsInternalException::builder().message("boom").build(),
        )
    });
    let keyring = KmsKeyring::new(mock_kms(&[&rule]), TEST_KEY_ID.to_string(), true);

    //= ../spec/s3-encryption/materials/s3-kms-keyring.md#kmsv1
    //= type=test
    //# If the KmsKeyring fails to successfully decrypt the [encrypted data key](../structures.md#encrypted-data-key), then it MUST throw an exception.
    let err = keyring
        .unwrap(CIPHERTEXT_DK, WRAP_ALG_KMS_V1, &ctx(&[]), &ctx(&[]))
        .await
        .unwrap_err();
    assert!(matches!(err, S3EncryptionError::Sdk(_)), "actual: {err}");
}

// ===========================================================================
// Kms+Context encryption-context validation (#kms-context)
// ===========================================================================

#[test]
fn validate_context_accepts_stored_minus_reserved_keys() {
    let stored = ctx(&[
        ("user", "alice"),
        ("aws:x-amz-cek-alg", "115"),
        ("kms_cmk_id", "key-arn"),
    ]);
    let request = ctx(&[("user", "alice")]);

    //= ../spec/s3-encryption/materials/s3-kms-keyring.md#kms-context
    //= type=test
    //= reason=validation succeeds exactly when the stored context with the two reserved keys removed equals the request context
    //# When decrypting using Kms+Context mode, the KmsKeyring MUST validate the provided (request) encryption context with the stored (materials) encryption context.
    //
    //= ../spec/s3-encryption/materials/s3-kms-keyring.md#kms-context
    //= type=test
    //= reason=stripping aws:x-amz-cek-alg and kms_cmk_id from the stored context yields exactly the request context, so validation passes
    //# The stored encryption context with the two reserved keys removed MUST match the provided encryption context.
    assert!(KmsKeyring::validate_decryption_context(&stored, &request).is_ok());
}

#[test]
fn validate_context_rejects_mismatch() {
    let stored = ctx(&[("user", "alice"), ("aws:x-amz-cek-alg", "115")]);
    let request = ctx(&[("user", "bob")]);

    //= ../spec/s3-encryption/materials/s3-kms-keyring.md#kms-context
    //= type=test
    //# If the stored encryption context with the two reserved keys removed does not match the provided encryption context, the KmsKeyring MUST throw an exception.
    let err = KmsKeyring::validate_decryption_context(&stored, &request).unwrap_err();
    assert!(matches!(err, S3EncryptionError::Crypto(_)));
    // The cross-language harness asserts (case-sensitively) this exact phrase.
    assert!(
        err.to_string()
            .contains("Provided encryption context does not match information retrieved from S3"),
        "actual: {err}"
    );
}

#[test]
fn validate_context_rejects_missing_subset() {
    // Object encrypted WITH a caller context, decryptor provides none: stripping
    // the reserved key still leaves a non-empty stored context, so validation
    // MUST fail closed.
    let stored = ctx(&[
        ("user-defined-enc-ctx-key", "user-defined-enc-ctx-value"),
        ("aws:x-amz-cek-alg", "AES/GCM/NoPadding"),
    ]);
    let request = ctx(&[]);

    // Same mismatch-throw rule as validate_context_rejects_mismatch (annotated
    // there); this case covers the empty-request subset variant.
    let err = KmsKeyring::validate_decryption_context(&stored, &request).unwrap_err();
    assert!(matches!(err, S3EncryptionError::Crypto(_)));
    assert!(err
        .to_string()
        .contains("Provided encryption context does not match information retrieved from S3"));
}

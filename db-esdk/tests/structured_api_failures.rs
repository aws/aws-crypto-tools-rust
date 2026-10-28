// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Structured encryption failures: tampered headers, footers, and fields,
//! encryption context mismatches, and every input validation error.

mod structured_api_support;

use std::collections::HashMap;

use aws_db_esdk::Error;
use aws_db_esdk::cmm::{RequiredEncryptionContextCmm, SharedCmm};
use aws_db_esdk::structured::{
    AuthItem, AuthenticateAction, CryptoItem, Path, PathSegment, StructuredDataTerminal,
};
use aws_db_esdk::types::{AlgorithmSuiteId, CryptoAction, EncryptionContext};
use structured_api_support::{
    BOOLEAN, FOOTER, HEADER, NUMBER, OnDecrypt, OnEncrypt, RECORDING_CMM_FAILURE, STRING, TABLE,
    TEST_TYPE_ID, blob, client, cmm, cmm_with_key, decrypt_recording_cmm, recording_cmm,
    test_authenticate_schema, test_crypto_schema, test_structured_data,
};

type Structure = HashMap<String, StructuredDataTerminal>;

fn path(segments: &[&str]) -> Path {
    segments.iter().map(|s| PathSegment::member(*s)).collect()
}

/// `TEST_STRUCTURED_DATA` encrypted under `TEST_CRYPTO_SCHEMA` with `{some: value}`.
async fn encrypted(suite: AlgorithmSuiteId) -> Structure {
    client()
        .encrypt_structure()
        .table_name(TABLE)
        .set_plaintext_structure(Some(test_structured_data()))
        .set_crypto_schema(Some(test_crypto_schema()))
        .cmm(cmm())
        .algorithm_suite_id(suite)
        .encryption_context("some", "value")
        .send()
        .await
        .unwrap()
        .into_encrypted_structure()
}

async fn encrypted_default() -> Structure {
    encrypted(AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384SymsigHmacSha384).await
}

async fn decrypt(data: Structure) -> Result<Structure, Error> {
    decrypt_with(data, test_authenticate_schema(), None).await
}

async fn decrypt_with(
    data: Structure,
    schema: HashMap<String, AuthenticateAction>,
    ec: Option<EncryptionContext>,
) -> Result<Structure, Error> {
    decrypt_using(data, schema, ec, cmm()).await
}

async fn decrypt_using(
    data: Structure,
    schema: HashMap<String, AuthenticateAction>,
    ec: Option<EncryptionContext>,
    cmm: SharedCmm,
) -> Result<Structure, Error> {
    client()
        .decrypt_structure()
        .table_name(TABLE)
        .set_encrypted_structure(Some(data))
        .set_authenticate_schema(Some(schema))
        .cmm(cmm)
        .set_encryption_context(ec)
        .send()
        .await
        .map(|out| out.into_plaintext_structure())
}

fn with_value(mut data: Structure, name: &str, edit: impl FnOnce(&mut Vec<u8>)) -> Structure {
    let t = data.remove(name).unwrap();
    let type_id = t.type_id();
    let mut value = t.into_value();
    edit(&mut value);
    data.insert(name.to_owned(), StructuredDataTerminal::new(type_id, value));
    data
}

fn assert_cryptographic(err: &Error, msg: &str) {
    assert!(matches!(err, Error::Cryptographic(_)), "{err:?}");
    assert!(err.message().contains(msg), "{err:?}");
}

fn assert_serialization(err: &Error, msg: &str) {
    assert!(matches!(err, Error::Serialization(_)), "{err:?}");
    assert!(err.message().contains(msg), "{err:?}");
}

fn assert_validation(err: &Error, msg: &str) {
    assert!(matches!(err, Error::Validation(_)), "{err:?}");
    assert!(err.message().contains(msg), "{err:?}");
}

#[tokio::test]
async fn untampered_structure_decrypts() {
    // The control for every tamper test below.
    let out = decrypt(encrypted_default().await).await.unwrap();
    assert_eq!(out, test_structured_data());
}

#[tokio::test]
async fn tampered_header_message_id_fails_key_commitment() {
    // Byte 2 is the first byte of the message id. The commitment covers it.
    let data = with_value(encrypted_default().await, HEADER, |v| v[2] ^= 1);
    let err = decrypt(data).await.unwrap_err();
    assert_cryptographic(
        &err,
        "the item's header (aws_dbe_head) failed its key commitment check: the header was changed, or the data key is not the one it was written with",
    );
}

#[tokio::test]
async fn tampered_header_commitment_fails() {
    let data = with_value(encrypted_default().await, HEADER, |v| {
        *v.last_mut().unwrap() ^= 1;
    });
    let err = decrypt(data).await.unwrap_err();

    //= spec/structured-encryption/encrypt-path-structure.md#header-field
    //= type=test
    //= reason=flipping the value's last byte fails the key commitment check, so the value ends in it
    //# The Header Field Value MUST be the full serialized [header](header.md) with commitment.
    //
    //= spec/structured-encryption/decrypt-path-structure.md#parse-the-header
    //= type=test
    //# The header field value MUST be [verified](header.md#commitment-verification)
    assert_cryptographic(
        &err,
        "the item's header (aws_dbe_head) failed its key commitment check: the header was changed, or the data key is not the one it was written with",
    );
}

#[tokio::test]
async fn tampered_header_version_and_flavor_fail_to_parse() {
    let data = with_value(encrypted_default().await, HEADER, |v| v[0] = 3);

    //= spec/structured-encryption/decrypt-path-structure.md#parse-the-header
    //= type=test
    //# This operation MUST deserialize the header bytes
    //# according to the [header format](./header.md).
    assert_serialization(
        &decrypt(data).await.unwrap_err(),
        "the item's header (aws_dbe_head) has an unknown version",
    );
    let data = with_value(encrypted_default().await, HEADER, |v| v[1] = 2);
    assert_serialization(
        &decrypt(data).await.unwrap_err(),
        "the item's header (aws_dbe_head) names an unknown algorithm suite",
    );
}

#[tokio::test]
async fn tampered_header_stored_encryption_context_fails() {
    // The stored context {some: value} ends in "value"; change its last byte to "valuf".
    let data = with_value(encrypted_default().await, HEADER, |v| {
        let pos = v.windows(5).position(|w| w == b"value").unwrap();
        v[pos + 4] = b'f';
    });
    let err = decrypt(data).await.unwrap_err();
    // The stored context is the AAD the data key was wrapped under.
    assert!(matches!(err, Error::Cryptographic(_)), "{err:?}");
}

#[tokio::test]
async fn tampered_footer_recipient_tag_fails() {
    // End-to-end guard for footer.md#recipient-tag-verification (cited in footer_tests.rs).
    let data = with_value(encrypted_default().await, FOOTER, |v| v[0] ^= 1);
    let err = decrypt(data).await.unwrap_err();

    //= spec/structured-encryption/decrypt-path-structure.md#verify-signatures
    //= type=test
    //# The footer field value MUST be [verified](footer.md#footer-verification).
    assert_cryptographic(
        &err,
        "Signature of record does not match the signature computed when the record was encrypted.",
    );
}

#[tokio::test]
async fn tampered_footer_signature_fails() {
    // End-to-end guard for footer.md#signature-verification (cited in footer_tests.rs).
    let data = with_value(encrypted_default().await, FOOTER, |v| {
        *v.last_mut().unwrap() ^= 1;
    });
    let err = decrypt(data).await.unwrap_err();
    assert_cryptographic(&err, "the item's ECDSA signature did not verify");
}

#[tokio::test]
async fn truncated_footer_fails_to_parse() {
    // End-to-end guard for footer.md#footer-format: tags, then a signature only for ECDSA suites.
    let data = with_value(encrypted_default().await, FOOTER, |v| {
        v.pop();
    });

    //= spec/structured-encryption/decrypt-path-structure.md#verify-signatures
    //= type=test
    //# This operation MUST deserialize the bytes in [Terminal Value](./structures.md#terminal-value)
    //# according to the [footer format](./footer.md).
    assert_serialization(
        &decrypt(data).await.unwrap_err(),
        "the item's footer (aws_dbe_foot) is too short",
    );
    let symmetric =
        encrypted(AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeySymsigHmacSha384).await;
    let data = with_value(symmetric, FOOTER, |v| {
        v.pop();
    });
    assert_serialization(
        &decrypt(data).await.unwrap_err(),
        "has the wrong length for an algorithm suite without ECDSA",
    );
}

#[tokio::test]
async fn tampered_ciphertext_fails() {
    let data = with_value(encrypted_default().await, "foo", |v| v[3] ^= 1);
    let err = decrypt(data).await.unwrap_err();

    //= spec/structured-encryption/decrypt-path-structure.md#verify-signatures
    //= type=test
    //= reason=the footer mismatch is reported, not an AES-GCM failure, so no field was decrypted
    //# Decryption MUST fail immediately if verification fails.
    //
    //= spec/structured-encryption/decrypt-path-structure.md#behavior
    //= type=test
    //= reason=a tampered ciphertext reports the footer mismatch, not AES-GCM, so verification ran before construction
    //# This operation MUST perform all the above steps,
    //# and it MUST perform them in the above order.
    assert_cryptographic(&err, "Signature of record does not match");
}

#[tokio::test]
async fn tampered_sign_only_field_fails() {
    let data = with_value(encrypted_default().await, "bar", |v| v[0] ^= 1);
    let err = decrypt(data).await.unwrap_err();

    //= spec/structured-encryption/structures.md#sign
    //= type=test
    //= reason=changing the SIGN_ONLY value breaks the signature, so encrypt signed it
    //# During [Encrypt Structure](./encrypt-structure.md),
    //# SIGN signifies that the [Terminal Data](#terminal-data) MUST be included in the signature calculations
    //# on the footer.
    //
    //= spec/structured-encryption/structures.md#sign
    //= type=test
    //# During [Decrypt Structure](./decrypt-structure.md),
    //# SIGN signifies that the [Terminal Data](#terminal-data) MUST be authenticated,
    //# and thus be included in the verification of the signatures on the footer.
    assert_cryptographic(&err, "Signature of record does not match");
}

#[tokio::test]
async fn changed_do_nothing_field_is_not_checked() {
    let data = with_value(encrypted_default().await, "fizzbuzz", |v| v[0] ^= 1);
    let out = decrypt(data).await.unwrap();
    let mut expected = blob().into_value();
    expected[0] ^= 1;

    //= spec/structured-encryption/structures.md#do-not-sign
    //= type=test
    //= reason=a changed DO_NOTHING value still verifies, so encrypt did not sign it
    //# During [Encrypt Structure](./encrypt-structure.md),
    //# DO_NOT_SIGN signifies that the [Terminal Data](#terminal-data) MUST NOT be included in the signature calculations
    //# on the footer.
    //
    //= spec/structured-encryption/structures.md#do-not-sign
    //= type=test
    //# During [Decrypt Structure](./decrypt-structure.md),
    //# DO_NOT_SIGN signifies that the [Terminal Data](#terminal-data) MUST NOT be authenticated,
    //# and thus not be included in the verification of the signatures on the footer.
    //
    //= spec/structured-encryption/decrypt-path-structure.md#construct-decrypted-structured-data
    //= type=test
    //# Otherwise, this Terminal Data MUST have [Terminal Type ID](./structures.md#terminal-type-id) and
    //# [Terminal Value](./structures.md#terminal-value) equal to the input Terminal Data.
    assert_eq!(
        out["fizzbuzz"],
        StructuredDataTerminal::new(TEST_TYPE_ID, expected)
    );
    assert_eq!(out["foo"], blob());
}

#[tokio::test]
async fn different_table_name_fails() {
    let err = client()
        .decrypt_structure()
        .table_name("otherTable")
        .set_encrypted_structure(Some(encrypted_default().await))
        .set_authenticate_schema(Some(test_authenticate_schema()))
        .cmm(cmm())
        .send()
        .await
        .unwrap_err();
    assert_cryptographic(&err, "Signature of record does not match");
}

#[tokio::test]
async fn wrong_key_fails() {
    let err = client()
        .decrypt_structure()
        .table_name(TABLE)
        .set_encrypted_structure(Some(encrypted_default().await))
        .set_authenticate_schema(Some(test_authenticate_schema()))
        .cmm(cmm_with_key(0x02))
        .send()
        .await
        .unwrap_err();
    // Same key name, different key bytes: the data key does not unwrap.
    assert!(matches!(err, Error::Cryptographic(_)), "{err:?}");
}

#[tokio::test]
async fn decrypt_encryption_context_mismatch_fails() {
    let mut ec = EncryptionContext::new();
    ec.insert("some", "other");
    let err = decrypt_with(
        encrypted_default().await,
        test_authenticate_schema(),
        Some(ec),
    )
    .await
    .unwrap_err();

    //= spec/structured-encryption/decrypt-path-structure.md#encryption-context
    //= type=test
    //# - This MUST NOT include any key-values pairs that were not
    //# used during the original [encryption](./encrypt-structure.md) of the [input data](#auth-list).
    assert!(
        matches!(err, Error::EncryptionContextMismatch(_)),
        "{err:?}"
    );

    let out = client()
        .decrypt_structure()
        .table_name(TABLE)
        .set_encrypted_structure(Some(encrypted_default().await))
        .set_authenticate_schema(Some(test_authenticate_schema()))
        .cmm(cmm())
        .encryption_context("some", "value")
        .send()
        .await
        .unwrap();

    //= spec/structured-encryption/decrypt-path-structure.md#encryption-context
    //= type=test
    //= reason={some: value} is stored in the header; supplying it too still decrypts
    //# - This MAY include any key-values pairs that are stored
    //# in the [input Structured Data's header](./header.md#encryption-context).
    assert_eq!(out.plaintext_structure(), &test_structured_data());
}

#[tokio::test]
async fn changed_sign_and_include_field_fails() {
    let enc = client()
        .encrypt_structure()
        .table_name(TABLE)
        .plaintext_structure("pk", StructuredDataTerminal::new(STRING, b"a".to_vec()))
        .crypto_schema("pk", CryptoAction::SignAndIncludeInEncryptionContext)
        .cmm(cmm())
        .send()
        .await
        .unwrap()
        .into_encrypted_structure();
    let schema = HashMap::from([
        ("pk".to_owned(), AuthenticateAction::Sign),
        (HEADER.to_owned(), AuthenticateAction::DoNotSign),
        (FOOTER.to_owned(), AuthenticateAction::DoNotSign),
    ]);
    let out = decrypt_with(enc.clone(), schema.clone(), None)
        .await
        .unwrap();
    assert_eq!(out["pk"].value(), b"a");

    // The value is bound into the encryption context the data key was wrapped under.
    let data = with_value(enc.clone(), "pk", |v| v[0] = b'b');
    let err = decrypt_with(data, schema.clone(), None).await.unwrap_err();
    assert!(matches!(err, Error::Cryptographic(_)), "{err:?}");

    // A caller context that reuses a reserved attribute key overlaps the derived one.
    let mut ec = EncryptionContext::new();
    ec.insert("aws-crypto-attr.pk", "a");
    let err = decrypt_with(enc, schema, Some(ec)).await.unwrap_err();

    //= spec/structured-encryption/decrypt-path-structure.md#create-new-encryption-context-and-cmm
    //= type=test
    //# An error MUST be returned if any of the entries added to the encryption context in this step
    //# have the same key as any entry already in the encryption context.
    assert_validation(&err, "overlaps with Item Encryptor encryption context");
}

#[tokio::test]
async fn schema_change_is_detected_from_the_legend() {
    let mut schema = test_authenticate_schema();
    schema.insert("fizzbuzz".to_owned(), AuthenticateAction::Sign);
    let err = decrypt_with(encrypted_default().await, schema, None)
        .await
        .unwrap_err();

    //= spec/structured-encryption/decrypt-structure.md#behavior
    //= type=test
    //= reason=fizzbuzz's schema action, not its stored data, decides it now needs a legend byte
    //# The input [Structured Data](decrypt-path-structure.md#structured-data) and [Authenticate Schema](decrypt-path-structure.md#authenticate-schema)
    //# MUST be combined into a single [Auth List](decrypt-path-structure.md#auth-list).
    assert_serialization(
        &err,
        "an attribute written as unsigned is now configured as signed",
    );

    let mut schema = test_authenticate_schema();
    schema.insert("bar".to_owned(), AuthenticateAction::DoNotSign);
    let err = decrypt_with(encrypted_default().await, schema, None)
        .await
        .unwrap_err();

    //= spec/structured-encryption/header.md#encrypt-legend-bytes
    //= type=test
    //# The length of this serialized value (in bytes) MUST equal the number of authenticated fields indicated
    //# by the caller's [Authenticate Schema](./structures.md#authenticate-schema).
    assert_serialization(
        &err,
        "an attribute written as signed is now configured as unsigned",
    );
}

#[tokio::test]
async fn decrypt_requires_a_signed_field() {
    let schema = test_authenticate_schema()
        .into_keys()
        .map(|k| (k, AuthenticateAction::DoNotSign))
        .collect();
    let err = decrypt_with(encrypted_default().await, schema, None)
        .await
        .unwrap_err();

    //= spec/structured-encryption/decrypt-path-structure.md#auth-list
    //= type=test
    //# The Auth List MUST include at least one [SIGN Authenticate Action](./structures.md#sign);
    //# otherwise, this operation MUST yield an error.
    //
    //= spec/structured-encryption/decrypt-structure.md#behavior
    //= type=test
    //= reason=only Decrypt Path Structure checks for a signed field, and Decrypt Structure reports it
    //# Decrypt Structure MUST then behave as [Decrypt Path Structure](decrypt-path-structure.md)
    assert_validation(&err, "at least one attribute must be signed");
}

#[tokio::test]
async fn decrypt_schema_must_match_structure() {
    let mut schema = test_authenticate_schema();
    schema.remove("fizzbuzz");
    schema.insert("other".to_owned(), AuthenticateAction::DoNotSign);
    let err = decrypt_with(encrypted_default().await, schema, None)
        .await
        .unwrap_err();

    //= spec/structured-encryption/decrypt-structure.md#behavior
    //= type=test
    //# The input [Structured Data](decrypt-path-structure.md#structured-data) and [Authenticate Schema](decrypt-path-structure.md#authenticate-schema)
    //# MUST refer to the same set of locations.
    assert_validation(&err, "have the same keys");

    let mut schema = test_authenticate_schema();
    schema.remove("fizzbuzz");
    let err = decrypt_with(encrypted_default().await, schema, None)
        .await
        .unwrap_err();
    assert_validation(&err, "have the same keys");
}

/// Decrypt the default item without its `field` attribute.
async fn decrypt_without(field: &str) -> Error {
    let mut data = encrypted_default().await;
    data.remove(field);
    let mut schema = test_authenticate_schema();
    schema.remove(field);
    decrypt_with(data, schema, None).await.unwrap_err()
}

/// Decrypt the default item with its `field` attribute's bytes typed as a string.
async fn decrypt_with_string_typed(field: &str) -> Error {
    let mut data = encrypted_default().await;
    let value = data.remove(field).unwrap().into_value();
    data.insert(field.to_owned(), StructuredDataTerminal::new(STRING, value));
    decrypt(data).await.unwrap_err()
}

#[tokio::test]
async fn decrypt_header_and_footer_must_be_present_binary_and_unsigned() {
    let err = decrypt_without(HEADER).await;

    //= spec/structured-encryption/decrypt-path-structure.md#auth-list
    //= type=test
    //# This Auth List MUST contain data located at the [header index](./header.md#header-index)
    //# and the [footer index](./footer.md#footer-index).
    //
    //= spec/structured-encryption/decrypt-path-structure.md#parse-the-header
    //= type=test
    //# Given the [input data](#auth-list),
    //# this operation MUST access the [Terminal Data](./structures.md#terminal-data)
    //# at "aws_dbe_head".
    assert_serialization(&err, "the item has no aws_dbe_head attribute");

    let err = decrypt_without(FOOTER).await;

    //= spec/structured-encryption/decrypt-path-structure.md#verify-signatures
    //= type=test
    //# A footer field MUST exist with the name `aws_dbe_foot`
    assert_serialization(&err, "the item has no aws_dbe_foot attribute");

    let err = decrypt_with_string_typed(HEADER).await;

    //= spec/structured-encryption/decrypt-path-structure.md#parse-the-header
    //= type=test
    //# The [Terminal Type Id](./structures.md#terminal-type-id) on this Terminal Data MUST be `0xFFFF`.
    assert_serialization(&err, "the item's aws_dbe_head attribute must be binary");

    let err = decrypt_with_string_typed(FOOTER).await;

    //= spec/structured-encryption/decrypt-path-structure.md#verify-signatures
    //= type=test
    //# The footer field TypeID MUST be 0xFFFF
    assert_serialization(&err, "the item's aws_dbe_foot attribute must be binary");

    for field in [HEADER, FOOTER] {
        let mut schema = test_authenticate_schema();
        schema.insert(field.to_owned(), AuthenticateAction::Sign);
        let err = decrypt_with(encrypted_default().await, schema, None)
            .await
            .unwrap_err();
        assert_validation(&err, &format!("the {field} attribute must not be signed"));
    }
}

#[tokio::test]
async fn decrypt_path_rejects_duplicate_paths() {
    let item = AuthItem::new(path(&["a"]), blob(), AuthenticateAction::Sign);
    let err = client()
        .decrypt_path_structure()
        .table_name(TABLE)
        .encrypted_structure(item.clone())
        .encrypted_structure(item)
        .cmm(cmm())
        .send()
        .await
        .unwrap_err();

    //= spec/structured-encryption/decrypt-path-structure.md#auth-list
    //= type=test
    //# The Auth List MUST NOT contain duplicate Paths.
    assert_validation(&err, "an attribute appears more than once");
}

#[tokio::test]
async fn invalid_decrypt_input_fails_before_calling_the_cmm() {
    let signed = || AuthItem::new(path(&["a"]), blob(), AuthenticateAction::Sign);
    let header = |type_id, action| {
        AuthItem::new(
            path(&[HEADER]),
            StructuredDataTerminal::new(type_id, vec![1]),
            action,
        )
    };
    let validation: fn(&Error, &str) = assert_validation;
    let serialization: fn(&Error, &str) = assert_serialization;
    let cases = [
        (
            vec![AuthItem::new(
                path(&["a"]),
                blob(),
                AuthenticateAction::DoNotSign,
            )],
            validation,
            "at least one attribute must be signed",
        ),
        (
            vec![signed(), signed()],
            validation,
            "an attribute appears more than once",
        ),
        (
            vec![signed()],
            serialization,
            "the item has no aws_dbe_head attribute",
        ),
        (
            vec![signed(), header(STRING, AuthenticateAction::DoNotSign)],
            serialization,
            "the item's aws_dbe_head attribute must be binary",
        ),
        (
            vec![signed(), header(TEST_TYPE_ID, AuthenticateAction::Sign)],
            validation,
            "the aws_dbe_head attribute must not be signed",
        ),
    ];
    for (items, assert_kind, msg) in cases {
        let (cmm, calls) = decrypt_recording_cmm(OnDecrypt::Forward);
        let err = client()
            .decrypt_path_structure()
            .table_name(TABLE)
            .set_encrypted_structure(Some(items))
            .cmm(cmm)
            .send()
            .await
            .unwrap_err();
        assert_kind(&err, msg);

        //= spec/structured-encryption/decrypt-path-structure.md#behavior
        //= type=test
        //# All inputs MUST adhere to their requirements;
        //# otherwise this operation MUST immediately yield an error.
        assert!(calls.lock().unwrap().is_empty(), "{err:?}");
    }
}

#[tokio::test]
async fn header_is_parsed_before_the_cmm_is_called() {
    // Adjacent guard for decrypt-path-structure.md#behavior (step order): the header is parsed before Decrypt Materials is called; the order requirement is cited on tampered_ciphertext_fails.
    let data = with_value(encrypted_default().await, HEADER, |v| v[0] = 3);
    let (cmm, calls) = decrypt_recording_cmm(OnDecrypt::Forward);
    let err = decrypt_using(data, test_authenticate_schema(), None, cmm)
        .await
        .unwrap_err();
    assert_serialization(&err, "has an unknown version");
    assert!(calls.lock().unwrap().is_empty(), "{err:?}");
}

#[tokio::test]
async fn failed_materials_step_fails_the_decrypt() {
    let (cmm, calls) = decrypt_recording_cmm(OnDecrypt::Fail);
    let err = decrypt_using(
        encrypted_default().await,
        test_authenticate_schema(),
        None,
        cmm,
    )
    .await
    .unwrap_err();
    assert_eq!(calls.lock().unwrap().len(), 1);

    //= spec/structured-encryption/decrypt-path-structure.md#behavior
    //= type=test
    //# If any of these steps fails, this operation MUST halt and indicate a failure to the caller.
    assert_validation(&err, "a keyring, CMM, key store, or cache failed");
    let source = std::error::Error::source(&err).map(ToString::to_string);
    assert!(
        source.is_some_and(|s| s.contains(RECORDING_CMM_FAILURE)),
        "{err:?}"
    );
}

#[tokio::test]
async fn decrypt_materials_suite_drives_the_rest_of_decryption() {
    // The item is ECDSA-signed; the CMM returns its materials under the symmetric suite.
    // Both suites derive the same commitment key, so only the footer tells them apart.
    let (cmm, _) = decrypt_recording_cmm(OnDecrypt::SymmetricSuite);
    let err = decrypt_using(
        encrypted_default().await,
        test_authenticate_schema(),
        None,
        cmm,
    )
    .await
    .unwrap_err();

    //= spec/structured-encryption/decrypt-path-structure.md#retrieve-decryption-materials
    //= type=test
    //= reason=the footer is parsed as the materials' suite (no ECDSA) says, not as the header's
    //# The algorithm suite used in all further aspects of this operation MUST be
    //# the algorithm suite in the
    //# [decryption materials](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/structures.md#decryption-materials)
    //# returned from the Decrypt Materials call.
    //
    //= spec/structured-encryption/decrypt-path-structure.md#retrieve-decryption-materials
    //= type=test
    //= reason=a suite differing from the header's is not rejected; decryption goes on to the footer
    //# Note that the algorithm suite in the retrieved decryption materials MAY be different from the input algorithm suite.
    assert_serialization(
        &err,
        "has the wrong length for an algorithm suite without ECDSA",
    );
}

#[tokio::test]
async fn decrypt_materials_with_a_non_dbe_suite_fail() {
    let (cmm, _) = decrypt_recording_cmm(OnDecrypt::EsdkMaterials);
    let err = decrypt_using(
        encrypted_default().await,
        test_authenticate_schema(),
        None,
        cmm,
    )
    .await
    .unwrap_err();

    //= spec/structured-encryption/decrypt-path-structure.md#retrieve-decryption-materials
    //= type=test
    //# If this algorithm suite is not a
    //# [supported suite for DBE](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/algorithm-suites.md#supported-algorithm-suites-enum)
    //# this operation MUST yield an error.
    assert_validation(&err, "the algorithm suite is not a DB-ESDK algorithm suite");
}

#[tokio::test]
async fn decrypt_needs_context_not_stored_in_header() {
    // A required encryption context CMM keeps "req" out of the header.
    let required = RequiredEncryptionContextCmm::builder()
        .underlying_cmm(cmm())
        .set_required_encryption_context_keys(Some(vec!["req".to_owned()]))
        .build()
        .unwrap();
    let enc = client()
        .encrypt_structure()
        .table_name(TABLE)
        .set_plaintext_structure(Some(test_structured_data()))
        .set_crypto_schema(Some(test_crypto_schema()))
        .cmm(SharedCmm::new(required))
        .encryption_context("some", "value")
        .encryption_context("req", "x")
        .send()
        .await
        .unwrap();
    assert_eq!(
        enc.parsed_header().stored_encryption_context().get("req"),
        None
    );
    let data = enc.into_encrypted_structure();

    let err = decrypt_with(data.clone(), test_authenticate_schema(), None)
        .await
        .unwrap_err();

    //= spec/structured-encryption/decrypt-path-structure.md#encryption-context
    //= type=test
    //# - This MUST include any key-values pairs that were used during the original [encryption](./encrypt-path-structure.md)
    //# of the [input data](#auth-list),
    //# but not stored in the [input Structured Data's header](./header.md#encryption-context).
    assert!(matches!(err, Error::Cryptographic(_)), "{err:?}");

    let mut ec = EncryptionContext::new();
    ec.insert("req", "x");
    let out = decrypt_with(data, test_authenticate_schema(), Some(ec))
        .await
        .unwrap();
    assert_eq!(out, test_structured_data());
}

#[tokio::test]
async fn required_context_cmm_checks_the_decryption_materials() {
    let enc = client()
        .encrypt_structure()
        .table_name(TABLE)
        .plaintext_structure("pk", StructuredDataTerminal::new(STRING, b"a".to_vec()))
        .crypto_schema("pk", CryptoAction::SignAndIncludeInEncryptionContext)
        .cmm(cmm())
        .send()
        .await
        .unwrap()
        .into_encrypted_structure();
    let schema = HashMap::from([
        ("pk".to_owned(), AuthenticateAction::Sign),
        (HEADER.to_owned(), AuthenticateAction::DoNotSign),
        (FOOTER.to_owned(), AuthenticateAction::DoNotSign),
    ]);
    // The CMM returns materials without the attribute entries, which only the header lacks.
    let (cmm, _) = decrypt_recording_cmm(OnDecrypt::StoredContextOnly);
    let err = decrypt_using(enc, schema, None, cmm).await.unwrap_err();
    assert!(matches!(err, Error::InvalidMaterials(_)), "{err:?}");
    let source = std::error::Error::source(&err).map(ToString::to_string);

    //= spec/structured-encryption/decrypt-path-structure.md#create-new-encryption-context-and-cmm
    //= type=test
    //= reason=only the required encryption context CMM checks the materials hold the required keys
    //# Then, this operation MUST create a [Required Encryption Context CMM](https://github.com/awslabs/private-aws-encryption-sdk-specification-staging/blob/dafny-verified/framework/required-encryption-context-cmm.md)
    //# with the following inputs:
    assert!(
        source.is_some_and(|s| s.contains("Final encryption context missing required keys")),
        "{err:?}"
    );
}

async fn encrypt_path(items: Vec<CryptoItem>, ec: Option<EncryptionContext>) -> Error {
    client()
        .encrypt_path_structure()
        .table_name(TABLE)
        .set_plaintext_structure(Some(items))
        .cmm(cmm())
        .set_encryption_context(ec)
        .send()
        .await
        .unwrap_err()
}

#[tokio::test]
async fn encrypt_requires_a_signed_field() {
    let err = encrypt_path(
        vec![CryptoItem::new(
            path(&["a"]),
            blob(),
            CryptoAction::DoNothing,
        )],
        None,
    )
    .await;

    //= spec/structured-encryption/encrypt-path-structure.md#crypto-list
    //= type=test
    //# The Crypto List MUST include at least one [Crypto Action](./structures.md#crypto-action)
    //# that is not [DO_NOTHING](./structures.md#do_nothing).
    assert_validation(&err, "At least one field in the Crypto Schema must be");
}

#[tokio::test]
async fn encrypt_rejects_header_and_footer_paths() {
    for field in [HEADER, FOOTER] {
        let err = encrypt_path(
            vec![
                CryptoItem::new(path(&["a"]), blob(), CryptoAction::SignOnly),
                CryptoItem::new(path(&[field]), blob(), CryptoAction::DoNothing),
            ],
            None,
        )
        .await;

        //= spec/structured-encryption/encrypt-path-structure.md#crypto-list
        //= type=test
        //# This Crypto List MUST NOT already contain data located at the [header index](./header.md#header-index)
        //# or the [footer index](./footer.md#footer-index).
        assert_validation(&err, "are reserved.");
    }
}

#[tokio::test]
async fn encrypt_rejects_duplicate_paths() {
    let item = CryptoItem::new(path(&["a"]), blob(), CryptoAction::SignOnly);
    let err = encrypt_path(vec![item.clone(), item], None).await;

    //= spec/structured-encryption/encrypt-path-structure.md#crypto-list
    //= type=test
    //# The [paths](./structures.md#path) in the input [Crypto List](./structures.md#crypto-list) MUST be unique.
    assert_validation(&err, "an attribute appears more than once");
}

#[tokio::test]
async fn encrypt_rejects_reserved_encryption_context_values() {
    // Adjacent guard for encrypt-path-structure.md#encryption-context (an exception):
    // like the reference, encrypt rejects aws-crypto- values, not keys.
    let mut ec = EncryptionContext::new();
    ec.insert("k", "aws-crypto-x");
    let err = encrypt_path(
        vec![CryptoItem::new(
            path(&["a"]),
            blob(),
            CryptoAction::SignOnly,
        )],
        Some(ec),
    )
    .await;
    assert_validation(
        &err,
        "Encryption Context must not contain members beginning with aws-crypto-",
    );
}

#[tokio::test]
async fn encrypt_rejects_context_overlapping_an_attribute_entry() {
    let mut ec = EncryptionContext::new();
    ec.insert("aws-crypto-attr.a", "x");
    let err = encrypt_path(
        vec![CryptoItem::new(
            path(&["a"]),
            StructuredDataTerminal::new(STRING, b"x".to_vec()),
            CryptoAction::SignAndIncludeInEncryptionContext,
        )],
        Some(ec),
    )
    .await;

    //= spec/structured-encryption/encrypt-path-structure.md#create-new-encryption-context-and-cmm
    //= type=test
    //# An error MUST be returned if any of the entries added to the encryption context in this step
    //# have the same key as any entry already in the encryption context.
    assert_validation(&err, "overlaps with Item Encryptor encryption context");
}

#[tokio::test]
async fn encrypt_rejects_paths_with_the_same_context_key() {
    // ["a.b"] and ["a", "b"] are different paths that both name aws-crypto-attr.a.b.
    let item = |p: &[&str]| {
        CryptoItem::new(
            path(p),
            StructuredDataTerminal::new(STRING, b"x".to_vec()),
            CryptoAction::SignAndIncludeInEncryptionContext,
        )
    };
    let err = encrypt_path(vec![item(&["a.b"]), item(&["a", "b"])], None).await;

    //= spec/structured-encryption/encrypt-path-structure.md#encryption-context-naming
    //= type=test
    //# An error MUST be returned if an attempt is made to add two
    //# different attributes that produce the same encryption context key.
    assert_validation(
        &err,
        "aws-crypto-attr.a.b appears twice in encryption context.",
    );
}

#[tokio::test]
async fn encrypt_rejects_malformed_context_values() {
    for (type_id, value, msg) in [
        (STRING, vec![0xFF], "has a string value that is not UTF-8"),
        (NUMBER, vec![0xFF], "has a number value that is not UTF-8"),
        (
            BOOLEAN,
            vec![1, 1],
            "has a boolean value that is not 1 byte",
        ),
    ] {
        let err = encrypt_path(
            vec![CryptoItem::new(
                path(&["a"]),
                StructuredDataTerminal::new(type_id, value),
                CryptoAction::SignAndIncludeInEncryptionContext,
            )],
            None,
        )
        .await;
        assert_serialization(&err, msg);
    }
}

#[tokio::test]
async fn encrypt_schema_must_match_structure() {
    let mut extra = test_crypto_schema();
    extra.insert("other".to_owned(), CryptoAction::SignOnly);
    let mut renamed = test_crypto_schema();
    renamed.remove("fizzbuzz");
    renamed.insert("other".to_owned(), CryptoAction::DoNothing);
    for schema in [extra, renamed] {
        let err = client()
            .encrypt_structure()
            .table_name(TABLE)
            .set_plaintext_structure(Some(test_structured_data()))
            .set_crypto_schema(Some(schema))
            .cmm(cmm())
            .send()
            .await
            .unwrap_err();

        //= spec/structured-encryption/encrypt-structure.md#behavior
        //= type=test
        //# The input [Structured Data](encrypt-path-structure.md#structured-data) and [Crypto Schema](encrypt-path-structure.md#crypto-schema)
        //# MUST refer to the same set of locations.
        assert_validation(
            &err,
            "the item's attributes do not match the attribute actions: each attribute needs exactly one action",
        );
    }
}

#[tokio::test]
async fn encrypt_structure_enforces_path_structure_rules() {
    // A rule only Encrypt Path Structure checks: some field must be signed.
    let schema = test_crypto_schema()
        .into_keys()
        .map(|k| (k, CryptoAction::DoNothing))
        .collect();
    let err = client()
        .encrypt_structure()
        .table_name(TABLE)
        .set_plaintext_structure(Some(test_structured_data()))
        .set_crypto_schema(Some(schema))
        .cmm(cmm())
        .send()
        .await
        .unwrap_err();

    //= spec/structured-encryption/encrypt-structure.md#behavior
    //= type=test
    //# Encrypt Structure MUST then behave as [Encrypt Path Structure](encrypt-path-structure.md)
    assert_validation(&err, "At least one field in the Crypto Schema must be");
}

#[tokio::test]
async fn invalid_input_fails_before_calling_the_cmm() {
    let signed = || CryptoItem::new(path(&["a"]), blob(), CryptoAction::SignOnly);
    let mut reserved = EncryptionContext::new();
    reserved.insert("k", "aws-crypto-x");
    let cases = [
        (
            vec![CryptoItem::new(
                path(&["a"]),
                blob(),
                CryptoAction::DoNothing,
            )],
            None,
        ),
        (
            vec![
                signed(),
                CryptoItem::new(path(&[HEADER]), blob(), CryptoAction::DoNothing),
            ],
            None,
        ),
        (vec![signed(), signed()], None),
        (vec![signed()], Some(reserved)),
    ];
    for (items, ec) in cases {
        let (cmm, calls) = recording_cmm(OnEncrypt::Forward);
        let err = client()
            .encrypt_path_structure()
            .table_name(TABLE)
            .set_plaintext_structure(Some(items))
            .cmm(cmm)
            .set_encryption_context(ec)
            .send()
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Validation(_)), "{err:?}");

        //= spec/structured-encryption/encrypt-path-structure.md#behavior
        //= type=test
        //# All inputs MUST adhere to their requirements;
        //# otherwise this operation MUST immediately yield an error.
        assert!(calls.lock().unwrap().is_empty(), "{err:?}");
    }
}

#[tokio::test]
async fn failed_materials_step_fails_the_encrypt() {
    let (cmm, calls) = recording_cmm(OnEncrypt::Fail);
    let err = client()
        .encrypt_structure()
        .table_name(TABLE)
        .set_plaintext_structure(Some(test_structured_data()))
        .set_crypto_schema(Some(test_crypto_schema()))
        .cmm(cmm)
        .send()
        .await
        .unwrap_err();
    assert_eq!(calls.lock().unwrap().len(), 1);

    //= spec/structured-encryption/encrypt-path-structure.md#behavior
    //= type=test
    //# If any of these steps fails, this operation MUST halt and indicate a failure to the caller.
    assert_validation(&err, "a keyring, CMM, key store, or cache failed");
    let source = std::error::Error::source(&err).map(ToString::to_string);
    assert!(
        source.is_some_and(|s| s.contains(RECORDING_CMM_FAILURE)),
        "{err:?}"
    );
}

#[tokio::test]
async fn materials_with_a_non_dbe_suite_fail() {
    let err = encrypt_with(OnEncrypt::EsdkMaterials).await;

    //= spec/structured-encryption/encrypt-path-structure.md#retrieve-encryption-materials
    //= type=test
    //# If this algorithm suite is not a
    //# [supported suite for Database Encryption (DBE)](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/algorithm-suites.md#supported-algorithm-suites-enum),
    //# this operation MUST yield an error.
    assert_validation(&err, "the algorithm suite is not a DB-ESDK algorithm suite");
}

/// Encrypt `test_structured_data` with the materials `on_encrypt` returns.
async fn encrypt_with(on_encrypt: OnEncrypt) -> Error {
    let (cmm, _) = recording_cmm(on_encrypt);
    client()
        .encrypt_structure()
        .table_name(TABLE)
        .set_plaintext_structure(Some(test_structured_data()))
        .set_crypto_schema(Some(test_crypto_schema()))
        .cmm(cmm)
        .send()
        .await
        .unwrap_err()
}

#[tokio::test]
async fn materials_without_a_plaintext_data_key_fail() {
    // Adjacent guard for encrypt-path-structure.md#calculate-cipherkey-and-nonce: the FieldRootKey needs the materials' plaintext data key; materials without one are rejected.
    let err = encrypt_with(OnEncrypt::NoPlaintextKey).await;
    assert!(matches!(err, Error::InvalidMaterials(_)), "{err:?}");
    assert!(
        err.message()
            .contains("the materials have no plaintext data key"),
        "{err:?}"
    );
}

#[tokio::test]
async fn materials_context_too_large_for_the_header_fails() {
    // Adjacent guard for encrypt-path-structure.md#header-field: the header must store the materials' encryption context; a context too large to serialize is rejected.
    let err = encrypt_with(OnEncrypt::OversizedContext).await;
    assert_validation(&err, "the materials' encryption context cannot be stored");
}

/// Decrypt the default encrypted structure with the materials `on_decrypt` returns.
async fn decrypt_with_materials(on_decrypt: OnDecrypt) -> Error {
    let (cmm, _) = decrypt_recording_cmm(on_decrypt);
    decrypt_using(
        encrypted_default().await,
        test_authenticate_schema(),
        None,
        cmm,
    )
    .await
    .unwrap_err()
}

#[tokio::test]
async fn decrypt_materials_without_a_plaintext_data_key_fail() {
    // Adjacent guard for decrypt-path-structure.md#calculate-cipherkey-and-nonce: the field keys need the materials' plaintext data key; decryption materials without one are rejected.
    let err = decrypt_with_materials(OnDecrypt::NoPlaintextKey).await;
    assert!(matches!(err, Error::InvalidMaterials(_)), "{err:?}");
    assert!(
        err.message()
            .contains("the materials have no plaintext data key"),
        "{err:?}"
    );
}

#[tokio::test]
async fn decrypt_materials_context_too_large_for_a_header_fails() {
    // Adjacent guard for header.md#encryption-context: the materials' encryption context must be storable in a header; a decryption context too large to serialize is rejected.
    let err = decrypt_with_materials(OnDecrypt::OversizedContext).await;
    assert_validation(&err, "the materials' encryption context cannot be stored");
}

#[tokio::test]
async fn resolve_auth_actions_failures() {
    let data = encrypted_default().await;
    let header = data[HEADER].value().to_vec();
    let item = |name: &str, action| AuthItem::new(path(&[name]), data[name].clone(), action);
    let resolve = |items: Vec<AuthItem>, header: Vec<u8>| {
        client()
            .resolve_auth_actions()
            .table_name(TABLE)
            .set_auth_actions(Some(items))
            .header_bytes(header)
            .send()
    };
    let sign = AuthenticateAction::Sign;
    let unsigned = AuthenticateAction::DoNotSign;
    let all = || {
        vec![
            item("foo", sign),
            item("bar", sign),
            item(HEADER, unsigned),
            item(FOOTER, unsigned),
        ]
    };

    let mut dup = all();
    dup.push(item("foo", sign));
    assert_validation(
        &resolve(dup, header.clone()).await.unwrap_err(),
        "an attribute appears more than once",
    );

    assert_serialization(
        &resolve(all(), header[..10].to_vec()).await.unwrap_err(),
        "the item's header (aws_dbe_head) is too short",
    );

    let no_header = vec![item("foo", sign), item("bar", sign), item(FOOTER, unsigned)];
    assert_validation(
        &resolve(no_header, header.clone()).await.unwrap_err(),
        "the item has no aws_dbe_head attribute",
    );

    let no_footer = vec![item("foo", sign), item("bar", sign), item(HEADER, unsigned)];
    assert_validation(
        &resolve(no_footer, header.clone()).await.unwrap_err(),
        "the item has no aws_dbe_foot attribute",
    );

    let mut extra_signed = all();
    extra_signed.push(item("fizzbuzz", sign));
    assert_serialization(
        &resolve(extra_signed, header).await.unwrap_err(),
        "an attribute written as unsigned is now configured as signed",
    );
}

#[tokio::test]
async fn every_required_input_is_checked() {
    let c = client();
    let encrypt = || {
        c.encrypt_structure()
            .table_name(TABLE)
            .set_plaintext_structure(Some(test_structured_data()))
            .set_crypto_schema(Some(test_crypto_schema()))
            .cmm(cmm())
    };
    let decrypt = || {
        c.decrypt_structure()
            .table_name(TABLE)
            .set_encrypted_structure(Some(test_structured_data()))
            .set_authenticate_schema(Some(test_authenticate_schema()))
            .cmm(cmm())
    };
    let item = || CryptoItem::new(path(&["a"]), blob(), CryptoAction::SignOnly);
    let encrypt_path = || {
        c.encrypt_path_structure()
            .table_name(TABLE)
            .plaintext_structure(item())
            .cmm(cmm())
    };
    let auth = || AuthItem::new(path(&["a"]), blob(), AuthenticateAction::Sign);
    let decrypt_path = || {
        c.decrypt_path_structure()
            .table_name(TABLE)
            .encrypted_structure(auth())
            .cmm(cmm())
    };

    let encrypt_cases: Vec<(&str, Result<(), Error>)> = vec![
        (
            "table_name",
            encrypt().set_table_name(None).send().await.map(drop),
        ),
        (
            "plaintext_structure",
            encrypt()
                .set_plaintext_structure(None)
                .send()
                .await
                .map(drop),
        ),
        (
            "crypto_schema",
            encrypt().set_crypto_schema(None).send().await.map(drop),
        ),
        ("cmm", encrypt().set_cmm(None).send().await.map(drop)),
    ];
    for (name, result) in encrypt_cases {
        let err = result.unwrap_err();

        //= spec/structured-encryption/encrypt-structure.md#input
        //= type=test
        //# The following inputs to this behavior are REQUIRED:
        assert_validation(&err, &format!("{name} is required"));
    }

    let encrypt_path_cases: Vec<(&str, Result<(), Error>)> = vec![
        (
            "table_name",
            encrypt_path().set_table_name(None).send().await.map(drop),
        ),
        (
            "plaintext_structure",
            encrypt_path()
                .set_plaintext_structure(None)
                .send()
                .await
                .map(drop),
        ),
        ("cmm", encrypt_path().set_cmm(None).send().await.map(drop)),
    ];
    for (name, result) in encrypt_path_cases {
        let err = result.unwrap_err();

        //= spec/structured-encryption/encrypt-path-structure.md#input
        //= type=test
        //# The following inputs to this behavior are REQUIRED:
        assert_validation(&err, &format!("{name} is required"));
    }

    let decrypt_cases: Vec<(&str, Result<(), Error>)> = vec![
        (
            "table_name",
            decrypt().set_table_name(None).send().await.map(drop),
        ),
        (
            "encrypted_structure",
            decrypt()
                .set_encrypted_structure(None)
                .send()
                .await
                .map(drop),
        ),
        (
            "authenticate_schema",
            decrypt()
                .set_authenticate_schema(None)
                .send()
                .await
                .map(drop),
        ),
        ("cmm", decrypt().set_cmm(None).send().await.map(drop)),
    ];
    for (name, result) in decrypt_cases {
        let err = result.unwrap_err();

        //= spec/structured-encryption/decrypt-structure.md#input
        //= type=test
        //# The following inputs to this behavior are REQUIRED:
        assert_validation(&err, &format!("{name} is required"));
    }

    let decrypt_path_cases: Vec<(&str, Result<(), Error>)> = vec![
        (
            "table_name",
            decrypt_path().set_table_name(None).send().await.map(drop),
        ),
        (
            "encrypted_structure",
            decrypt_path()
                .set_encrypted_structure(None)
                .send()
                .await
                .map(drop),
        ),
        ("cmm", decrypt_path().set_cmm(None).send().await.map(drop)),
    ];
    for (name, result) in decrypt_path_cases {
        let err = result.unwrap_err();

        //= spec/structured-encryption/decrypt-path-structure.md#input
        //= type=test
        //# The following inputs to this behavior are REQUIRED:
        assert_validation(&err, &format!("{name} is required"));
    }
}

#[tokio::test]
async fn resolve_auth_actions_requires_every_input() {
    let header = encrypted_default().await[HEADER].value().to_vec();
    let resolve = || {
        client()
            .resolve_auth_actions()
            .table_name(TABLE)
            .auth_actions(AuthItem::new(
                path(&["a"]),
                blob(),
                AuthenticateAction::Sign,
            ))
            .header_bytes(header.clone())
    };
    let cases = [
        ("table_name", resolve().set_table_name(None)),
        ("auth_actions", resolve().set_auth_actions(None)),
        ("header_bytes", resolve().set_header_bytes(None)),
    ];
    for (name, builder) in cases {
        let err = builder.send().await.unwrap_err();

        //= spec/structured-encryption/resolve-auth-actions.md#input
        //= type=test
        //# The following inputs to this behavior are REQUIRED:
        assert_validation(&err, &format!("{name} is required"));
    }
}

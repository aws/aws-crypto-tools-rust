// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Structured encryption failures: tampered headers, footers, and fields,
//! encryption context mismatches, and every input validation error.

mod structured_api_support;

use std::collections::HashMap;

use aws_db_esdk::Error;
use aws_db_esdk::structured::{
    AuthItem, AuthenticateAction, CryptoItem, Path, PathSegment, StructuredDataTerminal,
};
use aws_db_esdk::types::{AlgorithmSuiteId, CryptoAction, EncryptionContext};
use structured_api_support::{
    BOOLEAN, FOOTER, HEADER, NUMBER, STRING, TABLE, blob, client, cmm, cmm_with_key,
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
    client()
        .decrypt_structure()
        .table_name(TABLE)
        .set_encrypted_structure(Some(data))
        .set_authenticate_schema(Some(schema))
        .cmm(cmm())
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
    assert_cryptographic(
        &err,
        "the item's header (aws_dbe_head) failed its key commitment check: the header was changed, or the data key is not the one it was written with",
    );
}

#[tokio::test]
async fn tampered_header_version_and_flavor_fail_to_parse() {
    let data = with_value(encrypted_default().await, HEADER, |v| v[0] = 3);
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
    assert_cryptographic(&err, "Signature of record does not match");
}

#[tokio::test]
async fn tampered_sign_only_field_fails() {
    let data = with_value(encrypted_default().await, "bar", |v| v[0] ^= 1);
    let err = decrypt(data).await.unwrap_err();
    assert_cryptographic(&err, "Signature of record does not match");
}

#[tokio::test]
async fn changed_do_nothing_field_is_not_checked() {
    let data = with_value(encrypted_default().await, "fizzbuzz", |v| v[0] ^= 1);
    let out = decrypt(data).await.unwrap();
    let mut expected = blob().into_value();
    expected[0] ^= 1;
    assert_eq!(out["fizzbuzz"].value(), expected.as_slice());
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
    assert_validation(&err, "overlaps with Item Encryptor encryption context");
}

#[tokio::test]
async fn schema_change_is_detected_from_the_legend() {
    let mut schema = test_authenticate_schema();
    schema.insert("fizzbuzz".to_owned(), AuthenticateAction::Sign);
    let err = decrypt_with(encrypted_default().await, schema, None)
        .await
        .unwrap_err();
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
    assert_validation(&err, "have the same keys");

    let mut schema = test_authenticate_schema();
    schema.remove("fizzbuzz");
    let err = decrypt_with(encrypted_default().await, schema, None)
        .await
        .unwrap_err();
    assert_validation(&err, "have the same keys");
}

#[tokio::test]
async fn decrypt_header_and_footer_must_be_present_binary_and_unsigned() {
    for field in [HEADER, FOOTER] {
        let mut data = encrypted_default().await;
        data.remove(field);
        let mut schema = test_authenticate_schema();
        schema.remove(field);
        let err = decrypt_with(data, schema, None).await.unwrap_err();
        assert_serialization(&err, &format!("the item has no {field} attribute"));

        let data = encrypted_default().await;
        let mut data_wrong_type = data.clone();
        let value = data_wrong_type.remove(field).unwrap().into_value();
        data_wrong_type.insert(field.to_owned(), StructuredDataTerminal::new(STRING, value));
        let err = decrypt(data_wrong_type).await.unwrap_err();
        assert_serialization(
            &err,
            &format!("the item's {field} attribute must be binary"),
        );

        let mut schema = test_authenticate_schema();
        schema.insert(field.to_owned(), AuthenticateAction::Sign);
        let err = decrypt_with(data, schema, None).await.unwrap_err();
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
    assert_validation(&err, "an attribute appears more than once");
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
        assert_validation(&err, "are reserved.");
    }
}

#[tokio::test]
async fn encrypt_rejects_duplicate_paths() {
    let item = CryptoItem::new(path(&["a"]), blob(), CryptoAction::SignOnly);
    let err = encrypt_path(vec![item.clone(), item], None).await;
    assert_validation(&err, "an attribute appears more than once");
}

#[tokio::test]
async fn encrypt_rejects_reserved_encryption_context_values() {
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
        assert_validation(
            &err,
            "the item's attributes do not match the attribute actions: each attribute needs exactly one action",
        );
    }
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
    let resolve = || {
        c.resolve_auth_actions()
            .table_name(TABLE)
            .auth_actions(auth())
            .header_bytes(vec![0u8; 4])
    };

    let cases: Vec<(&str, Result<(), Error>)> = vec![
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
        (
            "table_name",
            resolve().set_table_name(None).send().await.map(drop),
        ),
        (
            "auth_actions",
            resolve().set_auth_actions(None).send().await.map(drop),
        ),
        (
            "header_bytes",
            resolve().set_header_bytes(None).send().await.map(drop),
        ),
    ];
    for (name, result) in cases {
        let err = result.unwrap_err();
        assert_validation(&err, &format!("{name} is required"));
    }
}

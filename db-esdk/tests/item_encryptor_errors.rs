// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! `ItemEncryptor` input errors, plaintext policies, tampering, and keyring failures.

mod item_encryptor_support;

use aws_db_esdk::async_trait;
use aws_db_esdk::aws_sdk_dynamodb::primitives::Blob;
use aws_db_esdk::aws_sdk_dynamodb::types::AttributeValue;
use aws_db_esdk::keyring::{
    Keyring, OnDecryptInput, OnDecryptOutput, OnEncryptInput, OnEncryptOutput,
};
use aws_db_esdk::mpl::Error as MplError;
use aws_db_esdk::types::{AlgorithmSuiteId, CryptoAction, PlaintextOverride};
use aws_db_esdk::{Error, ItemEncryptor, ParsedHeader};
use item_encryptor_support::*;

async fn encrypt(encryptor: &ItemEncryptor, input: Item) -> Result<Item, Error> {
    encryptor
        .encrypt_item()
        .plaintext_item(input)
        .send()
        .await
        .map(|o| o.into_encrypted_item())
}

async fn decrypt(encryptor: &ItemEncryptor, input: Item) -> Result<Item, Error> {
    encryptor
        .decrypt_item()
        .encrypted_item(input)
        .send()
        .await
        .map(|o| o.into_plaintext_item())
}

fn validation_message(result: Result<Item, Error>) -> String {
    match result {
        Err(Error::Validation(e)) => e.message().to_owned(),
        other => panic!("expected a Validation error, got {other:?}"),
    }
}

fn serialization_message(result: Result<Item, Error>) -> String {
    match result {
        Err(Error::Serialization(e)) => e.message().to_owned(),
        other => panic!("expected a Serialization error, got {other:?}"),
    }
}

async fn encrypted_v1_item() -> Item {
    encrypt(&default_encryptor(), v1_item()).await.unwrap()
}

fn binary(item: &Item, name: &str) -> Vec<u8> {
    match &item[name] {
        AttributeValue::B(b) => b.as_ref().to_vec(),
        other => panic!("{name} is not binary: {other:?}"),
    }
}

#[test]
fn build_requires_a_table() {
    let err = ItemEncryptor::builder().build().unwrap_err();

    //= spec/dynamodb-encryption-client/ddb-item-encryptor.md#initialization
    //= type=test
    //# On initialization of the DynamoDB Item Encryptor
    //# the caller MUST provide:
    assert!(
        matches!(&err, Error::Validation(e) if e.message() == "table is required"),
        "{err:?}"
    );
}

#[tokio::test]
async fn encrypt_requires_item() {
    let err = default_encryptor()
        .encrypt_item()
        .set_plaintext_item(None)
        .send()
        .await;

    //= spec/dynamodb-encryption-client/encrypt-item.md#input
    //= type=test
    //# The following inputs to this behavior are REQUIRED:
    assert_eq!(
        validation_message(err.map(|o| o.into_encrypted_item())),
        "plaintext_item is required"
    );
}

#[tokio::test]
async fn encrypt_rejects_unconfigured_attribute() {
    let mut input = v1_item();
    input.insert("unknown".to_owned(), s("other"));

    //= spec/dynamodb-encryption-client/encrypt-item.md#behavior
    //= type=test
    //# The [Attributes Actions](./ddb-table-encryption-config.md#attribute-actions)
    //# configured on this Item Encryptor MUST specify a Crypto Action
    //# for every attribute in the [input DynamoDB Item](#dynamodb-item)
    //# (Attribute Actions MAY specify a Crypto Action for an attribute not
    //# in the input DynamoDB Item).
    assert_eq!(
        validation_message(encrypt(&default_encryptor(), input).await),
        "No Crypto Action configured for attribute unknown"
    );
}

#[tokio::test]
async fn encrypt_rejects_missing_sort_key() {
    let encryptor = encryptor_from(
        config_builder(v1_actions())
            .sort_key_name("sort")
            .attribute_actions_on_encrypt("sort", CryptoAction::SignOnly),
    );
    let input = item([
        ("bar", s("key")),
        ("encrypt", s("foo")),
        ("sign", s("bar")),
        ("nothing", s("baz")),
    ]);

    //= spec/dynamodb-encryption-client/encrypt-item.md#dynamodb-item
    //= type=test
    //# If the [DynamoDB Item Encryptor](./ddb-item-encryptor.md)
    //# has a [DynamoDB Sort Key Name](./ddb-table-encryption-config.md#dynamodb-sort-key-name) configured,
    //# this item MUST include an Attribute with that name.
    assert_eq!(
        validation_message(encrypt(&encryptor, input).await),
        "On Encrypt : Sort key 'sort' does not exist in item. Item contains these attributes : bar encrypt nothing sign."
    );
}

#[tokio::test]
async fn encrypt_rejects_missing_context_attribute() {
    let encryptor = encryptor_from(config_builder(v2_actions()));
    let input = item([
        ("bar", s("key")),
        ("encrypt", s("text")),
        ("nothing", s("baz")),
    ]);

    //= spec/dynamodb-encryption-client/encrypt-item.md#dynamodb-item
    //= type=test
    //# If the [DynamoDB Item Encryptor](./ddb-item-encryptor.md)
    //# has any attribute configured as
    //# [SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT](../structured-encryption/structures.md#contextandsign)
    //# then this item MUST include an Attribute with that name.
    assert_eq!(
        validation_message(encrypt(&encryptor, input).await),
        "Attribute sign was configured with SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT but was not present in item to be encrypted."
    );
}

#[tokio::test]
async fn encrypt_rejects_attribute_name_over_65535_characters() {
    // The attribute name limit is a ddb-item-conversion.md requirement, outside this file's specs.
    let mut input = v1_item();
    input.insert("a".repeat(65_536), s("x"));
    assert_eq!(
        validation_message(encrypt(&default_encryptor(), input).await),
        "plaintext_item has an attribute name longer than 65535 characters"
    );
}

#[tokio::test]
async fn encrypt_rejects_invalid_number() {
    // Number validation is a ddb-attribute-serialization.md requirement, outside this file's specs.
    let mut input = v1_item();
    input.insert(
        "sign".to_owned(),
        AttributeValue::N("not a number".to_owned()),
    );
    let err = encrypt(&default_encryptor(), input).await.unwrap_err();
    assert!(matches!(err, Error::Validation(_)), "{err:?}");
}

#[tokio::test]
async fn decrypt_requires_item() {
    let err = default_encryptor()
        .decrypt_item()
        .set_encrypted_item(None)
        .send()
        .await;

    //= spec/dynamodb-encryption-client/decrypt-item.md#input
    //= type=test
    //# The following inputs to this behavior are REQUIRED:
    assert_eq!(
        validation_message(err.map(|o| o.into_plaintext_item())),
        "encrypted_item is required"
    );
}

#[tokio::test]
async fn decrypt_rejects_missing_partition_key() {
    let mut encrypted = encrypted_v1_item().await;
    encrypted.remove("bar");

    //= spec/dynamodb-encryption-client/decrypt-item.md#input-dynamodb-item
    //= type=test
    //# This item MUST include an Attribute with a name that matches the
    //# [DynamoDB Partition Key Name](./ddb-table-encryption-config.md#dynamodb-partition-key-name)
    //# configured on the [DynamoDB Item Encryptor](./ddb-item-encryptor.md).
    //
    //= spec/dynamodb-encryption-client/decrypt-item.md#input-dynamodb-item
    //= type=test
    //# Otherwise this operation MUST yield an error.
    assert_eq!(
        validation_message(decrypt(&default_encryptor(), encrypted).await),
        "On Decrypt : Partition key 'bar' does not exist in item. Item contains these attributes : aws_dbe_foot aws_dbe_head encrypt nothing sign."
    );
}

fn with_header(encrypted: &Item, header: Option<AttributeValue>) -> Item {
    let mut item = encrypted.clone();
    match header {
        Some(h) => item.insert(HEADER.to_owned(), h),
        None => item.remove(HEADER),
    };
    item
}

#[tokio::test]
async fn decrypt_rejects_malformed_header_attribute() {
    let encrypted = encrypted_v1_item().await;
    let encryptor = default_encryptor();

    let item = with_header(&encrypted, None);

    //= spec/dynamodb-encryption-client/decrypt-item.md#dynamodb-item-base-context
    //= type=test
    //# The item to be encrypted MUST have an attribute named `aws_dbe_head`.
    assert_eq!(
        serialization_message(decrypt(&encryptor, item).await),
        "the item has no aws_dbe_head attribute"
    );

    let item = with_header(&encrypted, Some(s("text")));

    //= spec/dynamodb-encryption-client/decrypt-item.md#dynamodb-item-base-context
    //= type=test
    //# The attribute named `aws_dbe_head` MUST be of type `B` Binary.
    assert_eq!(
        serialization_message(decrypt(&encryptor, item).await),
        "the item's aws_dbe_head attribute is not binary"
    );

    let item = with_header(&encrypted, Some(AttributeValue::B(Blob::new(Vec::new()))));
    // There is no first byte to read the Version Number from.
    assert_eq!(
        serialization_message(decrypt(&encryptor, item).await),
        "the item's aws_dbe_head attribute is empty"
    );

    let item = with_header(&encrypted, Some(AttributeValue::B(Blob::new(vec![3]))));

    //= spec/dynamodb-encryption-client/decrypt-item.md#dynamodb-item-base-context
    //= type=test
    //# If the Version Number is not 1 or 2, the operation MUST return an error.
    assert_eq!(
        serialization_message(decrypt(&encryptor, item).await),
        "the item's aws_dbe_head attribute has an unknown version"
    );
}

fn encryptor_with(policy: PlaintextOverride) -> ItemEncryptor {
    encryptor_from(config_builder(v1_actions()).plaintext_override(policy))
}

#[tokio::test]
async fn default_policy_rejects_plaintext_items() {
    let err = decrypt(&default_encryptor(), v1_item()).await;

    //= spec/dynamodb-encryption-client/decrypt-item.md#determining-plaintext-items
    //= type=test
    //# An item MUST be determined to be plaintext if it does not contain
    //# attributes with the names "aws_dbe_head" and "aws_dbe_foot".
    assert_eq!(
        serialization_message(err),
        "Encrypted item missing expected header and footer attributes"
    );
    let err = decrypt(
        &encryptor_with(PlaintextOverride::ForbidPlaintextWriteForbidPlaintextRead),
        v1_item(),
    )
    .await;
    assert_eq!(
        serialization_message(err),
        "Encrypted item missing expected header and footer attributes"
    );
}

#[tokio::test]
async fn force_plaintext_write_writes_items_unchanged() {
    let encryptor = encryptor_with(PlaintextOverride::ForcePlaintextWriteAllowPlaintextRead);
    let out = encryptor
        .encrypt_item()
        .plaintext_item(v1_item())
        .send()
        .await
        .unwrap();
    assert!(out.parsed_header().is_none());
    assert_eq!(
        out.algorithm_suite_id(),
        AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384SymsigHmacSha384
    );

    //= spec/dynamodb-encryption-client/encrypt-item.md#behavior
    //= type=test
    //# If a [Plaintext Policy](./ddb-table-encryption-config.md#plaintext-policy) of
    //# `FORCE_PLAINTEXT_WRITE_ALLOW_PLAINTEXT_READ` is specified,
    //# this operation MUST NOT encrypt the input item,
    //# and MUST passthrough that item as the output.
    assert_eq!(out.encrypted_item(), &v1_item());

    let suite = AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeySymsigHmacSha384;
    let configured = encryptor_from(
        config_builder(v1_actions())
            .plaintext_override(PlaintextOverride::ForcePlaintextWriteAllowPlaintextRead)
            .algorithm_suite_id(suite),
    );
    let out = configured
        .encrypt_item()
        .plaintext_item(v1_item())
        .send()
        .await
        .unwrap();
    assert_eq!(out.algorithm_suite_id(), suite);
}

#[tokio::test]
async fn force_plaintext_write_still_validates_the_item() {
    let encryptor = encryptor_with(PlaintextOverride::ForcePlaintextWriteAllowPlaintextRead);
    let mut input = v1_item();
    input.remove("bar");
    let msg = validation_message(encrypt(&encryptor, input).await);

    //= spec/dynamodb-encryption-client/encrypt-item.md#dynamodb-item
    //= type=test
    //# This item MUST include an Attribute with a name that matches the
    //# [DynamoDB Partition Key Name](./ddb-table-encryption-config.md#dynamodb-partition-key-name)
    //# configured on the [DynamoDB Item Encryptor](./ddb-item-encryptor.md).
    //
    //= spec/dynamodb-encryption-client/encrypt-item.md#dynamodb-item
    //= type=test
    //# Otherwise this operation MUST yield an error.
    assert!(
        msg.starts_with("On Encrypt : Partition key 'bar' does not exist in item."),
        "{msg}"
    );
}

#[tokio::test]
async fn allow_plaintext_read_reads_plaintext_and_encrypted_items() {
    let ciphertext = encrypted_v1_item().await;
    for policy in [
        PlaintextOverride::ForcePlaintextWriteAllowPlaintextRead,
        PlaintextOverride::ForbidPlaintextWriteAllowPlaintextRead,
    ] {
        let encryptor = encryptor_with(policy);
        let out = encryptor
            .decrypt_item()
            .encrypted_item(v1_item())
            .send()
            .await
            .unwrap();
        assert!(out.parsed_header().is_none());

        //= spec/dynamodb-encryption-client/decrypt-item.md#behavior
        //= type=test
        //# If a [Plaintext Policy](./ddb-table-encryption-config.md#plaintext-policy) of
        //# `FORCE_PLAINTEXT_WRITE_ALLOW_PLAINTEXT_READ` or `FORBID_PLAINTEXT_WRITE_ALLOW_PLAINTEXT_READ` is specified,
        //# and the input item [is a plaintext item](#determining-plaintext-items)
        //# this operation MUST NOT decrypt the input item,
        //# and MUST passthrough that item as the output.
        assert_eq!(out.plaintext_item(), &v1_item());
        let out = encryptor
            .decrypt_item()
            .encrypted_item(ciphertext.clone())
            .send()
            .await
            .unwrap();

        //= spec/dynamodb-encryption-client/decrypt-item.md#output
        //= type=test
        //# This operation MUST also output a [Parsed Header](#parsed-header) if the following is true:
        assert_eq!(
            out.parsed_header().map(ParsedHeader::algorithm_suite_id),
            Some(DEFAULT_SUITE)
        );
        assert_eq!(out.plaintext_item(), &v1_item());
    }
}

#[tokio::test]
async fn forbid_plaintext_write_allow_read_encrypts() {
    let encryptor = encryptor_with(PlaintextOverride::ForbidPlaintextWriteAllowPlaintextRead);
    let out = encrypt(&encryptor, v1_item()).await.unwrap();
    assert!(out.contains_key(HEADER) && out.contains_key(FOOTER));
    assert_ne!(out["encrypt"], v1_item()["encrypt"]);
}

#[tokio::test]
async fn tampered_signed_attribute_fails() {
    let mut item = encrypted_v1_item().await;
    item.insert("sign".to_owned(), s("tampered"));
    let err = decrypt(&default_encryptor(), item).await.unwrap_err();

    //= spec/dynamodb-encryption-client/decrypt-item.md#behavior
    //= type=test
    //= reason=A changed signed attribute fails verification, so the schema gave it SIGN
    //# - For every Attribute in the [input DynamoDB Item](#input-dynamodb-item)
    //# that is in the [signature scope](#signature-scope),
    //# there MUST exist a [SIGN Authenticate Action](../structured-encryption/structures.md#sign)
    //# in the Authenticate Schema,
    //# string indexed at the top level by that attribute name.
    assert!(matches!(err, Error::Cryptographic(_)), "{err:?}");
}

#[tokio::test]
async fn tampered_encrypted_attribute_fails() {
    let mut item = encrypted_v1_item().await;
    let mut ct = binary(&item, "encrypt");
    *ct.last_mut().unwrap() ^= 1;
    item.insert("encrypt".to_owned(), AttributeValue::B(Blob::new(ct)));
    let err = decrypt(&default_encryptor(), item).await.unwrap_err();

    //= spec/dynamodb-encryption-client/decrypt-item.md#behavior
    //= type=test
    //= reason=A flipped ciphertext byte in the item fails, so the item's own attributes are decrypted
    //# - Encrypted Structured Data MUST be the Structured Data converted above.
    assert!(matches!(err, Error::Cryptographic(_)), "{err:?}");
}

#[tokio::test]
async fn removed_signed_attribute_fails() {
    let mut item = encrypted_v1_item().await;
    item.remove("sign");

    //= spec/dynamodb-encryption-client/decrypt-item.md#behavior
    //= type=test
    //= reason=The schema has one action per item attribute, so the header's signed attribute is unmatched
    //# - The number of Authenticate Actions in the Authenticate Schema
    //# MUST EQUAL the number of Attributes on the [input DynamoDB Item](#input-dynamodb-item).
    assert_eq!(
        serialization_message(decrypt(&default_encryptor(), item).await),
        "the attribute actions do not match the item: an attribute written as signed is now configured as unsigned"
    );
}

#[tokio::test]
async fn added_signed_attribute_fails() {
    let mut item = encrypted_v1_item().await;
    item.insert("sign2".to_owned(), s("added"));

    //= spec/dynamodb-encryption-client/decrypt-item.md#signature-scope
    //= type=test
    //= reason=sign2 is not unauthenticated, so it is signed, and the header does not cover it
    //# Otherwise, Attributes MUST be considered as within the signature scope.
    assert_eq!(
        serialization_message(decrypt(&default_encryptor(), item).await),
        "the attribute actions do not match the item: an attribute written as unsigned is now configured as signed"
    );
}

#[tokio::test]
async fn tampered_header_or_footer_fails() {
    let encrypted = encrypted_v1_item().await;
    for field in [HEADER, FOOTER] {
        let mut bytes = binary(&encrypted, field);
        *bytes.last_mut().unwrap() ^= 1;
        let mut item = encrypted.clone();
        item.insert(field.to_owned(), AttributeValue::B(Blob::new(bytes)));
        let err = decrypt(&default_encryptor(), item).await.unwrap_err();

        //= spec/dynamodb-encryption-client/decrypt-item.md#behavior
        //= type=test
        //= reason=A flipped header or footer byte fails structured-encryption verification
        //# Given the converted [Structured Data](../structured-encryption/structures.md#structured-data),
        //# this operation MUST delegate decryption of this data to
        //# Structured Encryption Client's [Decrypt Structure](../structured-encryption/encrypt-structure.md),
        //# with the following inputs:
        assert!(matches!(err, Error::Cryptographic(_)), "{field}: {err:?}");
    }
}

#[tokio::test]
async fn unsigned_attribute_may_change() {
    let mut item = encrypted_v1_item().await;
    item.insert("nothing".to_owned(), s("changed"));
    let out = decrypt(&default_encryptor(), item).await.unwrap();
    let mut expected = v1_item();
    expected.insert("nothing".to_owned(), s("changed"));

    //= spec/dynamodb-encryption-client/decrypt-item.md#behavior
    //= type=test
    //= reason=A changed unauthenticated attribute still verifies, so the schema gave it DO_NOT_SIGN
    //# - For every Attribute in the [input DynamoDB Item](#input-dynamodb-item)
    //# that is not in the [signature scope](#signature-scope),
    //# there MUST exist a [DO_NOT_SIGN Authenticate Action](../structured-encryption/structures.md#do_not_sign)
    //# in the Authenticate Schema,
    //# string indexed at the top level by that attribute name.
    assert_eq!(out, expected);
}

#[tokio::test]
async fn wrong_wrapping_key_fails() {
    // Keyring behavior belongs to the Material Providers Library; nothing here to cite.
    let other = encryptor_from(config_builder(v1_actions()).keyring(keyring_with_key(vec![1; 32])));
    let err = decrypt(&other, encrypted_v1_item().await)
        .await
        .unwrap_err();
    // The raw AES keyring finds its own data key, but the tag does not verify.
    assert!(matches!(err, Error::Cryptographic(_)), "{err:?}");
    assert!(!err.is_retryable());
}

struct FailingKeyring;

#[async_trait]
impl Keyring for FailingKeyring {
    async fn on_encrypt(&self, _: OnEncryptInput) -> Result<OnEncryptOutput, MplError> {
        Err(MplError::invalid_materials("encrypt refused"))
    }

    async fn on_decrypt(&self, _: OnDecryptInput) -> Result<OnDecryptOutput, MplError> {
        Err(MplError::no_matching_data_key("decrypt refused"))
    }
}

#[tokio::test]
async fn keyring_errors_keep_their_variant() {
    // Error variants are this crate's API, not a requirement of these specs.
    let failing = encryptor_from(config_builder(v1_actions()).keyring(FailingKeyring));
    let err = encrypt(&failing, v1_item()).await.unwrap_err();
    assert!(matches!(err, Error::InvalidMaterials(_)), "{err:?}");
    let err = decrypt(&failing, encrypted_v1_item().await)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::NoMatchingDataKey(_)), "{err:?}");
}

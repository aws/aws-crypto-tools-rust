// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! `ItemEncryptor::encrypt_item`: its inputs, what it passes to the CMM, and its output.

mod item_encryptor_support;

use std::collections::BTreeSet;

use aws_db_esdk::aws_sdk_dynamodb::types::AttributeValue;
use aws_db_esdk::types::{AlgorithmSuiteId, CryptoAction};
use aws_db_esdk::{EncryptItemOutput, Error, ItemEncryptor, ParsedHeader};
use item_encryptor_support::*;

async fn encrypt(encryptor: &ItemEncryptor, input: Item) -> EncryptItemOutput {
    encryptor
        .encrypt_item()
        .plaintext_item(input)
        .send()
        .await
        .unwrap()
}

async fn encrypt_error(encryptor: &ItemEncryptor, input: Item) -> String {
    let result = encryptor.encrypt_item().plaintext_item(input).send().await;
    match result {
        Err(Error::Validation(e)) => e.message().to_owned(),
        other => panic!("expected a Validation error, got {other:?}"),
    }
}

#[tokio::test]
async fn encrypt_rejects_missing_partition_key() {
    let mut input = v1_item();
    input.remove("bar");
    let result = default_encryptor()
        .encrypt_item()
        .plaintext_item(input)
        .send()
        .await;
    let Err(Error::Validation(e)) = result else {
        panic!("expected a Validation error, got {result:?}");
    };

    //= spec/dynamodb-encryption-client/encrypt-item.md#dynamodb-item
    //= type=test
    //# This item MUST include an Attribute with a name that matches the
    //# [DynamoDB Partition Key Name](./ddb-table-encryption-config.md#dynamodb-partition-key-name)
    //# configured on the [DynamoDB Item Encryptor](./ddb-item-encryptor.md).
    assert!(
        e.message()
            .starts_with("On Encrypt : Partition key 'bar' does not exist in item."),
        "{}",
        e.message()
    );

    //= spec/dynamodb-encryption-client/encrypt-item.md#dynamodb-item
    //= type=test
    //# Otherwise this operation MUST yield an error.
    assert_eq!(
        e.message(),
        "On Encrypt : Partition key 'bar' does not exist in item. Item contains these attributes : encrypt nothing sign."
    );
}

#[tokio::test]
async fn encrypt_rejects_missing_partition_and_sort_key() {
    let encryptor = encryptor_from(
        config_builder(v1_actions())
            .sort_key_name("sort")
            .attribute_actions_on_encrypt("sort", CryptoAction::SignOnly),
    );
    let msg = encrypt_error(&encryptor, Item::new()).await;

    //= spec/dynamodb-encryption-client/encrypt-item.md#dynamodb-item
    //= type=test
    //# If the [DynamoDB Item Encryptor](./ddb-item-encryptor.md)
    //# has a [DynamoDB Sort Key Name](./ddb-table-encryption-config.md#dynamodb-sort-key-name) configured,
    //# this item MUST include an Attribute with that name.
    assert_eq!(
        msg,
        "On Encrypt : Partition key 'bar' does not exist in item. Sort key 'sort' does not exist in item. Item contains these attributes : item is empty."
    );
}

#[tokio::test]
async fn encrypt_lists_every_unconfigured_attribute_sorted() {
    let mut input = v1_item();
    input.insert("zz".to_owned(), s("1"));
    input.insert("aa".to_owned(), s("2"));
    let msg = encrypt_error(&default_encryptor(), input).await;

    //= spec/dynamodb-encryption-client/encrypt-item.md#behavior
    //= type=test
    //# The [Attributes Actions](./ddb-table-encryption-config.md#attribute-actions)
    //# configured on this Item Encryptor MUST specify a Crypto Action
    //# for every attribute in the [input DynamoDB Item](#dynamodb-item)
    //# (Attribute Actions MAY specify a Crypto Action for an attribute not
    //# in the input DynamoDB Item).
    assert_eq!(
        msg,
        "No Crypto Action configured for attribute aa\nNo Crypto Action configured for attribute zz"
    );
}

#[tokio::test]
async fn encrypt_lists_every_missing_context_attribute() {
    let mut acts = v2_actions();
    acts.insert(
        "sign2".to_owned(),
        CryptoAction::SignAndIncludeInEncryptionContext,
    );
    let encryptor = encryptor_from(config_builder(acts));
    let msg = encrypt_error(&encryptor, item([("bar", s("key"))])).await;

    //= spec/dynamodb-encryption-client/encrypt-item.md#dynamodb-item
    //= type=test
    //# If the [DynamoDB Item Encryptor](./ddb-item-encryptor.md)
    //# has any attribute configured as
    //# [SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT](../structured-encryption/structures.md#contextandsign)
    //# then this item MUST include an Attribute with that name.
    assert_eq!(
        msg,
        "These attributes were configured with SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT but were not present in item to be encrypted.sign,sign2"
    );
}

#[tokio::test]
async fn encrypt_outputs_the_encrypted_item() {
    let out = encrypt(&default_encryptor(), v1_item()).await;
    let item = out.encrypted_item();

    //= spec/dynamodb-encryption-client/encrypt-item.md#output
    //= type=test
    //# This operation MUST output the following:
    assert!(item.contains_key(HEADER) && item.contains_key(FOOTER));
    let AttributeValue::B(head) = &item[HEADER] else {
        panic!("header not binary");
    };

    //= spec/dynamodb-encryption-client/encrypt-item.md#behavior
    //= type=test
    //= reason=The output has a version 1 structured-encryption header and a ciphertext attribute
    //# Given the converted [Structured Data](../structured-encryption/structures.md#structured-data),
    //# this operation MUST delegate encryption of this data to
    //# Structured Encryption Client's [Encrypt Structure](../structured-encryption/encrypt-structure.md),
    //# with the following inputs:
    assert_eq!(head.as_ref()[0], 1);
    assert!(matches!(&item["encrypt"], AttributeValue::B(_)));
    assert_ne!(item["encrypt"], v1_item()["encrypt"]);
}

#[tokio::test]
async fn encrypt_outputs_a_parsed_header() {
    let out = encrypt(&default_encryptor(), v1_item()).await;

    //= spec/dynamodb-encryption-client/encrypt-item.md#output
    //= type=test
    //# This operation MUST also output a [Parsed Header](#parsed-header) if the following is true:
    assert_eq!(
        out.parsed_header().map(ParsedHeader::algorithm_suite_id),
        Some(DEFAULT_SUITE)
    );
}

#[tokio::test]
async fn encrypt_parsed_header_describes_the_header() {
    let out = encrypt(&default_encryptor(), v1_item()).await;
    let header = out.parsed_header().unwrap();
    let AttributeValue::B(head) = &out.encrypted_item()[HEADER] else {
        panic!("header not binary");
    };
    let stored: Vec<String> = aws_db_esdk::describe_header_encrypted_data_keys(head.as_ref())
        .unwrap()
        .iter()
        .map(|d| d.key_provider_id().to_owned())
        .collect();
    let parsed: Vec<String> = header
        .encrypted_data_keys()
        .iter()
        .map(|k| k.key_provider_id().to_owned())
        .collect();

    //= spec/dynamodb-encryption-client/encrypt-item.md#parsed-header
    //= type=test
    //# This structure MUST contain the following values,
    //# representing the deserialized form of the header of the input encrypted structure:
    assert_eq!(header.algorithm_suite_id(), DEFAULT_SUITE);
    assert_eq!(parsed, ["foo"]);
    assert_eq!(parsed, stored);

    //= spec/dynamodb-encryption-client/encrypt-item.md#behavior
    //= type=test
    //# - Crypto Schema MUST be a [Crypto Schema](../structured-encryption/structures.md#crypto-schema)
    //# analogous to the [configured Attribute Actions](./ddb-table-encryption-config.md#attribute-actions).
    assert_eq!(
        header.attribute_actions_on_encrypt(),
        &actions([
            ("bar", CryptoAction::SignOnly),
            ("encrypt", CryptoAction::EncryptAndSign),
            ("sign", CryptoAction::SignOnly),
        ])
    );
    // The selector context is the item key that a branch key ID supplier sees.
    assert_eq!(header.selector_context(), &item([("bar", s("key"))]));
}

#[tokio::test]
async fn encrypt_wraps_the_cmm_in_a_required_context_cmm() {
    let spy = SpyCmm::new();
    encrypt(&spy.encryptor(), v1_item()).await;
    let input = spy.last_encrypt();
    let expected: BTreeSet<String> = v1_base_context().into_keys().collect();

    //= spec/dynamodb-encryption-client/encrypt-item.md#behavior
    //= type=test
    //= reason=Only the required encryption context CMM sets the required keys the underlying CMM sees
    //# This operation MUST create a
    //# [Required Encryption Context CMM](https://github.com/awslabs/private-aws-encryption-sdk-specification-staging/blob/dafny-verified/framework/required-encryption-context-cmm.md)
    //# with the following inputs:
    //
    //= spec/dynamodb-encryption-client/encrypt-item.md#behavior
    //= type=test
    //= reason=The configured CMM sees these keys only when reached through the required-context CMM
    //# - The CMM MUST be the CMM created above.
    assert_eq!(input.required_encryption_context_keys(), &expected);
}

#[tokio::test]
async fn encrypt_encrypts_the_converted_item() {
    let encryptor = default_encryptor();
    let out = encrypt(&encryptor, v1_item()).await;
    assert_ne!(out.encrypted_item()["encrypt"], v1_item()["encrypt"]);
    let decrypted = encryptor
        .decrypt_item()
        .encrypted_item(out.into_encrypted_item())
        .send()
        .await
        .unwrap();

    //= spec/dynamodb-encryption-client/encrypt-item.md#behavior
    //= type=test
    //= reason=Decrypting the ciphertext yields the input item, so the converted item was encrypted
    //# - Structured Data MUST be the Structured Data converted above.
    assert_eq!(decrypted.plaintext_item(), &v1_item());
}

#[tokio::test]
async fn crypto_schema_omits_attributes_absent_from_the_item() {
    let mut input = v1_item();
    input.remove("sign");
    let out = encrypt(&default_encryptor(), input).await;
    let schema = out.parsed_header().unwrap().attribute_actions_on_encrypt();

    //= spec/dynamodb-encryption-client/encrypt-item.md#behavior
    //= type=test
    //# - The Crypto Schema MUST NOT contain more Crypto Actions than those specified by the previous point.
    assert!(!schema.contains_key("sign"), "{schema:?}");

    //= spec/dynamodb-encryption-client/encrypt-item.md#behavior
    //= type=test
    //= reason=The header lists the schema's action for each signed attribute of the item
    //# - For every attribute on the input Item,
    //# there MUST exist a Crypto Action in the Crypto Schema
    //# such that the Crypto Action indexed by that attribute name in the Crypto Schema
    //# equals the Crypto Action indexed by that attribute name in the configured Attribute Actions.
    assert_eq!(
        schema,
        &actions([
            ("bar", CryptoAction::SignOnly),
            ("encrypt", CryptoAction::EncryptAndSign),
        ])
    );
}

#[tokio::test]
async fn encrypt_passes_the_configured_suite() {
    let suite = AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeySymsigHmacSha384;
    let spy = SpyCmm::new();
    let encryptor = encryptor_from(
        config_builder(v1_actions())
            .set_keyring(None)
            .cmm(spy.clone())
            .algorithm_suite_id(suite),
    );
    encrypt(&encryptor, v1_item()).await;

    //= spec/dynamodb-encryption-client/encrypt-item.md#behavior
    //= type=test
    //# - If configured, the Algorithm Suite MUST be the
    //# [Algorithm Suite configured on this Item Encryptor](./ddb-table-encryption-config.md#algorithm-suite).
    assert_eq!(spy.last_encrypt().algorithm_suite_id(), Some(suite.into()));
}

#[tokio::test]
async fn encrypt_passes_the_base_context() {
    let spy = SpyCmm::new();
    encrypt(&spy.encryptor(), v1_item()).await;

    //= spec/dynamodb-encryption-client/encrypt-item.md#behavior
    //= type=test
    //# - Encryption Context MUST be this input Item's [DynamoDB Item Base Context](#dynamodb-item-base-context).
    assert_eq!(
        to_map(spy.last_encrypt().encryption_context()),
        v1_base_context()
    );
}

#[tokio::test]
async fn base_context_v1_contents() {
    let out = encrypt(&default_encryptor(), v1_item()).await;
    let ec = context_without_public_key(out.parsed_header().unwrap().encryption_context());

    //= spec/dynamodb-encryption-client/encrypt-item.md#dynamodb-item-base-context-version-1
    //= type=test
    //# The DynamoDB Item Base Context MUST contain:
    assert_eq!(ec, v1_base_context());

    //= spec/dynamodb-encryption-client/encrypt-item.md#base-context-value-version-1
    //= type=test
    //# The key MUST be as per [Encryption Context Naming]
    //# (../structured-encryption/encrypt-path-structure.md#encryption-context-naming).
    //
    //= spec/structured-encryption/encrypt-path-structure.md#encryption-context-naming
    //= type=test
    //# When a key-value pair is added to the encryption context,
    //# the key MUST be the concatenation of the literal
    //# "aws-crypto-attr." and the member strings of the
    //# path joined by the '.' character.
    assert!(ec.contains_key("aws-crypto-attr.bar"), "{ec:?}");

    //= spec/dynamodb-encryption-client/encrypt-item.md#dynamodb-item-base-context-version-1
    //= type=test
    //# If this item does not have a sort key attribute,
    //# the DynamoDB Item Context MUST NOT contain the key `aws-crypto-sort-name`.
    assert!(!ec.contains_key("aws-crypto-sort-name"));
}

#[tokio::test]
async fn base_context_follows_the_configuration_version() {
    let v1 = encrypt(&default_encryptor(), v1_item()).await;
    let v1_ec = v1.parsed_header().unwrap().encryption_context();
    let v2 = encrypt(&encryptor_from(config_builder(v2_actions())), v1_item()).await;
    let v2_ec = v2.parsed_header().unwrap().encryption_context();

    //= spec/dynamodb-encryption-client/encrypt-item.md#dynamodb-item-base-context
    //= type=test
    //= reason=Only the V1 context holds the encoded key value; V2 holds raw values and a legend
    //# If the [Configuration Version](./ddb-table-encryption-config.md#configuration-version) is 2,
    //# then the base context MUST be the [version 2](#dynamodb-item-base-context-version-2) context;
    //# otherwise, the base context MUST be the [version 1](#dynamodb-item-base-context-version-1) context.
    assert_eq!(v1_ec.get("aws-crypto-attr.bar"), Some("AAFrZXk="));
    assert!(!v1_ec.contains_key("aws-crypto-legend"));
    assert_eq!(v2_ec.get("aws-crypto-attr.bar"), Some("key"));
    assert!(v2_ec.contains_key("aws-crypto-legend"));
}

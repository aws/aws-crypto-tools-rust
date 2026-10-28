// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Validation of `TableConfig` and `ItemEncryptor` configurations.

mod item_encryptor_support;

use aws_db_esdk::aws_sdk_dynamodb::operation::put_item::PutItemInput;
use aws_db_esdk::cmm::DefaultCmm;
use aws_db_esdk::transforms::Transforms;
use aws_db_esdk::types::{AlgorithmSuiteId, CryptoAction, PlaintextOverride};
use aws_db_esdk::{Error, ItemEncryptor, TableConfig};
use item_encryptor_support::*;

/// The message of a `Validation` error; panics on any other result.
fn validation_message<T: std::fmt::Debug>(result: Result<T, Error>) -> String {
    match result {
        Err(Error::Validation(e)) => e.message().to_owned(),
        other => panic!("expected a Validation error, got {other:?}"),
    }
}

/// The error of building an item encryptor for `config`.
fn encryptor_error(config: aws_db_esdk::TableConfigBuilder) -> String {
    validation_message(
        ItemEncryptor::builder()
            .table(TABLE, config.build().unwrap())
            .build(),
    )
}

#[test]
fn table_config_getters_return_what_was_set() {
    let config = config_builder(v1_actions())
        .logical_table_name("logical")
        .sort_key_name("sort")
        .allowed_unsigned_attribute_prefix(":")
        .algorithm_suite_id(AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeySymsigHmacSha384)
        .plaintext_override(PlaintextOverride::ForbidPlaintextWriteAllowPlaintextRead)
        .build()
        .unwrap();
    assert_eq!(config.logical_table_name(), Some("logical"));
    assert_eq!(config.partition_key_name(), "bar");
    assert_eq!(config.sort_key_name(), Some("sort"));
    assert_eq!(config.attribute_actions_on_encrypt(), &v1_actions());
    assert_eq!(config.allowed_unsigned_attributes(), ["nothing".to_owned()]);
    assert_eq!(config.allowed_unsigned_attribute_prefix(), Some(":"));
    assert_eq!(
        config.algorithm_suite_id(),
        Some(AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeySymsigHmacSha384)
    );
    assert_eq!(
        config.plaintext_override(),
        PlaintextOverride::ForbidPlaintextWriteAllowPlaintextRead
    );
    assert!(config.search().is_none());
}

#[test]
fn table_config_defaults() {
    let config = TableConfig::builder()
        .partition_key_name("bar")
        .attribute_actions_on_encrypt("bar", CryptoAction::SignOnly)
        .keyring(keyring())
        .build()
        .unwrap();
    assert_eq!(config.logical_table_name(), None);
    assert_eq!(config.sort_key_name(), None);
    assert!(config.allowed_unsigned_attributes().is_empty());
    assert_eq!(config.allowed_unsigned_attribute_prefix(), None);
    assert_eq!(config.algorithm_suite_id(), None);
    assert_eq!(
        config.plaintext_override(),
        PlaintextOverride::ForbidPlaintextWriteForbidPlaintextRead
    );
    //= spec/dynamodb-encryption-client/ddb-table-encryption-config.md#structure
    //= type=test
    //= reason=A config with no sort key, unsigned attributes, suite, policy or search still builds an encryptor
    //# The following are OPTIONAL for DynamoDb Table Encryption Configuration:
    assert!(
        ItemEncryptor::builder()
            .table(TABLE, config)
            .build()
            .is_ok()
    );
}

#[test]
fn set_methods_clear_what_was_set() {
    let config = config_builder(v1_actions())
        .logical_table_name("x")
        .set_logical_table_name(None)
        .sort_key_name("x")
        .set_sort_key_name(None)
        .set_allowed_unsigned_attributes(None)
        .allowed_unsigned_attribute_prefix("x")
        .set_allowed_unsigned_attribute_prefix(None)
        .algorithm_suite_id(AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeySymsigHmacSha384)
        .set_algorithm_suite_id(None)
        .plaintext_override(PlaintextOverride::ForcePlaintextWriteAllowPlaintextRead)
        .set_plaintext_override(None)
        .set_search(None)
        .build()
        .unwrap();
    assert_eq!(config.logical_table_name(), None);
    assert_eq!(config.sort_key_name(), None);
    assert!(config.allowed_unsigned_attributes().is_empty());
    assert_eq!(config.allowed_unsigned_attribute_prefix(), None);
    assert_eq!(config.algorithm_suite_id(), None);
    assert_eq!(
        config.plaintext_override(),
        PlaintextOverride::ForbidPlaintextWriteForbidPlaintextRead
    );
}

#[test]
fn table_config_requires_partition_key_attribute_actions_and_materials() {
    let msg = validation_message(
        TableConfig::builder()
            .attribute_actions_on_encrypt("bar", CryptoAction::SignOnly)
            .keyring(keyring())
            .build(),
    );
    //= spec/dynamodb-encryption-client/ddb-table-encryption-config.md#structure
    //= type=test
    //= reason=Missing partition key, attribute actions, and keyring-or-CMM are each rejected; the logical name defaults to the table name
    //# The following are REQUIRED for DynamoDb Table Encryption Configuration:
    //
    //= spec/dynamodb-encryption-client/ddb-table-encryption-config.md#structure
    //= type=test
    //# - [DynamoDB Partition Key Name](#dynamodb-partition-key-name)
    assert_eq!(msg, "partition_key_name is required");
    let msg = validation_message(
        config_builder(v1_actions())
            .set_partition_key_name(None)
            .build(),
    );
    assert_eq!(msg, "partition_key_name is required");
    let msg = validation_message(
        TableConfig::builder()
            .partition_key_name("bar")
            .keyring(keyring())
            .build(),
    );
    //= spec/dynamodb-encryption-client/ddb-table-encryption-config.md#structure
    //= type=test
    //# - [Attribute Actions](#attribute-actions)
    assert_eq!(msg, "attribute_actions_on_encrypt is required");
    let msg = validation_message(config_builder(v1_actions()).set_keyring(None).build());
    //= spec/dynamodb-encryption-client/ddb-table-encryption-config.md#structure
    //= type=test
    //# - A [CMM](#cmm) or [Keyring](#keyring)
    assert_eq!(msg, "Must provide either a keyring or a CMM");
    let config = config_builder(v1_actions())
        .set_keyring(None)
        .cmm(DefaultCmm::new(keyring()))
        .set_cmm(None)
        .build();
    assert_eq!(
        validation_message(config),
        "Must provide either a keyring or a CMM"
    );
    let msg = validation_message(
        config_builder(v1_actions())
            .cmm(DefaultCmm::new(keyring()))
            .build(),
    );
    assert_eq!(msg, "Cannot provide both a keyring and a CMM");
}

#[test]
fn table_config_rejects_key_names_outside_1_to_255_characters() {
    let msg = validation_message(config_builder(v1_actions()).partition_key_name("").build());
    //= spec/dynamodb-encryption-client/ddb-table-encryption-config.md#dynamodb-partition-key-name
    //= type=test
    //# This Partition Key Name MUST be a valid DynamoDB Key Schema Attribute Name
    assert_eq!(
        msg,
        "partition_key_name must have between 1 and 255 characters"
    );
    let msg = validation_message(
        config_builder(v1_actions())
            .partition_key_name("a".repeat(256))
            .build(),
    );
    assert_eq!(
        msg,
        "partition_key_name must have between 1 and 255 characters"
    );
    let msg = validation_message(config_builder(v1_actions()).sort_key_name("").build());
    //= spec/dynamodb-encryption-client/ddb-table-encryption-config.md#dynamodb-sort-key-name
    //= type=test
    //# This Sort Key Name MUST be a valid DynamoDB Key Schema Attribute Name
    assert_eq!(msg, "sort_key_name must have between 1 and 255 characters");
    let msg = validation_message(
        config_builder(v1_actions())
            .sort_key_name("a".repeat(256))
            .build(),
    );
    assert_eq!(msg, "sort_key_name must have between 1 and 255 characters");
    // 255 characters is the longest allowed; the limit counts UTF-16 code units.
    assert!(
        config_builder(v1_actions())
            .partition_key_name("a".repeat(255))
            .build()
            .is_ok()
    );
    assert!(
        config_builder(v1_actions())
            .sort_key_name("a".repeat(255))
            .build()
            .is_ok()
    );
    let msg = validation_message(
        config_builder(v1_actions())
            .partition_key_name("\u{1F600}".repeat(128))
            .build(),
    );
    assert_eq!(
        msg,
        "partition_key_name must have between 1 and 255 characters"
    );
}

#[test]
fn table_config_rejects_attribute_names_over_65535_characters() {
    let long = "a".repeat(65_536);
    let msg = validation_message(
        config_builder(v1_actions())
            .attribute_actions_on_encrypt(long.clone(), CryptoAction::SignOnly)
            .build(),
    );
    assert_eq!(
        msg,
        "attribute_actions_on_encrypt has an attribute name longer than 65535 characters"
    );
    let msg = validation_message(
        config_builder(v1_actions())
            .allowed_unsigned_attributes(long)
            .build(),
    );
    //= spec/dynamodb-encryption-client/ddb-table-encryption-config.md#unauthenticated-attributes
    //= type=test
    //# Unauthenticated Attributes MUST be a set of Attribute Names.
    assert_eq!(
        msg,
        "allowed_unsigned_attributes has an attribute name longer than 65535 characters"
    );
}

#[test]
fn item_encryptor_requires_table() {
    //= spec/dynamodb-encryption-client/ddb-table-encryption-config.md#structure
    //= type=test
    //# The physical [DynamoDB Table Name](#dynamodb-table-name) is REQUIRED
    //# to be associated with the DynamoDb Table Encryption Configuration.
    assert_eq!(
        validation_message(ItemEncryptor::builder().build()),
        "table is required"
    );
}

#[test]
fn key_attributes_must_have_the_key_action() {
    for action in [CryptoAction::EncryptAndSign, CryptoAction::DoNothing] {
        let msg = encryptor_error(
            config_builder(v1_actions())
                .attribute_actions_on_encrypt("bar", action)
                .allowed_unsigned_attributes("bar"),
        );
        //= spec/dynamodb-encryption-client/ddb-table-encryption-config.md#attribute-actions
        //= type=test
        //# The [Key Action](#key-action)
        //# MUST be configured to the partition attribute and, if present, sort attribute.
        assert_eq!(msg, "Partition key attribute action MUST be SIGN_ONLY");
    }
    let mut no_key = v1_actions();
    no_key.remove("bar");
    assert_eq!(
        encryptor_error(config_builder(no_key)),
        "Partition key attribute action MUST be SIGN_ONLY"
    );
    let msg = encryptor_error(
        config_builder(v1_actions())
            .sort_key_name("sort")
            .attribute_actions_on_encrypt("sort", CryptoAction::EncryptAndSign),
    );
    assert_eq!(msg, "Sort key attribute action MUST be SIGN_ONLY");
    let msg = encryptor_error(config_builder(v1_actions()).sort_key_name("sort"));
    assert_eq!(msg, "Sort key attribute action MUST be SIGN_ONLY");
    let msg = encryptor_error(
        config_builder(v2_actions())
            .sort_key_name("sort")
            .attribute_actions_on_encrypt("sort", CryptoAction::SignOnly),
    );
    assert_eq!(
        msg,
        "Sort key attribute action MUST be SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT"
    );
}

#[test]
fn v2_partition_key_must_be_sign_and_include_in_encryption_context() {
    let msg = encryptor_error(
        config_builder(v2_actions()).attribute_actions_on_encrypt("bar", CryptoAction::SignOnly),
    );
    //= spec/dynamodb-encryption-client/ddb-table-encryption-config.md#key-action
    //= type=test
    //# if the [configuration version](#configuration-version) is 2, then
    //# the key action MUST be [SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT](../structured-encryption/structures.md#contextandsign);
    //# otherwise, the key action MUST be [SIGN_ONLY](../structured-encryption/structures.md#signonly).
    assert_eq!(
        msg,
        "Partition key attribute action MUST be SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT"
    );
}

#[test]
fn do_nothing_attribute_must_be_allowed_unsigned() {
    let msg = encryptor_error(
        config_builder(v1_actions()).attribute_actions_on_encrypt("other", CryptoAction::DoNothing),
    );
    assert_eq!(
        msg,
        "Attribute other is configured as DO_NOTHING but it must also be in unauthenticatedAttributes or begin with the unauthenticatedPrefix."
    );
    // Allowed by prefix instead of by name.
    let ok = ItemEncryptor::builder()
        .table(
            TABLE,
            config_builder(v1_actions())
                .attribute_actions_on_encrypt(":other", CryptoAction::DoNothing)
                .allowed_unsigned_attribute_prefix(":")
                .build()
                .unwrap(),
        )
        .build();
    assert!(ok.is_ok());
}

#[test]
fn signed_attribute_must_not_be_allowed_unsigned() {
    let msg = encryptor_error(
        config_builder(v1_actions())
            .attribute_actions_on_encrypt("nothing", CryptoAction::SignOnly),
    );
    assert_eq!(
        msg,
        "Attribute nothing is configured as SIGN_ONLY but it is also in unauthenticatedAttributes."
    );
    let msg = encryptor_error(
        config_builder(v1_actions())
            .attribute_actions_on_encrypt(":x", CryptoAction::EncryptAndSign)
            .allowed_unsigned_attribute_prefix(":"),
    );
    assert_eq!(
        msg,
        "Attribute :x is configured as ENCRYPT_AND_SIGN but it also begins with the unauthenticatedPrefix."
    );
    let msg = encryptor_error(config_builder(v2_actions()).attribute_actions_on_encrypt(
        "aws_dbe_x",
        CryptoAction::SignAndIncludeInEncryptionContext,
    ));
    assert_eq!(
        msg,
        "Attribute aws_dbe_x is configured as SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT but it also begins with the reserved prefix."
    );
}

#[test]
fn reserved_attribute_names_may_not_be_configured() {
    let msg = encryptor_error(
        config_builder(v1_actions())
            .attribute_actions_on_encrypt("aws_dbe_x", CryptoAction::DoNothing),
    );
    assert_eq!(
        msg,
        "Attribute: aws_dbe_x is reserved, and may not be configured."
    );
    let msg = encryptor_error(
        config_builder(v1_actions())
            .attribute_actions_on_encrypt("aws-crypto-x", CryptoAction::SignOnly),
    );
    assert_eq!(
        msg,
        "Attribute: aws-crypto-x is reserved, and may not be configured."
    );
}

#[test]
fn first_invalid_attribute_in_utf16_order_is_reported() {
    let msg = encryptor_error(
        config_builder(v1_actions())
            .attribute_actions_on_encrypt("b", CryptoAction::DoNothing)
            .attribute_actions_on_encrypt("a", CryptoAction::DoNothing),
    );
    assert!(
        msg.starts_with("Attribute a is configured as DO_NOTHING"),
        "{msg}"
    );
}

#[test]
fn item_encryptor_rejects_table_names_outside_3_to_255_characters() {
    let build = |name: String| {
        ItemEncryptor::builder()
            .table(name, config_builder(v1_actions()).build().unwrap())
            .build()
    };
    //= spec/dynamodb-encryption-client/ddb-table-encryption-config.md#dynamodb-table-name
    //= type=test
    //# This Table Name MUST be a valid DynamoDB Table Name.
    assert_eq!(
        validation_message(build("ab".to_owned())),
        "table name must have between 3 and 255 characters"
    );
    assert_eq!(
        validation_message(build("a".repeat(256))),
        "table name must have between 3 and 255 characters"
    );
    // The limit counts UTF-16 code units: 128 emoji are 256 units.
    assert_eq!(
        validation_message(build("\u{1F600}".repeat(128))),
        "table name must have between 3 and 255 characters"
    );
    assert!(build("abc".to_owned()).is_ok());
    assert!(build("a".repeat(255)).is_ok());
}

#[tokio::test]
async fn table_name_is_the_key_of_the_table_configs_map() {
    let transforms = Transforms::builder()
        .table_encryption_configs("configured", config_builder(v1_actions()).build().unwrap())
        .build()
        .unwrap();
    let put = |table: &str| {
        PutItemInput::builder()
            .table_name(table)
            .set_item(Some(v1_item()))
            .build()
            .unwrap()
    };
    let written = transforms
        .put_item_input(put("configured"))
        .await
        .unwrap()
        .item
        .unwrap();
    //= spec/dynamodb-encryption-client/ddb-table-encryption-config.md#dynamodb-table-name
    //= type=test
    //# If this config is being organized with other table configs in a map,
    //# this value MAY exist as a key value to identify other data in this config,
    //# instead of existing alongside this data in the same object.
    assert!(written.contains_key("aws_dbe_head"));
    let passed_through = transforms
        .put_item_input(put("other"))
        .await
        .unwrap()
        .item
        .unwrap();
    assert_eq!(passed_through, v1_item());
}

#[test]
fn two_tables_may_not_share_a_logical_table_name() {
    let logical = |name: &str| {
        config_builder(v1_actions())
            .logical_table_name(name)
            .build()
            .unwrap()
    };
    let msg = validation_message(
        Transforms::builder()
            .table_encryption_configs("physical1", logical("shared"))
            .table_encryption_configs("physical2", logical("shared"))
            .build(),
    );
    //= spec/dynamodb-encryption-client/ddb-table-encryption-config.md#logical-table-name
    //= type=test
    //# When mapping [DynamoDB Table Names](#dynamodb-table-name) to [logical table name](#logical-table-name)
    //# there MUST a one to one mapping between the two.
    assert_eq!(
        msg,
        "Duplicate logical table mapped to multiple physical tables: shared"
    );
    assert!(
        Transforms::builder()
            .table_encryption_configs("physical1", logical("one"))
            .table_encryption_configs("physical2", logical("two"))
            .build()
            .is_ok()
    );
}

#[tokio::test]
async fn unset_logical_table_name_defaults_to_the_table_name() {
    // The logical table name bound into an item encrypted by `encryptor`.
    let bound_name = |encryptor: ItemEncryptor| async move {
        let out = encryptor
            .encrypt_item()
            .plaintext_item(v1_item())
            .send()
            .await
            .unwrap();
        out.parsed_header()
            .unwrap()
            .encryption_context()
            .get("aws-crypto-table-name")
            .map(str::to_owned)
    };
    //= spec/dynamodb-encryption-client/ddb-table-encryption-config.md#structure
    //= type=test
    //# - [Logical Table Name](#logical-table-name)
    assert_eq!(
        bound_name(default_encryptor()).await.as_deref(),
        Some(TABLE)
    );
    let named = encryptor_from(config_builder(v1_actions()).logical_table_name("logical"));
    assert_eq!(bound_name(named).await.as_deref(), Some("logical"));
}

#[tokio::test]
async fn configuration_version_follows_sign_and_include_actions() {
    // The partition key's value in the encryption context of an item encrypted by `encryptor`.
    let partition_value = |encryptor: ItemEncryptor| async move {
        let out = encryptor
            .encrypt_item()
            .plaintext_item(v1_item())
            .send()
            .await
            .unwrap();
        out.parsed_header()
            .unwrap()
            .encryption_context()
            .get("aws-crypto-attr.bar")
            .map(str::to_owned)
    };
    // Version 1 binds the base64 of the typed value: type 0x0001 (string), then "key".
    assert_eq!(
        partition_value(default_encryptor()).await.as_deref(),
        Some("AAFrZXk=")
    );
    //= spec/dynamodb-encryption-client/ddb-table-encryption-config.md#configuration-version
    //= type=test
    //= reason=Only a version 1 config binds the base64 typed key value; version 2 binds the plain value
    //# If any of the [Attribute Actions](#attribute-actions) are configured as
    //# [SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT](../structured-encryption/structures.md#contextandsign)
    //# then the configuration version MUST be 2; otherwise,
    //# the configuration version MUST be 1.
    assert_eq!(
        partition_value(encryptor_from(config_builder(v2_actions())))
            .await
            .as_deref(),
        Some("key")
    );
}

#[tokio::test]
async fn keyring_config_uses_a_default_cmm_over_the_keyring() {
    let with_keyring = default_encryptor();
    let with_cmm = encryptor_from(
        config_builder(v1_actions())
            .set_keyring(None)
            .cmm(DefaultCmm::new(keyring())),
    );
    let roundtrip = |from: ItemEncryptor, to: ItemEncryptor| async move {
        let encrypted = from
            .encrypt_item()
            .plaintext_item(v1_item())
            .send()
            .await
            .unwrap()
            .into_encrypted_item();
        to.decrypt_item()
            .encrypted_item(encrypted)
            .send()
            .await
            .unwrap()
            .plaintext_item()
            .clone()
    };
    //= spec/dynamodb-encryption-client/ddb-table-encryption-config.md#cmm
    //= type=test
    //= reason=Items cross-decrypt with an explicit DefaultCmm over the same keyring, in both directions
    //# If not supplied during initialization,
    //# the CMM considered "configured" to this
    //# Item Encryptor MUST be a
    //# [default CMM](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/default-cmm.md)
    //# constructed using the [supplied keyring](#keyring) as input.
    assert_eq!(
        roundtrip(with_keyring.clone(), with_cmm.clone()).await,
        v1_item()
    );
    assert_eq!(roundtrip(with_cmm, with_keyring).await, v1_item());
}

#[tokio::test]
async fn configured_algorithm_suite_is_used_for_encryption() {
    let suite = AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeySymsigHmacSha384;
    assert_ne!(
        suite,
        AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384SymsigHmacSha384,
        "the configured suite must differ from the default"
    );
    let out = encryptor_from(config_builder(v1_actions()).algorithm_suite_id(suite))
        .encrypt_item()
        .plaintext_item(v1_item())
        .send()
        .await
        .unwrap();
    //= spec/dynamodb-encryption-client/ddb-table-encryption-config.md#algorithm-suite
    //= type=test
    //# The [algorithm suite](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/algorithm-suites.md) that SHOULD be used for encryption.
    assert_eq!(out.parsed_header().unwrap().algorithm_suite_id(), suite);
}

#[tokio::test]
async fn unspecified_plaintext_policy_encrypts_and_rejects_plaintext_items() {
    let encryptor = default_encryptor();
    let out = encryptor
        .encrypt_item()
        .plaintext_item(v1_item())
        .send()
        .await
        .unwrap();
    assert!(out.encrypted_item().contains_key("aws_dbe_head"));
    let result = encryptor
        .decrypt_item()
        .encrypted_item(v1_item())
        .send()
        .await;
    let Err(Error::Serialization(e)) = result else {
        panic!("expected a Serialization error, got {result:?}");
    };
    //= spec/dynamodb-encryption-client/ddb-table-encryption-config.md#plaintext-policy
    //= type=test
    //# If not specified, encryption and decryption MUST behave according to `FORBID_PLAINTEXT_WRITE_FORBID_PLAINTEXT_READ`.
    assert_eq!(
        e.message(),
        "Encrypted item missing expected header and footer attributes"
    );
}

// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Validation of `TableConfig` and `ItemEncryptor` configurations.

mod item_encryptor_support;

use aws_db_esdk::cmm::DefaultCmm;
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
fn table_config_requires_partition_key_name() {
    let msg = validation_message(
        TableConfig::builder()
            .attribute_actions_on_encrypt("bar", CryptoAction::SignOnly)
            .keyring(keyring())
            .build(),
    );
    assert_eq!(msg, "partition_key_name is required");
    let msg = validation_message(
        config_builder(v1_actions())
            .set_partition_key_name(None)
            .build(),
    );
    assert_eq!(msg, "partition_key_name is required");
}

#[test]
fn table_config_rejects_key_names_outside_1_to_255_characters() {
    let msg = validation_message(config_builder(v1_actions()).partition_key_name("").build());
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
fn table_config_requires_attribute_actions() {
    let msg = validation_message(
        TableConfig::builder()
            .partition_key_name("bar")
            .keyring(keyring())
            .build(),
    );
    assert_eq!(msg, "attribute_actions_on_encrypt is required");
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
    assert_eq!(
        msg,
        "allowed_unsigned_attributes has an attribute name longer than 65535 characters"
    );
}

#[test]
fn table_config_requires_exactly_one_of_keyring_and_cmm() {
    let msg = validation_message(
        config_builder(v1_actions())
            .cmm(DefaultCmm::new(keyring()))
            .build(),
    );
    assert_eq!(msg, "Cannot provide both a keyring and a CMM");
    let msg = validation_message(config_builder(v1_actions()).set_keyring(None).build());
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
}

#[test]
fn item_encryptor_requires_table() {
    assert_eq!(
        validation_message(ItemEncryptor::builder().build()),
        "table is required"
    );
}

#[test]
fn v1_partition_key_must_be_sign_only() {
    for action in [CryptoAction::EncryptAndSign, CryptoAction::DoNothing] {
        let msg = encryptor_error(
            config_builder(v1_actions())
                .attribute_actions_on_encrypt("bar", action)
                .allowed_unsigned_attributes("bar"),
        );
        assert_eq!(msg, "Partition key attribute action MUST be SIGN_ONLY");
    }
    let mut no_key = v1_actions();
    no_key.remove("bar");
    assert_eq!(
        encryptor_error(config_builder(no_key)),
        "Partition key attribute action MUST be SIGN_ONLY"
    );
}

#[test]
fn v2_partition_key_must_be_sign_and_include_in_encryption_context() {
    let msg = encryptor_error(
        config_builder(v2_actions()).attribute_actions_on_encrypt("bar", CryptoAction::SignOnly),
    );
    assert_eq!(
        msg,
        "Partition key attribute action MUST be SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT"
    );
}

#[test]
fn sort_key_must_have_the_key_action() {
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

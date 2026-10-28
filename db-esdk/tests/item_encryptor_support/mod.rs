// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Fixtures shared by the item encryptor tests, ported from the Dafny `TestFixtures`.

#![allow(dead_code)]

use std::collections::HashMap;

use aws_db_esdk::aws_sdk_dynamodb::types::AttributeValue;
use aws_db_esdk::keyring::RawAesKeyring;
use aws_db_esdk::types::{AesWrappingAlg, CryptoAction};
use aws_db_esdk::{ItemEncryptor, TableConfig, TableConfigBuilder};

/// The Dafny tests' logical table name.
pub const TABLE: &str = "foo";

pub type Item = HashMap<String, AttributeValue>;

/// The Dafny `GetKmsKeyring`: a raw AES keyring with an all-zero key.
pub fn keyring() -> RawAesKeyring {
    keyring_with_key(vec![0; 32])
}

pub fn keyring_with_key(key: Vec<u8>) -> RawAesKeyring {
    RawAesKeyring::builder()
        .key_namespace("foo")
        .key_name("bar")
        .wrapping_key(key)
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()
        .unwrap()
}

pub fn s(x: &str) -> AttributeValue {
    AttributeValue::S(x.to_owned())
}

pub fn item<const N: usize>(pairs: [(&str, AttributeValue); N]) -> Item {
    pairs.into_iter().map(|(k, v)| (k.to_owned(), v)).collect()
}

pub fn actions<const N: usize>(pairs: [(&str, CryptoAction); N]) -> HashMap<String, CryptoAction> {
    pairs.into_iter().map(|(k, v)| (k.to_owned(), v)).collect()
}

/// The Dafny `GetAttributeActions`.
pub fn v1_actions() -> HashMap<String, CryptoAction> {
    actions([
        ("bar", CryptoAction::SignOnly),
        ("encrypt", CryptoAction::EncryptAndSign),
        ("sign", CryptoAction::SignOnly),
        ("nothing", CryptoAction::DoNothing),
    ])
}

/// The Dafny `GetV2AttributeActions`.
pub fn v2_actions() -> HashMap<String, CryptoAction> {
    actions([
        ("bar", CryptoAction::SignAndIncludeInEncryptionContext),
        ("encrypt", CryptoAction::EncryptAndSign),
        ("sign", CryptoAction::SignAndIncludeInEncryptionContext),
        ("nothing", CryptoAction::DoNothing),
    ])
}

/// The Dafny `GetEncryptorConfigFromActions`, as a builder so a test can change one field.
pub fn config_builder(actions: HashMap<String, CryptoAction>) -> TableConfigBuilder {
    TableConfig::builder()
        .partition_key_name("bar")
        .set_attribute_actions_on_encrypt(Some(actions))
        .allowed_unsigned_attributes("nothing")
        .keyring(keyring())
}

pub fn encryptor_from(config: TableConfigBuilder) -> ItemEncryptor {
    ItemEncryptor::builder()
        .table(TABLE, config.build().unwrap())
        .build()
        .unwrap()
}

/// The Dafny `GetDynamoDbItemEncryptor`.
pub fn default_encryptor() -> ItemEncryptor {
    encryptor_from(config_builder(v1_actions()))
}

/// The Dafny `TestRoundTrip` input item.
pub fn v1_item() -> Item {
    item([
        ("bar", s("key")),
        ("encrypt", s("text")),
        ("sign", s("bar")),
        ("nothing", s("baz")),
    ])
}

/// The encryption context without the verification key, which changes every encrypt.
pub fn context_without_public_key(
    ec: &aws_db_esdk::types::EncryptionContext,
) -> HashMap<String, String> {
    assert!(ec.contains_key("aws-crypto-public-key"));
    ec.iter()
        .filter(|(k, _)| *k != "aws-crypto-public-key")
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect()
}

pub fn strings<const N: usize>(pairs: [(&str, &str); N]) -> HashMap<String, String> {
    pairs
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect()
}

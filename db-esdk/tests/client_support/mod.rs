// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Fixtures for the `Client` tests:
//! an in-process fake DynamoDB and the DynamoDbEncryptionTransforms test configuration (`TestFixtures.dfy`).
#![allow(dead_code)]

pub mod fake;
pub mod json;

use aws_db_esdk::aws_sdk_dynamodb::types::AttributeValue;
use aws_db_esdk::keyring::RawAesKeyring;
use aws_db_esdk::types::{AesWrappingAlg, CryptoAction};
use aws_db_esdk::{Client, TableConfig};

pub use fake::{FakeDdb, Item};

/// The configured table of `GetDynamoDbEncryptionTransforms2`.
pub const TABLE: &str = "foo";
/// A table with no configuration: its items pass through unencrypted.
pub const PLAIN_TABLE: &str = "no_such_table";

/// `GetStaticKeyring`: a Raw AES keyring with namespace `foo`, name `bar`, and a zero key.
pub fn keyring() -> RawAesKeyring {
    RawAesKeyring::builder()
        .key_namespace("foo")
        .key_name("bar")
        .wrapping_key(vec![0u8; 32])
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()
        .expect("a valid keyring")
}

/// The table of `GetDynamoDbEncryptionTransforms2`:
/// partition key `bar`, sort key `sign`, `encrypt` encrypted, and `plain` neither encrypted nor signed.
pub fn table_config() -> TableConfig {
    TableConfig::builder()
        .logical_table_name(TABLE)
        .partition_key_name("bar")
        .sort_key_name("sign")
        .attribute_actions_on_encrypt("bar", CryptoAction::SignOnly)
        .attribute_actions_on_encrypt("sign", CryptoAction::SignOnly)
        .attribute_actions_on_encrypt("encrypt", CryptoAction::EncryptAndSign)
        .attribute_actions_on_encrypt("plain", CryptoAction::DoNothing)
        .allowed_unsigned_attributes("plain")
        .keyring(keyring())
        .build()
        .expect("a valid table configuration")
}

/// A fake with [`TABLE`] and [`PLAIN_TABLE`], both keyed on `bar` and `sign`.
pub fn fake() -> FakeDdb {
    FakeDdb::new()
        .with_table(TABLE, "bar", Some("sign"))
        .with_table(PLAIN_TABLE, "bar", Some("sign"))
}

/// A fake, and a client that encrypts [`TABLE`] and sends its requests to the fake.
pub async fn setup() -> (FakeDdb, Client) {
    let fake = fake();
    let client = Client::builder()
        .ddb_client(fake.client())
        .table_encryption_configs(TABLE, table_config())
        .build()
        .await
        .expect("a valid client configuration");
    (fake, client)
}

pub fn s(v: &str) -> AttributeValue {
    AttributeValue::S(v.to_owned())
}

/// An item whose every attribute is a string.
pub fn item(attrs: &[(&str, &str)]) -> Item {
    attrs.iter().map(|(k, v)| ((*k).to_owned(), s(v))).collect()
}

/// The primary key `bar`, `sign`.
pub fn key(bar: &str, sign: &str) -> Item {
    item(&[("bar", bar), ("sign", sign)])
}

/// An item of `BatchWriteItemTransform.dfy`:
/// `Item1` is `(1, 1)`, `Item2` is `(2, 2)`, and `Item1a`, `Item1b`, `Item1c` are `(1, 2)`, `(1, 3)`, `(1, 4)`.
pub fn dafny_item(bar: u8, n: u8) -> Item {
    item(&[
        ("bar", &format!("bar{bar}")),
        ("sign", &format!("sign{n}")),
        ("encrypt", &format!("encrypt{n}")),
        ("plain", &format!("plain{n}")),
    ])
}

/// An item of [`TABLE`] with an attribute for each crypto action.
pub fn full_item(bar: &str, sign: &str) -> Item {
    item(&[
        ("bar", bar),
        ("sign", sign),
        ("encrypt", &format!("secret of {bar}/{sign}")),
        ("plain", "unsigned"),
    ])
}

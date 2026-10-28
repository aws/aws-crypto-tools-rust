// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Fixtures shared by the `structured_api_*` tests, ported from
//! `StructuredEncryption/test/StructuredDataTestFixtures.dfy`.

#![allow(dead_code)]

use std::collections::HashMap;

use aws_db_esdk::cmm::{DefaultCmm, SharedCmm};
use aws_db_esdk::keyring::RawAesKeyring;
use aws_db_esdk::structured::{AuthenticateAction, StructuredDataTerminal, StructuredEncryption};
use aws_db_esdk::types::{AesWrappingAlg, CryptoAction};

pub const TABLE: &str = "myTable";
pub const HEADER: &str = "aws_dbe_head";
pub const FOOTER: &str = "aws_dbe_foot";

pub const TEST_TYPE_ID: [u8; 2] = [0xFF, 0xFF];
pub const TEST_BLOB_VALUE: [u8; 13] = [
    0x21, 0x64, 0x6c, 0x72, 0x6f, 0x77, 0x20, 0x2c, 0x6f, 0x6c, 0x6c, 0x65, 0x68,
];

pub const STRING: [u8; 2] = [0x00, 0x01];
pub const NUMBER: [u8; 2] = [0x00, 0x02];
pub const BOOLEAN: [u8; 2] = [0x00, 0x04];
pub const NULL: [u8; 2] = [0x00, 0x00];

pub fn blob() -> StructuredDataTerminal {
    StructuredDataTerminal::new(TEST_TYPE_ID, TEST_BLOB_VALUE.to_vec())
}

/// `TEST_STRUCTURED_DATA`.
pub fn test_structured_data() -> HashMap<String, StructuredDataTerminal> {
    ["foo", "bar", "fizzbuzz"]
        .into_iter()
        .map(|k| (k.to_owned(), blob()))
        .collect()
}

/// `TEST_CRYPTO_SCHEMA`.
pub fn test_crypto_schema() -> HashMap<String, CryptoAction> {
    HashMap::from([
        ("foo".to_owned(), CryptoAction::EncryptAndSign),
        ("bar".to_owned(), CryptoAction::SignOnly),
        ("fizzbuzz".to_owned(), CryptoAction::DoNothing),
    ])
}

/// `TEST_CRYPTO_SCHEMA_AUTH_ONLY`.
pub fn test_crypto_schema_auth_only() -> HashMap<String, CryptoAction> {
    HashMap::from([
        ("foo".to_owned(), CryptoAction::EncryptAndSign),
        ("bar".to_owned(), CryptoAction::SignOnly),
    ])
}

/// `TEST_AUTHENTICATE_SCHEMA`.
pub fn test_authenticate_schema() -> HashMap<String, AuthenticateAction> {
    HashMap::from([
        ("foo".to_owned(), AuthenticateAction::Sign),
        ("bar".to_owned(), AuthenticateAction::Sign),
        ("fizzbuzz".to_owned(), AuthenticateAction::DoNotSign),
        (HEADER.to_owned(), AuthenticateAction::DoNotSign),
        (FOOTER.to_owned(), AuthenticateAction::DoNotSign),
    ])
}

/// A default CMM over a Raw AES keyring with a fixed 32-byte key,
/// standing in for the reference's KMS keyring so the tests run offline.
pub fn cmm_with_key(key_byte: u8) -> SharedCmm {
    let keyring = RawAesKeyring::builder()
        .key_namespace("structured-api-test")
        .key_name("aes-key")
        .wrapping_key(vec![key_byte; 32])
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()
        .unwrap();
    SharedCmm::new(DefaultCmm::new(keyring))
}

pub fn cmm() -> SharedCmm {
    cmm_with_key(0x01)
}

pub const fn client() -> StructuredEncryption {
    StructuredEncryption::new()
}

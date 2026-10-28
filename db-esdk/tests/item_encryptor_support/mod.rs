// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Fixtures shared by the item encryptor tests, ported from the Dafny `TestFixtures`.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use aws_db_esdk::async_trait;
use aws_db_esdk::aws_sdk_dynamodb::types::AttributeValue;
use aws_db_esdk::cmm::{
    Cmm, DecryptMaterialsInput, DecryptMaterialsOutput, DefaultCmm, GetEncryptionMaterialsInput,
    GetEncryptionMaterialsOutput,
};
use aws_db_esdk::keyring::RawAesKeyring;
use aws_db_esdk::mpl::Error as MplError;
use aws_db_esdk::types::{AesWrappingAlg, AlgorithmSuiteId, CryptoAction, EncryptionContext};
use aws_db_esdk::{ItemEncryptor, TableConfig, TableConfigBuilder};

/// The Dafny tests' logical table name.
pub const TABLE: &str = "foo";

pub const HEADER: &str = "aws_dbe_head";
pub const FOOTER: &str = "aws_dbe_foot";
/// The suite a table with no configured suite encrypts with.
pub const DEFAULT_SUITE: AlgorithmSuiteId =
    AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384SymsigHmacSha384;

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
pub fn context_without_public_key(ec: &EncryptionContext) -> HashMap<String, String> {
    assert!(ec.contains_key("aws-crypto-public-key"));
    ec.iter()
        .filter(|(k, _)| *k != "aws-crypto-public-key")
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect()
}

pub fn to_map(ec: &EncryptionContext) -> HashMap<String, String> {
    ec.iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect()
}

/// The V1 base context of `v1_item()` under `config_builder`.
pub fn v1_base_context() -> HashMap<String, String> {
    strings([
        ("aws-crypto-table-name", "foo"),
        ("aws-crypto-partition-name", "bar"),
        // base64 of type ID 0x0001 (string) followed by "key"
        ("aws-crypto-attr.bar", "AAFrZXk="),
    ])
}

pub fn strings<const N: usize>(pairs: [(&str, &str); N]) -> HashMap<String, String> {
    pairs
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect()
}

/// A CMM that records the last input it was called with, then forwards it to a [`DefaultCmm`].
#[derive(Clone)]
pub struct SpyCmm {
    inner: DefaultCmm,
    last_encrypt: Arc<Mutex<Option<GetEncryptionMaterialsInput>>>,
    last_decrypt: Arc<Mutex<Option<DecryptMaterialsInput>>>,
}

impl SpyCmm {
    pub fn new() -> Self {
        Self {
            inner: DefaultCmm::new(keyring()),
            last_encrypt: Arc::default(),
            last_decrypt: Arc::default(),
        }
    }

    /// The input of the last `get_encryption_materials` call.
    pub fn last_encrypt(&self) -> GetEncryptionMaterialsInput {
        self.last_encrypt.lock().unwrap().clone().unwrap()
    }

    /// The input of the last `decrypt_materials` call.
    pub fn last_decrypt(&self) -> DecryptMaterialsInput {
        self.last_decrypt.lock().unwrap().clone().unwrap()
    }

    /// An encryptor for the V1 actions whose only CMM is this spy.
    pub fn encryptor(&self) -> ItemEncryptor {
        encryptor_from(
            config_builder(v1_actions())
                .set_keyring(None)
                .cmm(self.clone()),
        )
    }
}

#[async_trait]
impl Cmm for SpyCmm {
    async fn get_encryption_materials(
        &self,
        input: GetEncryptionMaterialsInput,
    ) -> Result<GetEncryptionMaterialsOutput, MplError> {
        *self.last_encrypt.lock().unwrap() = Some(input.clone());
        self.inner
            .get_encryption_materials()
            .encryption_context(input.encryption_context().clone())
            .commitment_policy(input.commitment_policy())
            .set_algorithm_suite_id(input.algorithm_suite_id())
            .set_required_encryption_context_keys(input.required_encryption_context_keys().cloned())
            .set_max_plaintext_length(input.max_plaintext_length())
            .send()
            .await
    }

    async fn decrypt_materials(
        &self,
        input: DecryptMaterialsInput,
    ) -> Result<DecryptMaterialsOutput, MplError> {
        *self.last_decrypt.lock().unwrap() = Some(input.clone());
        self.inner
            .decrypt_materials()
            .algorithm_suite_id(input.algorithm_suite_id())
            .commitment_policy(input.commitment_policy())
            .encrypted_data_keys(input.encrypted_data_keys().to_vec())
            .encryption_context(input.encryption_context().clone())
            .set_reproduced_encryption_context(input.reproduced_encryption_context().cloned())
            .send()
            .await
    }
}

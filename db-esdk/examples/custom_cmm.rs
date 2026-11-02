// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines a custom cryptographic materials manager (CMM) by implementing the [`Cmm`] trait.
//!
//! `SigningSuiteOnlyCmm` wraps a [`DefaultCmm`] and rejects any algorithm suite without an asymmetric signature.
//!
//! A table config takes either a keyring or a CMM.
//!
//! Requires AWS credentials and a DynamoDB table with:
//! - partition key `partition_key`, type S
//! - sort key `sort_key`, type N

use std::collections::HashMap;

use aws_db_esdk::aws_sdk_dynamodb::types::AttributeValue;
use aws_db_esdk::cmm::{
    Cmm, DecryptMaterialsInput, DecryptMaterialsOutput, DefaultCmm, GetEncryptionMaterialsInput,
    GetEncryptionMaterialsOutput,
};
use aws_db_esdk::keyring::{RawAesKeyring, SharedKeyring};
use aws_db_esdk::mpl::Error as MplError;
use aws_db_esdk::mpl::shared::IntoShared;
use aws_db_esdk::types::{AesWrappingAlg, AlgorithmSuiteId, CryptoAction};
use aws_db_esdk::{Error, TableConfig, async_trait, aws_config, aws_sdk_dynamodb};

const TABLE_NAME: &str = "DynamoDbEncryptionInterceptorTestTableCS";

/// Passes requests to a [`DefaultCmm`] and fails any that would use a suite without an asymmetric signature.
#[derive(Clone)]
struct SigningSuiteOnlyCmm {
    inner: DefaultCmm,
}

impl SigningSuiteOnlyCmm {
    fn new(keyring: impl IntoShared<SharedKeyring>) -> Self {
        Self {
            inner: DefaultCmm::new(keyring),
        }
    }
}

#[async_trait]
impl Cmm for SigningSuiteOnlyCmm {
    async fn get_encryption_materials(
        &self,
        input: GetEncryptionMaterialsInput,
    ) -> Result<GetEncryptionMaterialsOutput, MplError> {
        // The table config may leave the suite unset and let the default CMM choose,
        // so check the suite on the materials it returns.
        let output = self
            .inner
            .get_encryption_materials()
            .set_encryption_context(Some(input.encryption_context().clone()))
            .commitment_policy(input.commitment_policy())
            .set_algorithm_suite_id(input.algorithm_suite_id())
            .set_required_encryption_context_keys(Some(
                input.required_encryption_context_keys().clone(),
            ))
            .set_max_plaintext_length(input.max_plaintext_length())
            .send()
            .await?;
        let suite = output.encryption_materials().algorithm_suite();
        if suite.asymmetric_signature_algorithm().is_none() {
            return Err(MplError::validation(
                "algorithm suite must use asymmetric signing",
            ));
        }
        Ok(output)
    }

    async fn decrypt_materials(
        &self,
        input: DecryptMaterialsInput,
    ) -> Result<DecryptMaterialsOutput, MplError> {
        if !input.algorithm_suite_id().has_asymmetric_signing() {
            return Err(MplError::validation(
                "algorithm suite must use asymmetric signing",
            ));
        }
        self.inner
            .decrypt_materials()
            .algorithm_suite_id(input.algorithm_suite_id())
            .commitment_policy(input.commitment_policy())
            .set_encrypted_data_keys(Some(input.encrypted_data_keys().to_vec()))
            .set_encryption_context(Some(input.encryption_context().clone()))
            .set_reproduced_encryption_context(input.reproduced_encryption_context().cloned())
            .send()
            .await
    }
}

fn table_config(
    cmm: SigningSuiteOnlyCmm,
    suite: Option<AlgorithmSuiteId>,
) -> Result<TableConfig, Error> {
    TableConfig::builder()
        .partition_key_name("partition_key")
        .sort_key_name("sort_key")
        .attribute_actions_on_encrypt("partition_key", CryptoAction::SignOnly)
        .attribute_actions_on_encrypt("sort_key", CryptoAction::SignOnly)
        .attribute_actions_on_encrypt("sensitive_data", CryptoAction::EncryptAndSign)
        .cmm(cmm)
        .set_algorithm_suite_id(suite)
        .build()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // For demonstration only.
    // A real application must load its wrapping key from a secure store, never hardcode it.
    let keyring = RawAesKeyring::builder()
        .key_namespace("my-key-namespace")
        .key_name("my-key-name")
        .wrapping_key(vec![0x01u8; 32])
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()?;
    let cmm = SigningSuiteOnlyCmm::new(keyring);

    let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let ddb_sdk = aws_sdk_dynamodb::Client::new(&sdk_config);

    let item = HashMap::from([
        (
            "partition_key".to_string(),
            AttributeValue::S("CustomCmmExample".into()),
        ),
        ("sort_key".to_string(), AttributeValue::N("0".into())),
        (
            "sensitive_data".to_string(),
            AttributeValue::S("encrypt and sign me!".into()),
        ),
    ]);

    // The default algorithm suite signs with ECDSA, so the CMM allows it.
    let ddb = aws_db_esdk::Client::builder()
        .ddb_client(ddb_sdk.clone())
        .table_encryption_configs(TABLE_NAME, table_config(cmm.clone(), None)?)
        .build()?;
    ddb.put_item()
        .table_name(TABLE_NAME)
        .set_item(Some(item.clone()))
        .send()
        .await?;

    // The CMM rejects a suite with only a symmetric signature.
    let ddb = aws_db_esdk::Client::builder()
        .ddb_client(ddb_sdk)
        .table_encryption_configs(
            TABLE_NAME,
            table_config(
                cmm,
                Some(AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeySymsigHmacSha384),
            )?,
        )
        .build()?;
    let result = ddb
        .put_item()
        .table_name(TABLE_NAME)
        .set_item(Some(item))
        .send()
        .await;
    assert!(
        matches!(result, Err(Error::Validation(_))),
        "a suite without an asymmetric signature must be rejected, got {result:?}"
    );

    println!("Success! The CMM allowed an ECDSA suite and rejected a symmetric-only one.");
    Ok(())
}

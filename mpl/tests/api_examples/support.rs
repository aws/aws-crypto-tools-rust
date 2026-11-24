// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Helpers and imports that the examples use.
//! The tests in this folder and the generated api_example_combos test both use this module.

pub use std::time::Duration;

pub use aws_crypto_mpl::cmc::{DefaultCmc, LocalCmc, SharedCmc, StormTrackingCmc};
pub use aws_crypto_mpl::cmm::DefaultCmm;
pub use aws_crypto_mpl::key_store::types::KmsConfiguration;
pub use aws_crypto_mpl::key_store::{DynamoDbKeyStore, SharedKeyStore};
pub use aws_crypto_mpl::keyring::{
    BranchKeyIdSupplier, GetBranchKeyIdInput, GetBranchKeyIdOutput, HierarchicalKeyring,
    RawAesKeyring, SharedBranchKeyIdSupplier,
};
pub use aws_crypto_mpl::types::AesWrappingAlg;
pub use aws_crypto_mpl::{Error, async_trait, aws_sdk_dynamodb, aws_sdk_kms};

/// Stands in for settings that the customer's application loads.
pub struct AppConfig {
    pub key_namespace: String,
    pub key_name: String,
    pub branch_key_id: String,
    pub partition_id: String,
}

pub fn app_config() -> AppConfig {
    AppConfig {
        key_namespace: "my-key-namespace".to_string(),
        key_name: "my-key-name".to_string(),
        branch_key_id: "my-branch-key-id".to_string(),
        partition_id: "my-partition-id".to_string(),
    }
}

/// Stands in for reading the key from a secret store.
pub fn wrapping_key_from_secret_store() -> Vec<u8> {
    vec![0x01; 32]
}

/// The tests never call AWS, so the clients have a fixed region and no credentials.
fn kms_client() -> aws_sdk_kms::Client {
    let config = aws_sdk_kms::Config::builder()
        .region(aws_sdk_kms::config::Region::new("us-west-2"))
        .behavior_version(aws_sdk_kms::config::BehaviorVersion::latest())
        .build();
    aws_sdk_kms::Client::from_conf(config)
}

fn dynamodb_client() -> aws_sdk_dynamodb::Client {
    let config = aws_sdk_dynamodb::Config::builder()
        .region(aws_sdk_dynamodb::config::Region::new("us-west-2"))
        .behavior_version(aws_sdk_dynamodb::config::BehaviorVersion::latest())
        .build();
    aws_sdk_dynamodb::Client::from_conf(config)
}

/// Building a key store with both clients passed in makes no AWS call.
pub async fn make_dynamodb_key_store() -> DynamoDbKeyStore {
    DynamoDbKeyStore::builder()
        .ddb_table_name("KeyStoreDdbTable")
        .logical_key_store_name("KeyStoreDdbTable")
        .kms_configuration(KmsConfiguration::kms_key_arn(
            "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
        ))
        .kms_client(kms_client())
        .ddb_client(dynamodb_client())
        .build()
        .await
        .expect("a key store with both clients builds")
}

pub fn make_raw_aes_keyring() -> RawAesKeyring {
    RawAesKeyring::builder()
        .key_namespace("my-key-namespace")
        .key_name("my-key-name")
        .wrapping_key(wrapping_key_from_secret_store())
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()
        .expect("a raw AES keyring with every option set builds")
}

/// Picks a tenant's branch key from the encryption context.
pub struct TenantBranchKeyIdSupplier;

#[async_trait]
impl BranchKeyIdSupplier for TenantBranchKeyIdSupplier {
    async fn get_branch_key_id(
        &self,
        input: GetBranchKeyIdInput,
    ) -> Result<GetBranchKeyIdOutput, Error> {
        let tenant = input
            .encryption_context()
            .get("tenant")
            .unwrap_or("default");
        GetBranchKeyIdOutput::builder()
            .branch_key_id(format!("{tenant}-branch-key-id"))
            .build()
    }
}

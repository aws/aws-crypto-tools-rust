// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! An example of every way to build each keyring and CMM.
//!
//! scripts/api-examples/surface.py lists the ways from the public API.
//! Each `// api-example:` line names one of those ways, and the code between
//! `// snippet-start` and `// snippet-end` under it is what a customer writes for it.
//! The api-examples script in aws-crypto-tools-commons collects these snippets for the API examples dashboard,
//! and fails CI when a way has no example.
//! Everything outside the markers is setup and assertions, which the dashboard does not show.

mod default_cmm;
mod hierarchical_keyring;
mod raw_aes_keyring;

use aws_crypto_mpl::aws_sdk_dynamodb;
use aws_crypto_mpl::aws_sdk_kms;
use aws_crypto_mpl::key_store::DynamoDbKeyStore;
use aws_crypto_mpl::key_store::types::KmsConfiguration;
use aws_crypto_mpl::keyring::RawAesKeyring;
use aws_crypto_mpl::types::AesWrappingAlg;

/// Stands in for settings that the customer's application loads.
struct AppConfig {
    key_namespace: String,
    key_name: String,
    branch_key_id: String,
    partition_id: String,
}

fn app_config() -> AppConfig {
    AppConfig {
        key_namespace: "my-key-namespace".to_string(),
        key_name: "my-key-name".to_string(),
        branch_key_id: "my-branch-key-id".to_string(),
        partition_id: "my-partition-id".to_string(),
    }
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
async fn dynamodb_key_store() -> DynamoDbKeyStore {
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

fn raw_aes_keyring() -> RawAesKeyring {
    RawAesKeyring::builder()
        .key_namespace("my-key-namespace")
        .key_name("my-key-name")
        .wrapping_key(vec![0x01; 32])
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()
        .expect("a raw AES keyring with every option set builds")
}

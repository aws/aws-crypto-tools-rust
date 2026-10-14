// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The errors real AWS KMS and DynamoDB failures produce, with the hierarchical keyring.
//!
//! Needs AWS credentials for the test account, like the other integration tests.

use std::time::Duration;

use aws_crypto_mpl::aws_config::{self, BehaviorVersion, Region};
use aws_crypto_mpl::aws_sdk_dynamodb;
use aws_crypto_mpl::aws_sdk_kms;
use aws_crypto_mpl::cmc::DefaultCmc;
use aws_crypto_mpl::error::ConflictReason;
use aws_crypto_mpl::structures::EncryptionContext;
use aws_crypto_mpl::{Discovery, HierarchicalKeyring, KeyStoreClient, KmsConfiguration};
use aws_esdk::Client;
use aws_esdk::error::{BranchKey, DynamoDbTable, Error, KmsKey, Resource, Service};

const TABLE: &str = "KeyStoreDdbTable";
const KMS_KEY_ARN: &str =
    "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126";
/// A branch key that exists in `TABLE`.
const BRANCH_KEY_ID: &str = "3f43a9af-08c5-4317-b694-3d3e883dcaef";
/// A key ID that does not exist in the test account.
const MISSING_KMS_KEY_ARN: &str =
    "arn:aws:kms:us-west-2:370957321024:key/00000000-0000-0000-0000-000000000000";
/// A key in another account, which the test account cannot use.
const OTHER_ACCOUNT_KMS_KEY_ARN: &str =
    "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f";

async fn sdk_config() -> aws_config::SdkConfig {
    aws_config::defaults(BehaviorVersion::latest())
        .region(Region::new("us-west-2"))
        .load()
        .await
}

async fn key_store(table: &str, kms_key_arn: &str) -> KeyStoreClient {
    let config = sdk_config().await;
    key_store_with(
        table,
        kms_key_arn,
        aws_sdk_kms::Client::new(&config),
        aws_sdk_dynamodb::Client::new(&config),
    )
    .await
}

async fn key_store_with(
    table: &str,
    kms_key_arn: &str,
    kms: aws_sdk_kms::Client,
    ddb: aws_sdk_dynamodb::Client,
) -> KeyStoreClient {
    KeyStoreClient::builder()
        .ddb_table_name(table)
        .logical_key_store_name(TABLE)
        .kms_configuration(KmsConfiguration::KmsKeyArn(kms_key_arn.into()))
        .kms_client(kms)
        .ddb_client(ddb)
        .build()
        .await
        .expect("the key store configuration is valid")
}

async fn encrypt_error(key_store: impl Into<KeyStoreClient>, branch_key_id: &str) -> Error {
    let keyring = HierarchicalKeyring::builder()
        .key_store(key_store)
        .branch_key_id(branch_key_id)
        .ttl(Duration::from_secs(600))
        .cache(
            DefaultCmc::builder()
                .entry_capacity(10)
                .build()
                .expect("a valid capacity"),
        )
        .build()
        .expect("the keyring configuration is valid");
    Client::default()
        .encrypt()
        .plaintext(b"hello")
        .keyring(keyring)
        .send()
        .await
        .expect_err("the AWS call fails")
}

fn random_id() -> String {
    format!(
        "missing-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )
}

#[tokio::test]
async fn integ_invalid_credentials_are_credentials() {
    let config = sdk_config().await;
    let credentials = aws_sdk_kms::config::Credentials::new(
        "AKIAIOSFODNN7EXAMPLE",
        "not-a-secret",
        None,
        None,
        "test",
    );
    let kms = aws_sdk_kms::Client::from_conf(
        aws_sdk_kms::config::Builder::from(&config)
            .credentials_provider(credentials.clone())
            .build(),
    );
    let ddb = aws_sdk_dynamodb::Client::from_conf(
        aws_sdk_dynamodb::config::Builder::from(&config)
            .credentials_provider(credentials)
            .build(),
    );
    let err = encrypt_error(
        key_store_with(TABLE, KMS_KEY_ARN, kms, ddb).await,
        BRANCH_KEY_ID,
    )
    .await;
    let Error::AccessDenied(e) = &err else {
        panic!("expected AccessDenied, got {err:?}");
    };
    assert!(e.is_credentials(), "{err:?}");
    assert_eq!(e.service(), Some(&Service::DynamoDb));
    assert_eq!(
        e.resource(),
        Some(&Resource::DynamoDbTable(DynamoDbTable::new(TABLE)))
    );
    assert!(e.request_id().is_some());
}

#[tokio::test]
async fn integ_a_missing_branch_key_names_the_branch_key() {
    let id = random_id();
    let err = encrypt_error(key_store(TABLE, KMS_KEY_ARN).await, &id).await;
    let Error::ResourceNotFound(e) = &err else {
        panic!("expected ResourceNotFound, got {err:?}");
    };
    assert_eq!(e.service(), Some(&Service::DynamoDb));
    assert_eq!(e.resource(), Some(&Resource::BranchKey(BranchKey::new(id))));
}

#[tokio::test]
async fn integ_a_missing_table_names_the_table() {
    // DynamoDB answers AccessDeniedException instead of ResourceNotFoundException
    // when the caller's permissions do not cover the table name.
    let table = random_id();
    let err = encrypt_error(key_store(&table, KMS_KEY_ARN).await, BRANCH_KEY_ID).await;
    let (service, resource) = match &err {
        Error::ResourceNotFound(e) => (e.service(), e.resource()),
        Error::AccessDenied(e) if !e.is_credentials() => (e.service(), e.resource()),
        _ => panic!("expected ResourceNotFound or AccessDenied, got {err:?}"),
    };
    assert_eq!(service, Some(&Service::DynamoDb));
    assert_eq!(
        resource,
        Some(&Resource::DynamoDbTable(DynamoDbTable::new(table)))
    );
    assert!(err.request_id().is_some());
}

#[tokio::test]
async fn integ_create_key_with_a_missing_kms_key_names_the_kms_key() {
    // AWS KMS answers AccessDeniedException instead of NotFoundException
    // when the caller's permissions do not cover the key ID.
    let err = key_store(TABLE, MISSING_KMS_KEY_ARN)
        .await
        .create_key()
        .send()
        .await
        .unwrap_err();
    let (service, resource) = match &err {
        aws_crypto_mpl::Error::ResourceNotFound(e) => (e.service(), e.resource()),
        aws_crypto_mpl::Error::AccessDenied(e) if !e.is_credentials() => {
            (e.service(), e.resource())
        }
        _ => panic!("expected ResourceNotFound or AccessDenied, got {err:?}"),
    };
    assert_eq!(service, Some(&Service::Kms));
    assert_eq!(
        resource,
        Some(&Resource::KmsKey(KmsKey::new(MISSING_KMS_KEY_ARN)))
    );
    assert!(err.request_id().is_some());
}

#[tokio::test]
async fn integ_create_key_with_another_accounts_kms_key_is_access_denied() {
    let err = key_store(TABLE, OTHER_ACCOUNT_KMS_KEY_ARN)
        .await
        .create_key()
        .send()
        .await
        .unwrap_err();
    let aws_crypto_mpl::Error::AccessDenied(e) = &err else {
        panic!("expected AccessDenied, got {err:?}");
    };
    assert!(!e.is_credentials());
    assert_eq!(e.service(), Some(&Service::Kms));
    assert_eq!(
        e.resource(),
        Some(&Resource::KmsKey(KmsKey::new(OTHER_ACCOUNT_KMS_KEY_ARN)))
    );
    assert_eq!(e.code(), Some("AccessDeniedException"));
    assert!(e.request_id().is_some());
}

#[tokio::test]
async fn integ_create_key_with_an_existing_id_is_an_already_exists_conflict() {
    let err = key_store(TABLE, KMS_KEY_ARN)
        .await
        .create_key()
        .branch_key_id(BRANCH_KEY_ID)
        .set_encryption_context(Some(EncryptionContext::from_iter([("purpose", "test")])))
        .send()
        .await
        .unwrap_err();
    let aws_crypto_mpl::Error::Conflict(e) = &err else {
        panic!("expected Conflict, got {err:?}");
    };
    assert_eq!(e.reason(), Some(&ConflictReason::AlreadyExists));
    assert_eq!(e.service(), Some(&Service::DynamoDb));
    assert_eq!(
        e.resource(),
        Some(&Resource::BranchKey(BranchKey::new(BRANCH_KEY_ID)))
    );
    assert_eq!(e.code(), Some("TransactionCanceledException"));
    assert!(e.request_id().is_some());
    assert!(!err.is_retryable());
}

/// A branch key whose record names a multi-Region key in us-east-1.
const EAST_BRANCH_KEY_ID: &str = "MyEastBranch2";
const EAST_MRK_ARN: &str =
    "arn:aws:kms:us-east-1:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7";

#[tokio::test]
async fn integ_a_discovery_key_store_names_the_kms_key_from_the_record() {
    // A discovery key store calls the KMS key the record names.
    // The us-west-2 client cannot use the us-east-1 key, so AWS KMS rejects it.
    let config = sdk_config().await;
    let key_store = KeyStoreClient::builder()
        .ddb_table_name(TABLE)
        .logical_key_store_name(TABLE)
        .kms_configuration(KmsConfiguration::Discovery(
            Discovery::builder().build().unwrap(),
        ))
        .kms_client(aws_sdk_kms::Client::new(&config))
        .ddb_client(aws_sdk_dynamodb::Client::new(&config))
        .build()
        .await
        .expect("the key store configuration is valid");
    let err = encrypt_error(key_store, EAST_BRANCH_KEY_ID).await;
    assert_eq!(err.service(), Some(&Service::Kms), "{err:?}");
    assert_eq!(
        err.resource(),
        Some(&Resource::KmsKey(KmsKey::new(EAST_MRK_ARN))),
        "{err:?}"
    );
    assert!(err.code().is_some(), "{err:?}");
    assert!(err.request_id().is_some(), "{err:?}");
}

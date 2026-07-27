// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Contract tests for the abstract `Keystore` trait.
//!
//! These tests verify the abstract `Keystore` trait shape via a `MockKeystore`.
//! They are intentionally NOT duvet-annotated — the corresponding requirements
//! are annotated as `type=exception` in `src/keystore/mod.rs` and will be
//! re-annotated as `type=implementation,test` once concrete keystores are added.

#![cfg(feature = "keystore")]

use async_trait::async_trait;

use aws_crypto_mpl::keystore::Keystore;
use aws_crypto_mpl::keystore::{
    KeyStoreConfig, KeyStoreInfo, KeystoreError, KeystoreErrorKind, KmsConfiguration,
};
use aws_crypto_mpl::structures::{BeaconKeyMaterials, BranchKeyMaterials, EncryptionContext};

/// A mock keystore that returns stub errors by default.
struct MockKeystore {
    config: KeyStoreConfig,
}

impl MockKeystore {
    fn new(config: KeyStoreConfig) -> Self {
        Self { config }
    }

    fn default_config() -> KeyStoreConfig {
        KeyStoreConfig {
            table_name: "test-table".to_string(),
            kms_configuration: KmsConfiguration::KmsKeyArn(
                "arn:aws:kms:us-east-1:123456789012:key/test-key-id".to_string(),
            ),
            logical_keystore_name: "test-logical-name".to_string(),
            keystore_id: Some("test-keystore-id".to_string()),
            aws_kms_grant_tokens: None,
        }
    }
}

#[async_trait]
impl Keystore for MockKeystore {
    async fn get_key_store_info(&self) -> Result<KeyStoreInfo, KeystoreError> {
        Ok(KeyStoreInfo {
            keystore_id: self
                .config
                .keystore_id
                .clone()
                .unwrap_or_else(|| "mock-id".to_string()),
            keystore_name: self.config.table_name.clone(),
            logical_keystore_name: self.config.logical_keystore_name.clone(),
            aws_kms_grant_tokens: self.config.aws_kms_grant_tokens.clone().unwrap_or_default(),
            aws_kms_configuration: self.config.kms_configuration.clone(),
        })
    }

    async fn create_key_store(&self) -> Result<String, KeystoreError> {
        Err(KeystoreError::new(
            KeystoreErrorKind::Internal,
            "MockKeystore: create_key_store not implemented",
        ))
    }

    async fn create_key(
        &self,
        _branch_key_id: Option<String>,
        _encryption_context: Option<EncryptionContext>,
    ) -> Result<String, KeystoreError> {
        Err(KeystoreError::new(
            KeystoreErrorKind::Internal,
            "MockKeystore: create_key not implemented",
        ))
    }

    async fn version_key(&self, _branch_key_id: String) -> Result<(), KeystoreError> {
        Err(KeystoreError::new(
            KeystoreErrorKind::Internal,
            "MockKeystore: version_key not implemented",
        ))
    }

    async fn get_active_branch_key(
        &self,
        _branch_key_id: String,
    ) -> Result<BranchKeyMaterials, KeystoreError> {
        Err(KeystoreError::new(
            KeystoreErrorKind::Internal,
            "MockKeystore: get_active_branch_key not implemented",
        ))
    }

    async fn get_branch_key_version(
        &self,
        _branch_key_id: String,
        _branch_key_version: String,
    ) -> Result<BranchKeyMaterials, KeystoreError> {
        Err(KeystoreError::new(
            KeystoreErrorKind::Internal,
            "MockKeystore: get_branch_key_version not implemented",
        ))
    }

    async fn get_beacon_key(
        &self,
        _branch_key_id: String,
    ) -> Result<BeaconKeyMaterials, KeystoreError> {
        Err(KeystoreError::new(
            KeystoreErrorKind::Internal,
            "MockKeystore: get_beacon_key not implemented",
        ))
    }
}

#[tokio::test]
async fn mock_keystore_satisfies_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<MockKeystore>();
    assert_send_sync::<Box<dyn Keystore>>();
}

#[tokio::test]
async fn keystore_can_be_boxed_dyn() {
    let config = MockKeystore::default_config();
    let _boxed: Box<dyn Keystore> = Box::new(MockKeystore::new(config));
}

#[tokio::test]
async fn keystore_get_key_store_info_returns_configured_values() {
    let config = MockKeystore::default_config();
    let ks = MockKeystore::new(config.clone());
    let info = ks.get_key_store_info().await.unwrap();
    assert_eq!(info.keystore_id, "test-keystore-id");
    assert_eq!(info.keystore_name, "test-table");
    assert_eq!(info.logical_keystore_name, "test-logical-name");
    assert!(info.aws_kms_grant_tokens.is_empty());
}

#[tokio::test]
async fn keystore_create_key_store_returns_error() {
    let ks = MockKeystore::new(MockKeystore::default_config());
    let err = ks.create_key_store().await.unwrap_err();
    assert_eq!(err.kind, KeystoreErrorKind::Internal);
}

#[tokio::test]
async fn keystore_create_key_returns_error() {
    let ks = MockKeystore::new(MockKeystore::default_config());
    let err = ks.create_key(None, None).await.unwrap_err();
    assert_eq!(err.kind, KeystoreErrorKind::Internal);
}

#[tokio::test]
async fn keystore_version_key_returns_error() {
    let ks = MockKeystore::new(MockKeystore::default_config());
    let err = ks
        .version_key("test-branch-key-id".to_string())
        .await
        .unwrap_err();
    assert_eq!(err.kind, KeystoreErrorKind::Internal);
}

#[tokio::test]
async fn keystore_get_active_branch_key_returns_error() {
    let ks = MockKeystore::new(MockKeystore::default_config());
    let err = ks
        .get_active_branch_key("test-branch-key-id".to_string())
        .await
        .unwrap_err();
    assert_eq!(err.kind, KeystoreErrorKind::Internal);
}

#[tokio::test]
async fn keystore_get_branch_key_version_returns_error() {
    let ks = MockKeystore::new(MockKeystore::default_config());
    let err = ks
        .get_branch_key_version("test-branch-key-id".to_string(), "v1".to_string())
        .await
        .unwrap_err();
    assert_eq!(err.kind, KeystoreErrorKind::Internal);
}

#[tokio::test]
async fn keystore_get_beacon_key_returns_error() {
    let ks = MockKeystore::new(MockKeystore::default_config());
    let err = ks
        .get_beacon_key("test-branch-key-id".to_string())
        .await
        .unwrap_err();
    assert_eq!(err.kind, KeystoreErrorKind::Internal);
}

#[tokio::test]
async fn kms_configuration_variants_construct() {
    let _key_arn = KmsConfiguration::KmsKeyArn("arn:aws:kms:us-east-1:111:key/abc".to_string());
    let _mr_key =
        KmsConfiguration::KmsMrKeyArn("arn:aws:kms:us-east-1:111:key/mrk-abc".to_string());
    let _discovery = KmsConfiguration::Discovery;
    let _mr_discovery = KmsConfiguration::MrDiscovery {
        region: "us-west-2".to_string(),
    };
}

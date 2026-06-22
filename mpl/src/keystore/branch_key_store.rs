// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! `BranchKeyStore` — concrete [`Keystore`] implementation backed by AWS KMS
//! and Amazon DynamoDB.
//!
//! This is slice 1a of the master keystore plan: construction surface and
//! the pure (no-IO) `GetKeyStoreInfo` operation only. `CreateKeyStore`,
//! `CreateKey`, `VersionKey`, `GetActiveBranchKey`, `GetBranchKeyVersion`,
//! and `GetBeaconKey` return an explicit "not yet implemented in this
//! slice" `KeystoreError` and will be filled in by subsequent slices in
//! the order:
//!
//! - 1b: `authenticating-a-keystore-item` helper (KMS `ReEncrypt`) +
//!   `aws-kms-branch-key-decryption` helper (KMS `Decrypt`).
//! - 1c: `get_active_branch_key` and `get_branch_key_version` (DDB
//!   `GetItem` + the helpers from 1b).
//! - 1d: real-SDK adapters / default-client constructors (the spec's
//!   "If no DynamoDb/KMS Client is provided, a new client MUST be
//!   created with region X" clauses).
//! - 1e: `create_key` (KMS `GenerateDataKeyWithoutPlaintext` + DDB
//!   `TransactWriteItems`).
//! - 1f: `version_key` (KMS `Decrypt` + `ReEncrypt` of ACTIVE under a
//!   fresh version + DDB `TransactWriteItems`).

use async_trait::async_trait;
use aws_lc_rs::rand::fill;
use aws_sdk_dynamodb::Client as DynamoDbClient;
use aws_sdk_kms::Client as KmsClient;

use crate::keystore::Keystore;
use crate::keystore::config::{KeyStoreConfig, KeyStoreInfo};
use crate::keystore::error::{KeystoreError, KeystoreErrorKind};
use crate::structures::{BeaconKeyMaterials, BranchKeyMaterials, EncryptionContext};

/// Concrete `Keystore` implementation backed by AWS KMS + Amazon DynamoDB.
///
/// Construct with [`BranchKeyStore::new`], passing an already-configured
/// pair of `aws_sdk_kms::Client` and `aws_sdk_dynamodb::Client`. The
/// keystore validates the [`KmsConfiguration`](crate::keystore::config::KmsConfiguration)
/// at construction time and resolves the optional caller-supplied
/// `keystore_id` against a freshly-generated v4 UUID per
/// `branch-key-store.md#keystore-id`.
pub struct BranchKeyStore {
    /// Caller-supplied configuration. Recorded once at construction; the
    /// keystore never mutates this field.
    config: KeyStoreConfig,
    /// AWS KMS client used by `Decrypt`, `ReEncrypt`, and
    /// `GenerateDataKeyWithoutPlaintext` calls. Held but not yet read in
    /// slice 1a — operations that consume it land in slices 1b/1e/1f.
    #[allow(dead_code)]
    kms_client: KmsClient,
    /// Amazon DynamoDB client used by `GetItem` and `TransactWriteItems`
    /// calls against the configured `table_name`. Held but not yet read
    /// in slice 1a — operations that consume it land in slices 1c/1e/1f.
    #[allow(dead_code)]
    ddb_client: DynamoDbClient,
    /// Resolved keystore identifier — either the caller-supplied value
    /// from `config.keystore_id`, or a freshly-generated v4 UUID when the
    /// caller passed `None`.
    keystore_id: String,
}

impl BranchKeyStore {
    /// Construct a new `BranchKeyStore`.
    ///
    /// Validates the KMS configuration ARN (when applicable) and resolves
    /// the keystore id. Both AWS clients are taken by value and stored
    /// verbatim — callers are responsible for any user-agent customization
    /// or region pinning before passing the clients in.
    ///
    /// Returns `KeystoreError::Configuration` if the KMS configuration is
    /// invalid (malformed ARN, alias, non-`kms` service).
    //= ../spec/framework/branch-key-store.md#kms-client
    //= type=todo
    //= tracking-issue=keystore-user-agent
    //# On initialization the KeyStore SHOULD
    //# append a user agent string to the AWS KMS SDK Client with
    //# the value `aws-kms-hierarchy`.
    pub fn new(
        config: KeyStoreConfig,
        kms_client: KmsClient,
        ddb_client: DynamoDbClient,
    ) -> Result<Self, KeystoreError> {
        // Validate the KMS configuration's ARN at construction time so a
        // malformed ARN fails before any operation is dispatched.
        config.kms_configuration.validate()?;

        let keystore_id = match config.keystore_id.clone() {
            Some(id) => id,
            //= ../spec/framework/branch-key-store.md#keystore-id
            //# If one is not supplied, then a [version 4 UUID](https://www.ietf.org/rfc/rfc4122.txt) MUST be used.
            None => generate_v4_uuid_string()?,
        };

        Ok(Self {
            config,
            kms_client,
            ddb_client,
            keystore_id,
        })
    }

    /// Returns the resolved keystore identifier — either caller-supplied
    /// or the v4 UUID generated at construction.
    pub fn keystore_id(&self) -> &str {
        &self.keystore_id
    }
}

#[async_trait]
impl Keystore for BranchKeyStore {
    async fn get_key_store_info(&self) -> Result<KeyStoreInfo, KeystoreError> {
        Ok(KeyStoreInfo {
            keystore_id: self.keystore_id.clone(),
            keystore_name: self.config.table_name.clone(),
            logical_keystore_name: self.config.logical_keystore_name.clone(),
            aws_kms_grant_tokens: self.config.aws_kms_grant_tokens.clone().unwrap_or_default(),
            aws_kms_configuration: self.config.kms_configuration.clone(),
        })
    }

    async fn create_key_store(&self) -> Result<String, KeystoreError> {
        Err(not_implemented_yet("create_key_store"))
    }

    async fn create_key(
        &self,
        _branch_key_id: Option<String>,
        _encryption_context: Option<EncryptionContext>,
    ) -> Result<String, KeystoreError> {
        Err(not_implemented_yet("create_key"))
    }

    async fn version_key(&self, _branch_key_id: String) -> Result<(), KeystoreError> {
        Err(not_implemented_yet("version_key"))
    }

    async fn get_active_branch_key(
        &self,
        _branch_key_id: String,
    ) -> Result<BranchKeyMaterials, KeystoreError> {
        Err(not_implemented_yet("get_active_branch_key"))
    }

    async fn get_branch_key_version(
        &self,
        _branch_key_id: String,
        _branch_key_version: String,
    ) -> Result<BranchKeyMaterials, KeystoreError> {
        Err(not_implemented_yet("get_branch_key_version"))
    }

    async fn get_beacon_key(
        &self,
        _branch_key_id: String,
    ) -> Result<BeaconKeyMaterials, KeystoreError> {
        Err(not_implemented_yet("get_beacon_key"))
    }
}

/// Build the slice-1a "operation not yet implemented" error. Replaced
/// with real implementations by the slice that owns each operation.
fn not_implemented_yet(op: &str) -> KeystoreError {
    KeystoreError::new(
        KeystoreErrorKind::Internal,
        format!("BranchKeyStore::{op} is not yet implemented in this slice"),
    )
}

/// Generate the canonical 36-character (8-4-4-4-12) hex string
/// representation of a fresh v4 UUID using the `aws_lc_rs` CSPRNG, with
/// version and variant bits set per RFC 4122 §4.4.
fn generate_v4_uuid_string() -> Result<String, KeystoreError> {
    let mut bytes = [0u8; 16];
    fill(&mut bytes).map_err(|_| {
        KeystoreError::new(
            KeystoreErrorKind::Internal,
            "BranchKeyStore: failed to obtain entropy for v4-UUID keystore-id",
        )
    })?;
    // RFC 4122 §4.4: set the version (top 4 bits of byte 6) to 0b0100 (4).
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    // RFC 4122 §4.4: set the variant (top 2 bits of byte 8) to 0b10.
    bytes[8] = (bytes[8] & 0x3F) | 0x80;

    let mut s = String::with_capacity(36);
    for (i, &b) in bytes.iter().enumerate() {
        if i == 4 || i == 6 || i == 8 || i == 10 {
            s.push('-');
        }
        s.push_str(&format!("{b:02x}"));
    }
    Ok(s)
}

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

use std::collections::BTreeMap;

use async_trait::async_trait;
use aws_sdk_dynamodb::Client as DynamoDbClient;
use aws_sdk_dynamodb::primitives::Blob;
use aws_sdk_dynamodb::types::AttributeValue;
use aws_sdk_kms::Client as KmsClient;
use uuid::Uuid;

use crate::keystore::Keystore;
use crate::keystore::config::{KeyStoreConfig, KeyStoreInfo};
use crate::keystore::error::{KeystoreError, KeystoreErrorKind};
use crate::keystore::kms_ops::decrypt_branch_key;
use crate::keystore::record::{
    EncryptedRecord, FIELD_BRANCH_KEY_ID, FIELD_ENC, FIELD_TYPE, TYPE_BRANCH_ACTIVE,
    TYPE_BRANCH_VERSION_PREFIX, branch_key_materials_from_authenticated_encryption_context,
};
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
    /// `GenerateDataKeyWithoutPlaintext` calls.
    kms_client: KmsClient,
    /// Amazon DynamoDB client used by `GetItem` and `TransactWriteItems`
    /// calls against the configured `table_name`.
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
            None => Uuid::new_v4().to_string(),
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

    /// Borrow the configured grant tokens (or an empty slice if `None`).
    fn grant_tokens(&self) -> &[String] {
        self.config.aws_kms_grant_tokens.as_deref().unwrap_or(&[])
    }

    /// Build the authenticated encryption context for a fetched record.
    /// All record attributes are echoed verbatim and `tablename` is bound
    /// to the configured logical keystore name. The `enc` ciphertext is
    /// not part of the EC by `EncryptedRecord`'s shape.
    fn build_auth_ec(&self, record: &EncryptedRecord) -> BTreeMap<String, String> {
        let mut ec = record.attributes.clone();
        ec.insert(
            "tablename".to_string(),
            self.config.logical_keystore_name.clone(),
        );
        ec
    }

    /// Fetch a single keystore record by `(branch-key-id, type)` from
    /// the configured DynamoDB table.
    ///
    /// Errors:
    /// - `KeystoreErrorKind::Dynamodb` — the SDK call itself failed
    ///   (network, credentials, throttling, etc.).
    /// - `KeystoreErrorKind::RecordNotFound` — the GetItem call
    ///   succeeded but returned no item.
    /// - `KeystoreErrorKind::RecordMalformed` — the item is missing a
    ///   required attribute or has an unexpected shape.
    async fn fetch_record(
        &self,
        branch_key_id: &str,
        sort_key: &str,
    ) -> Result<EncryptedRecord, KeystoreError> {
        let response = self
            .ddb_client
            .get_item()
            .table_name(&self.config.table_name)
            .key(
                FIELD_BRANCH_KEY_ID,
                AttributeValue::S(branch_key_id.to_string()),
            )
            .key(FIELD_TYPE, AttributeValue::S(sort_key.to_string()))
            .send()
            .await
            .map_err(|e| {
                KeystoreError::new(
                    KeystoreErrorKind::Dynamodb,
                    format!("DynamoDB GetItem failed: {e}"),
                )
            })?;

        let item = response.item.ok_or_else(|| {
            KeystoreError::new(
                KeystoreErrorKind::RecordNotFound,
                format!("No keystore record for branch-key-id={branch_key_id}, type={sort_key}",),
            )
        })?;

        record_from_ddb_item(item)
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
        branch_key_id: String,
    ) -> Result<BranchKeyMaterials, KeystoreError> {
        //= ../spec/framework/branch-key-store.md#getactivebranchkey
        //# To get the active version for the branch key id from the keystore
        //# this operation MUST call AWS DDB `GetItem`
        //# using the `branch-key-id` as the Partition Key and `"branch:ACTIVE"` value as the Sort Key.
        let record = self
            .fetch_record(&branch_key_id, TYPE_BRANCH_ACTIVE)
            .await?;

        //= ../spec/framework/branch-key-store.md#getactivebranchkey
        //# The operation MUST decrypt the branch key according to the [AWS KMS Branch Key Decryption](#aws-kms-branch-key-decryption) section.
        let plaintext = decrypt_branch_key(
            &self.kms_client,
            &self.config.kms_configuration,
            &record,
            &self.config.logical_keystore_name,
            self.grant_tokens(),
        )
        .await?;

        let auth_ec = self.build_auth_ec(&record);

        //= ../spec/framework/branch-key-store.md#getactivebranchkey
        //# This GetActiveBranchKey MUST construct [branch key materials](./structures.md#branch-key-materials)
        //# according to [Branch Key Materials From Authenticated Encryption Context](#branch-key-materials-from-authenticated-encryption-context).
        //
        //= ../spec/framework/branch-key-store.md#getactivebranchkey
        //# This operation MUST return the constructed [branch key materials](./structures.md#branch-key-materials).
        branch_key_materials_from_authenticated_encryption_context(&auth_ec, plaintext)
    }

    async fn get_branch_key_version(
        &self,
        branch_key_id: String,
        branch_key_version: String,
    ) -> Result<BranchKeyMaterials, KeystoreError> {
        //= ../spec/framework/branch-key-store.md#getbranchkeyversion
        //# To get a branch key from the keystore this operation MUST call AWS DDB `GetItem`
        //# using the `branch-key-id` as the Partition Key and "branch:version:" + `branchKeyVersion` value as the Sort Key.
        let sort_key = format!("{TYPE_BRANCH_VERSION_PREFIX}{branch_key_version}");
        let record = self.fetch_record(&branch_key_id, &sort_key).await?;

        //= ../spec/framework/branch-key-store.md#getbranchkeyversion
        //# The operation MUST decrypt the branch key according to the [AWS KMS Branch Key Decryption](#aws-kms-branch-key-decryption) section.
        let plaintext = decrypt_branch_key(
            &self.kms_client,
            &self.config.kms_configuration,
            &record,
            &self.config.logical_keystore_name,
            self.grant_tokens(),
        )
        .await?;

        let auth_ec = self.build_auth_ec(&record);

        //= ../spec/framework/branch-key-store.md#getbranchkeyversion
        //# This GetBranchKeyVersion MUST construct [branch key materials](./structures.md#branch-key-materials)
        //# according to [Branch Key Materials From Authenticated Encryption Context](#branch-key-materials-from-authenticated-encryption-context).
        //
        //= ../spec/framework/branch-key-store.md#getbranchkeyversion
        //# This operation MUST return the constructed [branch key materials](./structures.md#branch-key-materials).
        branch_key_materials_from_authenticated_encryption_context(&auth_ec, plaintext)
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

/// Convert a DynamoDB GetItem response item into an [`EncryptedRecord`].
///
/// The branch-key-store record format defines `enc` as a binary
/// attribute and all other attributes as strings. Non-string attributes
/// other than `enc` are rejected as `RecordMalformed`.
fn record_from_ddb_item(
    mut item: std::collections::HashMap<String, AttributeValue>,
) -> Result<EncryptedRecord, KeystoreError> {
    //= ../spec/framework/branch-key-store.md#getactivebranchkey
    //# The AWS DDB response MUST contain the fields defined in the [branch keystore record format](#record-format).
    //
    //= ../spec/framework/branch-key-store.md#getbranchkeyversion
    //# The AWS DDB response MUST contain the fields defined in the [branch keystore record format](#record-format).
    let enc_attr = item.remove(FIELD_ENC).ok_or_else(|| {
        //= ../spec/framework/branch-key-store.md#getactivebranchkey
        //# If the record does not contain the defined fields, this operation MUST fail.
        //
        //= ../spec/framework/branch-key-store.md#getbranchkeyversion
        //# If the record does not contain the defined fields, this operation MUST fail.
        KeystoreError::new(
            KeystoreErrorKind::RecordMalformed,
            format!("Record is missing the '{FIELD_ENC}' attribute"),
        )
    })?;

    let enc_blob: Blob = match enc_attr {
        AttributeValue::B(b) => b,
        other => {
            return Err(KeystoreError::new(
                KeystoreErrorKind::RecordMalformed,
                format!("Record '{FIELD_ENC}' attribute must be Binary, got {other:?}",),
            ));
        }
    };

    let mut attributes: BTreeMap<String, String> = BTreeMap::new();
    for (k, v) in item {
        match v {
            AttributeValue::S(s) => {
                attributes.insert(k, s);
            }
            other => {
                return Err(KeystoreError::new(
                    KeystoreErrorKind::RecordMalformed,
                    format!("Record attribute '{k}' must be String, got {other:?}",),
                ));
            }
        }
    }

    Ok(EncryptedRecord {
        attributes,
        enc: enc_blob.into_inner(),
    })
}

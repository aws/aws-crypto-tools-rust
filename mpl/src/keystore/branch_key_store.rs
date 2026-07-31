// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! `BranchKeyStore` — concrete [`Keystore`] implementation backed by AWS KMS
//! and Amazon DynamoDB.
//!
//! Construct with [`BranchKeyStore::new`], which takes a [`KeyStoreConfig`].
//! The KMS and DynamoDB clients are optional config inputs; when omitted, a
//! default client is built using the Region parsed from the configured KMS
//! ARN, per `branch-key-store.md`.

use std::collections::BTreeMap;

use async_trait::async_trait;
use aws_config::{BehaviorVersion, Region};
use aws_sdk_dynamodb::Client as DynamoDbClient;
use aws_sdk_dynamodb::primitives::Blob;
use aws_sdk_dynamodb::types::AttributeValue;
use aws_sdk_kms::Client as KmsClient;
use uuid::Uuid;

use crate::keystore::Keystore;
use crate::keystore::attributes::{
    ATTR_BRANCH_KEY_ID, ATTR_ENC, ATTR_TYPE, TYPE_BRANCH_ACTIVE, TYPE_BRANCH_VERSION_PREFIX,
};
use crate::keystore::config::{KeyStoreConfig, KeyStoreInfo, KmsConfiguration};
use crate::keystore::error::{KeystoreError, KeystoreErrorKind};
use crate::keystore::kms_config::parse_arn;
use crate::keystore::kms_ops::decrypt_branch_key;
use crate::keystore::record::{
    EncryptedRecord, branch_key_materials_from_authenticated_encryption_context,
};
use crate::structures::{BeaconKeyMaterials, BranchKeyMaterials, EncryptionContext};

/// Concrete `Keystore` implementation backed by AWS KMS + Amazon DynamoDB.
///
/// Construct with [`BranchKeyStore::new`] from a [`KeyStoreConfig`]. The KMS
/// and DynamoDB clients are optional config inputs; when omitted, a default
/// client is built from the Region parsed from the configured KMS ARN. The
/// keystore validates the [`KmsConfiguration`](crate::keystore::config::KmsConfiguration)
/// at construction time and resolves the optional caller-supplied
/// `id` against a freshly-generated v4 UUID per
/// `branch-key-store.md#keystore-id`.
pub struct BranchKeyStore {
    /// Caller-supplied configuration. Recorded once at construction; the
    /// keystore never mutates this field.
    config: KeyStoreConfig,
    /// Resolved AWS KMS client used by `Decrypt`, `ReEncrypt`, and
    /// `GenerateDataKeyWithoutPlaintext` calls.
    kms_client: KmsClient,
    /// Resolved Amazon DynamoDB client used by `GetItem` and
    /// `TransactWriteItems` calls against the configured `ddb_table_name`.
    ddb_client: DynamoDbClient,
    /// Resolved keystore identifier — either the caller-supplied value
    /// from `config.id`, or a freshly-generated v4 UUID when the
    /// caller passed `None`.
    keystore_id: String,
}

impl BranchKeyStore {
    /// Construct a new `BranchKeyStore` from a [`KeyStoreConfig`].
    ///
    /// Validates the KMS configuration ARN (when applicable) and resolves
    /// the keystore id (caller-supplied `config.id`, else a fresh v4 UUID).
    /// For each of the KMS and DynamoDB clients, the caller-supplied client
    /// in the config is used when present; otherwise a default client is
    /// built using the Region parsed from the configured KMS ARN (the SDK's
    /// default region provider chain is used for `Discovery`).
    ///
    /// Returns `KeystoreError::Configuration` if the KMS configuration is
    /// invalid (malformed ARN, alias, non-`kms` service).
    pub async fn new(config: KeyStoreConfig) -> Result<Self, KeystoreError> {
        // Validate the KMS configuration's ARN at construction time so a
        // malformed ARN fails before any operation is dispatched.
        config.kms_configuration.validate()?;

        let keystore_id = config
            .id
            .clone()
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        // Resolve clients: caller-supplied where present, otherwise a
        // default client built from the Region in the KMS ARN.
        let (kms_client, ddb_client) = match (config.kms_client.clone(), config.ddb_client.clone())
        {
            (Some(kms), Some(ddb)) => (kms, ddb),
            (maybe_kms, maybe_ddb) => {
                let sdk_config = default_sdk_config(&config.kms_configuration).await;
                let kms = maybe_kms.unwrap_or_else(|| KmsClient::new(&sdk_config));
                let ddb = maybe_ddb.unwrap_or_else(|| DynamoDbClient::new(&sdk_config));
                (kms, ddb)
            }
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
        self.config.grant_tokens.as_deref().unwrap_or(&[])
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
            .table_name(&self.config.ddb_table_name)
            .key(
                ATTR_BRANCH_KEY_ID,
                AttributeValue::S(branch_key_id.to_string()),
            )
            .key(ATTR_TYPE, AttributeValue::S(sort_key.to_string()))
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
            keystore_name: self.config.ddb_table_name.clone(),
            logical_keystore_name: self.config.logical_keystore_name.clone(),
            grant_tokens: self.config.grant_tokens.clone().unwrap_or_default(),
            kms_configuration: self.config.kms_configuration.clone(),
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
        let record = self
            .fetch_record(&branch_key_id, TYPE_BRANCH_ACTIVE)
            .await?;

        let plaintext = decrypt_branch_key(
            &self.kms_client,
            &self.config.kms_configuration,
            &record,
            &self.config.logical_keystore_name,
            self.grant_tokens(),
        )
        .await?;

        let auth_ec = self.build_auth_ec(&record);

        branch_key_materials_from_authenticated_encryption_context(&auth_ec, plaintext)
    }

    async fn get_branch_key_version(
        &self,
        branch_key_id: String,
        branch_key_version: String,
    ) -> Result<BranchKeyMaterials, KeystoreError> {
        let sort_key = format!("{TYPE_BRANCH_VERSION_PREFIX}{branch_key_version}");
        let record = self.fetch_record(&branch_key_id, &sort_key).await?;

        let plaintext = decrypt_branch_key(
            &self.kms_client,
            &self.config.kms_configuration,
            &record,
            &self.config.logical_keystore_name,
            self.grant_tokens(),
        )
        .await?;

        let auth_ec = self.build_auth_ec(&record);

        branch_key_materials_from_authenticated_encryption_context(&auth_ec, plaintext)
    }

    async fn get_beacon_key(
        &self,
        _branch_key_id: String,
    ) -> Result<BeaconKeyMaterials, KeystoreError> {
        Err(not_implemented_yet("get_beacon_key"))
    }
}

/// Build the "operation not yet implemented" error returned by the
/// keystore operations that are not yet implemented.
fn not_implemented_yet(op: &str) -> KeystoreError {
    KeystoreError::new(
        KeystoreErrorKind::Internal,
        format!("BranchKeyStore::{op} is not yet implemented"),
    )
}

/// Determine the Region for a default client from the KMS configuration:
/// the Region in the KMS ARN for the ARN-based variants, the explicit
/// region for `MrDiscovery`, and `None` for `Discovery` (in which case the
/// SDK's default region provider chain is used).
fn region_from_kms_config(config: &KmsConfiguration) -> Option<String> {
    match config {
        KmsConfiguration::KmsKeyArn(arn) | KmsConfiguration::KmsMrKeyArn(arn) => {
            parse_arn(arn).ok().map(|parts| parts.region)
        }
        KmsConfiguration::MrDiscovery { region } => Some(region.clone()),
        KmsConfiguration::Discovery => None,
    }
}

/// Build a default [`aws_config::SdkConfig`] for constructing KMS / DynamoDB
/// clients, pinning the Region parsed from the KMS configuration when
/// available.
async fn default_sdk_config(config: &KmsConfiguration) -> aws_config::SdkConfig {
    let loader = aws_config::defaults(BehaviorVersion::latest());
    match region_from_kms_config(config) {
        Some(region) => loader.region(Region::new(region)).load().await,
        None => loader.load().await,
    }
}

/// Convert a DynamoDB GetItem response item into an [`EncryptedRecord`].
///
/// The branch-key-store record format defines `enc` as a binary
/// attribute and all other attributes as strings. Non-string attributes
/// other than `enc` are rejected as `RecordMalformed`.
fn record_from_ddb_item(
    mut item: std::collections::HashMap<String, AttributeValue>,
) -> Result<EncryptedRecord, KeystoreError> {
    let enc_attr = item.remove(ATTR_ENC).ok_or_else(|| {
        KeystoreError::new(
            KeystoreErrorKind::RecordMalformed,
            format!("Record is missing the '{ATTR_ENC}' attribute"),
        )
    })?;

    let enc_blob: Blob = match enc_attr {
        AttributeValue::B(b) => b,
        other => {
            return Err(KeystoreError::new(
                KeystoreErrorKind::RecordMalformed,
                format!("Record '{ATTR_ENC}' attribute must be Binary, got {other:?}",),
            ));
        }
    };

    let mut attributes: BTreeMap<String, String> = BTreeMap::new();
    for (k, v) in item {
        match v {
            // String attributes (branch-key-id, type, version, kms-arn,
            // create-time, custom-ec keys) are echoed verbatim.
            AttributeValue::S(s) => {
                attributes.insert(k, s);
            }
            // Number attributes (notably `hierarchy-version`) are stored
            // by DDB as decimal strings; carry that string through. The
            // EC bound on the encrypt side stringifies Numbers the same
            // way (see `keystore::encryption_context::build_base`), so
            // round-tripping the decimal string preserves the EC bound
            // through KMS.
            AttributeValue::N(n) => {
                attributes.insert(k, n);
            }
            other => {
                return Err(KeystoreError::new(
                    KeystoreErrorKind::RecordMalformed,
                    format!("Record attribute '{k}' must be String or Number, got {other:?}",),
                ));
            }
        }
    }

    Ok(EncryptedRecord {
        attributes,
        enc: enc_blob.into_inner(),
    })
}

// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! `BranchKeyStore` — concrete [`Keystore`] implementation backed by AWS KMS
//! and Amazon DynamoDB.
//!
//! Construct with [`BranchKeyStore::new`], which takes a [`KeyStoreConfig`].
//! The KMS and DynamoDB clients are optional config inputs; when omitted, a
//! default client is built using the Region parsed from the configured KMS
//! ARN, per `branch-key-store.md`.

use std::collections::{BTreeMap, HashMap};

use async_trait::async_trait;
use aws_config::{BehaviorVersion, Region};
use aws_sdk_dynamodb::Client as DynamoDbClient;
use aws_sdk_dynamodb::operation::describe_table::DescribeTableError;
use aws_sdk_dynamodb::primitives::Blob;
use aws_sdk_dynamodb::types::{
    AttributeDefinition, AttributeValue, BillingMode, KeySchemaElement, KeyType, Put,
    ScalarAttributeType, TableDescription, TransactWriteItem,
};
use aws_sdk_kms::Client as KmsClient;
use time::OffsetDateTime;
use time::macros::format_description;
use uuid::Uuid;

use crate::keystore::Keystore;
use crate::keystore::attributes::{
    ATTR_BRANCH_KEY_ID, ATTR_ENC, ATTR_HIERARCHY_VERSION, ATTR_TABLENAME, ATTR_TYPE,
    TYPE_BRANCH_ACTIVE, TYPE_BRANCH_VERSION_PREFIX,
};
use crate::keystore::config::{KeyStoreConfig, KeyStoreInfo, KmsConfiguration};
use crate::keystore::encryption_context::{
    EncryptionContextInput, active_encryption_context, beacon_key_encryption_context,
    decrypt_only_encryption_context,
};
use crate::keystore::error::{KeystoreError, KeystoreErrorKind};
use crate::keystore::kms_config::parse_arn;
use crate::keystore::kms_ops::{decrypt_branch_key, generate_wrapped_key, reencrypt_wrapped_key};
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
    /// Caller-supplied configuration, with the KMS and DynamoDB clients
    /// resolved to concrete instances at construction (any `None` client
    /// is replaced with a default built from the KMS ARN region).
    config: KeyStoreConfig,
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
    /// default region provider chain is used for `Discovery`) and stored
    /// back into the config.
    ///
    /// Returns `KeystoreError::Configuration` if the KMS configuration is
    /// invalid (malformed ARN, alias, non-`kms` service).
    pub async fn new(mut config: KeyStoreConfig) -> Result<Self, KeystoreError> {
        // Validate the KMS configuration's ARN at construction time so a
        // malformed ARN fails before any operation is dispatched.
        config.kms_configuration.validate()?;

        let keystore_id = config
            .id
            .clone()
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        // Resolve any absent client to a default built from the Region in
        // the KMS ARN, storing it back into the config so the config always
        // holds concrete clients after construction.
        if config.kms_client.is_none() || config.ddb_client.is_none() {
            let sdk_config = default_sdk_config(&config.kms_configuration).await;
            if config.kms_client.is_none() {
                config.kms_client = Some(KmsClient::new(&sdk_config));
            }
            if config.ddb_client.is_none() {
                config.ddb_client = Some(DynamoDbClient::new(&sdk_config));
            }
        }

        Ok(Self {
            config,
            keystore_id,
        })
    }

    /// The resolved AWS KMS client. Guaranteed present after construction.
    fn kms_client(&self) -> &KmsClient {
        self.config
            .kms_client
            .as_ref()
            .expect("kms_client is resolved during construction")
    }

    /// The resolved Amazon DynamoDB client. Guaranteed present after
    /// construction.
    fn ddb_client(&self) -> &DynamoDbClient {
        self.config
            .ddb_client
            .as_ref()
            .expect("ddb_client is resolved during construction")
    }

    /// The single configured KMS Key ARN. `CreateKey` / `VersionKey`
    /// require a single-key configuration; `Discovery` / `MRDiscovery`
    /// have no single ARN to wrap under and are rejected.
    fn configured_kms_key_arn(&self) -> Result<&str, KeystoreError> {
        match &self.config.kms_configuration {
            KmsConfiguration::KmsKeyArn(arn) | KmsConfiguration::KmsMrKeyArn(arn) => Ok(arn),
            KmsConfiguration::Discovery | KmsConfiguration::MrDiscovery { .. } => {
                Err(KeystoreError::new(
                    KeystoreErrorKind::Configuration,
                    "operation requires a single-key KMS configuration (KmsKeyArn or \
                     KmsMrKeyArn); Discovery and MRDiscovery are not supported",
                ))
            }
        }
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
            .ddb_client()
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
        let table_name = &self.config.ddb_table_name;

        // Per branch-key-store.md#createkeystore: first DescribeTable.
        match self
            .ddb_client()
            .describe_table()
            .table_name(table_name)
            .send()
            .await
        {
            // Table exists: validate it has the expected KeySchema, then
            // return its ARN.
            Ok(resp) => {
                let table = resp.table().ok_or_else(|| {
                    KeystoreError::new(
                        KeystoreErrorKind::Dynamodb,
                        "DescribeTable succeeded but returned no table description",
                    )
                })?;
                if !table_has_expected_schema(table) {
                    return Err(KeystoreError::new(
                        KeystoreErrorKind::Configuration,
                        format!(
                            "Table '{table_name}' does not conform to the expected Key Store KeySchema"
                        ),
                    ));
                }
                table_arn(table, table_name)
            }
            // ResourceNotFoundException: create the table with the expected
            // schema. Any other error is surfaced as a DynamoDB error.
            Err(err) => {
                let is_not_found = err
                    .as_service_error()
                    .is_some_and(DescribeTableError::is_resource_not_found_exception);
                if !is_not_found {
                    return Err(KeystoreError::new(
                        KeystoreErrorKind::Dynamodb,
                        format!("DynamoDB DescribeTable failed: {err}"),
                    ));
                }

                let resp = self
                    .ddb_client()
                    .create_table()
                    .table_name(table_name)
                    .set_attribute_definitions(Some(expected_attribute_definitions()?))
                    .set_key_schema(Some(expected_key_schema()?))
                    .billing_mode(BillingMode::PayPerRequest)
                    .send()
                    .await
                    .map_err(|e| {
                        KeystoreError::new(
                            KeystoreErrorKind::Dynamodb,
                            format!("DynamoDB CreateTable failed: {e}"),
                        )
                    })?;

                let table = resp.table_description().ok_or_else(|| {
                    KeystoreError::new(
                        KeystoreErrorKind::Dynamodb,
                        "CreateTable succeeded but returned no table description",
                    )
                })?;
                table_arn(table, table_name)
            }
        }
    }

    async fn create_key(
        &self,
        branch_key_id: Option<String>,
        encryption_context: Option<EncryptionContext>,
    ) -> Result<String, KeystoreError> {
        // A caller-supplied branch key id requires an explicit encryption
        // context (branch-key-store.md#createkey).
        if branch_key_id.is_some() && encryption_context.is_none() {
            return Err(KeystoreError::new(
                KeystoreErrorKind::Configuration,
                "CreateKey with a caller-supplied branch key id requires an encryption context",
            ));
        }

        // CreateKey requires a single-key KMS configuration.
        let key_arn = self.configured_kms_key_arn()?.to_string();

        let branch_key_id = branch_key_id.unwrap_or_else(|| Uuid::new_v4().to_string());
        let version = Uuid::new_v4().to_string();
        let timestamp = now_iso8601_micros()?;

        let ec_input = EncryptionContextInput {
            branch_key_id: &branch_key_id,
            create_time: &timestamp,
            logical_keystore_name: &self.config.logical_keystore_name,
            kms_arn: &key_arn,
            hierarchy_version: 1,
            custom_ec: encryption_context.as_ref(),
        };

        let decrypt_only_ec = decrypt_only_encryption_context(&ec_input, &version)?;
        let active_ec = active_encryption_context(&ec_input, &version)?;
        let beacon_ec = beacon_key_encryption_context(&ec_input)?;

        let grant_tokens = self.grant_tokens();
        let kms = self.kms_client();

        // Wrapped DECRYPT_ONLY branch key.
        let decrypt_only_blob =
            generate_wrapped_key(kms, &key_arn, &decrypt_only_ec, grant_tokens).await?;
        // Wrapped ACTIVE branch key: ReEncrypt DECRYPT_ONLY -> ACTIVE.
        let active_blob = reencrypt_wrapped_key(
            kms,
            &key_arn,
            &decrypt_only_blob,
            &decrypt_only_ec,
            &active_ec,
            grant_tokens,
        )
        .await?;
        // Wrapped beacon key.
        let beacon_blob = generate_wrapped_key(kms, &key_arn, &beacon_ec, grant_tokens).await?;

        // Write all three items atomically, each guarded so it cannot
        // clobber an existing branch key id.
        let items = [
            item_from_ec_and_enc(&decrypt_only_ec, decrypt_only_blob),
            item_from_ec_and_enc(&active_ec, active_blob),
            item_from_ec_and_enc(&beacon_ec, beacon_blob),
        ];
        let mut transact_items = Vec::with_capacity(items.len());
        for item in items {
            let put = Put::builder()
                .table_name(&self.config.ddb_table_name)
                .set_item(Some(item))
                .condition_expression("attribute_not_exists(#branch_key_id)")
                .expression_attribute_names("#branch_key_id", ATTR_BRANCH_KEY_ID)
                .build()
                .map_err(ddb_build_err)?;
            transact_items.push(TransactWriteItem::builder().put(put).build());
        }

        self.ddb_client()
            .transact_write_items()
            .set_transact_items(Some(transact_items))
            .send()
            .await
            .map_err(|e| {
                KeystoreError::new(
                    KeystoreErrorKind::Dynamodb,
                    format!("DynamoDB TransactWriteItems failed: {e}"),
                )
            })?;

        Ok(branch_key_id)
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
            self.kms_client(),
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
            self.kms_client(),
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

/// The `AttributeDefinitions` a branch-key-store table MUST have:
/// `branch-key-id` (S) and `type` (S). See
/// `branch-key-store.md#keyschema`.
fn expected_attribute_definitions() -> Result<Vec<AttributeDefinition>, KeystoreError> {
    let branch_key_id = AttributeDefinition::builder()
        .attribute_name(ATTR_BRANCH_KEY_ID)
        .attribute_type(ScalarAttributeType::S)
        .build()
        .map_err(ddb_build_err)?;
    let type_attr = AttributeDefinition::builder()
        .attribute_name(ATTR_TYPE)
        .attribute_type(ScalarAttributeType::S)
        .build()
        .map_err(ddb_build_err)?;
    Ok(vec![branch_key_id, type_attr])
}

/// The `KeySchema` a branch-key-store table MUST have: `branch-key-id`
/// as the partition (HASH) key and `type` as the sort (RANGE) key.
fn expected_key_schema() -> Result<Vec<KeySchemaElement>, KeystoreError> {
    let hash = KeySchemaElement::builder()
        .attribute_name(ATTR_BRANCH_KEY_ID)
        .key_type(KeyType::Hash)
        .build()
        .map_err(ddb_build_err)?;
    let range = KeySchemaElement::builder()
        .attribute_name(ATTR_TYPE)
        .key_type(KeyType::Range)
        .build()
        .map_err(ddb_build_err)?;
    Ok(vec![hash, range])
}

/// Returns true if `table` carries at least the expected branch-key-store
/// KeySchema and attribute definitions. The table MAY carry additional
/// attributes / indexes (per the spec), so this is a superset check.
fn table_has_expected_schema(table: &TableDescription) -> bool {
    let key_schema = table.key_schema();
    let has_hash = key_schema
        .iter()
        .any(|e| e.attribute_name() == ATTR_BRANCH_KEY_ID && *e.key_type() == KeyType::Hash);
    let has_range = key_schema
        .iter()
        .any(|e| e.attribute_name() == ATTR_TYPE && *e.key_type() == KeyType::Range);

    let attrs = table.attribute_definitions();
    let has_bkid_attr = attrs.iter().any(|a| {
        a.attribute_name() == ATTR_BRANCH_KEY_ID && *a.attribute_type() == ScalarAttributeType::S
    });
    let has_type_attr = attrs
        .iter()
        .any(|a| a.attribute_name() == ATTR_TYPE && *a.attribute_type() == ScalarAttributeType::S);

    has_hash && has_range && has_bkid_attr && has_type_attr
}

/// Extract the `TableArn` from a table description, erroring if absent.
fn table_arn(table: &TableDescription, table_name: &str) -> Result<String, KeystoreError> {
    table.table_arn().map(String::from).ok_or_else(|| {
        KeystoreError::new(
            KeystoreErrorKind::Dynamodb,
            format!("Table '{table_name}' description is missing a TableArn"),
        )
    })
}

/// Map a DynamoDB request-builder `BuildError` into a `KeystoreError`.
fn ddb_build_err(e: aws_sdk_dynamodb::error::BuildError) -> KeystoreError {
    KeystoreError::new(
        KeystoreErrorKind::Internal,
        format!("failed to build a DynamoDB request: {e}"),
    )
}

/// Current UTC time as an ISO 8601 timestamp to microsecond precision
/// (`YYYY-MM-DDTHH:mm:ss.ssssssZ`), per branch-key-store.md#createkey.
fn now_iso8601_micros() -> Result<String, KeystoreError> {
    const FORMAT: &[time::format_description::FormatItem<'_>] =
        format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:6]Z");
    OffsetDateTime::now_utc().format(FORMAT).map_err(|e| {
        KeystoreError::new(
            KeystoreErrorKind::Internal,
            format!("failed to format a keystore timestamp: {e}"),
        )
    })
}

/// Build the DynamoDB item for a keystore record from its encryption
/// context and wrapped-key ciphertext, mirroring the reference
/// `Structure.ToAttributeMap`: every EC entry is carried as a String
/// attribute except `hierarchy-version` (Number) and `tablename` (dropped
/// — it is reconstructed from config on read); the wrapped key is added as
/// the binary `enc` attribute.
fn item_from_ec_and_enc(
    encryption_context: &BTreeMap<String, String>,
    enc: Vec<u8>,
) -> HashMap<String, AttributeValue> {
    let mut item: HashMap<String, AttributeValue> = HashMap::new();
    for (key, value) in encryption_context {
        if key == ATTR_TABLENAME {
            continue;
        }
        let attr = if key == ATTR_HIERARCHY_VERSION {
            AttributeValue::N(value.clone())
        } else {
            AttributeValue::S(value.clone())
        };
        item.insert(key.clone(), attr);
    }
    item.insert(ATTR_ENC.to_string(), AttributeValue::B(Blob::new(enc)));
    item
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

// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! `BranchKeyStore` — concrete [`Keystore`] implementation backed by AWS KMS
//! and Amazon DynamoDB.
//!
//! Construct with [`BranchKeyStore::builder`]. The KMS and DynamoDB clients
//! are optional; when omitted, a default client is built using the Region
//! parsed from the configured KMS ARN.

use crate::Error;
use crate::error::{ConflictReason, Kind, Resource, RetryKind, Service};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use async_trait::async_trait;
use aws_config::{BehaviorVersion, Region};
use aws_sdk_dynamodb::Client as DynamoDbClient;
use aws_sdk_dynamodb::config::http::HttpResponse;
use aws_sdk_dynamodb::error::{ProvideErrorMetadata, SdkError};
use aws_sdk_dynamodb::operation::describe_table::DescribeTableError;
use aws_sdk_dynamodb::operation::transact_write_items::TransactWriteItemsError;
use aws_sdk_dynamodb::primitives::Blob;
use aws_sdk_dynamodb::types::{
    AttributeDefinition, AttributeValue, BillingMode, KeySchemaElement, KeyType, Put,
    ScalarAttributeType, TableDescription, TransactWriteItem,
};
use aws_sdk_kms::Client as KmsClient;
use time::OffsetDateTime;
use time::macros::format_description;
use uuid::Uuid;

use crate::aws_kms::user_agent::with_user_agent;
use crate::keystore::Keystore;
use crate::keystore::attributes::{
    ATTR_BRANCH_KEY_ID, ATTR_CREATE_TIME, ATTR_ENC, ATTR_HIERARCHY_VERSION, ATTR_KMS_ARN,
    ATTR_TABLENAME, ATTR_TYPE, ATTR_VERSION, TYPE_BEACON_ACTIVE, TYPE_BRANCH_ACTIVE,
    TYPE_BRANCH_VERSION_PREFIX,
};
use crate::keystore::config::{KeyStoreInfo, KmsConfiguration};
use crate::keystore::encryption_context::{
    EncryptionContextInput, active_encryption_context, beacon_key_encryption_context,
    decrypt_only_encryption_context,
};
use crate::keystore::kms_config::parse_arn;
use crate::keystore::kms_ops::{
    decrypt_branch_key, generate_wrapped_key, reencrypt_wrapped_key, resolve_keystore_arn,
};
use crate::keystore::record::{
    EncryptedRecord, branch_key_materials_from_authenticated_encryption_context,
    custom_encryption_context_from_authenticated_encryption_context,
};
use crate::structures::{BeaconKeyMaterials, BranchKeyMaterials, EncryptionContext};

/// Concrete `Keystore` implementation backed by AWS KMS + Amazon DynamoDB.
///
/// Construct with [`BranchKeyStore::builder`].
#[derive(Clone)]
pub struct BranchKeyStore {
    inner: Arc<BranchKeyStoreInner>,
}

struct BranchKeyStoreInner {
    ddb_table_name: String,
    logical_keystore_name: String,
    kms_configuration: KmsConfiguration,
    grant_tokens: Vec<String>,
    /// The client the caller passed in, or one built for the KMS configuration's Region.
    kms_client: KmsClient,
    /// The client the caller passed in, or one built for the KMS configuration's Region.
    ddb_client: DynamoDbClient,
    /// The caller's `id`, or a v4 UUID generated at construction when unset.
    keystore_id: String,
}

/// DynamoDB's documented table-name bounds.
const DDB_TABLE_NAME_MIN_LEN: usize = 3;
const DDB_TABLE_NAME_MAX_LEN: usize = 255;

impl BranchKeyStore {
    /// Start a builder for `BranchKeyStore`.
    #[must_use]
    pub fn builder() -> BranchKeyStoreBuilder {
        BranchKeyStoreBuilder::default()
    }

    fn kms_client(&self) -> &KmsClient {
        &self.inner.kms_client
    }

    fn ddb_client(&self) -> &DynamoDbClient {
        &self.inner.ddb_client
    }

    /// The single configured KMS Key ARN. `CreateKey` / `VersionKey`
    /// require a single-key configuration; `Discovery` / `MRDiscovery`
    /// have no single ARN to wrap under and are rejected.
    fn configured_kms_key_arn(&self) -> Result<&str, Error> {
        match &self.inner.kms_configuration {
            KmsConfiguration::KmsKeyArn(arn) | KmsConfiguration::KmsMrKeyArn(arn) => Ok(arn),
            KmsConfiguration::Discovery | KmsConfiguration::MrDiscovery { .. } => Err(Error::new(
                Kind::Validation,
                "operation requires a single-key KMS configuration (KmsKeyArn or \
                     KmsMrKeyArn); Discovery and MRDiscovery are not supported",
            )),
        }
    }

    /// Returns the resolved keystore identifier — either caller-supplied
    /// or the v4 UUID generated at construction.
    pub fn keystore_id(&self) -> &str {
        &self.inner.keystore_id
    }

    /// Borrow the configured grant tokens (or an empty slice if `None`).
    fn grant_tokens(&self) -> &[String] {
        &self.inner.grant_tokens
    }

    /// Build the authenticated encryption context for a fetched record.
    /// All record attributes are echoed verbatim and `tablename` is bound
    /// to the configured logical keystore name. The `enc` ciphertext is
    /// not part of the EC by `EncryptedRecord`'s shape.
    fn build_auth_ec(&self, record: &EncryptedRecord) -> BTreeMap<String, String> {
        let mut ec = record.attributes.clone();
        ec.insert(
            "tablename".to_string(),
            self.inner.logical_keystore_name.clone(),
        );
        ec
    }

    /// Fetch a single keystore record by `(branch-key-id, type)` from
    /// the configured DynamoDB table.
    ///
    /// Errors:
    /// - the variant classified from the SDK error when the GetItem call
    ///   itself fails.
    /// - `ResourceNotFound` naming the branch key when the call succeeds but
    ///   returns no item.
    /// - `InvalidMaterials` naming the branch key when the item is missing a
    ///   required attribute or has an unexpected shape.
    async fn fetch_record(
        &self,
        branch_key_id: &str,
        sort_key: &str,
    ) -> Result<EncryptedRecord, Error> {
        let response = self
            .ddb_client()
            .get_item()
            .table_name(&self.inner.ddb_table_name)
            .key(
                ATTR_BRANCH_KEY_ID,
                AttributeValue::S(branch_key_id.to_string()),
            )
            .key(ATTR_TYPE, AttributeValue::S(sort_key.to_string()))
            .send()
            .await
            .map_err(|e| {
                map_ddb_error(
                    &format!("GetItem for branch key {branch_key_id}"),
                    &self.inner.ddb_table_name,
                    e,
                )
            })?;

        let item = response.item.ok_or_else(|| {
            Error::new(
                Kind::ResourceNotFound,
                format!("no keystore record for branch-key-id={branch_key_id}, type={sort_key}",),
            )
            .about(
                Some(Service::DynamoDb),
                Some(Resource::BranchKey(branch_key_id.to_string())),
            )
        })?;

        record_from_ddb_item(item, branch_key_id)
    }
}

/// Builder for [`BranchKeyStore`].
///
/// `ddb_table_name`, `logical_keystore_name`, and `kms_configuration` are
/// required. Everything else is optional.
#[derive(Debug, Clone, Default)]
pub struct BranchKeyStoreBuilder {
    ddb_table_name: Option<String>,
    logical_keystore_name: Option<String>,
    kms_configuration: Option<KmsConfiguration>,
    id: Option<String>,
    grant_tokens: Option<Vec<String>>,
    kms_client: Option<KmsClient>,
    ddb_client: Option<DynamoDbClient>,
}

impl BranchKeyStoreBuilder {
    /// Set the DynamoDB table name backing this keystore. Required.
    #[must_use]
    pub fn ddb_table_name(mut self, name: impl Into<String>) -> Self {
        self.ddb_table_name = Some(name.into());
        self
    }

    /// Set the logical name cryptographically bound to all keys in the
    /// table. Required.
    #[must_use]
    pub fn logical_keystore_name(mut self, name: impl Into<String>) -> Self {
        self.logical_keystore_name = Some(name.into());
        self
    }

    /// Set the KMS key configuration governing encryption and decryption.
    /// Required.
    #[must_use]
    pub fn kms_configuration(mut self, config: KmsConfiguration) -> Self {
        self.kms_configuration = Some(config);
        self
    }

    /// Set the keystore identifier. Defaults to a fresh v4 UUID.
    #[must_use]
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Set or clear the keystore identifier, for forwarding an existing `Option`.
    /// `None` applies the default documented on [`id`](Self::id).
    #[must_use]
    pub fn set_id(mut self, id: Option<String>) -> Self {
        self.id = id;
        self
    }

    /// Set the AWS KMS grant tokens. Defaults to none.
    #[must_use]
    pub fn grant_tokens(mut self, tokens: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.grant_tokens = Some(tokens.into_iter().map(Into::into).collect());
        self
    }

    /// Set or clear the AWS KMS grant tokens, for forwarding an existing `Option`.
    /// `None` applies the default documented on [`grant_tokens`](Self::grant_tokens).
    #[must_use]
    pub fn set_grant_tokens(mut self, tokens: Option<Vec<String>>) -> Self {
        self.grant_tokens = tokens;
        self
    }

    /// Set the AWS KMS client. Defaults to a client for the Region parsed
    /// from the KMS configuration (the SDK's default region provider chain
    /// for `Discovery`).
    #[must_use]
    pub fn kms_client(mut self, client: KmsClient) -> Self {
        self.kms_client = Some(client);
        self
    }

    /// Set or clear the AWS KMS client, for forwarding an existing `Option`.
    /// `None` applies the default documented on [`kms_client`](Self::kms_client).
    #[must_use]
    pub fn set_kms_client(mut self, client: Option<KmsClient>) -> Self {
        self.kms_client = client;
        self
    }

    /// Set the Amazon DynamoDB client. Defaults to a client for the Region
    /// parsed from the KMS configuration (the SDK's default region provider
    /// chain for `Discovery`).
    #[must_use]
    pub fn ddb_client(mut self, client: DynamoDbClient) -> Self {
        self.ddb_client = Some(client);
        self
    }

    /// Set or clear the Amazon DynamoDB client, for forwarding an existing `Option`.
    /// `None` applies the default documented on [`ddb_client`](Self::ddb_client).
    #[must_use]
    pub fn set_ddb_client(mut self, client: Option<DynamoDbClient>) -> Self {
        self.ddb_client = client;
        self
    }

    /// Validate the configuration, default any absent client, and resolve the keystore id.
    ///
    /// Building a default client is the only reason this is `async`.
    /// With both clients supplied it does no IO and completes on the first poll.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): a required field is unset, the table name is outside DynamoDB's 3-255 character bounds, or the KMS configuration is invalid (malformed ARN, alias, or non-`kms` service).
    pub async fn build(self) -> Result<BranchKeyStore, Error> {
        let ddb_table_name = required(self.ddb_table_name, "ddb_table_name")?;
        let logical_keystore_name = required(self.logical_keystore_name, "logical_keystore_name")?;
        let kms_configuration = required(self.kms_configuration, "kms_configuration")?;

        // Validate the ARN before its Region is used to build a default client,
        // so a malformed ARN fails here instead of on the first operation.
        kms_configuration.validate()?;

        // DynamoDB limits table names to 3-255 characters.
        // Checking here fails at construction instead of on the first request.
        // The keystore spec doesn't require this; it mirrors the service limit.
        let name_len = ddb_table_name.len();
        if !(DDB_TABLE_NAME_MIN_LEN..=DDB_TABLE_NAME_MAX_LEN).contains(&name_len) {
            return Err(Error::new(
                Kind::Validation,
                format!(
                    "ddb_table_name must be between {DDB_TABLE_NAME_MIN_LEN} and {DDB_TABLE_NAME_MAX_LEN} characters, got {name_len}",
                ),
            ));
        }

        let (kms_client, ddb_client) = match (self.kms_client, self.ddb_client) {
            (Some(kms), Some(ddb)) => (kms, ddb),
            (kms, ddb) => {
                let sdk_config = default_sdk_config(&kms_configuration).await;
                (
                    kms.unwrap_or_else(|| KmsClient::new(&sdk_config)),
                    ddb.unwrap_or_else(|| DynamoDbClient::new(&sdk_config)),
                )
            }
        };

        let keystore_id = self.id.unwrap_or_else(|| Uuid::new_v4().to_string());

        Ok(BranchKeyStore {
            inner: Arc::new(BranchKeyStoreInner {
                ddb_table_name,
                logical_keystore_name,
                kms_configuration,
                grant_tokens: self.grant_tokens.unwrap_or_default(),
                // The KMS client might be ours or one the caller passed in.
                // Adding the user agent here covers both.
                kms_client: with_user_agent(kms_client),
                ddb_client,
                keystore_id,
            }),
        })
    }
}

fn required<T>(value: Option<T>, field: &str) -> Result<T, Error> {
    value.ok_or_else(|| Error::new(Kind::Validation, format!("{field} is required")))
}

#[async_trait]
impl Keystore for BranchKeyStore {
    /// # Errors
    ///
    /// Reads only in-memory configuration and never returns an error.
    fn get_key_store_info(&self) -> Result<KeyStoreInfo, Error> {
        Ok(KeyStoreInfo {
            keystore_id: self.inner.keystore_id.clone(),
            keystore_name: self.inner.ddb_table_name.clone(),
            logical_keystore_name: self.inner.logical_keystore_name.clone(),
            grant_tokens: self.inner.grant_tokens.clone(),
            kms_configuration: self.inner.kms_configuration.clone(),
        })
    }

    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): the table exists but does not match the required key store schema.
    /// - [`AccessDenied`](crate::Error::AccessDenied), [`ResourceNotFound`](crate::Error::ResourceNotFound), [`Throttling`](crate::Error::Throttling), [`Service`](crate::Error::Service), [`Dispatch`](crate::Error::Dispatch): an Amazon DynamoDB call failed, or returned a success response with no table description or ARN (`Service`); `resource()` is the table.
    /// - [`Internal`](crate::Error::Internal): building a DynamoDB request failed.
    async fn create_key_store(&self) -> Result<String, Error> {
        let table_name = &self.inner.ddb_table_name;

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
                    Error::new(
                        Kind::Service,
                        "DescribeTable succeeded but returned no table description",
                    )
                    .about(
                        Some(Service::DynamoDb),
                        Some(Resource::DynamoDbTable(table_name.clone())),
                    )
                })?;
                if !table_has_expected_schema(table) {
                    return Err(Error::new(
                        Kind::Validation,
                        format!(
                            "table '{table_name}' does not conform to the expected Key Store KeySchema"
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
                    return Err(map_ddb_error("DescribeTable", table_name, err));
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
                    .map_err(|e| map_ddb_error("CreateTable", table_name, e))?;

                let table = resp.table_description().ok_or_else(|| {
                    Error::new(
                        Kind::Service,
                        "CreateTable succeeded but returned no table description",
                    )
                    .about(
                        Some(Service::DynamoDb),
                        Some(Resource::DynamoDbTable(table_name.clone())),
                    )
                })?;
                table_arn(table, table_name)
            }
        }
    }

    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): the input is invalid, for example a caller-supplied branch key id without an encryption context, a non-single-key KMS configuration, or an invalid encryption context.
    /// - [`Conflict`](crate::Error::Conflict): the branch key id already exists; `resource()` is the branch key.
    /// - [`AccessDenied`](crate::Error::AccessDenied), [`ResourceNotFound`](crate::Error::ResourceNotFound), [`Throttling`](crate::Error::Throttling), [`Service`](crate::Error::Service), [`Dispatch`](crate::Error::Dispatch): an AWS KMS or Amazon DynamoDB call failed, or AWS KMS returned no ciphertext (`Service`); `resource()` is the KMS key or the table.
    /// - [`Internal`](crate::Error::Internal): building a DynamoDB request or formatting the record timestamp failed.
    async fn create_key(
        &self,
        branch_key_id: Option<String>,
        encryption_context: Option<EncryptionContext>,
    ) -> Result<String, Error> {
        // A caller-supplied branch key id requires an explicit encryption
        // context (branch-key-store.md#createkey).
        if branch_key_id.is_some() && encryption_context.is_none() {
            return Err(Error::new(
                Kind::Validation,
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
            logical_keystore_name: &self.inner.logical_keystore_name,
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
                .table_name(&self.inner.ddb_table_name)
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
                map_transact_write_error(
                    e,
                    &self.inner.ddb_table_name,
                    &branch_key_id,
                    ConflictReason::AlreadyExists,
                    format!("branch key {branch_key_id} already exists"),
                )
            })?;

        Ok(branch_key_id)
    }

    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): the KMS configuration is not a single key, or the record's `kms-arn` is not compatible with the configured KMS key.
    /// - [`InvalidMaterials`](crate::Error::InvalidMaterials): the ACTIVE record is missing a required attribute or is malformed; `resource()` is the branch key.
    /// - [`Cryptographic`](crate::Error::Cryptographic): AWS KMS rejected the stored ACTIVE record as tampered with (`InvalidCiphertextException`).
    /// - [`Conflict`](crate::Error::Conflict): the branch key was rotated concurrently; `resource()` is the branch key.
    /// - [`AccessDenied`](crate::Error::AccessDenied), [`ResourceNotFound`](crate::Error::ResourceNotFound), [`Throttling`](crate::Error::Throttling), [`Service`](crate::Error::Service), [`Dispatch`](crate::Error::Dispatch): an AWS KMS or Amazon DynamoDB call failed, or AWS KMS returned no ciphertext (`Service`); `resource()` is the KMS key or the table. `ResourceNotFound` also when no ACTIVE record exists for the branch key (`resource()` is the branch key).
    /// - [`Internal`](crate::Error::Internal): building a DynamoDB request or formatting the record timestamp failed.
    async fn version_key(&self, branch_key_id: String) -> Result<(), Error> {
        // VersionKey requires a single-key KMS configuration.
        let configured_arn = self.configured_kms_key_arn()?.to_string();

        // Fetch the current ACTIVE record.
        let record = self
            .fetch_record(&branch_key_id, TYPE_BRANCH_ACTIVE)
            .await?;

        // The stored kms-arn MUST be compatible with the configured KMS
        // configuration, and MUST be preserved across the version bump.
        let stored_kms_arn = record
            .attributes
            .get(ATTR_KMS_ARN)
            .ok_or_else(|| {
                malformed_record(
                    &branch_key_id,
                    "ACTIVE record is missing the 'kms-arn' attribute",
                )
            })?
            .clone();
        let resolved_arn = resolve_keystore_arn(
            &self.inner.kms_configuration,
            &stored_kms_arn,
            &branch_key_id,
        )?;

        // The encryption context reconstructed from the stored item (the
        // logical keystore name is bound as `tablename`).
        let old_active_ec = self.build_auth_ec(&record);
        let grant_tokens = self.grant_tokens();
        let kms = self.kms_client();

        // Authenticate the stored item: a successful ReEncrypt with the
        // reconstructed EC as both source and destination proves the item
        // has not been tampered with. The result ciphertext is discarded.
        reencrypt_wrapped_key(
            kms,
            &resolved_arn,
            &record.enc,
            &old_active_ec,
            &old_active_ec,
            grant_tokens,
        )
        .await
        .map_err(|e| {
            // KMS rejects a ciphertext whose encryption context was altered.
            if e.code() == Some("InvalidCiphertextException") {
                Error::with_cause(
                    Kind::Cryptographic,
                    format!("failed to authenticate ACTIVE record for '{branch_key_id}'"),
                    e,
                )
            } else {
                e
            }
        })?;

        // Build the new version's encryption contexts from the old ACTIVE
        // EC, preserving branch-key-id, kms-arn, hierarchy-version, and the
        // custom encryption context (which MUST be equal across versions).
        let version = Uuid::new_v4().to_string();
        let timestamp = now_iso8601_micros()?;

        let mut new_decrypt_only_ec = old_active_ec;
        new_decrypt_only_ec.insert(
            ATTR_TYPE.to_string(),
            format!("{TYPE_BRANCH_VERSION_PREFIX}{version}"),
        );
        new_decrypt_only_ec.insert(ATTR_CREATE_TIME.to_string(), timestamp);
        new_decrypt_only_ec.remove(ATTR_VERSION);

        let mut new_active_ec = new_decrypt_only_ec.clone();
        // ACTIVE moves the `branch:version:<v>` value into `version` and
        // sets `type` to `branch:ACTIVE`.
        new_active_ec.insert(
            ATTR_VERSION.to_string(),
            new_decrypt_only_ec[ATTR_TYPE].clone(),
        );
        new_active_ec.insert(ATTR_TYPE.to_string(), TYPE_BRANCH_ACTIVE.to_string());

        // Wrap a fresh branch key for the new version (DECRYPT_ONLY, then
        // ReEncrypt to ACTIVE) under the configured KMS key.
        let wrapped_decrypt_only =
            generate_wrapped_key(kms, &configured_arn, &new_decrypt_only_ec, grant_tokens).await?;
        let wrapped_active = reencrypt_wrapped_key(
            kms,
            &configured_arn,
            &wrapped_decrypt_only,
            &new_decrypt_only_ec,
            &new_active_ec,
            grant_tokens,
        )
        .await?;

        // Write the new DECRYPT_ONLY (must not already exist) and overwrite
        // ACTIVE only if it is unchanged since the read (optimistic lock).
        let decrypt_only_item = item_from_ec_and_enc(&new_decrypt_only_ec, wrapped_decrypt_only);
        let decrypt_only_put = Put::builder()
            .table_name(&self.inner.ddb_table_name)
            .set_item(Some(decrypt_only_item))
            .condition_expression("attribute_not_exists(#branch_key_id)")
            .expression_attribute_names("#branch_key_id", ATTR_BRANCH_KEY_ID)
            .build()
            .map_err(ddb_build_err)?;

        let active_item = item_from_ec_and_enc(&new_active_ec, wrapped_active);
        let active_put = Put::builder()
            .table_name(&self.inner.ddb_table_name)
            .set_item(Some(active_item))
            .condition_expression("attribute_exists(#branch_key_id) AND #enc = :encOld")
            .expression_attribute_names("#branch_key_id", ATTR_BRANCH_KEY_ID)
            .expression_attribute_names("#enc", ATTR_ENC)
            .expression_attribute_values(
                ":encOld",
                AttributeValue::B(Blob::new(record.enc.clone())),
            )
            .build()
            .map_err(ddb_build_err)?;

        let transact_items = vec![
            TransactWriteItem::builder().put(decrypt_only_put).build(),
            TransactWriteItem::builder().put(active_put).build(),
        ];

        self.ddb_client()
            .transact_write_items()
            .set_transact_items(Some(transact_items))
            .send()
            .await
            .map_err(|e| {
                map_transact_write_error(
                    e,
                    &self.inner.ddb_table_name,
                    &branch_key_id,
                    ConflictReason::ConcurrentModification,
                    format!("branch key {branch_key_id} was rotated concurrently"),
                )
            })?;

        Ok(())
    }

    /// # Errors
    ///
    /// - [`InvalidMaterials`](crate::Error::InvalidMaterials): the keystore record is malformed or missing a required attribute; `resource()` is the branch key.
    /// - [`Validation`](crate::Error::Validation): the record's `kms-arn` is not compatible with the configured KMS key.
    /// - [`AccessDenied`](crate::Error::AccessDenied), [`ResourceNotFound`](crate::Error::ResourceNotFound), [`Throttling`](crate::Error::Throttling), [`Service`](crate::Error::Service), [`Dispatch`](crate::Error::Dispatch): an AWS KMS or Amazon DynamoDB call failed, or AWS KMS returned no plaintext (`Service`); `resource()` is the KMS key or the table. `ResourceNotFound` also when no keystore record exists for the branch key (`resource()` is the branch key).
    async fn get_active_branch_key(
        &self,
        branch_key_id: String,
    ) -> Result<BranchKeyMaterials, Error> {
        let record = self
            .fetch_record(&branch_key_id, TYPE_BRANCH_ACTIVE)
            .await?;

        let plaintext = decrypt_branch_key(
            self.kms_client(),
            &self.inner.kms_configuration,
            &record,
            &branch_key_id,
            &self.inner.logical_keystore_name,
            self.grant_tokens(),
        )
        .await?;

        let auth_ec = self.build_auth_ec(&record);

        branch_key_materials_from_authenticated_encryption_context(&auth_ec, plaintext)
    }

    /// # Errors
    ///
    /// - [`InvalidMaterials`](crate::Error::InvalidMaterials): the keystore record is malformed or missing a required attribute; `resource()` is the branch key.
    /// - [`Validation`](crate::Error::Validation): the record's `kms-arn` is not compatible with the configured KMS key.
    /// - [`AccessDenied`](crate::Error::AccessDenied), [`ResourceNotFound`](crate::Error::ResourceNotFound), [`Throttling`](crate::Error::Throttling), [`Service`](crate::Error::Service), [`Dispatch`](crate::Error::Dispatch): an AWS KMS or Amazon DynamoDB call failed, or AWS KMS returned no plaintext (`Service`); `resource()` is the KMS key or the table. `ResourceNotFound` also when no keystore record exists for the branch key (`resource()` is the branch key).
    async fn get_branch_key_version(
        &self,
        branch_key_id: String,
        branch_key_version: String,
    ) -> Result<BranchKeyMaterials, Error> {
        let sort_key = format!("{TYPE_BRANCH_VERSION_PREFIX}{branch_key_version}");
        let record = self.fetch_record(&branch_key_id, &sort_key).await?;

        let plaintext = decrypt_branch_key(
            self.kms_client(),
            &self.inner.kms_configuration,
            &record,
            &branch_key_id,
            &self.inner.logical_keystore_name,
            self.grant_tokens(),
        )
        .await?;

        let auth_ec = self.build_auth_ec(&record);

        branch_key_materials_from_authenticated_encryption_context(&auth_ec, plaintext)
    }

    /// # Errors
    ///
    /// - [`InvalidMaterials`](crate::Error::InvalidMaterials): the keystore record is malformed or missing a required attribute; `resource()` is the branch key.
    /// - [`Validation`](crate::Error::Validation): the record's `kms-arn` is not compatible with the configured KMS key.
    /// - [`AccessDenied`](crate::Error::AccessDenied), [`ResourceNotFound`](crate::Error::ResourceNotFound), [`Throttling`](crate::Error::Throttling), [`Service`](crate::Error::Service), [`Dispatch`](crate::Error::Dispatch): an AWS KMS or Amazon DynamoDB call failed, or AWS KMS returned no plaintext (`Service`); `resource()` is the KMS key or the table. `ResourceNotFound` also when no keystore record exists for the branch key (`resource()` is the branch key).
    async fn get_beacon_key(&self, branch_key_id: String) -> Result<BeaconKeyMaterials, Error> {
        let record = self
            .fetch_record(&branch_key_id, TYPE_BEACON_ACTIVE)
            .await?;

        let plaintext = decrypt_branch_key(
            self.kms_client(),
            &self.inner.kms_configuration,
            &record,
            &branch_key_id,
            &self.inner.logical_keystore_name,
            self.grant_tokens(),
        )
        .await?;

        let auth_ec = self.build_auth_ec(&record);
        let custom_ec = custom_encryption_context_from_authenticated_encryption_context(&auth_ec)?;
        // The beacon key id is the `branch-key-id` field on the record.
        let beacon_key_id = auth_ec
            .get(ATTR_BRANCH_KEY_ID)
            .cloned()
            .unwrap_or(branch_key_id);

        Ok(BeaconKeyMaterials::new(
            beacon_key_id,
            custom_ec,
            Some(plaintext),
            None,
        ))
    }
}

/// The `AttributeDefinitions` a branch-key-store table MUST have:
/// `branch-key-id` (S) and `type` (S). See
/// `branch-key-store.md#keyschema`.
fn expected_attribute_definitions() -> Result<Vec<AttributeDefinition>, Error> {
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
fn expected_key_schema() -> Result<Vec<KeySchemaElement>, Error> {
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
/// attributes / indexes, so this is a superset check.
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
fn table_arn(table: &TableDescription, table_name: &str) -> Result<String, Error> {
    table.table_arn().map(String::from).ok_or_else(|| {
        Error::new(
            Kind::Service,
            format!("table '{table_name}' description is missing a TableArn"),
        )
        .about(
            Some(Service::DynamoDb),
            Some(Resource::DynamoDbTable(table_name.to_owned())),
        )
    })
}

/// Map a DynamoDB request-builder `BuildError` into an `Internal` error.
fn ddb_build_err(e: aws_sdk_dynamodb::error::BuildError) -> Error {
    Error::with_cause(Kind::Internal, "failed to build a DynamoDB request", e)
}

/// Classify a failed DynamoDB call.
///
/// `operation` names the call, and the branch key when there is one,
/// for example `GetItem for branch key my-branch-key`.
fn map_ddb_error<E>(operation: &str, table_name: &str, err: SdkError<E, HttpResponse>) -> Error
where
    E: ProvideErrorMetadata + std::error::Error + Send + Sync + 'static,
{
    Error::from_sdk(
        Service::DynamoDb,
        &format!("DynamoDB {operation}"),
        Some(Resource::DynamoDbTable(table_name.to_owned())),
        err,
    )
}

/// Classify a failed `TransactWriteItems` that writes branch key `branch_key_id`.
///
/// A `ConditionalCheckFailed` cancellation means the write's condition on the
/// branch key failed, which only the caller can interpret: it becomes a
/// `Conflict` with `reason` and `conflict_message`.
/// A `TransactionConflict` cancellation is retryable.
fn map_transact_write_error(
    err: SdkError<TransactWriteItemsError, HttpResponse>,
    table_name: &str,
    branch_key_id: &str,
    reason: ConflictReason,
    conflict_message: String,
) -> Error {
    let has_reason = |code: &str| {
        err.as_service_error()
            .and_then(|e| match e {
                TransactWriteItemsError::TransactionCanceledException(t) => {
                    Some(t.cancellation_reasons())
                }
                _ => None,
            })
            .unwrap_or_default()
            .iter()
            .any(|r| r.code() == Some(code))
    };
    let condition_failed = has_reason("ConditionalCheckFailed");
    let transaction_conflict = has_reason("TransactionConflict");
    let mut sdk = map_ddb_error("TransactWriteItems", table_name, err);
    if condition_failed {
        let code = sdk.code().map(str::to_owned);
        let request_id = sdk.request_id().map(str::to_owned);
        let meta = ProvideErrorMetadata::meta(&sdk).clone();
        let mut conflict = Error::with_cause(Kind::Conflict, conflict_message, sdk).about(
            Some(Service::DynamoDb),
            Some(Resource::BranchKey(branch_key_id.to_owned())),
        );
        conflict.set_sdk(code, request_id, Some(meta));
        conflict.set_reason(reason);
        conflict.set_retry(None);
        return conflict;
    }
    if transaction_conflict {
        sdk.set_retry(Some(RetryKind::Transient));
    }
    sdk
}

/// An error for a malformed branch key record.
fn malformed_record(branch_key_id: &str, message: impl Into<String>) -> Error {
    Error::new(Kind::InvalidMaterials, message).about(
        Some(Service::DynamoDb),
        Some(Resource::BranchKey(branch_key_id.to_owned())),
    )
}

/// The name of `value`'s DynamoDB type, for error messages that must not
/// include the value itself.
fn attribute_type(value: &AttributeValue) -> &'static str {
    match value {
        AttributeValue::B(_) => "Binary",
        AttributeValue::Bool(_) => "Boolean",
        AttributeValue::Bs(_) => "Binary Set",
        AttributeValue::L(_) => "List",
        AttributeValue::M(_) => "Map",
        AttributeValue::N(_) => "Number",
        AttributeValue::Ns(_) => "Number Set",
        AttributeValue::Null(_) => "Null",
        AttributeValue::S(_) => "String",
        AttributeValue::Ss(_) => "String Set",
        _ => "an unknown type",
    }
}

/// Current UTC time as an ISO 8601 timestamp to microsecond precision
/// (`YYYY-MM-DDTHH:mm:ss.ssssssZ`), per branch-key-store.md#createkey.
fn now_iso8601_micros() -> Result<String, Error> {
    const FORMAT: &[time::format_description::FormatItem<'_>] =
        format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:6]Z");
    OffsetDateTime::now_utc()
        .format(FORMAT)
        .map_err(|e| Error::with_cause(Kind::Internal, "failed to format a keystore timestamp", e))
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
/// other than `enc` are rejected as `InvalidMaterials` errors naming the
/// branch key, with the attribute's name and type but never its value.
fn record_from_ddb_item(
    mut item: std::collections::HashMap<String, AttributeValue>,
    branch_key_id: &str,
) -> Result<EncryptedRecord, Error> {
    let enc_attr = item.remove(ATTR_ENC).ok_or_else(|| {
        malformed_record(
            branch_key_id,
            format!("record is missing the '{ATTR_ENC}' attribute"),
        )
    })?;

    let enc_blob: Blob = match enc_attr {
        AttributeValue::B(b) => b,
        other => {
            return Err(malformed_record(
                branch_key_id,
                format!(
                    "record '{ATTR_ENC}' attribute must be Binary, got {}",
                    attribute_type(&other)
                ),
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
                return Err(malformed_record(
                    branch_key_id,
                    format!(
                        "record attribute '{k}' must be String or Number, got {}",
                        attribute_type(&other)
                    ),
                ));
            }
        }
    }

    Ok(EncryptedRecord {
        attributes,
        enc: enc_blob.into_inner(),
    })
}

/// Internal accessors exposed solely so integration tests under `tests/` can
/// assert on the SDK clients resolved during construction. Gated behind
/// `test-utils` so it is not compiled for library consumers. Not part of the
/// public API. Do not use.
///
/// Everything in this module is exempt from semantic versioning and may be
/// changed, renamed, or removed at any time.
#[cfg(feature = "test-utils")]
#[doc(hidden)]
pub mod __test_internals {
    use super::BranchKeyStore;

    pub fn kms_client(store: &BranchKeyStore) -> &aws_sdk_kms::Client {
        store.kms_client()
    }

    pub fn ddb_client(store: &BranchKeyStore) -> &aws_sdk_dynamodb::Client {
        store.ddb_client()
    }
}

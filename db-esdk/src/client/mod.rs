// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! [`Client`]: a DynamoDB client that encrypts items before writing them,
//! and verifies and decrypts them after reading them.

mod operations;

use std::collections::HashMap;

use aws_crypto_mpl::aws_sdk_dynamodb;

use crate::error::{Error, Kind, val_err};
use crate::table_config::TableConfig;
use crate::transforms::Transforms;

pub use operations::{
    BatchExecuteStatementFluentBuilder, BatchGetItemFluentBuilder, BatchWriteItemFluentBuilder,
    DeleteItemFluentBuilder, ExecuteStatementFluentBuilder, ExecuteTransactionFluentBuilder,
    GetItemFluentBuilder, PutItemFluentBuilder, QueryFluentBuilder, ResolveAttributesFluentBuilder,
    ScanFluentBuilder, TransactGetItemsFluentBuilder, TransactWriteItemsFluentBuilder,
    UpdateItemFluentBuilder,
};

/// A DynamoDB client that encrypts and signs each item before it is written,
/// and verifies and decrypts it after it is read.
///
/// It has the same operations, inputs, and outputs as [`aws_sdk_dynamodb::Client`].
/// Requests for a table with no configuration pass through unchanged.
/// Every operation returns [`Error`].
/// When the DynamoDB call fails, [`Error::as_service_error`] returns DynamoDB's own error.
///
/// Cloning is cheap: clones share the configuration.
///
#[cfg_attr(feature = "default-aws-sdk-clients", doc = "```no_run")]
#[cfg_attr(not(feature = "default-aws-sdk-clients"), doc = "```ignore")]
/// use aws_db_esdk::keyring::RawAesKeyring;
/// use aws_db_esdk::types::{AesWrappingAlg, CryptoAction};
/// use aws_db_esdk::{TableConfig, aws_config, aws_sdk_dynamodb};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let keyring = RawAesKeyring::builder()
///     .key_namespace("my-key-namespace")
///     .key_name("my-key-name")
///     .wrapping_key(vec![0x01u8; 32])
///     .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
///     .build()?;
/// let table = TableConfig::builder()
///     .partition_key_name("partition_key")
///     .attribute_actions_on_encrypt("partition_key", CryptoAction::SignOnly)
///     .attribute_actions_on_encrypt("secret", CryptoAction::EncryptAndSign)
///     .keyring(keyring)
///     .build()?;
/// let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
/// let ddb = aws_db_esdk::Client::builder()
///     .ddb_client(aws_sdk_dynamodb::Client::new(&sdk_config))
///     .table_encryption_configs("my-table", table)
///     .build()
///     .await?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct Client {
    ddb: aws_sdk_dynamodb::Client,
    transforms: Transforms,
}

//= spec/dynamodb-encryption-client/ddb-sdk-integration.md#api-modification
//= type=implication
//= reason=Client has no passthrough-API methods; they run unmodified on the caller's aws_sdk_dynamodb::Client
//# The [Allowed Passthrough DynamoDB APIs](#allowed-passthrough-dynamodb-apis)
//# MUST NOT be modified.
//
//= spec/dynamodb-encryption-client/ddb-sdk-integration.md#api-modification
//= type=implication
//= reason=Client has methods only for the specified operations; calling any other does not compile
//# Any DynamoDB API not specified is this document either
//# MUST NOT be callable or MUST yield an error,
//# and that error SHOULD indicate that the operation
//# is not supported with DynamoDB client-side encryption.
impl Client {
    /// A builder for a client.
    #[must_use]
    pub fn builder() -> ClientBuilder {
        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#overview
        //# There MUST be some process by which
        //# the customer can create this AWS SDK with
        //# additional encryption behavior, which
        //# this document will refer to as a [DynamoDB Encryption Client](#dynamodb-encryption-client).
        ClientBuilder::default()
    }

    /// Write an item, encrypted when its table is configured.
    #[must_use]
    pub fn put_item(&self) -> PutItemFluentBuilder {
        PutItemFluentBuilder::new(self.ddb.put_item(), self.transforms.clone())
    }

    /// Read an item, verified and decrypted when its table is configured.
    #[must_use]
    pub fn get_item(&self) -> GetItemFluentBuilder {
        GetItemFluentBuilder::new(self.ddb.get_item(), self.transforms.clone())
    }

    /// Update an item.
    ///
    /// On a configured table the update must not touch a signed attribute.
    #[must_use]
    pub fn update_item(&self) -> UpdateItemFluentBuilder {
        UpdateItemFluentBuilder::new(self.ddb.update_item(), self.transforms.clone())
    }

    /// Delete an item.
    ///
    /// On a configured table the condition must not read an encrypted attribute.
    #[must_use]
    pub fn delete_item(&self) -> DeleteItemFluentBuilder {
        DeleteItemFluentBuilder::new(self.ddb.delete_item(), self.transforms.clone())
    }

    /// Write and delete items in several tables, encrypting each item written to a configured table.
    #[must_use]
    pub fn batch_write_item(&self) -> BatchWriteItemFluentBuilder {
        BatchWriteItemFluentBuilder::new(self.ddb.batch_write_item(), self.transforms.clone())
    }

    /// Write items in one transaction, encrypting each item put in a configured table.
    #[must_use]
    pub fn transact_write_items(&self) -> TransactWriteItemsFluentBuilder {
        TransactWriteItemsFluentBuilder::new(
            self.ddb.transact_write_items(),
            self.transforms.clone(),
        )
    }

    /// Query a table, verifying and decrypting each item when the table is configured.
    ///
    /// On a configured table the query must not read an encrypted attribute.
    #[must_use]
    pub fn query(&self) -> QueryFluentBuilder {
        QueryFluentBuilder::new(self.ddb.query(), self.transforms.clone())
    }

    /// Scan a table, verifying and decrypting each item when the table is configured.
    ///
    /// On a configured table the filter must not read an encrypted attribute.
    #[must_use]
    pub fn scan(&self) -> ScanFluentBuilder {
        ScanFluentBuilder::new(self.ddb.scan(), self.transforms.clone())
    }

    /// Read items from several tables, verifying and decrypting each item of a configured table.
    #[must_use]
    pub fn batch_get_item(&self) -> BatchGetItemFluentBuilder {
        BatchGetItemFluentBuilder::new(self.ddb.batch_get_item(), self.transforms.clone())
    }

    /// Read items in one transaction, verifying and decrypting each item of a configured table.
    #[must_use]
    pub fn transact_get_items(&self) -> TransactGetItemsFluentBuilder {
        TransactGetItemsFluentBuilder::new(self.ddb.transact_get_items(), self.transforms.clone())
    }

    /// Run a PartiQL statement.
    ///
    /// The client rejects a statement on a configured table.
    #[must_use]
    pub fn execute_statement(&self) -> ExecuteStatementFluentBuilder {
        ExecuteStatementFluentBuilder::new(self.ddb.execute_statement(), self.transforms.clone())
    }

    /// Run a batch of PartiQL statements.
    ///
    /// The client rejects a statement on a configured table.
    #[must_use]
    pub fn batch_execute_statement(&self) -> BatchExecuteStatementFluentBuilder {
        BatchExecuteStatementFluentBuilder::new(
            self.ddb.batch_execute_statement(),
            self.transforms.clone(),
        )
    }

    /// Run PartiQL statements in one transaction.
    ///
    /// The client rejects a statement on a configured table.
    #[must_use]
    pub fn execute_transaction(&self) -> ExecuteTransactionFluentBuilder {
        ExecuteTransactionFluentBuilder::new(
            self.ddb.execute_transaction(),
            self.transforms.clone(),
        )
    }

    /// Compute the plaintext values of an item's virtual fields and compound beacons.
    ///
    /// Use it while developing a search configuration.
    /// It sends nothing to DynamoDB.
    #[must_use]
    pub fn resolve_attributes(&self) -> ResolveAttributesFluentBuilder {
        ResolveAttributesFluentBuilder::new(self.transforms.clone())
    }
}

/// A builder for [`Client`].
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct ClientBuilder {
    ddb_client: Option<aws_sdk_dynamodb::Client>,

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#dynamodb-encryption-client-configuration
    //= type=implication
    //= reason=the field always exists; unset is an empty map, as Dafny's required map may be empty
    //# The client configuration consists of the following REQUIRED field:
    //
    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#dynamodb-table-encryption-configs
    //= type=implication
    //= reason=the map's value type is TableConfig, so nothing else can be stored
    //# A map of DynamoDb table names to a structure that MUST contain
    //# data as described by [DynamoDb Table Encryption Config](./ddb-table-encryption-config.md).
    table_encryption_configs: HashMap<String, TableConfig>,
}

impl ClientBuilder {
    /// The DynamoDB client that sends each request. Required.
    #[must_use]
    pub fn ddb_client(mut self, client: impl Into<aws_sdk_dynamodb::Client>) -> Self {
        self.ddb_client = Some(client.into());
        self
    }

    /// The DynamoDB client. See [`Self::ddb_client`].
    #[must_use]
    pub fn set_ddb_client(mut self, client: Option<aws_sdk_dynamodb::Client>) -> Self {
        self.ddb_client = client;
        self
    }

    /// Add the configuration for table `name`, as requests name the table.
    ///
    /// Call once per table. A table with no configuration passes through unencrypted.
    #[must_use]
    pub fn table_encryption_configs(
        mut self,
        name: impl Into<String>,
        config: TableConfig,
    ) -> Self {
        self.table_encryption_configs.insert(name.into(), config);
        self
    }

    /// Replace every table configuration. See [`Self::table_encryption_configs`].
    #[must_use]
    pub fn set_table_encryption_configs(
        mut self,
        configs: Option<HashMap<String, TableConfig>>,
    ) -> Self {
        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#overview
        //# There is no restriction on what this process is,
        //# other than the fact that at some point the customer
        //# MUST specify a [DynamoDB Encryption Client Configuration](#dynamodb-encryption-client-configuration).
        self.table_encryption_configs = configs.unwrap_or_default();
        self
    }

    /// Build the client.
    ///
    /// # Errors
    ///
    /// A `Validation` error when no DynamoDB client is set, a table configuration is invalid,
    /// or two tables have the same logical table name.
    #[allow(clippy::unused_async, clippy::unused_async_trait_impl)] // async on every builder that holds an AWS client
    pub async fn build(self) -> Result<Client, Error> {
        let ddb = self
            .ddb_client
            .ok_or_else(|| val_err("ddb_client is required"))?;

        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#overview
        //# This configuration MUST be the configuration ultimately used by
        //# the behaviors within the DynamoDB Encryption Client.
        //
        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#dynamodb-encryption-client-configuration
        //# The DynamoDB Encryption Client Configuration is a structure that
        //# the customer MUST provide in the process of creating a [DynamoDB Encryption Client](#dynamodb-encryption-client).
        let transforms = Transforms::builder()
            .set_table_encryption_configs(Some(self.table_encryption_configs))
            .build()?;
        Ok(Client { ddb, transforms })
    }
}

/// The `Validation` error for a request that the AWS SDK builder could not build.
fn build_error(err: aws_sdk_dynamodb::error::BuildError) -> Error {
    Error::with_cause(Kind::Validation, "the DynamoDB request is invalid", err)
}

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
    BatchWriteItemFluentBuilder, DeleteItemFluentBuilder, GetItemFluentBuilder,
    PutItemFluentBuilder, TransactWriteItemsFluentBuilder, UpdateItemFluentBuilder,
};

/// A DynamoDB client that encrypts and signs each item before it is written,
/// and verifies and decrypts it after it is read.
///
/// It has the same operations, inputs, and outputs as [`aws_sdk_dynamodb::Client`].
/// Requests for a table with no configuration pass through unchanged.
/// Every operation returns [`Error`]; a failed DynamoDB call keeps DynamoDB's own error,
/// which [`Error::as_service_error`] returns.
///
/// Cloning is cheap: clones share the configuration.
///
/// ```no_run
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
///     .build()?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct Client {
    ddb: aws_sdk_dynamodb::Client,
    transforms: Transforms,
}

impl Client {
    /// A builder for a client.
    #[must_use]
    pub fn builder() -> ClientBuilder {
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

    /// Update an item. On a configured table the update must not touch a signed attribute.
    #[must_use]
    pub fn update_item(&self) -> UpdateItemFluentBuilder {
        UpdateItemFluentBuilder::new(self.ddb.update_item(), self.transforms.clone())
    }

    /// Delete an item. On a configured table the condition must not read an encrypted attribute.
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
}

/// A builder for [`Client`].
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct ClientBuilder {
    ddb_client: Option<aws_sdk_dynamodb::Client>,
    table_encryption_configs: HashMap<String, TableConfig>,
}

impl ClientBuilder {
    /// The DynamoDB client that sends each request. Required.
    #[must_use]
    pub fn ddb_client(mut self, client: aws_sdk_dynamodb::Client) -> Self {
        self.ddb_client = Some(client);
        self
    }

    /// The DynamoDB client. See [`Self::ddb_client`].
    #[must_use]
    pub fn set_ddb_client(mut self, client: Option<aws_sdk_dynamodb::Client>) -> Self {
        self.ddb_client = client;
        self
    }

    /// Add the configuration of table `name`, the table name requests use.
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
        self.table_encryption_configs = configs.unwrap_or_default();
        self
    }

    /// Build the client.
    ///
    /// # Errors
    ///
    /// A `Validation` error when no DynamoDB client is set, a table configuration is invalid,
    /// or two tables have the same logical table name.
    pub fn build(self) -> Result<Client, Error> {
        let ddb = self
            .ddb_client
            .ok_or_else(|| val_err("ddb_client is required"))?;
        let transforms = Transforms::builder()
            .set_table_encryption_configs(Some(self.table_encryption_configs))
            .build()?;
        Ok(Client { ddb, transforms })
    }
}

/// A request the AWS SDK builder could not build.
fn build_error(err: aws_sdk_dynamodb::error::BuildError) -> Error {
    Error::with_cause(Kind::Validation, "the DynamoDB request is invalid", err)
}

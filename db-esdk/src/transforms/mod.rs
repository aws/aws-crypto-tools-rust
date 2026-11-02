// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The request and response transforms behind [`Client`](crate::Client).
//!
//! Each DynamoDB operation has two transforms:
//! the input transform runs on the request before the client sends it,
//! and the output transform runs on the response before the client returns it.
//! A write's input transform encrypts the items that it writes;
//! a read's output transform decrypts the items that it returns.
//! The PartiQL input transforms reject a statement on a configured table.
//! A request for a table with no configuration passes through unchanged.

// Every transform is `async` so that callers await each one the same way,
// including the pass-through transforms that have nothing to await.
#![allow(clippy::unused_async, clippy::unused_async_trait_impl)]

mod partiql;
mod read;
mod resolve;
mod write;

pub use resolve::{ResolveAttributesInput, ResolveAttributesInputBuilder, ResolveAttributesOutput};

use std::collections::HashMap;
use std::sync::Arc;

use aws_crypto_mpl::aws_sdk_dynamodb::types::AttributeValue;

use crate::ddb::{Item, filter_expr, update_expr};
use crate::error::{Error, val_err};
use crate::item_encryptor::{ItemEncryptor, ParsedHeader};
use crate::search::BeaconKeySource;
use crate::search::beacon::MaybeKeyId;
use crate::search::convert;
use crate::search::info::SearchInfo;
use crate::structured::util::RESERVED_PREFIX;
use crate::table_config::TableConfig;
use crate::types::{CryptoAction, PlaintextOverride};

/// The transforms for a set of tables, each with its own configuration.
///
/// Cloning is cheap: clones share the configuration.
#[derive(Clone, Debug)]
pub struct Transforms {
    tables: Arc<HashMap<String, Table>>,
}

/// One configured table.
#[derive(Debug)]
struct Table {
    encryptor: ItemEncryptor,
    /// The table's beacons, if it has a search configuration.
    search: Option<SearchInfo>,
    /// With a multi key store, the attribute that holds an item's beacon key id.
    key_field_name: Option<String>,
}

impl Transforms {
    /// A builder for transforms.
    #[must_use]
    pub fn builder() -> TransformsBuilder {
        TransformsBuilder::default()
    }

    /// The item encryptor of table `name`, if the table is configured.
    fn table(&self, name: Option<&str>) -> Option<&ItemEncryptor> {
        self.table_info(name).map(|t| &t.encryptor)
    }

    /// Table `name`, if it is configured.
    fn table_info(&self, name: Option<&str>) -> Option<&Table> {
        name.and_then(|n| self.tables.get(n))
    }

    /// Table `name`, unless its writes are plaintext.
    fn encrypted_write(&self, name: Option<&str>) -> Option<&Table> {
        self.table_info(name).filter(|t| {
            t.encryptor.config().plaintext_override
                != PlaintextOverride::ForcePlaintextWriteAllowPlaintextRead
        })
    }
}

/// A builder for [`Transforms`].
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct TransformsBuilder {
    table_encryption_configs: HashMap<String, TableConfig>,
}

impl TransformsBuilder {
    /// Add the configuration of table `name`, the `TableName` that requests use.
    #[must_use]
    pub fn table_encryption_configs(
        mut self,
        name: impl Into<String>,
        config: TableConfig,
    ) -> Self {
        //= spec/dynamodb-encryption-client/ddb-table-encryption-config.md#dynamodb-table-name
        //# If this config is being organized with other table configs in a map,
        //# this value MAY exist as a key value to identify other data in this config,
        //# instead of existing alongside this data in the same object.
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

    /// Build the transforms.
    ///
    /// # Errors
    ///
    /// A `Validation` error when a table configuration is invalid,
    /// or when two tables have the same logical table name.
    pub fn build(self) -> Result<Transforms, Error> {
        let mut names: Vec<String> = self.table_encryption_configs.keys().cloned().collect();
        names.sort();
        let mut configs = self.table_encryption_configs;
        let mut tables = HashMap::with_capacity(names.len());
        let mut logical_names = Vec::with_capacity(names.len());
        for name in names {
            let Some(mut config) = configs.remove(&name) else {
                continue;
            };
            let search = convert::convert(&config)?;
            let key_field_name = config
                .search()
                .and_then(|s| s.versions().first())
                .and_then(|v| match v.key_source() {
                    BeaconKeySource::Multi(m) => Some(m.key_field_name().to_owned()),
                    BeaconKeySource::Single(_) => None,
                });
            if let Some(search) = &search {
                // The client writes a fully signed compound beacon in plaintext, so its action is SIGN_ONLY.
                for beacon in search.version.signed_beacon_names() {
                    //= spec/searchable-encryption/beacons.md#signed-beacons
                    //# `NAME` MUST be automatically configured with an attribute action of SIGN_ONLY.
                    config
                        .attribute_actions_on_encrypt
                        .insert(beacon, CryptoAction::SignOnly);
                }
            }

            //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#dynamodb-table-encryption-configs
            //# During initialization, this client MUST construct a
            //# [DynamoDb Item Encryptor](./ddb-table-encryption-config.md)
            //# per configured table, using these table encryption configs.
            let encryptor = ItemEncryptor::builder()
                .table(name.clone(), config)
                .build()?;
            let logical = encryptor.config().logical_table_name.clone();
            //= spec/dynamodb-encryption-client/ddb-table-encryption-config.md#logical-table-name
            //# When mapping [DynamoDB Table Names](#dynamodb-table-name) to [logical table name](#logical-table-name)
            //# there MUST a one to one mapping between the two.
            if logical_names.contains(&logical) {
                return Err(val_err(format!(
                    "Duplicate logical table mapped to multiple physical tables: {logical}"
                )));
            }
            logical_names.push(logical);
            tables.insert(
                name,
                Table {
                    encryptor,
                    search,
                    key_field_name,
                },
            );
        }
        Ok(Transforms {
            tables: Arc::new(tables),
        })
    }
}

/// Whether `m` is absent or empty.
fn no_map<K, V>(m: Option<&HashMap<K, V>>) -> bool {
    m.is_none_or(HashMap::is_empty)
}

/// Reject an item that writes an attribute whose name begins with `aws_dbe_`.
fn is_writeable(item: &Item) -> Result<(), Error> {
    let mut reserved: Vec<&str> = item
        .keys()
        .map(String::as_str)
        .filter(|k| k.starts_with(RESERVED_PREFIX))
        .collect();
    if reserved.is_empty() {
        return Ok(());
    }
    reserved.sort_unstable();

    //= spec/dynamodb-encryption-client/ddb-support.md#writable
    //# Writeable MUST reject any item containing an attribute which begins with `aws_dbe_`.
    Err(val_err(format!(
        "Writing reserved attributes not allowed : {}",
        reserved.join("\n")
    )))
}

fn is_encrypted(actions: &HashMap<String, CryptoAction>, attr: &str) -> bool {
    actions.get(attr) == Some(&CryptoAction::EncryptAndSign)
}

fn is_signed(actions: &HashMap<String, CryptoAction>, attr: &str) -> bool {
    actions
        .get(attr)
        .is_some_and(|a| *a != CryptoAction::DoNothing)
}

/// Reject a condition expression that reads an encrypted attribute.
fn test_condition_expression(
    table: &ItemEncryptor,
    expr: Option<&str>,
    names: Option<&HashMap<String, String>>,
) -> Result<(), Error> {
    let Some(expr) = expr else {
        return Ok(());
    };
    let actions = &table.config().attribute_actions_on_encrypt;
    let attrs: Vec<String> = filter_expr::extract_attributes(expr, names)
        .into_iter()
        .filter(|a| is_encrypted(actions, a))
        .collect();
    if attrs.is_empty() {
        Ok(())
    } else {
        //= spec/dynamodb-encryption-client/ddb-support.md#testconditionexpression
        //# TestConditionExpression MUST fail if any operand in the condition expression is an encrypted attribute name.
        Err(val_err(format!(
            "Condition Expressions forbidden on encrypted attributes : {}",
            attrs.join(",")
        )))
    }
}

/// Reject an update expression that names a signed attribute.
fn test_update_expression(
    table: &ItemEncryptor,
    expr: Option<&str>,
    names: Option<&HashMap<String, String>>,
) -> Result<(), Error> {
    let Some(expr) = expr else {
        return Ok(());
    };
    let actions = &table.config().attribute_actions_on_encrypt;
    let attrs: Vec<String> = update_expr::extract_attributes(expr, names)
        .into_iter()
        .filter(|a| is_signed(actions, a))
        .collect();
    if attrs.is_empty() {
        Ok(())
    } else {
        //= spec/dynamodb-encryption-client/ddb-support.md#testupdateexpression
        //# TestUpdateExpression MUST fail if any operand in the update expression is a signed attribute name.
        Err(val_err(format!(
            "Update Expressions forbidden on signed attributes : {}",
            attrs.join(",")
        )))
    }
}

/// The longest key condition or filter expression a search request may have, in UTF-16 code units.
const MAX_EXPRESSION_LENGTH: usize = 4096;

/// Reject expression `name` when it is longer than [`MAX_EXPRESSION_LENGTH`].
fn validate_expression_length(expr: Option<&str>, name: &str) -> Result<(), Error> {
    match expr {
        Some(e) if e.encode_utf16().count() > MAX_EXPRESSION_LENGTH => Err(val_err(format!(
            "{name} exceeds maximum length of {MAX_EXPRESSION_LENGTH} characters."
        ))),
        _ => Ok(()),
    }
}

/// Reject a key condition or filter expression that reads an encrypted attribute:
/// without beacons, DynamoDB cannot search an encrypted attribute.
fn test_beaconize(
    table: &ItemEncryptor,
    key_expr: Option<&str>,
    filter_expr: Option<&str>,
    names: Option<&HashMap<String, String>>,
) -> Result<(), Error> {
    let actions = &table.config().attribute_actions_on_encrypt;
    for expr in [key_expr, filter_expr].into_iter().flatten() {
        if let Some(attr) = filter_expr::all_attributes(expr, names)
            .into_iter()
            .find(|a| is_encrypted(actions, a))
        {
            return Err(val_err(format!("Query is using encrypted field : {attr}.")));
        }
    }
    Ok(())
}

/// Verify and decrypt each item read from `table`, in order.
async fn decrypt_all(table: &ItemEncryptor, items: Vec<Item>) -> Result<Vec<Item>, Error> {
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        out.push(decrypt(table, item).await?);
    }
    Ok(out)
}

/// The key provider id of the hierarchical keyring.
const HIERARCHICAL_KEYRING_ID: &str = "aws-kms-hierarchy";

/// With a multi key store, the beacon key id of an item: the branch key id that encrypted it.
fn key_id_from_header(
    search: &SearchInfo,
    header: Option<&ParsedHeader>,
) -> Result<MaybeKeyId, Error> {
    if !search.is_multi_key() {
        return Ok(MaybeKeyId::DontUse);
    }
    let header =
        header.ok_or_else(|| val_err("In multi-tenant mode, the parsed header is required."))?;
    let [key] = header.encrypted_data_keys() else {
        //= spec/searchable-encryption/search-config.md#get-beacon-key-id-from-parsed-header
        //# If the [Parsed Header](../dynamodb-encryption-client/encrypt-item.md#parsed-header)'s encrypted data keys
        //# do not contain only one encrypted data key
        //# this function MUST fail.
        return Err(val_err(
            "Encrypt header has more than one Encrypted Data Key",
        ));
    };
    if key.key_provider_id() != HIERARCHICAL_KEYRING_ID {
        //= spec/searchable-encryption/search-config.md#get-beacon-key-id-from-parsed-header
        //# If this single encrypted data key's
        //# [Key Provider ID](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/../structured-encryption/structures.md#key-provider-id)
        //# does not equal the provider ID
        //# for the [AWS KMS Hierarchical Keyring](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt)
        //# this function MUST fail.
        return Err(val_err(
            "In multi-tenant mode, keyProviderId must be aws-kms-hierarchy",
        ));
    }
    let id = String::from_utf8(key.key_provider_info().to_vec())
        .map_err(|e| val_err(format!("the branch key id is not UTF-8: {e}")))?;

    //= spec/searchable-encryption/search-config.md#get-beacon-key-id-from-parsed-header
    //# This function MUST return the [Key Provider Information](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/../structured-encryption/structures.md#key-provider-id).
    Ok(MaybeKeyId::Id(id))
}

/// Encrypt and sign an item for a write to `table`, and add its beacons.
async fn encrypt(table: &Table, item: Item) -> Result<Item, Error> {
    let Some(search) = &table.search else {
        return Ok(table
            .encryptor
            .encrypt_item()
            .plaintext_item(item)
            .send()
            .await?
            .into_encrypted_item());
    };
    let partition = search
        .get_partition(&item, &table.encryptor.config().logical_table_name)
        .await?;

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-putitem
    //# Signed Beacons MUST be [added](ddb-support.md#addsignedbeacons).
    //
    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-batchwriteitem
    //# Signed Beacons MUST be [added](ddb-support.md#addsignedbeacons).
    //
    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-transactwriteitems
    //# - Signed Beacons MUST be [added](ddb-support.md#addsignedbeacons).
    //
    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-putitem
    //= reason=add_signed_beacons removes the key field unless it is configured SIGN_ONLY
    //# If the [Beacon Key Source](../searchable-encryption/search-config.md#beacon-key-source)
    //# is a [Multi Key Store](../searchable-encryption/search-config.md#multi-key-store-initialization)
    //# the [Beacon Key Field Name](../searchable-encryption/search-config.md#beacon-key-field-name)
    //# MUST be [handled](./ddb-support.md#handlebeaconkeyfieldname).
    //
    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-batchwriteitem
    //= reason=add_signed_beacons removes the key field unless it is configured SIGN_ONLY
    //# If the [Beacon Key Source](../searchable-encryption/search-config.md#beacon-key-source)
    //# is a [Multi Key Store](../searchable-encryption/search-config.md#multi-key-store-initialization)
    //# the [Beacon Key Field Name](../searchable-encryption/search-config.md#beacon-key-field-name)
    //# MUST be [handled](./ddb-support.md#handlebeaconkeyfieldname).
    //
    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-transactwriteitems
    //= reason=add_signed_beacons removes the key field unless it is configured SIGN_ONLY
    //# - If the [Beacon Key Source](../searchable-encryption/search-config.md#beacon-key-source)
    //# is a [Multi Key Store](../searchable-encryption/search-config.md#multi-key-store-initialization)
    //# the [Beacon Key Field Name](../searchable-encryption/search-config.md#beacon-key-field-name)
    //# MUST be [handled](./ddb-support.md#handlebeaconkeyfieldname).
    let with_signed = search.add_signed_beacons(item.clone(), partition)?;

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-putitem
    //# If the [Beacon Key Source](../searchable-encryption/search-config.md#beacon-key-source)
    //# is a [Multi Key Store](../searchable-encryption/search-config.md#multi-key-store-initialization)
    //# the [Item Encryptor](./ddb-item-encryptor.md) MUST perform
    //# [Encrypt Item](./encrypt-item.md),
    //# where the input [DynamoDB Item](./encrypt-item.md#dynamodb-item)
    //# is output of [handling the beacon key field name](ddb-support.md#handlebeaconkeyfieldname) operation.
    //
    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-putitem
    //# If the [Beacon Key Source](../searchable-encryption/search-config.md#beacon-key-source)
    //# is a [Single Key Store](../searchable-encryption/search-config.md#single-key-store-initialization)
    //# the [Item Encryptor](./ddb-item-encryptor.md) MUST perform
    //# [Encrypt Item](./encrypt-item.md),
    //# where the input [DynamoDB Item](./encrypt-item.md#dynamodb-item)
    //# is output of [adding the signed beacons](ddb-support.md#addsignedbeacons) operation.
    //
    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-batchwriteitem
    //# If the [Beacon Key Source](../searchable-encryption/search-config.md#beacon-key-source)
    //# is a [Multi Key Store](../searchable-encryption/search-config.md#multi-key-store-initialization)
    //# the [Item Encryptor](./ddb-item-encryptor.md) MUST perform
    //# [Encrypt Item](./encrypt-item.md),
    //# where the input [DynamoDB Item](./encrypt-item.md#dynamodb-item)
    //# is output of [handling the beacon key field name](ddb-support.md#handlebeaconkeyfieldname) operation.
    //
    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-batchwriteitem
    //# If the [Beacon Key Source](../searchable-encryption/search-config.md#beacon-key-source)
    //# is a [Single Key Store](../searchable-encryption/search-config.md#single-key-store-initialization)
    //# the [Item Encryptor](./ddb-item-encryptor.md) MUST perform
    //# [Encrypt Item](./encrypt-item.md),
    //# where the input [DynamoDB Item](./encrypt-item.md#dynamodb-item)
    //# is output of [adding the signed beacons](ddb-support.md#addsignedbeacons) operation.
    //
    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-transactwriteitems
    //# - If the [Beacon Key Source](../searchable-encryption/search-config.md#beacon-key-source)
    //# is a [Multi Key Store](../searchable-encryption/search-config.md#multi-key-store-initialization)
    //# the [Item Encryptor](./ddb-item-encryptor.md) MUST perform
    //# [Encrypt Item](./encrypt-item.md),
    //# where the input [DynamoDB Item](./encrypt-item.md#dynamodb-item)
    //# is output of [handling the beacon key field name](ddb-support.md#handlebeaconkeyfieldname) operation.
    //
    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-transactwriteitems
    //# - If the [Beacon Key Source](../searchable-encryption/search-config.md#beacon-key-source)
    //# is a [Single Key Store](../searchable-encryption/search-config.md#single-key-store-initialization)
    //# the [Item Encryptor](./ddb-item-encryptor.md) MUST perform
    //# [Encrypt Item](./encrypt-item.md),
    //# where the input [DynamoDB Item](./encrypt-item.md#dynamodb-item)
    //# is output of [adding the signed beacons](ddb-support.md#addsignedbeacons) operation.
    let encrypted = table
        .encryptor
        .encrypt_item()
        .plaintext_item(with_signed)
        .send()
        .await?;

    //= spec/searchable-encryption/search-config.md#get-beacon-key-after-encrypt
    //= reason=key_id_from_header returns DontUse for a single key store
    //# If the [Beacon Key Source](#beacon-key-source) is a [Multi Key Store](#multi-key-store-initialization)
    //# then `beacon key id` MUST be obtained from [Get beacon key id from parsed header](#get-beacon-key-id-from-parsed-header).
    let key_id = key_id_from_header(search, encrypted.parsed_header())?;
    // `item` is the item before `add_signed_beacons`, so it still has the key field.
    if let (Some(key_field_name), MaybeKeyId::Id(header_id)) = (&table.key_field_name, &key_id)
        && let Some(item_key_id) = item.get(key_field_name)
        && *item_key_id != AttributeValue::S(header_id.clone())
    {
        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-putitem
        //# If the [Beacon Key Source](../searchable-encryption/search-config.md#beacon-key-source)
        //# is a [Multi Key Store](../searchable-encryption/search-config.md#multi-key-store-initialization)
        //# and a `branch key id` was returned from [handling the beacon key field name](ddb-support.md#handlebeaconkeyfieldname)
        //# this `branch key id` MUST match the value
        //# returned from [Get beacon key id from Parsed Header](../searchable-encryption/search-config.md#get-beacon-key-id-from-parsed-header).
        //
        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-batchwriteitem
        //# If the [Beacon Key Source](../searchable-encryption/search-config.md#beacon-key-source)
        //# is a [Multi Key Store](../searchable-encryption/search-config.md#multi-key-store-initialization)
        //# and a `branch key id` was returned from [handling the beacon key field name](ddb-support.md#handlebeaconkeyfieldname)
        //# this `branch key id` MUST match the value
        //# returned from [Get beacon key id from Parsed Header](../searchable-encryption/search-config.md#get-beacon-key-id-from-parsed-header).
        //
        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-transactwriteitems
        //# - If the [Beacon Key Source](../searchable-encryption/search-config.md#beacon-key-source)
        //# is a [Multi Key Store](../searchable-encryption/search-config.md#multi-key-store-initialization)
        //# and a `branch key id` was returned from [handling the beacon key field name](ddb-support.md#handlebeaconkeyfieldname)
        //# this `branch key id` MUST match the value
        //# returned from [Get beacon key id from Parsed Header](../searchable-encryption/search-config.md#get-beacon-key-id-from-parsed-header).
        return Err(val_err(format!(
            "The beacon key id in {key_field_name} does not match the branch key id {header_id} that encrypted the item."
        )));
    }
    let beacons = search
        .get_encrypted_beacons(&item, &key_id, partition)
        .await?;
    let mut out = encrypted.into_encrypted_item();

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-putitem
    //# Encrypted Beacons MUST be [added](ddb-support.md#addencryptedbeacons).
    //
    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-batchwriteitem
    //# Encrypted Beacons MUST be [added](ddb-support.md#addencryptedbeacons).
    //
    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-transactwriteitems
    //# - Encrypted Beacons MUST be [added](ddb-support.md#addencryptedbeacons).
    out.extend(beacons);
    Ok(out)
}

/// Verify and decrypt an item read from `table`, and remove its `aws_dbe_` attributes.
async fn decrypt(table: &ItemEncryptor, item: Item) -> Result<Item, Error> {
    let plaintext = table
        .decrypt_item()
        .encrypted_item(item)
        .send()
        .await?
        .into_plaintext_item();

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-getitem
    //# Beacons MUST be [removed](ddb-support.md#removebeacons) from the result.
    //
    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-putitem
    //# Beacons MUST be [removed](ddb-support.md#removebeacons) from the result.
    //
    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-deleteitem
    //# Beacons MUST be [removed](ddb-support.md#removebeacons) from the result.
    //
    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-updateitem
    //# Beacons MUST be [removed](ddb-support.md#removebeacons) from the result.
    //
    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-batchgetitem
    //# Beacons MUST be [removed](ddb-support.md#removebeacons) from the result.
    //
    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-transactgetitems
    //# Beacons MUST be [removed](ddb-support.md#removebeacons) from the result.
    Ok(remove_beacons(plaintext))
}

/// Verify and decrypt the items of a query or scan of `table`,
/// then filter them again with the original expressions and remove their beacons.
///
/// With a multi key store, drop each item that was encrypted under a beacon key
/// other than the one that the query names.
async fn decrypt_search_results(
    table: &Table,
    items: Vec<Item>,
    key_expr: Option<&str>,
    filter_expr: Option<&str>,
    names: Option<&HashMap<String, String>>,
    values: Option<&HashMap<String, AttributeValue>>,
    what: &str,
) -> Result<Vec<Item>, Error> {
    //= spec/dynamodb-encryption-client/ddb-support.md#queryoutputforbeacons
    //= reason=get_beacon_key_id gives the id the query fetches its key materials under; none are kept here
    //# If the [Beacon Key Source](../searchable-encryption/search-config.md#beacon-key-source) for the configured table
    //# is a [Multi Key Store](../searchable-encryption/search-config.md#multi-key-store-initialization)
    //# you MUST construct an `expected beacon key id` equal to the [Beacon Key Id](../searchable-encryption/search-config.md#beacon-key-materials)
    //# on materials obtained from [Get beacon key for query](../searchable-encryption/search-config.md#get-beacon-key-for-query)
    //# These [Beacon Key Materials](../searchable-encryption/search-config.md#beacon-key-materials)
    //# SHOULD then be discarded.
    let key_id = match &table.search {
        None => MaybeKeyId::DontUse,
        Some(search) => search
            .version
            .get_beacon_key_id(key_expr, filter_expr, values, names)?,
    };
    let mut decrypted = Vec::with_capacity(items.len());
    for item in items {
        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-query
        //# For each list entry in `Items` in the response,
        //# if there exists an Item Encryptor specified within the
        //# [DynamoDB Encryption Client Config](#dynamodb-encryption-client-configuration)
        //# with a [DynamoDB Table Name](./ddb-item-encryptor.md#dynamodb-table-name)
        //# equal to the `TableName` on the request,
        //# the corresponding Item Encryptor MUST perform [Decrypt Item](./decrypt-item.md)
        //# where the input [DynamoDB Item](./decrypt-item.md#dynamodb-item)
        //# is this list entry.
        //
        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-scan
        //# For each list entry in `Items` in the response,
        //# if there exists an Item Encryptor specified within the
        //# [DynamoDB Encryption Client Config](#dynamodb-encryption-client-configuration)
        //# with a [DynamoDB Table Name](./ddb-item-encryptor.md#dynamodb-table-name)
        //# equal to the `TableName` on the request,
        //# the corresponding Item Encryptor MUST perform [Decrypt Item](./decrypt-item.md)
        //# where the input [DynamoDB Item](./decrypt-item.md#dynamodb-item)
        //# is this list entry.
        //
        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-query
        //# If any [Decrypt Item](./decrypt-item.md) fails,
        //# Query MUST yield an error.
        //
        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-scan
        //# If any [Decrypt Item](./decrypt-item.md) operation fails,
        //# Scan MUST yield an error.
        let out = table
            .encryptor
            .decrypt_item()
            .encrypted_item(item)
            .send()
            .await?;
        if let (MaybeKeyId::Id(id), Some(header)) = (&key_id, out.parsed_header()) {
            let [key] = header.encrypted_data_keys() else {
                return Err(val_err(format!(
                    "{what} result has more than one Encrypted Data Key"
                )));
            };

            //= spec/dynamodb-encryption-client/ddb-support.md#queryoutputforbeacons
            //# Using the constructed `expected beacon key id`,
            //# for each item the result
            //# the [Get beacon key id from Parsed Header](../searchable-encryption/search-config.md#get-beacon-key-id-from-parsed-header)
            //# MUST match the `expected beacon key id`.
            if key.key_provider_info() != id.as_bytes() {
                //= spec/dynamodb-encryption-client/ddb-support.md#queryoutputforbeacons
                //= reason=Deviation: a header without exactly one EDK fails the query; an item with no parsed header is kept
                //# If [Get beacon key id from Parsed Header](../searchable-encryption/search-config.md#get-beacon-key-id-from-parsed-header)
                //# fails or an item does not match it MUST be discarded.
                continue;
            }
        }
        decrypted.push(out.into_plaintext_item());
    }
    validate_expression_length(key_expr, "KeyConditionExpression")?;
    validate_expression_length(filter_expr, "FilterExpression")?;

    //= spec/dynamodb-encryption-client/ddb-support.md#queryoutputforbeacons
    //# For this reason,
    //# any error encountered during filtering MUST result in a failure of the query operation.
    let filtered = match &table.search {
        None => decrypted,
        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-query
        //# The resulting decrypted response MUST be [filtered](ddb-support.md#queryoutputforbeacons) from the result.
        //
        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-scan
        //# The resulting decrypted response MUST be [filtered](ddb-support.md#scanoutputforbeacons) from the result.
        Some(search) => {
            search
                .version
                .filter_results(decrypted, key_expr, filter_expr, names, values)?
        }
    };
    Ok(filtered.into_iter().map(remove_beacons).collect())
}

/// `item` without the attributes whose names begin with `aws_dbe_`.
fn remove_beacons(item: HashMap<String, AttributeValue>) -> Item {
    //= spec/dynamodb-encryption-client/ddb-support.md#removebeacons
    //# RemoveBeacons MUST remove any attributes whose name begins with `aws_dbe_`,
    //# and leave all other attributes unchanged.
    item.into_iter()
        .filter(|(k, _)| !k.starts_with(RESERVED_PREFIX))
        .collect()
}

// The item encryptor already drops `aws_dbe_` attributes,
// so only a direct call shows whether `remove_beacons` removes them itself.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remove_beacons_drops_reserved_attributes() {
        let s = |v: &str| AttributeValue::S(v.to_owned());
        let item = HashMap::from([
            ("a".to_owned(), s("1")),
            ("aws_dbe_b_a".to_owned(), s("beacon")),
            ("aws_dbe_head".to_owned(), s("header")),
            ("aws_dbe_foot".to_owned(), s("footer")),
        ]);

        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-getitem
        //= type=test
        //= reason=decrypt() passes every getitem result through remove_beacons
        //# Beacons MUST be [removed](ddb-support.md#removebeacons) from the result.
        //
        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-putitem
        //= type=test
        //= reason=decrypt() passes every putitem result through remove_beacons
        //# Beacons MUST be [removed](ddb-support.md#removebeacons) from the result.
        //
        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-deleteitem
        //= type=test
        //= reason=decrypt() passes every deleteitem result through remove_beacons
        //# Beacons MUST be [removed](ddb-support.md#removebeacons) from the result.
        //
        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-updateitem
        //= type=test
        //= reason=decrypt() passes every updateitem result through remove_beacons
        //# Beacons MUST be [removed](ddb-support.md#removebeacons) from the result.
        //
        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-batchgetitem
        //= type=test
        //= reason=decrypt() passes every batchgetitem result through remove_beacons
        //# Beacons MUST be [removed](ddb-support.md#removebeacons) from the result.
        //
        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-transactgetitems
        //= type=test
        //= reason=decrypt() passes every transactgetitems result through remove_beacons
        //# Beacons MUST be [removed](ddb-support.md#removebeacons) from the result.
        assert_eq!(
            remove_beacons(item),
            HashMap::from([("a".to_owned(), s("1"))])
        );
    }
}

// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The request and response transforms behind [`Client`](crate::Client).
//!
//! Each DynamoDB operation has an input transform, run on the request before it is sent,
//! and an output transform, run on the response before it is returned.
//! A write's input transform encrypts the items it writes;
//! a read's output transform decrypts the items it returns.
//! A PartiQL statement on a configured table is rejected.
//! A request for a table with no configuration passes through unchanged.

mod partiql;
mod read;
mod write;

use std::collections::HashMap;
use std::sync::Arc;

use aws_crypto_mpl::aws_sdk_dynamodb::types::AttributeValue;

use crate::ddb::{Item, filter_expr, update_expr};
use crate::error::{Error, val_err};
use crate::item_encryptor::ItemEncryptor;
use crate::structured::util::RESERVED_PREFIX;
use crate::table_config::TableConfig;
use crate::types::{CryptoAction, PlaintextOverride};

/// The transforms for a set of tables, each with its own configuration.
///
/// Cloning is cheap: clones share the configuration.
#[derive(Clone, Debug)]
pub struct Transforms {
    tables: Arc<HashMap<String, ItemEncryptor>>,
}

impl Transforms {
    /// A builder for transforms.
    #[must_use]
    pub fn builder() -> TransformsBuilder {
        TransformsBuilder::default()
    }

    /// The item encryptor of table `name`, if the table is configured.
    fn table(&self, name: Option<&str>) -> Option<&ItemEncryptor> {
        name.and_then(|n| self.tables.get(n))
    }

    /// The item encryptor of table `name`, unless its writes are plaintext.
    fn encrypted_write(&self, name: Option<&str>) -> Option<&ItemEncryptor> {
        self.table(name).filter(|t| {
            t.config().plaintext_override
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
    /// Add the configuration of table `name`, the table name requests use.
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
            let Some(config) = configs.remove(&name) else {
                continue;
            };
            let encryptor = ItemEncryptor::builder()
                .table(name.clone(), config)
                .build()?;
            let logical = encryptor.config().logical_table_name.clone();
            if logical_names.contains(&logical) {
                return Err(val_err(format!(
                    "Duplicate logical table mapped to multiple physical tables: {logical}"
                )));
            }
            logical_names.push(logical);
            tables.insert(name, encryptor);
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
/// with no beacons, an encrypted attribute cannot be searched.
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

/// Encrypt and sign an item about to be written to `table`.
async fn encrypt(table: &ItemEncryptor, item: Item) -> Result<Item, Error> {
    Ok(table
        .encrypt_item()
        .plaintext_item(item)
        .send()
        .await?
        .into_encrypted_item())
}

/// Verify and decrypt an item read from `table`, without its `aws_dbe_` attributes.
async fn decrypt(table: &ItemEncryptor, item: Item) -> Result<Item, Error> {
    let plaintext = table
        .decrypt_item()
        .encrypted_item(item)
        .send()
        .await?
        .into_plaintext_item();
    Ok(remove_beacons(plaintext))
}

/// `item` without the attributes whose names begin with `aws_dbe_`.
fn remove_beacons(item: HashMap<String, AttributeValue>) -> Item {
    item.into_iter()
        .filter(|(k, _)| !k.starts_with(RESERVED_PREFIX))
        .collect()
}

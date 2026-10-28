// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Encrypt and decrypt DynamoDB items directly, with no call to DynamoDB.

pub(crate) mod config;

use std::collections::HashMap;
use std::sync::Arc;

use aws_crypto_mpl::aws_sdk_dynamodb::types::AttributeValue;

use crate::ddb::{self, Item};
use crate::error::{Error, ser_err, val_err};
use crate::structured::util::{FOOTER_FIELD, HEADER_FIELD};
use crate::structured::{self, DEFAULT_SUITE};
use crate::table_config::{TableConfig, check_attribute_name};
use crate::types::{
    AlgorithmSuiteId, CryptoAction, EncryptedDataKey, EncryptionContext, PlaintextOverride,
};
use config::Config;

/// Encrypts and decrypts the items of one table, with no call to DynamoDB.
///
/// Use it when you hold an item and make no put or get call,
/// for example to decrypt an item from a DynamoDB stream.
/// Cloning is cheap: clones share the configuration.
#[derive(Clone, Debug)]
pub struct ItemEncryptor {
    config: Arc<Config>,
}

impl ItemEncryptor {
    /// A builder for an item encryptor.
    #[must_use]
    pub fn builder() -> ItemEncryptorBuilder {
        ItemEncryptorBuilder::default()
    }

    /// Encrypt and sign an item.
    #[must_use]
    pub fn encrypt_item(&self) -> EncryptItemFluentBuilder {
        EncryptItemFluentBuilder {
            config: Arc::clone(&self.config),
            plaintext_item: None,
        }
    }

    /// Verify and decrypt an item.
    #[must_use]
    pub fn decrypt_item(&self) -> DecryptItemFluentBuilder {
        DecryptItemFluentBuilder {
            config: Arc::clone(&self.config),
            encrypted_item: None,
        }
    }

    /// The resolved table configuration.
    pub(crate) fn config(&self) -> &Config {
        &self.config
    }
}

/// A builder for [`ItemEncryptor`].
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct ItemEncryptorBuilder {
    table: Option<(String, TableConfig)>,
}

impl ItemEncryptorBuilder {
    /// The table whose items this encrypts, and its configuration. Required.
    ///
    /// `name` is the logical table name bound into every item,
    /// unless the configuration sets its own.
    #[must_use]
    pub fn table(mut self, name: impl Into<String>, config: TableConfig) -> Self {
        self.table = Some((name.into(), config));
        self
    }

    /// Build the item encryptor.
    ///
    /// # Errors
    ///
    /// A `Validation` error when no table is set, or the table configuration is invalid:
    /// for example a key attribute with the wrong action,
    /// or a `DO_NOTHING` attribute that is not allowed unsigned.
    pub fn build(self) -> Result<ItemEncryptor, Error> {
        let (name, table) = self.table.ok_or_else(|| val_err("table is required"))?;
        Ok(ItemEncryptor {
            config: Arc::new(Config::new(name, table)?),
        })
    }
}

/// What the header of an encrypted item says.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ParsedHeader {
    attribute_actions_on_encrypt: HashMap<String, CryptoAction>,
    algorithm_suite_id: AlgorithmSuiteId,
    encrypted_data_keys: Vec<EncryptedDataKey>,
    stored_encryption_context: EncryptionContext,
    encryption_context: EncryptionContext,
}

impl ParsedHeader {
    /// The action of each signed attribute.
    #[must_use]
    pub const fn attribute_actions_on_encrypt(&self) -> &HashMap<String, CryptoAction> {
        &self.attribute_actions_on_encrypt
    }

    /// The algorithm suite that encrypted the item.
    #[must_use]
    pub const fn algorithm_suite_id(&self) -> AlgorithmSuiteId {
        self.algorithm_suite_id
    }

    /// The item's encrypted data keys.
    #[must_use]
    pub fn encrypted_data_keys(&self) -> &[EncryptedDataKey] {
        &self.encrypted_data_keys
    }

    /// The encryption context stored in the header.
    #[must_use]
    pub const fn stored_encryption_context(&self) -> &EncryptionContext {
        &self.stored_encryption_context
    }

    /// The full encryption context the item is bound to.
    #[must_use]
    pub const fn encryption_context(&self) -> &EncryptionContext {
        &self.encryption_context
    }
}

fn parsed_header(
    config: &Config,
    header: structured::ParsedHeader,
    schema: HashMap<String, CryptoAction>,
) -> Result<ParsedHeader, Error> {
    if schema.keys().any(|k| !config.in_signature_scope(k)) {
        return Err(val_err(
            "Received unexpected Crypto Schema: mismatch with signature scope",
        ));
    }
    Ok(ParsedHeader {
        attribute_actions_on_encrypt: schema,
        algorithm_suite_id: header.algorithm_suite_id,
        encrypted_data_keys: header.encrypted_data_keys,
        stored_encryption_context: header.stored_encryption_context,
        encryption_context: header.encryption_context,
    })
}

/// The encrypt-item operation. Set the item, then call [`send`](Self::send).
#[derive(Clone, Debug)]
pub struct EncryptItemFluentBuilder {
    config: Arc<Config>,
    plaintext_item: Option<Item>,
}

impl EncryptItemFluentBuilder {
    /// The item to encrypt. Required.
    #[must_use]
    pub fn plaintext_item(mut self, item: HashMap<String, AttributeValue>) -> Self {
        self.plaintext_item = Some(item);
        self
    }

    /// The item to encrypt. See [`Self::plaintext_item`].
    #[must_use]
    pub fn set_plaintext_item(mut self, item: Option<HashMap<String, AttributeValue>>) -> Self {
        self.plaintext_item = item;
        self
    }

    /// Encrypt and sign the item.
    ///
    /// # Errors
    ///
    /// A `Validation` error when the item lacks a key attribute, has an attribute with no action,
    /// or has a value that cannot be stored (such as an invalid number).
    /// An error from the keyring or CMM keeps its variant.
    pub async fn send(self) -> Result<EncryptItemOutput, Error> {
        let item = self
            .plaintext_item
            .ok_or_else(|| val_err("plaintext_item is required"))?;
        encrypt_item(&self.config, item).await
    }
}

/// The encrypted item.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct EncryptItemOutput {
    encrypted_item: Item,
    algorithm_suite_id: AlgorithmSuiteId,
    parsed_header: Option<ParsedHeader>,
}

impl EncryptItemOutput {
    /// The encrypted item.
    #[must_use]
    pub const fn encrypted_item(&self) -> &HashMap<String, AttributeValue> {
        &self.encrypted_item
    }

    /// The encrypted item, by value.
    #[must_use]
    pub fn into_encrypted_item(self) -> HashMap<String, AttributeValue> {
        self.encrypted_item
    }

    /// The algorithm suite that encrypted the item.
    ///
    /// When [`PlaintextOverride::ForcePlaintextWriteAllowPlaintextRead`] writes the item
    /// as plaintext, this is the suite the table would have encrypted it with.
    #[must_use]
    pub const fn algorithm_suite_id(&self) -> AlgorithmSuiteId {
        self.algorithm_suite_id
    }

    /// The header of the encrypted item; `None` when the item was written as plaintext.
    #[must_use]
    pub const fn parsed_header(&self) -> Option<&ParsedHeader> {
        self.parsed_header.as_ref()
    }
}

async fn encrypt_item(config: &Config, item: Item) -> Result<EncryptItemOutput, Error> {
    for name in item.keys() {
        check_attribute_name("plaintext_item", name)?;
    }
    if let Some(msg) = config.key_missing(&item, "Encrypt") {
        return Err(val_err(msg));
    }
    if let Some(msg) = config.context_missing(&item) {
        return Err(val_err(msg));
    }
    if config.plaintext_override == PlaintextOverride::ForcePlaintextWriteAllowPlaintextRead {
        return Ok(EncryptItemOutput {
            encrypted_item: item,
            algorithm_suite_id: config.algorithm_suite_id.unwrap_or(DEFAULT_SUITE),
            parsed_header: None,
        });
    }
    let plaintext =
        ddb::item_to_structured(&item, &config.attribute_actions_on_encrypt).map_err(val_err)?;
    let context = config.encryption_context(config.version, &plaintext)?;
    let schema = config.crypto_schema(&plaintext)?;
    let cmm = structured::required_context_cmm(
        config.cmm.clone(),
        context.keys().map(str::to_owned).collect(),
    )?;
    let out = structured::encrypt_structure(
        &config.logical_table_name,
        &plaintext,
        &schema,
        cmm,
        config.algorithm_suite_id,
        Some(context),
    )
    .await?;
    let encrypted_item =
        ddb::structured_to_item_encrypt(&out.data, &item, &config.attribute_actions_on_encrypt)
            .map_err(val_err)?;
    let header = parsed_header(config, out.parsed_header, out.schema)?;
    Ok(EncryptItemOutput {
        encrypted_item,
        algorithm_suite_id: header.algorithm_suite_id,
        parsed_header: Some(header),
    })
}

/// The decrypt-item operation. Set the item, then call [`send`](Self::send).
#[derive(Clone, Debug)]
pub struct DecryptItemFluentBuilder {
    config: Arc<Config>,
    encrypted_item: Option<Item>,
}

impl DecryptItemFluentBuilder {
    /// The item to decrypt. Required.
    #[must_use]
    pub fn encrypted_item(mut self, item: HashMap<String, AttributeValue>) -> Self {
        self.encrypted_item = Some(item);
        self
    }

    /// The item to decrypt. See [`Self::encrypted_item`].
    #[must_use]
    pub fn set_encrypted_item(mut self, item: Option<HashMap<String, AttributeValue>>) -> Self {
        self.encrypted_item = item;
        self
    }

    /// Verify and decrypt the item.
    ///
    /// # Errors
    ///
    /// A `Serialization` error when the item is not a well-formed encrypted item,
    /// and a `Cryptographic` error when its signature does not verify.
    /// An error from the keyring or CMM keeps its variant.
    pub async fn send(self) -> Result<DecryptItemOutput, Error> {
        let item = self
            .encrypted_item
            .ok_or_else(|| val_err("encrypted_item is required"))?;
        decrypt_item(&self.config, item).await
    }
}

/// The decrypted item.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct DecryptItemOutput {
    plaintext_item: Item,
    parsed_header: Option<ParsedHeader>,
}

impl DecryptItemOutput {
    /// The decrypted item.
    #[must_use]
    pub const fn plaintext_item(&self) -> &HashMap<String, AttributeValue> {
        &self.plaintext_item
    }

    /// The decrypted item, by value.
    #[must_use]
    pub fn into_plaintext_item(self) -> HashMap<String, AttributeValue> {
        self.plaintext_item
    }

    /// The header of the item; `None` when a plaintext item was read.
    #[must_use]
    pub const fn parsed_header(&self) -> Option<&ParsedHeader> {
        self.parsed_header.as_ref()
    }
}

fn is_plaintext_item(item: &Item) -> bool {
    !item.contains_key(HEADER_FIELD) && !item.contains_key(FOOTER_FIELD)
}

async fn decrypt_item(config: &Config, item: Item) -> Result<DecryptItemOutput, Error> {
    if let Some(msg) = config.key_missing(&item, "Decrypt") {
        return Err(val_err(msg));
    }
    let reads_plaintext = matches!(
        config.plaintext_override,
        PlaintextOverride::ForcePlaintextWriteAllowPlaintextRead
            | PlaintextOverride::ForbidPlaintextWriteAllowPlaintextRead
    );
    if reads_plaintext && is_plaintext_item(&item) {
        return Ok(DecryptItemOutput {
            plaintext_item: item,
            parsed_header: None,
        });
    }
    if is_plaintext_item(&item) {
        return Err(ser_err(
            "Encrypted item missing expected header and footer attributes",
        ));
    }
    let encrypted =
        ddb::item_to_structured(&item, &config.attribute_actions_on_encrypt).map_err(ser_err)?;
    let header = match item.get(HEADER_FIELD) {
        None => return Err(ser_err("Header field, \"aws_dbe_head\", not in item.")),
        Some(AttributeValue::B(b)) => b.as_ref(),
        Some(_) => return Err(ser_err("Header field, \"aws_dbe_head\", not binary")),
    };
    let version = *header
        .first()
        .ok_or_else(|| ser_err("Unexpected empty header field."))?;
    if version != 1 && version != 2 {
        return Err(ser_err("Header attribute has unexpected version number"));
    }
    let context = config.encryption_context(version, &encrypted)?;
    let auth = config.authenticate_schema(&encrypted);
    let cmm = structured::required_context_cmm(
        config.cmm.clone(),
        context.keys().map(str::to_owned).collect(),
    )?;
    let out = structured::decrypt_structure(
        &config.logical_table_name,
        &encrypted,
        &auth,
        cmm,
        Some(context),
    )
    .await?;
    let plaintext_item =
        ddb::structured_to_item_decrypt(&out.data, &item, &out.schema).map_err(ser_err)?;
    let header = parsed_header(config, out.parsed_header, out.schema)?;
    Ok(DecryptItemOutput {
        plaintext_item,
        parsed_header: Some(header),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsed_header_rejects_unsigned_attribute_in_schema() {
        let config = config::tests::config();
        let header = structured::ParsedHeader {
            algorithm_suite_id: DEFAULT_SUITE,
            encrypted_data_keys: Vec::new(),
            stored_encryption_context: EncryptionContext::new(),
            encryption_context: EncryptionContext::new(),
        };
        let schema = HashMap::from([(":free".to_owned(), CryptoAction::SignOnly)]);
        match parsed_header(&config, header, schema) {
            Err(Error::Validation(e)) => assert_eq!(
                e.message(),
                "Received unexpected Crypto Schema: mismatch with signature scope"
            ),
            other => panic!("{other:?}"),
        }
    }
}

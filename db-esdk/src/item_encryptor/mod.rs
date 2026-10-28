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
    //= spec/dynamodb-encryption-client/ddb-item-encryptor.md#encryptitem
    //= type=implication
    //= reason=The method exists by construction; its behavior is cited against encrypt-item.md
    //# The DynamoDB Item Encryptor MUST provide a function that adheres to [EncryptItem](./encrypt-item.md).
    #[must_use]
    pub fn encrypt_item(&self) -> EncryptItemFluentBuilder {
        EncryptItemFluentBuilder {
            config: Arc::clone(&self.config),
            plaintext_item: None,
        }
    }

    /// Verify and decrypt an item.
    //= spec/dynamodb-encryption-client/ddb-item-encryptor.md#decryptitem
    //= type=implication
    //= reason=The method exists by construction; its behavior is cited against decrypt-item.md
    //# The DynamoDB Item Encryptor MUST provide a function that adheres to [DecryptItem](./decrypt-item.md).
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
    /// A `Validation` error when no table is set,
    /// the table name has fewer than 3 or more than 255 characters,
    /// or the table configuration is invalid:
    /// for example a key attribute with the wrong action,
    /// or a `DO_NOTHING` attribute that is not allowed unsigned.
    pub fn build(self) -> Result<ItemEncryptor, Error> {
        //= spec/dynamodb-encryption-client/ddb-item-encryptor.md#initialization
        //= reason=The table name comes with a TableConfig, whose build requires key name, actions, and keyring or CMM
        //# On initialization of the DynamoDB Item Encryptor
        //# the caller MUST provide:
        //
        //= spec/dynamodb-encryption-client/ddb-table-encryption-config.md#structure
        //# The physical [DynamoDB Table Name](#dynamodb-table-name) is REQUIRED
        //# to be associated with the DynamoDb Table Encryption Configuration.
        let (name, table) = self.table.ok_or_else(|| val_err("table is required"))?;
        Ok(ItemEncryptor {
            //= spec/dynamodb-encryption-client/ddb-item-encryptor.md#initialization
            //= reason=Config::new accepts a TableConfig with the sort key, unsigned attributes, suite, and policy unset
            //# The following are OPTIONAL for the DynamoDB Item Encryptor:
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
    selector_context: HashMap<String, AttributeValue>,
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

    /// The item key a branch key ID supplier sees for this item.
    #[must_use]
    pub const fn selector_context(&self) -> &HashMap<String, AttributeValue> {
        &self.selector_context
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
    let selector_context =
        crate::branch_key_supplier::item_key_from_context(&header.encryption_context)
            .map_err(val_err)?;

    //= spec/dynamodb-encryption-client/encrypt-item.md#parsed-header
    //# This structure MUST contain the following values,
    //# representing the deserialized form of the header of the input encrypted structure:
    //
    //= spec/dynamodb-encryption-client/decrypt-item.md#parsed-header
    //# This structure MUST contain the following values,
    //# representing the deserialized form of the header of the input encrypted structure:
    Ok(ParsedHeader {
        attribute_actions_on_encrypt: schema,
        algorithm_suite_id: header.algorithm_suite_id,
        encrypted_data_keys: header.encrypted_data_keys,
        stored_encryption_context: header.stored_encryption_context,
        encryption_context: header.encryption_context,
        selector_context,
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
        //= spec/dynamodb-encryption-client/encrypt-item.md#input
        //# The following inputs to this behavior are REQUIRED:
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

//= spec/dynamodb-encryption-client/encrypt-item.md#behavior
//= type=exception
//= reason=TableConfig has no Legacy Config, so no Legacy Policy can be specified
//# If a [Legacy Policy](./ddb-table-encryption-config.md#legacy-policy) of
//# `FORCE_LEGACY_ENCRYPT_ALLOW_LEGACY_DECRYPT` is specified,
//# this operation MUST delegate encryption of this item to the
//# [Legacy Encryptor](./ddb-table-encryption-config.md#legacy-encryptor),
//# using the configured [Attribute Flags](./ddb-table-encryption-config.md) as input.
//
//= spec/dynamodb-encryption-client/encrypt-item.md#behavior
//= type=exception
//= reason=TableConfig has no Legacy Config, so no Legacy Policy can be specified
//# The item returned by this operation MUST be the item outputted by the
//# [Legacy Encryptor](./ddb-table-encryption-config.md#legacy-encryptor).
async fn encrypt_item(config: &Config, item: Item) -> Result<EncryptItemOutput, Error> {
    // Input

    for name in item.keys() {
        check_attribute_name("plaintext_item", name)?;
    }
    if let Some(msg) = config.key_missing(&item, "Encrypt") {
        //= spec/dynamodb-encryption-client/encrypt-item.md#dynamodb-item
        //# This item MUST include an Attribute with a name that matches the
        //# [DynamoDB Partition Key Name](./ddb-table-encryption-config.md#dynamodb-partition-key-name)
        //# configured on the [DynamoDB Item Encryptor](./ddb-item-encryptor.md).
        //
        //= spec/dynamodb-encryption-client/encrypt-item.md#dynamodb-item
        //# Otherwise this operation MUST yield an error.
        //
        //= spec/dynamodb-encryption-client/encrypt-item.md#dynamodb-item
        //# If the [DynamoDB Item Encryptor](./ddb-item-encryptor.md)
        //# has a [DynamoDB Sort Key Name](./ddb-table-encryption-config.md#dynamodb-sort-key-name) configured,
        //# this item MUST include an Attribute with that name.
        return Err(val_err(msg));
    }
    if let Some(msg) = config.context_missing(&item) {
        //= spec/dynamodb-encryption-client/encrypt-item.md#dynamodb-item
        //# If the [DynamoDB Item Encryptor](./ddb-item-encryptor.md)
        //# has any attribute configured as
        //# [SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT](../structured-encryption/structures.md#contextandsign)
        //# then this item MUST include an Attribute with that name.
        return Err(val_err(msg));
    }

    // Plaintext policy

    //= spec/dynamodb-encryption-client/encrypt-item.md#behavior
    //# If a [Plaintext Policy](./ddb-table-encryption-config.md#plaintext-policy) of
    //# `FORCE_PLAINTEXT_WRITE_ALLOW_PLAINTEXT_READ` is specified,
    //# this operation MUST NOT encrypt the input item,
    //# and MUST passthrough that item as the output.
    if config.plaintext_override == PlaintextOverride::ForcePlaintextWriteAllowPlaintextRead {
        return Ok(EncryptItemOutput {
            encrypted_item: item,
            algorithm_suite_id: config.algorithm_suite_id.unwrap_or(DEFAULT_SUITE),
            parsed_header: None,
        });
    }

    // Base context

    let plaintext =
        ddb::item_to_structured(&item, &config.attribute_actions_on_encrypt).map_err(val_err)?;

    //= spec/dynamodb-encryption-client/encrypt-item.md#dynamodb-item-base-context
    //# If the [Configuration Version](./ddb-table-encryption-config.md#configuration-version) is 2,
    //# then the base context MUST be the [version 2](#dynamodb-item-base-context-version-2) context;
    //# otherwise, the base context MUST be the [version 1](#dynamodb-item-base-context-version-1) context.
    let context = config.encryption_context(config.version, &plaintext)?;

    //= spec/dynamodb-encryption-client/encrypt-item.md#behavior
    //# - Crypto Schema MUST be a [Crypto Schema](../structured-encryption/structures.md#crypto-schema)
    //# analogous to the [configured Attribute Actions](./ddb-table-encryption-config.md#attribute-actions).
    let schema = config.crypto_schema(&plaintext)?;

    // Required encryption context CMM

    //= spec/dynamodb-encryption-client/encrypt-item.md#behavior
    //# This operation MUST create a
    //# [Required Encryption Context CMM](https://github.com/awslabs/private-aws-encryption-sdk-specification-staging/blob/dafny-verified/framework/required-encryption-context-cmm.md)
    //# with the following inputs:
    let cmm = structured::required_context_cmm(
        config.cmm.clone(),
        context.keys().map(str::to_owned).collect(),
    )?;

    // Encrypt Structure

    //= spec/dynamodb-encryption-client/encrypt-item.md#behavior
    //# Given the converted [Structured Data](../structured-encryption/structures.md#structured-data),
    //# this operation MUST delegate encryption of this data to
    //# Structured Encryption Client's [Encrypt Structure](../structured-encryption/encrypt-structure.md),
    //# with the following inputs:
    let out = structured::encrypt_structure(
        &config.logical_table_name,
        //= spec/dynamodb-encryption-client/encrypt-item.md#behavior
        //# - Structured Data MUST be the Structured Data converted above.
        plaintext,
        &schema,
        //= spec/dynamodb-encryption-client/encrypt-item.md#behavior
        //# - The CMM MUST be the CMM created above.
        cmm,
        //= spec/dynamodb-encryption-client/ddb-table-encryption-config.md#algorithm-suite
        //# The [algorithm suite](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/algorithm-suites.md) that SHOULD be used for encryption.
        //
        //= spec/dynamodb-encryption-client/encrypt-item.md#behavior
        //# - If configured, the Algorithm Suite MUST be the
        //# [Algorithm Suite configured on this Item Encryptor](./ddb-table-encryption-config.md#algorithm-suite).
        //
        //= spec/dynamodb-encryption-client/encrypt-item.md#behavior
        //= type=implication
        //= reason=An unconfigured suite is None, passed unchanged; Encrypt Structure's default hides it from the CMM
        //# If not configured on the Item Encryptor, Algorithm Suite MUST NOT be specified.
        config.algorithm_suite_id,
        //= spec/dynamodb-encryption-client/encrypt-item.md#behavior
        //# - Encryption Context MUST be this input Item's [DynamoDB Item Base Context](#dynamodb-item-base-context).
        Some(context),
    )
    .await?;

    // Output

    let encrypted_item =
        ddb::structured_to_item_encrypt(&out.data, &item, &config.attribute_actions_on_encrypt)
            .map_err(val_err)?;
    let header = parsed_header(config, out.parsed_header, out.schema)?;

    //= spec/dynamodb-encryption-client/encrypt-item.md#output
    //# This operation MUST output the following:
    Ok(EncryptItemOutput {
        encrypted_item,
        algorithm_suite_id: header.algorithm_suite_id,
        //= spec/dynamodb-encryption-client/encrypt-item.md#output
        //# This operation MUST also output a [Parsed Header](#parsed-header) if the following is true:
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
        //= spec/dynamodb-encryption-client/decrypt-item.md#input
        //# The following inputs to this behavior are REQUIRED:
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
    //= spec/dynamodb-encryption-client/decrypt-item.md#determining-plaintext-items
    //# An item MUST be determined to be plaintext if it does not contain
    //# attributes with the names "aws_dbe_head" and "aws_dbe_foot".
    !item.contains_key(HEADER_FIELD) && !item.contains_key(FOOTER_FIELD)
}

//= spec/dynamodb-encryption-client/decrypt-item.md#behavior
//= type=exception
//= reason=TableConfig has no Legacy Config, so no Legacy Policy can be configured
//# If a [Legacy Policy](./ddb-table-encryption-config.md#legacy-policy) of
//# `FORBID_LEGACY_ENCRYPT_FORBID_LEGACY_DECRYPT` is configured,
//# and the input item [is an item written in the legacy format](#determining-legacy-items),
//# this operation MUST fail.
//
//= spec/dynamodb-encryption-client/decrypt-item.md#behavior
//= type=exception
//= reason=TableConfig has no Legacy Config, so no Legacy Policy can be configured
//# If a [Legacy Policy](./ddb-table-encryption-config.md#legacy-policy) of
//# `FORCE_LEGACY_ENCRYPT_ALLOW_LEGACY_DECRYPT` or `FORBID_LEGACY_ENCRYPT_ALLOW_LEGACY_DECRYPT` is configured,
//# and the input item [is an item written in the legacy format](#determining-legacy-items),
//# this operation MUST delegate decryption of this item to the
//# [Legacy Encryptor](./ddb-table-encryption-config.md#legacy-encryptor),
//# using the configured [Attribute Flags](./ddb-table-encryption-config.md) as input.
//
//= spec/dynamodb-encryption-client/decrypt-item.md#behavior
//= type=exception
//= reason=TableConfig has no Legacy Config, so no Legacy Policy can be configured
//# The item returned by this operation MUST be the item outputted by the
//# [Legacy Encryptor](./ddb-table-encryption-config.md#legacy-encryptor).
//
//= spec/dynamodb-encryption-client/decrypt-item.md#determining-legacy-items
//= type=exception
//= reason=No Legacy Config is supported, so no item is ever treated as legacy
//# An item MUST be determined to be encrypted under the legacy format if it contains
//# attributes for the material description and the signature.
async fn decrypt_item(config: &Config, item: Item) -> Result<DecryptItemOutput, Error> {
    // Input

    if let Some(msg) = config.key_missing(&item, "Decrypt") {
        //= spec/dynamodb-encryption-client/decrypt-item.md#input-dynamodb-item
        //# This item MUST include an Attribute with a name that matches the
        //# [DynamoDB Partition Key Name](./ddb-table-encryption-config.md#dynamodb-partition-key-name)
        //# configured on the [DynamoDB Item Encryptor](./ddb-item-encryptor.md).
        //
        //= spec/dynamodb-encryption-client/decrypt-item.md#input-dynamodb-item
        //# Otherwise this operation MUST yield an error.
        //
        //= spec/dynamodb-encryption-client/decrypt-item.md#input-dynamodb-item
        //# If the [DynamoDB Item Encryptor](./ddb-item-encryptor.md)
        //# has a [DynamoDB Sort Key Name](./ddb-table-encryption-config.md#dynamodb-sort-key-name) configured,
        //# this item MUST include an Attribute with that name.
        return Err(val_err(msg));
    }

    // Plaintext policy

    let reads_plaintext = matches!(
        config.plaintext_override,
        PlaintextOverride::ForcePlaintextWriteAllowPlaintextRead
            | PlaintextOverride::ForbidPlaintextWriteAllowPlaintextRead
    );

    //= spec/dynamodb-encryption-client/decrypt-item.md#behavior
    //# If a [Plaintext Policy](./ddb-table-encryption-config.md#plaintext-policy) of
    //# `FORCE_PLAINTEXT_WRITE_ALLOW_PLAINTEXT_READ` or `FORBID_PLAINTEXT_WRITE_ALLOW_PLAINTEXT_READ` is specified,
    //# and the input item [is a plaintext item](#determining-plaintext-items)
    //# this operation MUST NOT decrypt the input item,
    //# and MUST passthrough that item as the output.
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

    // Base context

    let header = match item.get(HEADER_FIELD) {
        //= spec/dynamodb-encryption-client/decrypt-item.md#dynamodb-item-base-context
        //# The item to be encrypted MUST have an attribute named `aws_dbe_head`.
        None => return Err(ser_err("the item has no aws_dbe_head attribute")),
        Some(AttributeValue::B(b)) => b.as_ref(),
        //= spec/dynamodb-encryption-client/decrypt-item.md#dynamodb-item-base-context
        //# The attribute named `aws_dbe_head` MUST be of type `B` Binary.
        Some(_) => return Err(ser_err("the item's aws_dbe_head attribute is not binary")),
    };
    let version = *header
        .first()
        .ok_or_else(|| ser_err("the item's aws_dbe_head attribute is empty"))?;
    if version != 1 && version != 2 {
        //= spec/dynamodb-encryption-client/decrypt-item.md#dynamodb-item-base-context
        //# If the Version Number is not 1 or 2, the operation MUST return an error.
        return Err(ser_err(
            "the item's aws_dbe_head attribute has an unknown version",
        ));
    }

    //= spec/dynamodb-encryption-client/decrypt-item.md#dynamodb-item-base-context
    //# If the Version Number is 2, then the base context MUST be the [version 2](./encrypt-item.md#dynamodb-item-base-context-version-2) context.
    //
    //= spec/dynamodb-encryption-client/decrypt-item.md#dynamodb-item-base-context
    //# If the Version Number is 1, the base context MUST be the [version 1](./encrypt-item.md#dynamodb-item-base-context-version-1) context.
    let context = config.encryption_context(version, &encrypted)?;

    //= spec/dynamodb-encryption-client/decrypt-item.md#behavior
    //# - Authenticate Schema MUST be a [Authenticate Schema](../structured-encryption/structures.md#crypto-schema)
    //# built with the following requirements:
    let auth = config.authenticate_schema(&encrypted);

    // Required encryption context CMM

    //= spec/dynamodb-encryption-client/decrypt-item.md#behavior
    //# This operation MUST create a
    //# [Required Encryption Context CMM](https://github.com/awslabs/private-aws-encryption-sdk-specification-staging/blob/dafny-verified/framework/required-encryption-context-cmm.md)
    //# with the following inputs:
    let cmm = structured::required_context_cmm(
        config.cmm.clone(),
        context.keys().map(str::to_owned).collect(),
    )?;

    // Decrypt Structure

    //= spec/dynamodb-encryption-client/decrypt-item.md#behavior
    //# Given the converted [Structured Data](../structured-encryption/structures.md#structured-data),
    //# this operation MUST delegate decryption of this data to
    //# Structured Encryption Client's [Decrypt Structure](../structured-encryption/encrypt-structure.md),
    //# with the following inputs:
    let out = structured::decrypt_structure(
        &config.logical_table_name,
        //= spec/dynamodb-encryption-client/decrypt-item.md#behavior
        //# - Encrypted Structured Data MUST be the Structured Data converted above.
        encrypted,
        &auth,
        //= spec/dynamodb-encryption-client/decrypt-item.md#behavior
        //# - CMM MUST be the CMM constructed above.
        cmm,
        //= spec/dynamodb-encryption-client/decrypt-item.md#behavior
        //# - Encryption Context MUST be the input Item's [DynamoDB Item Base Context](./encrypt-item.md#dynamodb-item-base-context).
        Some(context),
    )
    .await?;

    // Output

    let plaintext_item =
        ddb::structured_to_item_decrypt(&out.data, &item, &out.schema).map_err(ser_err)?;

    //= spec/dynamodb-encryption-client/decrypt-item.md#behavior
    //# The output MUST also include a [Parsed Header](#parsed-header) that contains
    //# data that was serialized into the header included in the output DynamoDb Item.
    let header = parsed_header(config, out.parsed_header, out.schema)?;

    //= spec/dynamodb-encryption-client/decrypt-item.md#output
    //# This operation MUST output the following:
    Ok(DecryptItemOutput {
        plaintext_item,
        //= spec/dynamodb-encryption-client/decrypt-item.md#output
        //# This operation MUST also output a [Parsed Header](#parsed-header) if the following is true:
        parsed_header: Some(header),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::structured::util::{AuthAction, STRING, Terminal};
    use aws_crypto_mpl::keyring::RawAesKeyring;
    use aws_crypto_mpl::types::AesWrappingAlg;

    fn terminals(names: &[&str]) -> HashMap<String, Terminal> {
        names
            .iter()
            .map(|n| ((*n).to_owned(), Terminal::new(STRING, b"v".to_vec())))
            .collect()
    }

    fn context_map(ec: &EncryptionContext) -> HashMap<&str, &str> {
        ec.iter().collect()
    }

    /// Partition key `pk` and no sort key, with `secret` encrypted, `free` and prefix `:` unsigned.
    fn config_without_sort_key() -> Config {
        let keyring = RawAesKeyring::builder()
            .key_namespace("ns")
            .key_name("name")
            .wrapping_key(vec![0; 32])
            .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
            .build()
            .unwrap();
        let table = TableConfig::builder()
            .partition_key_name("pk")
            .attribute_actions_on_encrypt("pk", CryptoAction::SignOnly)
            .attribute_actions_on_encrypt("secret", CryptoAction::EncryptAndSign)
            .attribute_actions_on_encrypt("free", CryptoAction::DoNothing)
            .allowed_unsigned_attributes("free")
            .allowed_unsigned_attribute_prefix(":")
            .keyring(keyring)
            .build()
            .unwrap();
        Config::new("table".to_owned(), table).unwrap()
    }

    #[test]
    fn crypto_schema_copies_each_configured_action() {
        let config = config_without_sort_key();
        let item = terminals(&["pk", "secret"]);
        let schema = config.crypto_schema(&item).unwrap();
        for k in item.keys() {
            assert_eq!(schema[k], config.attribute_actions_on_encrypt[k], "{k}");
        }
        // `free` is configured but not in the item.
        assert_eq!(schema.len(), item.len());
    }

    #[test]
    fn base_context_v1_contents() {
        let ec = config_without_sort_key()
            .encryption_context(1, &terminals(&["pk", "secret"]))
            .unwrap();
        assert_eq!(
            context_map(&ec),
            HashMap::from([
                ("aws-crypto-table-name", "table"),
                ("aws-crypto-partition-name", "pk"),
                // 0x0001 (string) followed by "v"
                ("aws-crypto-attr.pk", "AAF2"),
            ])
        );
        assert!(!ec.contains_key("aws-crypto-sort-name"));
    }

    #[test]
    fn base_context_v2_contents() {
        let ec = config_without_sort_key()
            .encryption_context(2, &terminals(&["pk", "secret"]))
            .unwrap();
        assert_eq!(
            context_map(&ec),
            HashMap::from([
                ("aws-crypto-table-name", "table"),
                ("aws-crypto-partition-name", "pk"),
            ])
        );
        assert!(!ec.contains_key("aws-crypto-sort-name"));
    }

    #[test]
    fn base_context_v2_with_sort_key() {
        let ec = config::tests::config()
            .encryption_context(2, &terminals(&["pk", "sk"]))
            .unwrap();
        assert_eq!(ec.get("aws-crypto-sort-name"), Some("sk"));
        assert!(!ec.keys().any(|k| k.starts_with("aws-crypto-attr.")));
    }

    #[test]
    fn authenticate_schema_follows_the_signature_scope() {
        let config = config::tests::config();
        let item = terminals(&["pk", "sk", ":free"]);
        let auth = config.authenticate_schema(&item);
        assert_eq!(
            auth,
            HashMap::from([
                ("pk".to_owned(), AuthAction::Sign),
                ("sk".to_owned(), AuthAction::Sign),
                (":free".to_owned(), AuthAction::DoNotSign),
            ])
        );
        assert_eq!(auth["pk"], AuthAction::Sign);
        assert_eq!(auth[":free"], AuthAction::DoNotSign);
        assert_eq!(auth.len(), item.len());
    }

    #[test]
    fn signature_scope_excludes_unauthenticated_attributes() {
        let config = config_without_sort_key();
        assert!(!config.in_signature_scope("free"));
        assert!(!config.in_signature_scope(":x"));
        assert!(config.in_signature_scope("pk"));
        assert!(config.in_signature_scope("secret"));
    }

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

    #[test]
    fn parsed_header_rejects_a_context_with_no_item_key() {
        let header = structured::ParsedHeader {
            algorithm_suite_id: DEFAULT_SUITE,
            encrypted_data_keys: Vec::new(),
            stored_encryption_context: EncryptionContext::new(),
            encryption_context: EncryptionContext::new(),
        };
        let schema = HashMap::from([("pk".to_owned(), CryptoAction::SignOnly)]);
        match parsed_header(&config::tests::config(), header, schema) {
            Err(Error::Validation(e)) => assert_eq!(
                e.message(),
                "Invalid encryption context: Missing partition name"
            ),
            other => panic!("{other:?}"),
        }
    }
}

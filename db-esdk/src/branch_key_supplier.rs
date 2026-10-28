// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Picking a hierarchical keyring's branch key from an item's primary key.
//!
//! The MPL's [`BranchKeySupplier`] sees only an encryption context.
//! [`ItemKeyBranchKeySupplier`] rebuilds the item's primary key from that context
//! and hands it to an [`ItemKeySupplier`], so the supplier works with DynamoDB attributes.

use std::collections::HashMap;

use aws_crypto_mpl::Error as MplError;
use aws_crypto_mpl::aws_sdk_dynamodb::types::AttributeValue;
use aws_crypto_mpl::keyring::{BranchKeySupplier, GetBranchKeyIdInput, GetBranchKeyIdOutput};
use aws_crypto_mpl::types::EncryptionContext;

use crate::ddb::terminal_to_attr;
use crate::error::{Error, val_err};
use crate::item_encryptor::config::{PARTITION_NAME, SORT_NAME, TABLE_NAME};
use crate::structured::util::{ATTR_PREFIX, LEGEND, Terminal, utf16_len};

/// The key the logical table name is given in the item key a supplier sees.
const SELECTOR_TABLE_NAME: &str = "aws_dbe_table_name";
/// The key the partition key's name is given in the item key a supplier sees.
const SELECTOR_PARTITION_NAME: &str = "aws_dbe_partition_name";
/// The key the sort key's name is given in the item key a supplier sees.
const SELECTOR_SORT_NAME: &str = "aws_dbe_sort_name";

const MAX_ATTR_NAME_LEN: usize = 65_535;

/// Input for [`ItemKeySupplier::get_branch_key_id`].
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct GetBranchKeyIdFromItemKeyInput {
    item_key: HashMap<String, AttributeValue>,
}

impl GetBranchKeyIdFromItemKeyInput {
    /// Start a builder for `GetBranchKeyIdFromItemKeyInput`.
    #[must_use]
    pub fn builder() -> GetBranchKeyIdFromItemKeyInputBuilder {
        GetBranchKeyIdFromItemKeyInputBuilder::default()
    }

    /// The primary key of the item being encrypted or decrypted.
    ///
    /// It holds the partition key and, if the table has one, the sort key.
    /// When the table's `SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT` attributes are in the
    /// encryption context, it holds those too, plus `aws_dbe_table_name`,
    /// `aws_dbe_partition_name`, and (with a sort key) `aws_dbe_sort_name`.
    /// It never holds an encrypted attribute.
    #[must_use]
    pub const fn item_key(&self) -> &HashMap<String, AttributeValue> {
        &self.item_key
    }

    /// Take the item key out of the input.
    #[must_use]
    pub fn into_item_key(self) -> HashMap<String, AttributeValue> {
        self.item_key
    }
}

/// Builder for [`GetBranchKeyIdFromItemKeyInput`].
#[derive(Debug, Clone, Default)]
pub struct GetBranchKeyIdFromItemKeyInputBuilder {
    item_key: Option<HashMap<String, AttributeValue>>,
}

impl GetBranchKeyIdFromItemKeyInputBuilder {
    /// Add one attribute of the item key. Call again to add more.
    #[must_use]
    pub fn item_key(mut self, name: impl Into<String>, value: AttributeValue) -> Self {
        self.item_key
            .get_or_insert_with(HashMap::new)
            .insert(name.into(), value);
        self
    }

    /// Set or clear the whole item key.
    /// To add one attribute, use [`Self::item_key`].
    #[must_use]
    pub fn set_item_key(mut self, item_key: Option<HashMap<String, AttributeValue>>) -> Self {
        self.item_key = item_key;
        self
    }

    /// The item key, if set.
    #[must_use]
    pub const fn get_item_key(&self) -> &Option<HashMap<String, AttributeValue>> {
        &self.item_key
    }

    /// Build the `GetBranchKeyIdFromItemKeyInput`.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): `item_key` is unset.
    pub fn build(self) -> Result<GetBranchKeyIdFromItemKeyInput, Error> {
        Ok(GetBranchKeyIdFromItemKeyInput {
            item_key: self
                .item_key
                .ok_or_else(|| val_err("item_key is required"))?,
        })
    }
}

/// User-supplied callback that maps an item's primary key to a branch key id.
///
/// Wrap it in an [`ItemKeyBranchKeySupplier`] and pass that to
/// [`HierarchicalKeyringBuilder::branch_key_id_supplier`](crate::keyring::HierarchicalKeyringBuilder::branch_key_id_supplier).
#[aws_crypto_mpl::async_trait]
pub trait ItemKeySupplier: Send + Sync {
    /// Return the branch key id to use for the item with this primary key.
    ///
    /// # Errors
    ///
    /// Any error returned fails the encrypt or decrypt as-is.
    //= spec/dynamodb-encryption-client/ddb-encryption-branch-key-id-supplier.md#dynamodbkeybranchkeyidsupplier
    //= type=implication
    //# This operation MUST return a branch key id (string) as output.
    async fn get_branch_key_id(
        &self,
        input: GetBranchKeyIdFromItemKeyInput,
    ) -> Result<GetBranchKeyIdOutput, MplError>;
}

/// A [`BranchKeySupplier`] that asks an [`ItemKeySupplier`] for each item's branch key.
pub struct ItemKeyBranchKeySupplier {
    inner: Box<dyn ItemKeySupplier>,
}

impl std::fmt::Debug for ItemKeyBranchKeySupplier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ItemKeyBranchKeySupplier")
            .finish_non_exhaustive()
    }
}

impl ItemKeyBranchKeySupplier {
    /// Wrap `supplier` so a hierarchical keyring can use it.
    //= spec/dynamodb-encryption-client/ddb-encryption-branch-key-id-supplier.md#input
    //= type=implication
    //# This operation MUST take in a [DynamoDbKeyBranchKeyIdSupplier](#dynamodbkeybranchkeyidsupplier) as input.
    //
    //= spec/dynamodb-encryption-client/ddb-encryption-branch-key-id-supplier.md#output
    //= type=implication
    //= reason=Self implements the MPL BranchKeySupplier the hierarchical keyring takes
    //# This operation MUST output a BranchKeyIdSupplierReference.
    pub fn new(supplier: impl ItemKeySupplier + 'static) -> Self {
        Self {
            inner: Box::new(supplier),
        }
    }
}

#[aws_crypto_mpl::async_trait]
impl BranchKeySupplier for ItemKeyBranchKeySupplier {
    async fn get_branch_key_id(
        &self,
        input: GetBranchKeyIdInput,
    ) -> Result<GetBranchKeyIdOutput, MplError> {
        let item_key =
            item_key_from_context(input.encryption_context()).map_err(MplError::validation)?;
        let branch_key_id = self
            .inner
            //= spec/dynamodb-encryption-client/ddb-encryption-branch-key-id-supplier.md#dynamodbkeybranchkeyidsupplier
            //# This operation MUST take in a DDB `Key` structure
            //# (an attribute map containing the partition and sort attributes,
            //# along with the values of any attributes configured as SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT)
            //# as input.
            .get_branch_key_id(GetBranchKeyIdFromItemKeyInput { item_key })
            //= spec/dynamodb-encryption-client/ddb-encryption-branch-key-id-supplier.md#behavior
            //# - Otherwise, this operation MUST fail.
            .await?;

        //= spec/dynamodb-encryption-client/ddb-encryption-branch-key-id-supplier.md#behavior
        //# - If successful, the resulting string MUST be outputted by this operation.
        Ok(branch_key_id.into_branch_key_id().into())
    }
}

/// The item key an encryption context written by this library describes.
pub(crate) fn item_key_from_context(
    context: &EncryptionContext,
) -> Result<HashMap<String, AttributeValue>, String> {
    //= spec/dynamodb-encryption-client/ddb-encryption-branch-key-id-supplier.md#behavior
    //# - It MUST deserialize the "aws-crypto-partition-name" value in the input encryption context to determine the partition name.
    let partition_name = context
        .get(PARTITION_NAME)
        //= spec/dynamodb-encryption-client/ddb-encryption-branch-key-id-supplier.md#behavior
        //# - If the partition name does not exist in the encryption context, this operation MUST fail.
        .ok_or("Invalid encryption context: Missing partition name")?;

    //= spec/dynamodb-encryption-client/ddb-encryption-branch-key-id-supplier.md#behavior
    //# - It MUST get the serialized partition value by grabbing the `aws-crypto-attr.<partition_name>` from the encryption context.
    let partition_value_key = format!("{ATTR_PREFIX}{partition_name}");
    let partition_value = context
        .get(&partition_value_key)
        //= spec/dynamodb-encryption-client/ddb-encryption-branch-key-id-supplier.md#behavior
        //# - If the partition value does not exist in the encryption context, this operation MUST fail.
        .ok_or("Invalid encryption context: Missing partition value")?;

    //= spec/dynamodb-encryption-client/ddb-encryption-branch-key-id-supplier.md#behavior
    //# - It MUST check for the existence of "aws-crypto-sort-name" in the input encryption context.
    let sort_value_key = context
        .get(SORT_NAME)
        //= spec/dynamodb-encryption-client/ddb-encryption-branch-key-id-supplier.md#behavior
        //= reason=builds the sort value key; contains_key below confirms it is present
        //# - If this key exists, it MUST get the serialized sort value by grabbing the `aws-crypto.attr:<sort_name>` from the encryption context.
        .map(|sort_name| format!("{ATTR_PREFIX}{sort_name}"));
    if let Some(key) = &sort_value_key
        && !context.contains_key(key)
    {
        //= spec/dynamodb-encryption-client/ddb-encryption-branch-key-id-supplier.md#behavior
        //# - If the sort value does not exist in the context, this operation MUST fail.
        return Err("Invalid encryption context: Missing sort value".to_owned());
    }

    //= spec/dynamodb-encryption-client/ddb-encryption-branch-key-id-supplier.md#behavior
    //# - If the field "aws-crypto-legend" exists in the encryption context,
    //# it MUST [deserialize](./ddb-attribute-serialization.md), all values with keys beginning "aws-crypto-attr.",
    //# and create a Key with these values, using names with the "aws-crypto-attr." removed.
    if let Some(legend) = context.get(LEGEND) {
        let mut item_key = v2_attributes(context, legend)?;
        let table_name = context
            .get(TABLE_NAME)
            .ok_or("Internal error, table name not in encryption context.")?;
        item_key.insert(
            SELECTOR_TABLE_NAME.to_owned(),
            AttributeValue::S(table_name.to_owned()),
        );
        item_key.insert(
            SELECTOR_PARTITION_NAME.to_owned(),
            AttributeValue::S(partition_name.to_owned()),
        );
        if let Some(sort_name) = context.get(SORT_NAME) {
            item_key.insert(
                SELECTOR_SORT_NAME.to_owned(),
                AttributeValue::S(sort_name.to_owned()),
            );
        }
        return Ok(item_key);
    }

    //= spec/dynamodb-encryption-client/ddb-encryption-branch-key-id-supplier.md#behavior
    //# - If the field "aws-crypto-legend" does not exist in the encryption context, it MUST [deserialize the partition (and optionally sort) value](./ddb-attribute-serialization.md), and create a Key with these values.
    let mut item_key = HashMap::new();
    let (name, value) = encoded_attribute(&partition_value_key, partition_value)?;
    item_key.insert(name, value);
    if let Some(key) = &sort_value_key {
        let encoded = context
            .get(key)
            .ok_or("Invalid encryption context: Missing sort value")?;
        let (name, value) = encoded_attribute(key, encoded)?;
        item_key.insert(name, value);
    }
    Ok(item_key)
}

/// Every `aws-crypto-attr.` entry of a context that carries a legend,
/// decoded as its legend character says, in key order.
fn v2_attributes(
    context: &EncryptionContext,
    legend: &str,
) -> Result<HashMap<String, AttributeValue>, String> {
    let mut legend = legend.chars();
    let mut out = HashMap::new();
    // The context is ordered by key bytes, the order the legend was written in.
    for (key, value) in context.iter() {
        if key.len() <= ATTR_PREFIX.len() || !key.starts_with(ATTR_PREFIX) {
            continue;
        }
        let legend_char = legend
            .next()
            .ok_or("Encryption Context Legend is too short.")?;
        let name = attribute_name(key)?;
        out.insert(name, legend_value(value, legend_char)?);
    }
    if legend.next().is_some() {
        return Err("Encryption Context Legend is too long.".to_owned());
    }
    Ok(out)
}

/// The attribute value of a legend-encoded context entry.
fn legend_value(value: &str, legend_char: char) -> Result<AttributeValue, String> {
    match legend_char {
        'S' => Ok(AttributeValue::S(value.to_owned())),
        'N' => Ok(AttributeValue::N(value.to_owned())),
        'L' => match value {
            "true" => Ok(AttributeValue::Bool(true)),
            "false" => Ok(AttributeValue::Bool(false)),
            "null" => Ok(AttributeValue::Null(true)),
            _ => Err(format!(
                "Encryption Context literal value has unexpected value : '{value}'."
            )),
        },
        'B' => terminal_to_attr(&decode_terminal(value)?),
        _ => Err(format!(
            "Encryption Context Legend has unexpected character : '{legend_char}'."
        )),
    }
}

/// The attribute name and value of a base64 terminal context entry.
fn encoded_attribute(key: &str, encoded: &str) -> Result<(String, AttributeValue), String> {
    let name = attribute_name(key)?;
    let value = terminal_to_attr(&decode_terminal(encoded)?)?;
    Ok((name, value))
}

/// The attribute name of an `aws-crypto-attr.<name>` key.
fn attribute_name(key: &str) -> Result<String, String> {
    let name = key.get(ATTR_PREFIX.len()..).unwrap_or_default();
    if utf16_len(name) > MAX_ATTR_NAME_LEN {
        return Err("Invalid serialization of DDB Attribute in encryption context.".to_owned());
    }
    Ok(name.to_owned())
}

/// A terminal stored in an encryption context: its type id and value, base64-encoded.
fn decode_terminal(encoded: &str) -> Result<Terminal, String> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| format!("Invalid base64 in encryption context: {e}"))?;
    let [a, b, rest @ ..] = bytes.as_slice() else {
        return Err("Invalid serialization of DDB Attribute in encryption context.".to_owned());
    };
    Ok(Terminal::new([*a, *b], rest.to_vec()))
}

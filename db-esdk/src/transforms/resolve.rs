// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! ResolveAttributes: the plaintext values of an item's virtual fields and compound beacons.

use std::collections::HashMap;

use aws_crypto_mpl::aws_sdk_dynamodb::types::AttributeValue;

use super::Transforms;
use crate::error::{Error, val_err};

/// The input of [`Transforms::resolve_attributes`].
#[derive(Clone, Debug, Default, PartialEq)]
#[non_exhaustive]
pub struct ResolveAttributesInput {
    /// The table whose configuration to use.
    pub table_name: String,
    /// The plaintext item to examine.
    pub item: HashMap<String, AttributeValue>,
}

impl ResolveAttributesInput {
    /// A builder for the input.
    #[must_use]
    pub fn builder() -> ResolveAttributesInputBuilder {
        ResolveAttributesInputBuilder::default()
    }

    /// The table whose configuration to use.
    #[must_use]
    pub fn table_name(&self) -> &str {
        &self.table_name
    }

    /// The plaintext item to examine.
    #[must_use]
    pub const fn item(&self) -> &HashMap<String, AttributeValue> {
        &self.item
    }
}

/// A builder for [`ResolveAttributesInput`].
#[derive(Clone, Debug, Default, PartialEq)]
#[non_exhaustive]
pub struct ResolveAttributesInputBuilder {
    table_name: Option<String>,
    item: Option<HashMap<String, AttributeValue>>,
}

impl ResolveAttributesInputBuilder {
    /// The table whose configuration to use. Required.
    #[must_use]
    pub fn table_name(mut self, name: impl Into<String>) -> Self {
        self.table_name = Some(name.into());
        self
    }

    /// The table name. See [`Self::table_name`].
    #[must_use]
    pub fn set_table_name(mut self, name: Option<String>) -> Self {
        self.table_name = name;
        self
    }

    /// The table name set so far.
    #[must_use]
    pub const fn get_table_name(&self) -> &Option<String> {
        &self.table_name
    }

    /// The plaintext item to examine. Required.
    #[must_use]
    pub fn item(mut self, item: HashMap<String, AttributeValue>) -> Self {
        self.item = Some(item);
        self
    }

    /// The item. See [`Self::item`].
    #[must_use]
    pub fn set_item(mut self, item: Option<HashMap<String, AttributeValue>>) -> Self {
        self.item = item;
        self
    }

    /// The item set so far.
    #[must_use]
    pub const fn get_item(&self) -> &Option<HashMap<String, AttributeValue>> {
        &self.item
    }

    /// Build the input.
    ///
    /// # Errors
    ///
    /// A `Validation` error when the table name or the item is not set.
    pub fn build(self) -> Result<ResolveAttributesInput, Error> {
        Ok(ResolveAttributesInput {
            table_name: self
                .table_name
                .ok_or_else(|| val_err("table_name is required"))?,
            item: self.item.ok_or_else(|| val_err("item is required"))?,
        })
    }
}

/// The output of [`Transforms::resolve_attributes`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ResolveAttributesOutput {
    /// The plaintext value of each virtual field the item has, by field name.
    pub virtual_fields: HashMap<String, String>,
    /// The plaintext value of each compound beacon the item has, by beacon name.
    pub compound_beacons: HashMap<String, String>,
}

impl ResolveAttributesOutput {
    /// The plaintext value of each virtual field the item has, by field name.
    #[must_use]
    pub const fn virtual_fields(&self) -> &HashMap<String, String> {
        &self.virtual_fields
    }

    /// The plaintext value of each compound beacon the item has, by beacon name.
    ///
    /// The client writes the beaconized form of each value to the table, not this plaintext.
    #[must_use]
    pub const fn compound_beacons(&self) -> &HashMap<String, String> {
        &self.compound_beacons
    }
}

impl Transforms {
    /// The plaintext values of an item's virtual fields and compound beacons,
    /// computed with the configuration of its table.
    ///
    /// For a table with no configuration or no search configuration, both maps are empty.
    ///
    /// # Errors
    ///
    /// A `Validation` error when an item value that makes up part of a compound beacon contains the beacon's split character.
    pub async fn resolve_attributes(
        &self,
        input: ResolveAttributesInput,
    ) -> Result<ResolveAttributesOutput, Error> {
        let Some(table) = self.table_info(Some(&input.table_name)) else {
            return Ok(ResolveAttributesOutput::default());
        };
        let Some(search) = table.search.as_ref() else {
            return Ok(ResolveAttributesOutput::default());
        };
        let partition = search
            .get_partition(&input.item, &table.encryptor.config().logical_table_name)
            .await?;
        Ok(ResolveAttributesOutput {
            virtual_fields: search.version.virtual_field_values(&input.item)?,
            compound_beacons: search
                .version
                .compound_beacon_values(&input.item, partition)?,
        })
    }
}

// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Choosing the beacon partition an item is written in.
//!
//! A beacon version with a `maximum_number_of_partitions` above 1 writes each item's
//! beacons in one of that many partitions, which spreads items with the same plaintext
//! across several beacon values. A [`PartitionSelector`] picks the partition;
//! without one, each item gets a random partition.

use std::sync::Arc;

use aws_crypto_mpl::aws_sdk_dynamodb::types::AttributeValue;
use aws_crypto_mpl::shared::FromUnshared;
use aws_mpl_primitives::generate_random_bytes;

use crate::ddb::Item;
use crate::error::{Error, val_err};

/// Input for [`PartitionSelector::get_partition_number`].
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct GetPartitionNumberInput {
    item: Item,
    number_of_partitions: u8,
    logical_table_name: String,
}

impl GetPartitionNumberInput {
    /// A builder for the input.
    #[must_use]
    pub fn builder() -> GetPartitionNumberInputBuilder {
        GetPartitionNumberInputBuilder::default()
    }

    /// The plaintext item being written.
    #[must_use]
    pub const fn item(&self) -> &Item {
        &self.item
    }

    /// The number of partitions of the beacon version: the partition returned must be less.
    #[must_use]
    pub const fn number_of_partitions(&self) -> u8 {
        self.number_of_partitions
    }

    /// The logical table name of the table the item is written to.
    #[must_use]
    pub fn logical_table_name(&self) -> &str {
        &self.logical_table_name
    }
}

/// A builder for [`GetPartitionNumberInput`].
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct GetPartitionNumberInputBuilder {
    item: Option<Item>,
    number_of_partitions: Option<u8>,
    logical_table_name: Option<String>,
}

impl GetPartitionNumberInputBuilder {
    /// Add one attribute of the item. Call again to add more.
    #[must_use]
    pub fn item(mut self, name: impl Into<String>, value: AttributeValue) -> Self {
        self.item
            .get_or_insert_with(Item::new)
            .insert(name.into(), value);
        self
    }

    /// Set or clear the whole item. To add one attribute, use [`Self::item`].
    #[must_use]
    pub fn set_item(mut self, item: Option<Item>) -> Self {
        self.item = item;
        self
    }

    /// The number of partitions. Required.
    #[must_use]
    pub const fn number_of_partitions(mut self, count: u8) -> Self {
        self.number_of_partitions = Some(count);
        self
    }

    /// The number of partitions. See [`Self::number_of_partitions`].
    #[must_use]
    pub const fn set_number_of_partitions(mut self, count: Option<u8>) -> Self {
        self.number_of_partitions = count;
        self
    }

    /// The logical table name. Required.
    #[must_use]
    pub fn logical_table_name(mut self, name: impl Into<String>) -> Self {
        self.logical_table_name = Some(name.into());
        self
    }

    /// The logical table name. See [`Self::logical_table_name`].
    #[must_use]
    pub fn set_logical_table_name(mut self, name: Option<String>) -> Self {
        self.logical_table_name = name;
        self
    }

    /// Build the input.
    ///
    /// # Errors
    ///
    /// A `Validation` error when the item, number of partitions, or logical table name is unset.
    pub fn build(self) -> Result<GetPartitionNumberInput, Error> {
        Ok(GetPartitionNumberInput {
            item: self.item.ok_or_else(|| val_err("item is required"))?,
            number_of_partitions: self
                .number_of_partitions
                .ok_or_else(|| val_err("number_of_partitions is required"))?,
            logical_table_name: self
                .logical_table_name
                .ok_or_else(|| val_err("logical_table_name is required"))?,
        })
    }
}

/// Output of [`PartitionSelector::get_partition_number`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct GetPartitionNumberOutput {
    partition_number: u8,
}

impl GetPartitionNumberOutput {
    /// A builder for the output.
    #[must_use]
    pub fn builder() -> GetPartitionNumberOutputBuilder {
        GetPartitionNumberOutputBuilder::default()
    }

    /// The partition the item is written in.
    #[must_use]
    pub const fn partition_number(&self) -> u8 {
        self.partition_number
    }
}

/// A builder for [`GetPartitionNumberOutput`].
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct GetPartitionNumberOutputBuilder {
    partition_number: Option<u8>,
}

impl GetPartitionNumberOutputBuilder {
    /// The partition the item is written in. Required; must be less than the number of partitions.
    #[must_use]
    pub const fn partition_number(mut self, partition: u8) -> Self {
        self.partition_number = Some(partition);
        self
    }

    /// The partition. See [`Self::partition_number`].
    #[must_use]
    pub const fn set_partition_number(mut self, partition: Option<u8>) -> Self {
        self.partition_number = partition;
        self
    }

    /// Build the output.
    ///
    /// # Errors
    ///
    /// A `Validation` error when the partition number is unset.
    pub fn build(self) -> Result<GetPartitionNumberOutput, Error> {
        Ok(GetPartitionNumberOutput {
            partition_number: self
                .partition_number
                .ok_or_else(|| val_err("partition_number is required"))?,
        })
    }
}

/// User-supplied callback that picks the beacon partition an item is written in.
///
/// Set it with
/// [`BeaconVersionBuilder::partition_selector`](crate::search::BeaconVersionBuilder::partition_selector).
/// Without one, each item gets a random partition.
#[aws_crypto_mpl::async_trait]
pub trait PartitionSelector: Send + Sync {
    /// Return the partition to write `input.item()` in:
    /// a number less than `input.number_of_partitions()`.
    ///
    /// # Errors
    ///
    /// Any error returned fails the write as-is.
    async fn get_partition_number(
        &self,
        input: GetPartitionNumberInput,
    ) -> Result<GetPartitionNumberOutput, Error>;
}

/// A partition selector whose concrete type is chosen at runtime.
///
/// Callers that know their selector's type pass it directly and never need this one.
#[derive(Clone)]
pub struct SharedPartitionSelector(Arc<dyn PartitionSelector>);

impl SharedPartitionSelector {
    /// Wrap `selector` in a handle. An existing handle is returned as-is.
    pub fn new(selector: impl aws_crypto_mpl::shared::IntoShared<Self>) -> Self {
        selector.into_shared()
    }

    /// Whether both handles refer to the same selector.
    #[must_use]
    pub fn ptr_eq(this: &Self, other: &Self) -> bool {
        std::ptr::addr_eq(Arc::as_ptr(&this.0), Arc::as_ptr(&other.0))
    }

    /// Ask the selector for the partition of an item.
    pub(crate) async fn get_partition_number(
        &self,
        input: GetPartitionNumberInput,
    ) -> Result<GetPartitionNumberOutput, Error> {
        self.0.get_partition_number(input).await
    }
}

impl std::fmt::Debug for SharedPartitionSelector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedPartitionSelector")
            .finish_non_exhaustive()
    }
}

impl<T: PartitionSelector + 'static> FromUnshared<T> for SharedPartitionSelector {
    fn from_unshared(value: T) -> Self {
        Self(Arc::new(value))
    }
}

/// A handle converts to itself, so an existing handle is not wrapped again.
impl FromUnshared<Self> for SharedPartitionSelector {
    fn from_unshared(value: Self) -> Self {
        value
    }
}

/// The partition selector used when none is configured: a random partition.
#[derive(Debug)]
pub(crate) struct RandomPartitionSelector;

#[aws_crypto_mpl::async_trait]
impl PartitionSelector for RandomPartitionSelector {
    async fn get_partition_number(
        &self,
        input: GetPartitionNumberInput,
    ) -> Result<GetPartitionNumberOutput, Error> {
        let num = input.number_of_partitions;
        if num <= 1 {
            return Ok(GetPartitionNumberOutput {
                partition_number: 0,
            });
        }
        let mut rand = [0u8; 1];
        generate_random_bytes(&mut rand)?;
        Ok(GetPartitionNumberOutput {
            partition_number: rand[0] % num,
        })
    }
}

#[cfg(test)]
#[path = "partition_tests.rs"]
mod tests;

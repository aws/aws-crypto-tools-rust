// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Inputs and outputs of the [`Cmc`](super::Cmc) operations.
//! Names follow the Smithy model of the Dafny MPL.

use std::sync::Arc;

use super::CacheEntry;
use crate::Error;
use crate::error::Kind;

fn required<T>(value: Option<T>, field: &str) -> Result<T, Error> {
    value.ok_or_else(|| Error::new(Kind::Validation, format!("{field} is required")))
}

/// Input for [`Cmc::put_cache_entry`](super::Cmc::put_cache_entry).
#[derive(Debug)]
#[non_exhaustive]
pub struct PutCacheEntryInput {
    identifier: Vec<u8>,
    entry: CacheEntry,
}

impl PutCacheEntryInput {
    /// Start a builder for `PutCacheEntryInput`.
    #[must_use]
    pub fn builder() -> PutCacheEntryInputBuilder {
        PutCacheEntryInputBuilder::default()
    }

    /// The cache identifier to store the entry under.
    #[must_use]
    pub fn identifier(&self) -> &[u8] {
        &self.identifier
    }

    /// The entry to store.
    #[must_use]
    pub const fn entry(&self) -> &CacheEntry {
        &self.entry
    }

    /// Consume the input, yielding the identifier and the entry.
    #[must_use]
    pub fn into_parts(self) -> (Vec<u8>, CacheEntry) {
        (self.identifier, self.entry)
    }
}

/// Builder for [`PutCacheEntryInput`], returned by [`PutCacheEntryInput::builder`].
#[derive(Debug, Default)]
pub struct PutCacheEntryInputBuilder {
    identifier: Option<Vec<u8>>,
    entry: Option<CacheEntry>,
}

impl PutCacheEntryInputBuilder {
    /// Set the cache identifier. Required.
    #[must_use]
    pub fn identifier(mut self, identifier: impl Into<Vec<u8>>) -> Self {
        self.identifier = Some(identifier.into());
        self
    }

    /// Set or clear the cache identifier, for forwarding an existing `Option`.
    #[must_use]
    pub fn set_identifier(mut self, identifier: Option<Vec<u8>>) -> Self {
        self.identifier = identifier;
        self
    }

    /// Set the entry to store. Required.
    #[must_use]
    pub fn entry(mut self, entry: impl Into<CacheEntry>) -> Self {
        self.entry = Some(entry.into());
        self
    }

    /// Set or clear the entry, for forwarding an existing `Option`.
    #[must_use]
    pub fn set_entry(mut self, entry: Option<CacheEntry>) -> Self {
        self.entry = entry;
        self
    }

    /// Construct the input.
    ///
    /// # Errors
    ///
    /// Returns a validation error ([`Error::is_validation`])
    /// if `identifier` or `entry` is unset.
    pub fn build(self) -> Result<PutCacheEntryInput, Error> {
        Ok(PutCacheEntryInput {
            identifier: required(self.identifier, "identifier")?,
            entry: required(self.entry, "entry")?,
        })
    }
}

/// Output of [`Cmc::put_cache_entry`](super::Cmc::put_cache_entry).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PutCacheEntryOutput {}

impl PutCacheEntryOutput {
    /// Start a builder for `PutCacheEntryOutput`.
    #[must_use]
    pub fn builder() -> PutCacheEntryOutputBuilder {
        PutCacheEntryOutputBuilder::default()
    }
}

/// Builder for [`PutCacheEntryOutput`], returned by [`PutCacheEntryOutput::builder`].
#[derive(Debug, Clone, Default)]
pub struct PutCacheEntryOutputBuilder {}

impl PutCacheEntryOutputBuilder {
    /// Construct the output.
    ///
    /// # Errors
    ///
    /// Never returns an error.
    pub const fn build(self) -> Result<PutCacheEntryOutput, Error> {
        Ok(PutCacheEntryOutput {})
    }
}

/// Input for [`Cmc::get_cache_entry`](super::Cmc::get_cache_entry).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct GetCacheEntryInput {
    identifier: Vec<u8>,
}

impl GetCacheEntryInput {
    /// Start a builder for `GetCacheEntryInput`.
    #[must_use]
    pub fn builder() -> GetCacheEntryInputBuilder {
        GetCacheEntryInputBuilder::default()
    }

    /// The cache identifier to look up.
    #[must_use]
    pub fn identifier(&self) -> &[u8] {
        &self.identifier
    }

    /// Consume the input, yielding the identifier.
    #[must_use]
    pub fn into_identifier(self) -> Vec<u8> {
        self.identifier
    }
}

/// Builder for [`GetCacheEntryInput`], returned by [`GetCacheEntryInput::builder`].
#[derive(Debug, Clone, Default)]
pub struct GetCacheEntryInputBuilder {
    identifier: Option<Vec<u8>>,
}

impl GetCacheEntryInputBuilder {
    /// Set the cache identifier. Required.
    #[must_use]
    pub fn identifier(mut self, identifier: impl Into<Vec<u8>>) -> Self {
        self.identifier = Some(identifier.into());
        self
    }

    /// Set or clear the cache identifier, for forwarding an existing `Option`.
    #[must_use]
    pub fn set_identifier(mut self, identifier: Option<Vec<u8>>) -> Self {
        self.identifier = identifier;
        self
    }

    /// Construct the input.
    ///
    /// # Errors
    ///
    /// Returns a validation error ([`Error::is_validation`])
    /// if `identifier` is unset.
    pub fn build(self) -> Result<GetCacheEntryInput, Error> {
        Ok(GetCacheEntryInput {
            identifier: required(self.identifier, "identifier")?,
        })
    }
}

/// Output of [`Cmc::get_cache_entry`](super::Cmc::get_cache_entry).
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct GetCacheEntryOutput {
    entry: Option<Arc<CacheEntry>>,
}

impl GetCacheEntryOutput {
    /// Start a builder for `GetCacheEntryOutput`.
    #[must_use]
    pub fn builder() -> GetCacheEntryOutputBuilder {
        GetCacheEntryOutputBuilder::default()
    }

    /// The cached entry, or `None` on a cache miss.
    #[must_use]
    pub const fn entry(&self) -> Option<&Arc<CacheEntry>> {
        self.entry.as_ref()
    }

    /// Consume the output, yielding the cached entry, or `None` on a cache miss.
    #[must_use]
    pub fn into_entry(self) -> Option<Arc<CacheEntry>> {
        self.entry
    }
}

/// Builder for [`GetCacheEntryOutput`], returned by [`GetCacheEntryOutput::builder`].
#[derive(Debug, Clone, Default)]
pub struct GetCacheEntryOutputBuilder {
    entry: Option<Arc<CacheEntry>>,
}

impl GetCacheEntryOutputBuilder {
    /// Set the cached entry. Leave unset for a cache miss.
    #[must_use]
    pub fn entry(mut self, entry: impl Into<Arc<CacheEntry>>) -> Self {
        self.entry = Some(entry.into());
        self
    }

    /// Set or clear the cached entry. `None` is a cache miss.
    #[must_use]
    pub fn set_entry(mut self, entry: Option<Arc<CacheEntry>>) -> Self {
        self.entry = entry;
        self
    }

    /// Construct the output.
    ///
    /// # Errors
    ///
    /// Never returns an error.
    pub fn build(self) -> Result<GetCacheEntryOutput, Error> {
        Ok(GetCacheEntryOutput { entry: self.entry })
    }
}

/// Input for [`Cmc::delete_cache_entry`](super::Cmc::delete_cache_entry).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeleteCacheEntryInput {
    identifier: Vec<u8>,
}

impl DeleteCacheEntryInput {
    /// Start a builder for `DeleteCacheEntryInput`.
    #[must_use]
    pub fn builder() -> DeleteCacheEntryInputBuilder {
        DeleteCacheEntryInputBuilder::default()
    }

    /// The cache identifier to delete.
    #[must_use]
    pub fn identifier(&self) -> &[u8] {
        &self.identifier
    }

    /// Consume the input, yielding the identifier.
    #[must_use]
    pub fn into_identifier(self) -> Vec<u8> {
        self.identifier
    }
}

/// Builder for [`DeleteCacheEntryInput`], returned by [`DeleteCacheEntryInput::builder`].
#[derive(Debug, Clone, Default)]
pub struct DeleteCacheEntryInputBuilder {
    identifier: Option<Vec<u8>>,
}

impl DeleteCacheEntryInputBuilder {
    /// Set the cache identifier. Required.
    #[must_use]
    pub fn identifier(mut self, identifier: impl Into<Vec<u8>>) -> Self {
        self.identifier = Some(identifier.into());
        self
    }

    /// Set or clear the cache identifier, for forwarding an existing `Option`.
    #[must_use]
    pub fn set_identifier(mut self, identifier: Option<Vec<u8>>) -> Self {
        self.identifier = identifier;
        self
    }

    /// Construct the input.
    ///
    /// # Errors
    ///
    /// Returns a validation error ([`Error::is_validation`])
    /// if `identifier` is unset.
    pub fn build(self) -> Result<DeleteCacheEntryInput, Error> {
        Ok(DeleteCacheEntryInput {
            identifier: required(self.identifier, "identifier")?,
        })
    }
}

/// Output of [`Cmc::delete_cache_entry`](super::Cmc::delete_cache_entry).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeleteCacheEntryOutput {}

impl DeleteCacheEntryOutput {
    /// Start a builder for `DeleteCacheEntryOutput`.
    #[must_use]
    pub fn builder() -> DeleteCacheEntryOutputBuilder {
        DeleteCacheEntryOutputBuilder::default()
    }
}

/// Builder for [`DeleteCacheEntryOutput`], returned by [`DeleteCacheEntryOutput::builder`].
#[derive(Debug, Clone, Default)]
pub struct DeleteCacheEntryOutputBuilder {}

impl DeleteCacheEntryOutputBuilder {
    /// Construct the output.
    ///
    /// # Errors
    ///
    /// Never returns an error.
    pub const fn build(self) -> Result<DeleteCacheEntryOutput, Error> {
        Ok(DeleteCacheEntryOutput {})
    }
}

/// Input for [`Cmc::update_usage_metadata`](super::Cmc::update_usage_metadata).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UpdateUsageMetadataInput {
    identifier: Vec<u8>,
    bytes_used: u64,
}

impl UpdateUsageMetadataInput {
    /// Start a builder for `UpdateUsageMetadataInput`.
    #[must_use]
    pub fn builder() -> UpdateUsageMetadataInputBuilder {
        UpdateUsageMetadataInputBuilder::default()
    }

    /// The cache identifier of the entry to update.
    #[must_use]
    pub fn identifier(&self) -> &[u8] {
        &self.identifier
    }

    /// The plaintext bytes of the one message being counted against the entry.
    #[must_use]
    pub const fn bytes_used(&self) -> u64 {
        self.bytes_used
    }
}

/// Builder for [`UpdateUsageMetadataInput`], returned by [`UpdateUsageMetadataInput::builder`].
#[derive(Debug, Clone, Default)]
pub struct UpdateUsageMetadataInputBuilder {
    identifier: Option<Vec<u8>>,
    bytes_used: Option<u64>,
}

impl UpdateUsageMetadataInputBuilder {
    /// Set the cache identifier. Required.
    #[must_use]
    pub fn identifier(mut self, identifier: impl Into<Vec<u8>>) -> Self {
        self.identifier = Some(identifier.into());
        self
    }

    /// Set or clear the cache identifier, for forwarding an existing `Option`.
    #[must_use]
    pub fn set_identifier(mut self, identifier: Option<Vec<u8>>) -> Self {
        self.identifier = identifier;
        self
    }

    /// Set the plaintext bytes of the message. Required.
    #[must_use]
    pub const fn bytes_used(mut self, bytes_used: u64) -> Self {
        self.bytes_used = Some(bytes_used);
        self
    }

    /// Set or clear the plaintext bytes, for forwarding an existing `Option`.
    #[must_use]
    pub const fn set_bytes_used(mut self, bytes_used: Option<u64>) -> Self {
        self.bytes_used = bytes_used;
        self
    }

    /// Construct the input.
    ///
    /// # Errors
    ///
    /// Returns a validation error ([`Error::is_validation`])
    /// if `identifier` or `bytes_used` is unset.
    pub fn build(self) -> Result<UpdateUsageMetadataInput, Error> {
        Ok(UpdateUsageMetadataInput {
            identifier: required(self.identifier, "identifier")?,
            bytes_used: required(self.bytes_used, "bytes_used")?,
        })
    }
}

/// Output of [`Cmc::update_usage_metadata`](super::Cmc::update_usage_metadata).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct UpdateUsageMetadataOutput {}

impl UpdateUsageMetadataOutput {
    /// Start a builder for `UpdateUsageMetadataOutput`.
    #[must_use]
    pub fn builder() -> UpdateUsageMetadataOutputBuilder {
        UpdateUsageMetadataOutputBuilder::default()
    }
}

/// Builder for [`UpdateUsageMetadataOutput`], returned by [`UpdateUsageMetadataOutput::builder`].
#[derive(Debug, Clone, Default)]
pub struct UpdateUsageMetadataOutputBuilder {}

impl UpdateUsageMetadataOutputBuilder {
    /// Construct the output.
    ///
    /// # Errors
    ///
    /// Never returns an error.
    pub const fn build(self) -> Result<UpdateUsageMetadataOutput, Error> {
        Ok(UpdateUsageMetadataOutput {})
    }
}

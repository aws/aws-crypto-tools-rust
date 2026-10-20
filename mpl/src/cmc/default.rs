// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The default Cryptographic Materials Cache.

use std::time::Duration;

use async_trait::async_trait;

use super::{
    Cmc, DeleteCacheEntryInput, DeleteCacheEntryOutput, GetCacheEntryInput, GetCacheEntryOutput,
    PutCacheEntryInput, PutCacheEntryOutput, StormTrackingCmc, UpdateUsageMetadataInput,
    UpdateUsageMetadataOutput,
};
use crate::Error;
use crate::builder::required;

/// The default Cryptographic Materials Cache.
///
/// A [`StormTrackingCmc`] with the defaults documented on [`StormTrackingCmcBuilder`](super::StormTrackingCmcBuilder),
/// except for the entry capacity, which you set.
/// Construct with [`DefaultCmc::builder`].
///
/// A clone refers to the same cache, not a copy of it.
#[derive(Clone, Debug)]
pub struct DefaultCmc {
    inner: StormTrackingCmc,
}

impl DefaultCmc {
    /// Start a builder for `DefaultCmc`.
    #[must_use]
    pub fn builder() -> DefaultCmcBuilder {
        DefaultCmcBuilder::default()
    }

    /// Maximum number of entries the cache holds.
    #[must_use]
    pub fn entry_capacity(&self) -> usize {
        self.inner.entry_capacity()
    }
}

/// Builder for [`DefaultCmc`], returned by [`DefaultCmc::builder`].
#[derive(Clone, Debug, Default)]
pub struct DefaultCmcBuilder {
    entry_capacity: Option<usize>,
}

impl DefaultCmcBuilder {
    /// Set the maximum number of entries. Required.
    #[must_use]
    pub const fn entry_capacity(mut self, n: usize) -> Self {
        self.entry_capacity = Some(n);
        self
    }

    /// Set or clear the maximum number of entries, for forwarding an existing `Option`.
    #[must_use]
    pub const fn set_entry_capacity(mut self, n: Option<usize>) -> Self {
        self.entry_capacity = n;
        self
    }

    /// The entry capacity, if set.
    #[must_use]
    pub const fn get_entry_capacity(&self) -> &Option<usize> {
        &self.entry_capacity
    }

    /// Construct the cache.
    ///
    /// # Errors
    ///
    /// Returns a validation error ([`Error::is_validation`])
    /// if `entry_capacity` is unset.
    pub fn build(self) -> Result<DefaultCmc, Error> {
        let entry_capacity = required(self.entry_capacity, "entry_capacity")?;
        Ok(DefaultCmc {
            inner: StormTrackingCmc::builder()
                .entry_capacity(entry_capacity)
                .build()?,
        })
    }
}

#[async_trait]
impl Cmc for DefaultCmc {
    async fn put_cache_entry(
        &self,
        input: PutCacheEntryInput,
    ) -> Result<PutCacheEntryOutput, Error> {
        Cmc::put_cache_entry(&self.inner, input).await
    }

    async fn get_cache_entry(
        &self,
        input: GetCacheEntryInput,
    ) -> Result<GetCacheEntryOutput, Error> {
        Cmc::get_cache_entry(&self.inner, input).await
    }

    async fn delete_cache_entry(
        &self,
        input: DeleteCacheEntryInput,
    ) -> Result<DeleteCacheEntryOutput, Error> {
        Cmc::delete_cache_entry(&self.inner, input).await
    }

    async fn update_usage_metadata(
        &self,
        input: UpdateUsageMetadataInput,
    ) -> Result<UpdateUsageMetadataOutput, Error> {
        Cmc::update_usage_metadata(&self.inner, input).await
    }

    fn grace_period(&self) -> Option<Duration> {
        self.inner.grace_period()
    }
}

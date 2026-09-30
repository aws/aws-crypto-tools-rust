// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The default Cryptographic Materials Cache: the cache to use when the only
//! setting that matters is how many entries it holds.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use super::{CacheEntry, Cmc, StormTrackingCmc};
use crate::Error;
use crate::error::Kind;

/// The default Cryptographic Materials Cache.
///
/// Construct with [`DefaultCmc::builder`].
/// It is a [`StormTrackingCmc`] with Dafny's `StormTracker.DefaultStorm()` settings
/// and the caller's entry capacity.
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

    /// Construct the cache.
    ///
    /// # Errors
    ///
    /// Returns a [`Validation`](crate::Error::Validation)
    /// error if `entry_capacity` is unset.
    pub fn build(self) -> Result<DefaultCmc, Error> {
        let Some(entry_capacity) = self.entry_capacity else {
            return Err(Error::new(
                Kind::Validation,
                "an entry capacity is required",
            ));
        };
        Ok(DefaultCmc {
            inner: StormTrackingCmc::builder()
                .entry_capacity(entry_capacity)
                .build()?,
        })
    }
}

#[async_trait]
impl Cmc for DefaultCmc {
    async fn put_cache_entry(&self, cache_id: &[u8], entry: CacheEntry) -> Result<(), Error> {
        self.inner.put_cache_entry(cache_id, entry).await
    }

    async fn get_cache_entry(&self, cache_id: &[u8]) -> Result<Option<Arc<CacheEntry>>, Error> {
        self.inner.get_cache_entry(cache_id).await
    }

    async fn delete_cache_entry(&self, cache_id: &[u8]) -> Result<(), Error> {
        self.inner.delete_cache_entry(cache_id).await
    }

    fn grace_period(&self) -> Option<Duration> {
        Cmc::grace_period(&self.inner)
    }
}

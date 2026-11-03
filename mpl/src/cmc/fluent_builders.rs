// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Fluent builders for the [`SharedCmc`] operations.

use super::{
    CacheEntry, Cmc, DeleteCacheEntryInput, DeleteCacheEntryInputBuilder, DeleteCacheEntryOutput,
    GetCacheEntryInput, GetCacheEntryInputBuilder, GetCacheEntryOutput, PutCacheEntryInput,
    PutCacheEntryInputBuilder, PutCacheEntryOutput, SharedCmc, UpdateUsageMetadataInput,
    UpdateUsageMetadataInputBuilder, UpdateUsageMetadataOutput,
};
use crate::Error;

impl SharedCmc {
    /// Start a [`Cmc::put_cache_entry`] call.
    pub fn put_cache_entry(&self) -> PutCacheEntryFluentBuilder {
        PutCacheEntryFluentBuilder {
            handle: self.clone(),
            inner: PutCacheEntryInput::builder(),
        }
    }

    /// Start a [`Cmc::get_cache_entry`] call.
    pub fn get_cache_entry(&self) -> GetCacheEntryFluentBuilder {
        GetCacheEntryFluentBuilder {
            handle: self.clone(),
            inner: GetCacheEntryInput::builder(),
        }
    }

    /// Start a [`Cmc::delete_cache_entry`] call.
    pub fn delete_cache_entry(&self) -> DeleteCacheEntryFluentBuilder {
        DeleteCacheEntryFluentBuilder {
            handle: self.clone(),
            inner: DeleteCacheEntryInput::builder(),
        }
    }

    /// Start a [`Cmc::update_usage_metadata`] call.
    pub fn update_usage_metadata(&self) -> UpdateUsageMetadataFluentBuilder {
        UpdateUsageMetadataFluentBuilder {
            handle: self.clone(),
            inner: UpdateUsageMetadataInput::builder(),
        }
    }
}

/// Fluent builder for [`SharedCmc::put_cache_entry`].
#[derive(Debug, Clone)]
#[must_use = "does nothing until `send` is called"]
pub struct PutCacheEntryFluentBuilder {
    handle: SharedCmc,
    inner: PutCacheEntryInputBuilder,
}

impl PutCacheEntryFluentBuilder {
    /// The input set so far.
    #[must_use]
    pub fn as_input(&self) -> &PutCacheEntryInputBuilder {
        &self.inner
    }

    /// Set the cache identifier. Required.
    pub fn identifier(mut self, identifier: impl Into<Vec<u8>>) -> Self {
        self.inner = self.inner.identifier(identifier);
        self
    }

    /// Set or clear the cache identifier, for forwarding an existing `Option`.
    pub fn set_identifier(mut self, identifier: Option<Vec<u8>>) -> Self {
        self.inner = self.inner.set_identifier(identifier);
        self
    }

    /// The identifier, if set.
    #[must_use]
    pub fn get_identifier(&self) -> &Option<Vec<u8>> {
        self.inner.get_identifier()
    }

    /// Set the entry to store. Required.
    pub fn entry(mut self, entry: impl Into<CacheEntry>) -> Self {
        self.inner = self.inner.entry(entry);
        self
    }

    /// Set or clear the entry, for forwarding an existing `Option`.
    pub fn set_entry(mut self, entry: Option<CacheEntry>) -> Self {
        self.inner = self.inner.set_entry(entry);
        self
    }

    /// The entry, if set.
    #[must_use]
    pub fn get_entry(&self) -> &Option<CacheEntry> {
        self.inner.get_entry()
    }

    /// Send the request.
    ///
    /// # Errors
    ///
    /// Returns a validation error ([`Error::is_validation`])
    /// if `identifier` or `entry` is unset.
    ///
    /// Otherwise, the errors [`Cmc::put_cache_entry`] documents.
    pub async fn send(self) -> Result<PutCacheEntryOutput, Error> {
        let input = self.inner.build()?;
        Cmc::put_cache_entry(&*self.handle.0, input).await
    }
}

/// Fluent builder for [`SharedCmc::get_cache_entry`].
#[derive(Debug, Clone)]
#[must_use = "does nothing until `send` is called"]
pub struct GetCacheEntryFluentBuilder {
    handle: SharedCmc,
    inner: GetCacheEntryInputBuilder,
}

impl GetCacheEntryFluentBuilder {
    /// The input set so far.
    #[must_use]
    pub fn as_input(&self) -> &GetCacheEntryInputBuilder {
        &self.inner
    }

    /// Set the cache identifier. Required.
    pub fn identifier(mut self, identifier: impl Into<Vec<u8>>) -> Self {
        self.inner = self.inner.identifier(identifier);
        self
    }

    /// Set or clear the cache identifier, for forwarding an existing `Option`.
    pub fn set_identifier(mut self, identifier: Option<Vec<u8>>) -> Self {
        self.inner = self.inner.set_identifier(identifier);
        self
    }

    /// The identifier, if set.
    #[must_use]
    pub fn get_identifier(&self) -> &Option<Vec<u8>> {
        self.inner.get_identifier()
    }

    /// Send the request.
    ///
    /// # Errors
    ///
    /// Returns a validation error ([`Error::is_validation`])
    /// if `identifier` is unset.
    ///
    /// Otherwise, the errors [`Cmc::get_cache_entry`] documents.
    pub async fn send(self) -> Result<GetCacheEntryOutput, Error> {
        let input = self.inner.build()?;
        Cmc::get_cache_entry(&*self.handle.0, input).await
    }
}

/// Fluent builder for [`SharedCmc::delete_cache_entry`].
#[derive(Debug, Clone)]
#[must_use = "does nothing until `send` is called"]
pub struct DeleteCacheEntryFluentBuilder {
    handle: SharedCmc,
    inner: DeleteCacheEntryInputBuilder,
}

impl DeleteCacheEntryFluentBuilder {
    /// The input set so far.
    #[must_use]
    pub fn as_input(&self) -> &DeleteCacheEntryInputBuilder {
        &self.inner
    }

    /// Set the cache identifier. Required.
    pub fn identifier(mut self, identifier: impl Into<Vec<u8>>) -> Self {
        self.inner = self.inner.identifier(identifier);
        self
    }

    /// Set or clear the cache identifier, for forwarding an existing `Option`.
    pub fn set_identifier(mut self, identifier: Option<Vec<u8>>) -> Self {
        self.inner = self.inner.set_identifier(identifier);
        self
    }

    /// The identifier, if set.
    #[must_use]
    pub fn get_identifier(&self) -> &Option<Vec<u8>> {
        self.inner.get_identifier()
    }

    /// Send the request.
    ///
    /// # Errors
    ///
    /// Returns a validation error ([`Error::is_validation`])
    /// if `identifier` is unset.
    ///
    /// Otherwise, the errors [`Cmc::delete_cache_entry`] documents.
    pub async fn send(self) -> Result<DeleteCacheEntryOutput, Error> {
        let input = self.inner.build()?;
        Cmc::delete_cache_entry(&*self.handle.0, input).await
    }
}

/// Fluent builder for [`SharedCmc::update_usage_metadata`].
#[derive(Debug, Clone)]
#[must_use = "does nothing until `send` is called"]
pub struct UpdateUsageMetadataFluentBuilder {
    handle: SharedCmc,
    inner: UpdateUsageMetadataInputBuilder,
}

impl UpdateUsageMetadataFluentBuilder {
    /// The input set so far.
    #[must_use]
    pub fn as_input(&self) -> &UpdateUsageMetadataInputBuilder {
        &self.inner
    }

    /// Set the cache identifier. Required.
    pub fn identifier(mut self, identifier: impl Into<Vec<u8>>) -> Self {
        self.inner = self.inner.identifier(identifier);
        self
    }

    /// Set or clear the cache identifier, for forwarding an existing `Option`.
    pub fn set_identifier(mut self, identifier: Option<Vec<u8>>) -> Self {
        self.inner = self.inner.set_identifier(identifier);
        self
    }

    /// The identifier, if set.
    #[must_use]
    pub fn get_identifier(&self) -> &Option<Vec<u8>> {
        self.inner.get_identifier()
    }

    /// Set the plaintext bytes of the message. Required.
    pub fn bytes_used(mut self, bytes_used: u64) -> Self {
        self.inner = self.inner.bytes_used(bytes_used);
        self
    }

    /// Set or clear the plaintext bytes, for forwarding an existing `Option`.
    pub fn set_bytes_used(mut self, bytes_used: Option<u64>) -> Self {
        self.inner = self.inner.set_bytes_used(bytes_used);
        self
    }

    /// The bytes used, if set.
    #[must_use]
    pub fn get_bytes_used(&self) -> &Option<u64> {
        self.inner.get_bytes_used()
    }

    /// Send the request.
    ///
    /// # Errors
    ///
    /// Returns a validation error ([`Error::is_validation`])
    /// if `identifier` or `bytes_used` is unset.
    ///
    /// Otherwise, the errors [`Cmc::update_usage_metadata`] documents.
    pub async fn send(self) -> Result<UpdateUsageMetadataOutput, Error> {
        let input = self.inner.build()?;
        Cmc::update_usage_metadata(&*self.handle.0, input).await
    }
}

/// Add the [`SharedCmc`] fluent calls to a built-in cache.
macro_rules! fluent_cmc {
    ($($ty:ty),+) => {$(
        impl $ty {
            /// Start a [`Cmc::put_cache_entry`] call.
            pub fn put_cache_entry(&self) -> PutCacheEntryFluentBuilder {
                SharedCmc::new(crate::shared::Builtin(self.clone())).put_cache_entry()
            }

            /// Start a [`Cmc::get_cache_entry`] call.
            pub fn get_cache_entry(&self) -> GetCacheEntryFluentBuilder {
                SharedCmc::new(crate::shared::Builtin(self.clone())).get_cache_entry()
            }

            /// Start a [`Cmc::delete_cache_entry`] call.
            pub fn delete_cache_entry(&self) -> DeleteCacheEntryFluentBuilder {
                SharedCmc::new(crate::shared::Builtin(self.clone())).delete_cache_entry()
            }

            /// Start a [`Cmc::update_usage_metadata`] call.
            pub fn update_usage_metadata(&self) -> UpdateUsageMetadataFluentBuilder {
                SharedCmc::new(crate::shared::Builtin(self.clone())).update_usage_metadata()
            }
        }

        impl crate::shared::FromUnshared<$ty> for SharedCmc {
            fn from_unshared(value: $ty) -> Self {
                SharedCmc::new(crate::shared::Builtin(value))
            }
        }
    )+};
}

fluent_cmc!(super::LocalCmc);
#[cfg(feature = "rt-tokio")]
fluent_cmc!(super::DefaultCmc, super::StormTrackingCmc);

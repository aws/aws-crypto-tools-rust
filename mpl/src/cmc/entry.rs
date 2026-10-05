// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Cache entry, usage metadata, and the cached-materials enum for the
//! cryptographic materials cache.

use std::time::SystemTime;

use crate::Error;
use crate::error::Kind;

use crate::structures::{
    BeaconKeyMaterials, BranchKeyMaterials, DecryptionMaterials, EncryptionMaterials,
};

/// The cryptographic materials kept in a single CMC entry.
///
/// Per the CMC spec's `#materials` section, a cache entry may carry one of
/// four material kinds: encryption, decryption, branch-key, or beacon-key
/// materials. The variant tracks which kind of materials this entry holds.
#[derive(Debug)]
#[non_exhaustive]
pub enum CachedMaterials {
    /// Encryption materials cached by a caching CMM on the encrypt path.
    Encryption(EncryptionMaterials),
    /// Decryption materials cached by a caching CMM on the decrypt path.
    Decryption(DecryptionMaterials),
    /// Branch-key materials cached by a hierarchical keyring.
    BranchKey(BranchKeyMaterials),
    /// Beacon-key materials cached by a structured-encryption client.
    BeaconKey(BeaconKeyMaterials),
}

/// Number of messages that have been encrypted with the cached encryption
/// materials.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub struct MessageUsage(u64);

impl MessageUsage {
    /// Construct a message count.
    #[must_use]
    pub const fn new(messages: u64) -> Self {
        Self(messages)
    }

    /// The number of messages.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl From<u64> for MessageUsage {
    fn from(messages: u64) -> Self {
        Self(messages)
    }
}

/// Number of plaintext bytes that have been encrypted with the cached
/// encryption materials.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub struct BytesUsage(u64);

impl BytesUsage {
    /// Construct a byte count.
    #[must_use]
    pub const fn new(bytes: u64) -> Self {
        Self(bytes)
    }

    /// The number of bytes.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl From<u64> for BytesUsage {
    fn from(bytes: u64) -> Self {
        Self(bytes)
    }
}

/// Per-entry usage metadata. The caching CMM consults these counters when
/// deciding whether the cached materials are still safe to reuse.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct UsageMetadata {
    messages_used: MessageUsage,
    bytes_used: BytesUsage,
}

impl UsageMetadata {
    /// Start a builder for `UsageMetadata`.
    #[must_use]
    pub fn builder() -> UsageMetadataBuilder {
        UsageMetadataBuilder::default()
    }

    /// Number of messages encrypted by the cached encryption materials.
    #[must_use]
    pub const fn messages_used(&self) -> MessageUsage {
        self.messages_used
    }

    /// Number of plaintext bytes encrypted by the cached encryption materials.
    #[must_use]
    pub const fn bytes_used(&self) -> BytesUsage {
        self.bytes_used
    }
}

/// Builder for [`UsageMetadata`], returned by [`UsageMetadata::builder`].
#[derive(Debug, Clone, Copy, Default)]
pub struct UsageMetadataBuilder {
    messages_used: Option<MessageUsage>,
    bytes_used: Option<BytesUsage>,
}

impl UsageMetadataBuilder {
    /// Set the number of messages encrypted. Defaults to 0.
    #[must_use]
    pub const fn messages_used(mut self, messages_used: MessageUsage) -> Self {
        self.messages_used = Some(messages_used);
        self
    }

    /// Set or clear the message count, for forwarding an existing `Option`.
    /// `None` applies the default documented on [`messages_used`](Self::messages_used).
    #[must_use]
    pub const fn set_messages_used(mut self, messages_used: Option<MessageUsage>) -> Self {
        self.messages_used = messages_used;
        self
    }

    /// Set the number of plaintext bytes encrypted. Defaults to 0.
    #[must_use]
    pub const fn bytes_used(mut self, bytes_used: BytesUsage) -> Self {
        self.bytes_used = Some(bytes_used);
        self
    }

    /// Set or clear the byte count, for forwarding an existing `Option`.
    /// `None` applies the default documented on [`bytes_used`](Self::bytes_used).
    #[must_use]
    pub const fn set_bytes_used(mut self, bytes_used: Option<BytesUsage>) -> Self {
        self.bytes_used = bytes_used;
        self
    }

    /// Construct the usage metadata.
    ///
    /// # Errors
    ///
    /// Never returns an error.
    pub fn build(self) -> Result<UsageMetadata, Error> {
        Ok(UsageMetadata {
            messages_used: self.messages_used.unwrap_or_default(),
            bytes_used: self.bytes_used.unwrap_or_default(),
        })
    }
}

/// A single entry in a Cryptographic Materials Cache.
///
/// `CacheEntry` is the data type every concrete CMC stores per cache
/// identifier. It holds the four pieces of state that the CMC
/// spec's `#cache-entry` section enumerates: the materials, the creation
/// time, the expiry time (TTL), and the usage metadata.
#[derive(Debug)]
#[non_exhaustive]
pub struct CacheEntry {
    materials: CachedMaterials,
    creation_time: SystemTime,
    expiry_time: SystemTime,
    usage_metadata: UsageMetadata,
}

impl CacheEntry {
    /// Start a builder for `CacheEntry`.
    #[must_use]
    pub fn builder() -> CacheEntryBuilder {
        CacheEntryBuilder::default()
    }

    /// Cached cryptographic materials.
    #[must_use]
    pub const fn materials(&self) -> &CachedMaterials {
        &self.materials
    }

    /// Wall-clock time when this entry was created.
    #[must_use]
    pub const fn creation_time(&self) -> SystemTime {
        self.creation_time
    }

    /// Time-to-live (TTL): the wall-clock instant after which the entry is
    /// TTL-expired and MUST NOT be returned to any caller.
    #[must_use]
    pub const fn expiry_time(&self) -> SystemTime {
        self.expiry_time
    }

    /// Usage counters tracked alongside the cached materials.
    #[must_use]
    pub const fn usage_metadata(&self) -> UsageMetadata {
        self.usage_metadata
    }
}

/// Builder for [`CacheEntry`], returned by [`CacheEntry::builder`].
#[derive(Debug, Default)]
pub struct CacheEntryBuilder {
    materials: Option<CachedMaterials>,
    creation_time: Option<SystemTime>,
    expiry_time: Option<SystemTime>,
    usage_metadata: Option<UsageMetadata>,
}

impl CacheEntryBuilder {
    /// Set the cached materials. Required.
    #[must_use]
    pub fn materials(mut self, materials: impl Into<CachedMaterials>) -> Self {
        self.materials = Some(materials.into());
        self
    }

    /// Set or clear the cached materials, for forwarding an existing `Option`.
    #[must_use]
    pub fn set_materials(mut self, materials: Option<CachedMaterials>) -> Self {
        self.materials = materials;
        self
    }

    /// Set the creation time. Required.
    #[must_use]
    pub const fn creation_time(mut self, creation_time: SystemTime) -> Self {
        self.creation_time = Some(creation_time);
        self
    }

    /// Set or clear the creation time, for forwarding an existing `Option`.
    #[must_use]
    pub const fn set_creation_time(mut self, creation_time: Option<SystemTime>) -> Self {
        self.creation_time = creation_time;
        self
    }

    /// Set the expiry time. Required.
    #[must_use]
    pub const fn expiry_time(mut self, expiry_time: SystemTime) -> Self {
        self.expiry_time = Some(expiry_time);
        self
    }

    /// Set or clear the expiry time, for forwarding an existing `Option`.
    #[must_use]
    pub const fn set_expiry_time(mut self, expiry_time: Option<SystemTime>) -> Self {
        self.expiry_time = expiry_time;
        self
    }

    /// Set the usage metadata. Defaults to zero messages and zero bytes.
    #[must_use]
    pub const fn usage_metadata(mut self, usage_metadata: UsageMetadata) -> Self {
        self.usage_metadata = Some(usage_metadata);
        self
    }

    /// Set or clear the usage metadata, for forwarding an existing `Option`.
    /// `None` applies the default documented on [`usage_metadata`](Self::usage_metadata).
    #[must_use]
    pub const fn set_usage_metadata(mut self, usage_metadata: Option<UsageMetadata>) -> Self {
        self.usage_metadata = usage_metadata;
        self
    }

    /// Construct the entry.
    ///
    /// # Errors
    ///
    /// Returns a validation error ([`Error::is_validation`])
    /// error if `materials`, `creation_time`, or `expiry_time` is unset.
    pub fn build(self) -> Result<CacheEntry, Error> {
        Ok(CacheEntry {
            materials: required(self.materials, "materials")?,
            creation_time: required(self.creation_time, "creation_time")?,
            expiry_time: required(self.expiry_time, "expiry_time")?,
            usage_metadata: self.usage_metadata.unwrap_or_default(),
        })
    }
}

fn required<T>(value: Option<T>, field: &str) -> Result<T, Error> {
    value.ok_or_else(|| Error::new(Kind::Validation, format!("{field} is required")))
}

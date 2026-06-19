// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Cache entry, usage metadata, and the cached-materials enum for the
//! cryptographic materials cache.

use std::time::SystemTime;

use crate::structures::{
    BeaconKeyMaterials, BranchKeyMaterials, DecryptionMaterials, EncryptionMaterials,
};

/// The cryptographic materials kept in a single CMC entry.
///
/// Per the CMC spec's `#materials` section, a cache entry may carry one of
/// four material kinds: encryption, decryption, branch-key, or beacon-key
/// materials. The variant tracks which kind of materials this entry holds.
#[derive(Debug)]
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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct MessageUsage(pub u64);

/// Number of plaintext bytes that have been encrypted with the cached
/// encryption materials.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct BytesUsage(pub u64);

/// Per-entry usage metadata. The caching CMM consults these counters when
/// deciding whether the cached materials are still safe to reuse.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UsageMetadata {
    /// Number of messages encrypted by the cached encryption materials.
    pub messages_used: MessageUsage,
    /// Number of plaintext bytes encrypted by the cached encryption
    /// materials.
    pub bytes_used: BytesUsage,
}

impl UsageMetadata {
    /// Construct a new `UsageMetadata` with both counters set.
    pub const fn new(messages_used: MessageUsage, bytes_used: BytesUsage) -> Self {
        Self {
            messages_used,
            bytes_used,
        }
    }
}

/// A single entry in a Cryptographic Materials Cache.
///
/// `CacheEntry` is the data type every concrete CMC stores per cache
/// identifier. Its fields are exactly the four pieces of state that the CMC
/// spec's `#cache-entry` section enumerates: the materials, the creation
/// time, the expiry time (TTL), and the usage metadata.
//= ../spec/framework/cryptographic-materials-cache.md#cache-entry
//= type=implication
//# A cache entry represents an entry in the cryptographic materials cache
//# and MUST have the following information.
#[derive(Debug)]
pub struct CacheEntry {
    /// Cached cryptographic materials (encryption, decryption, branch-key,
    /// or beacon-key).
    pub materials: CachedMaterials,
    /// Wall-clock time when this entry was created.
    pub creation_time: SystemTime,
    /// Time-to-live (TTL) — wall-clock instant after which the entry is
    /// considered TTL-expired and MUST NOT be returned to any caller.
    //= ../spec/framework/cryptographic-materials-cache.md#time-to-live-ttl
    //= type=implication
    //# Each cache entry has a time-to-live (TTL)
    //# that represents a point in time at which the cache entry
    //# MUST be considered invalid.
    pub expiry_time: SystemTime,
    /// Usage counters tracked alongside the cached materials.
    pub usage_metadata: UsageMetadata,
}

impl CacheEntry {
    /// Construct a new `CacheEntry` with all four required pieces of state.
    pub const fn new(
        materials: CachedMaterials,
        creation_time: SystemTime,
        expiry_time: SystemTime,
        usage_metadata: UsageMetadata,
    ) -> Self {
        Self {
            materials,
            creation_time,
            expiry_time,
            usage_metadata,
        }
    }
}

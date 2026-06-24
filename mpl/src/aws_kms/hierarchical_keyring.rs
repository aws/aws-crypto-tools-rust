// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! AWS KMS Hierarchical Keyring.
//!
//! Implements `spec/framework/aws-kms/aws-kms-hierarchical-keyring.md`:
//! construction / configuration surface (`#initialization`,
//! `#partition-id`, `#cache-type`, `#cache-limit-ttl`), the OnEncrypt
//! and OnDecrypt operations, and the keystore- / cache-fallthrough
//! they share. Pure-crypto leaves live in [`super::branch_key_wrap`]
//! and the cache identifier formulas in [`super::cache_entry_identifier`].

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;

use crate::Keyring;
use crate::aws_kms::branch_key_wrap;
use crate::aws_kms::cache_entry_identifier;
use crate::cmc::{
    CacheEntry, CachedMaterials, Cmc, LocalCmc, StormTrackingCmc, TimeUnits, UsageMetadata,
};
use crate::keystore::Keystore;
use crate::structures::{
    AlgorithmSuite, BranchKeyMaterials, DecryptionMaterials, EncryptedDataKey, EncryptionContext,
    EncryptionMaterials, MaterialsError, PlaintextDataKey,
};

/// Default entry capacity for the keyring-local CMC. Spec text: "If no
/// max cache size is provided, the cryptographic materials cache MUST be
/// configured to a max cache size of 1000."
const DEFAULT_CACHE_ENTRY_CAPACITY: usize = 1000;

/// Default entry-pruning tail size for the keyring-local CMC. The spec
/// constrains `entry_capacity` (above) but not the pruning tail size;
/// 64 strikes a reasonable balance between pruning amortization and
/// per-`get` work.
const DEFAULT_CACHE_PRUNING_TAIL_SIZE: usize = 64;

/// Identifier source for the hierarchical keyring's branch key.
///
/// Spec text: "On initialization, the caller … MUST provide either a
/// Branch Key Identifier or a [Branch Key Supplier](#branch-key-supplier)".
/// The "either … or" is enforced at the type level by this enum.
pub enum BranchKeySource {
    /// A static branch-key id chosen at construction time.
    Identifier(String),
    /// A user-supplied [`BranchKeySupplier`] that selects a branch key id
    /// at OnEncrypt / OnDecrypt time based on the encryption context.
    Supplier(Arc<dyn BranchKeySupplier>),
}

/// Configuration for a keyring-local "default" Cryptographic Materials
/// Cache (a wrapped [`LocalCmc`]). Carried by [`CacheType::Default`].
///
/// Use [`DefaultCache::default()`] to get the spec-mandated entry capacity
/// (1000) and a sensible pruning tail size; use [`DefaultCache::builder`]
/// to customize either field.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DefaultCache {
    /// Maximum number of entries the cache holds. Per spec
    /// `aws-kms-hierarchical-keyring.md#initialization`, the default value
    /// when none is provided MUST be 1000.
    pub entry_capacity: usize,
    /// Number of LRU entries scanned per get for TTL-aware pruning. The
    /// spec is silent on this knob; 64 strikes a balance between
    /// pruning amortization and per-`get` work.
    pub entry_pruning_tail_size: usize,
}

impl Default for DefaultCache {
    fn default() -> Self {
        Self {
            entry_capacity: DEFAULT_CACHE_ENTRY_CAPACITY,
            entry_pruning_tail_size: DEFAULT_CACHE_PRUNING_TAIL_SIZE,
        }
    }
}

impl DefaultCache {
    /// Construct a `DefaultCache` with explicit capacity and pruning tail size.
    #[must_use]
    pub const fn new(entry_capacity: usize, entry_pruning_tail_size: usize) -> Self {
        Self {
            entry_capacity,
            entry_pruning_tail_size,
        }
    }

    /// Start a fluent builder for `DefaultCache`. Unset fields default to
    /// the spec/implementation defaults (entry_capacity = 1000,
    /// entry_pruning_tail_size = 64).
    #[must_use]
    pub fn builder() -> DefaultCacheBuilder {
        DefaultCacheBuilder::default()
    }
}

/// Fluent builder for [`DefaultCache`]. Call [`Self::build`] to produce the
/// configured `DefaultCache`; unset fields fall back to the spec defaults.
#[derive(Debug, Clone, Default)]
pub struct DefaultCacheBuilder {
    entry_capacity: Option<usize>,
    entry_pruning_tail_size: Option<usize>,
}

impl DefaultCacheBuilder {
    /// Override the maximum number of entries held by the cache.
    #[must_use]
    pub const fn entry_capacity(mut self, n: usize) -> Self {
        self.entry_capacity = Some(n);
        self
    }

    /// Override the number of LRU entries scanned per `get` for pruning.
    #[must_use]
    pub const fn entry_pruning_tail_size(mut self, n: usize) -> Self {
        self.entry_pruning_tail_size = Some(n);
        self
    }

    /// Finalize the builder into a [`DefaultCache`].
    #[must_use]
    pub fn build(self) -> DefaultCache {
        DefaultCache {
            entry_capacity: self.entry_capacity.unwrap_or(DEFAULT_CACHE_ENTRY_CAPACITY),
            entry_pruning_tail_size: self
                .entry_pruning_tail_size
                .unwrap_or(DEFAULT_CACHE_PRUNING_TAIL_SIZE),
        }
    }
}

/// Configuration for a keyring-local Storm-tracking Cryptographic Materials
/// Cache. Carried by [`CacheType::StormTracking`].
///
/// Mirrors the parameter set accepted by [`StormTrackingCmc::new`]; bundled
/// into a struct so the [`CacheType::StormTracking`] variant stays ergonomic.
/// Use [`StormTrackingCache::builder`] for a fluent constructor, or set the
/// fields directly.
#[derive(Debug, Clone)]
pub struct StormTrackingCache {
    /// Maximum number of entries the underlying [`LocalCmc`] holds.
    pub entry_capacity: usize,
    /// Number of LRU entries scanned per get for TTL-aware pruning.
    pub entry_pruning_tail_size: usize,
    /// Window during which a soon-to-expire entry is still served.
    pub grace_period: u64,
    /// Window during which a recent NoSuchEntry is treated as inflight.
    pub grace_interval: u64,
    /// Maximum concurrent in-flight refresh fan-out.
    pub fan_out: usize,
    /// Maximum time an inflight entry may remain inflight before failing.
    pub inflight_ttl: u64,
    /// Sleep granularity (always milliseconds).
    pub sleep_milli: u64,
    /// Time unit for the duration parameters above. Defaults to seconds.
    pub time_units: Option<TimeUnits>,
}

impl StormTrackingCache {
    /// Start a fluent builder for `StormTrackingCache`. All numeric fields
    /// must be supplied via the builder before [`StormTrackingCacheBuilder::build`]
    /// is called; `time_units` is optional and defaults to seconds.
    #[must_use]
    pub fn builder() -> StormTrackingCacheBuilder {
        StormTrackingCacheBuilder::default()
    }
}

/// Fluent builder for [`StormTrackingCache`]. All seven numeric fields
/// (`entry_capacity`, `entry_pruning_tail_size`, `grace_period`,
/// `grace_interval`, `fan_out`, `inflight_ttl`, `sleep_milli`) are
/// required; [`StormTrackingCacheBuilder::build`] returns an error if any
/// were left unset. `time_units` is optional.
#[derive(Debug, Clone, Default)]
pub struct StormTrackingCacheBuilder {
    entry_capacity: Option<usize>,
    entry_pruning_tail_size: Option<usize>,
    grace_period: Option<u64>,
    grace_interval: Option<u64>,
    fan_out: Option<usize>,
    inflight_ttl: Option<u64>,
    sleep_milli: Option<u64>,
    time_units: Option<TimeUnits>,
}

impl StormTrackingCacheBuilder {
    /// Set `entry_capacity`. See [`StormTrackingCache::entry_capacity`].
    #[must_use]
    pub const fn entry_capacity(mut self, n: usize) -> Self {
        self.entry_capacity = Some(n);
        self
    }

    /// Set `entry_pruning_tail_size`.
    #[must_use]
    pub const fn entry_pruning_tail_size(mut self, n: usize) -> Self {
        self.entry_pruning_tail_size = Some(n);
        self
    }

    /// Set `grace_period`.
    #[must_use]
    pub const fn grace_period(mut self, n: u64) -> Self {
        self.grace_period = Some(n);
        self
    }

    /// Set `grace_interval`.
    #[must_use]
    pub const fn grace_interval(mut self, n: u64) -> Self {
        self.grace_interval = Some(n);
        self
    }

    /// Set `fan_out`.
    #[must_use]
    pub const fn fan_out(mut self, n: usize) -> Self {
        self.fan_out = Some(n);
        self
    }

    /// Set `inflight_ttl`.
    #[must_use]
    pub const fn inflight_ttl(mut self, n: u64) -> Self {
        self.inflight_ttl = Some(n);
        self
    }

    /// Set `sleep_milli`.
    #[must_use]
    pub const fn sleep_milli(mut self, n: u64) -> Self {
        self.sleep_milli = Some(n);
        self
    }

    /// Set `time_units` (defaults to seconds when unset).
    #[must_use]
    pub const fn time_units(mut self, u: TimeUnits) -> Self {
        self.time_units = Some(u);
        self
    }

    /// Finalize the builder. Returns an error naming the first missing
    /// required field if any of the seven numeric fields were left unset.
    pub fn build(self) -> Result<StormTrackingCache, MaterialsError> {
        Ok(StormTrackingCache {
            entry_capacity: self.entry_capacity.ok_or_else(|| {
                MaterialsError::new("StormTrackingCacheBuilder: entry_capacity is required")
            })?,
            entry_pruning_tail_size: self.entry_pruning_tail_size.ok_or_else(|| {
                MaterialsError::new(
                    "StormTrackingCacheBuilder: entry_pruning_tail_size is required",
                )
            })?,
            grace_period: self.grace_period.ok_or_else(|| {
                MaterialsError::new("StormTrackingCacheBuilder: grace_period is required")
            })?,
            grace_interval: self.grace_interval.ok_or_else(|| {
                MaterialsError::new("StormTrackingCacheBuilder: grace_interval is required")
            })?,
            fan_out: self.fan_out.ok_or_else(|| {
                MaterialsError::new("StormTrackingCacheBuilder: fan_out is required")
            })?,
            inflight_ttl: self.inflight_ttl.ok_or_else(|| {
                MaterialsError::new("StormTrackingCacheBuilder: inflight_ttl is required")
            })?,
            sleep_milli: self.sleep_milli.ok_or_else(|| {
                MaterialsError::new("StormTrackingCacheBuilder: sleep_milli is required")
            })?,
            time_units: self.time_units,
        })
    }
}

/// Cache configuration for a [`HierarchicalKeyring`].
///
/// The three variants correspond to the spec's `#cache-type` discussion:
/// a keyring-local default cache, an externally-supplied `Shared` cache
/// that may be reused across multiple Cryptographic Material Providers,
/// and a keyring-local Storm-tracking cache for high-fan-out workloads.
#[non_exhaustive]
pub enum CacheType {
    /// A keyring-local [`LocalCmc`] configured by the carried
    /// [`DefaultCache`]. Per spec `#initialization`: "If no max cache size
    /// is provided, the cryptographic materials cache MUST be configured
    /// to a max cache size of 1000." Use [`DefaultCache::default()`] for
    /// the spec defaults.
    Default(DefaultCache),
    /// Use the caller-supplied [`Cmc`] impl directly. Common when one
    /// cache is shared across multiple Hierarchical Keyrings (or other
    /// CMPs); see `#shared-cache-considerations`.
    Shared(Arc<dyn Cmc>),
    /// Build a keyring-local [`StormTrackingCmc`] with the carried
    /// [`StormTrackingCache`] parameters. The keyring validates that
    /// `grace_period < cache limit TTL` per spec `#initialization`.
    StormTracking(StormTrackingCache),
}

/// User-supplied callback that maps an encryption context to a branch key id.
///
/// Implementations are typically used by callers running multi-tenant workloads
/// who want to pick the branch key based on encryption-context metadata.
#[async_trait]
pub trait BranchKeySupplier: Send + Sync {
    /// Return the branch key id to use for a given encryption context.
    //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-supplier
    //= type=implication
    //# This operation MUST take in an encryption context as input,
    //# and return a branch key id (string) as output.
    async fn get_branch_key_id(
        &self,
        encryption_context: &EncryptionContext,
    ) -> Result<String, MaterialsError>;
}

/// AWS KMS Hierarchical Keyring.
///
/// See [`HierarchicalKeyring::new`] for construction. The [`Keyring`]
/// impl wires the configured cache and keystore into the spec's
/// OnEncrypt / OnDecrypt algorithms.
pub struct HierarchicalKeyring {
    //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#initialization
    //= type=implication
    //# - MUST provide a [Keystore](../branch-key-store.md)
    keystore: Arc<dyn Keystore>,

    //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#initialization
    //= type=implication
    //# - MUST provide a [cache limit TTL](#cache-limit-ttl)
    //
    //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#cache-limit-ttl
    //= type=implication
    //# The client MUST set a time-to-live (TTL) for [branch key materials](../structures.md#branch-key-materials) in the underlying cache.
    ttl_seconds: u64,

    //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#initialization
    //= type=implication
    //# - MUST provide either a Branch Key Identifier or a [Branch Key Supplier](#branch-key-supplier)
    branch_key_source: BranchKeySource,

    //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#partition-id
    //= type=implication
    //# The Partition ID MUST NOT be changed after initialization.
    //
    //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#partition-id-1
    //= type=implication
    //# The constructor of the Hierarchical Keyring MUST record these bytes at construction time.
    partition_id_bytes: Vec<u8>,

    /// Cryptographic-materials cache for branch-key materials. Either a
    /// keyring-local `LocalCmc`/`StormTrackingCmc` built at construction
    /// time, or a `Shared` cache supplied by the caller.
    cache: Arc<dyn Cmc>,
}

impl HierarchicalKeyring {
    /// Construct a new hierarchical keyring.
    ///
    /// `ttl_seconds` MUST be greater than zero per
    /// `aws-kms-hierarchical-keyring.md#cache-limit-ttl`.
    ///
    /// If `partition_id` is `None`, a fresh v4 UUID is generated and stored
    /// as the 16-byte partition id, per
    /// `aws-kms-hierarchical-keyring.md#partition-id`.
    ///
    /// `cache_type` selects the cache backing — see [`CacheType`]. When
    /// `None`, behaves as `Some(CacheType::Default(DefaultCache::default()))`.
    pub fn new(
        keystore: Arc<dyn Keystore>,
        ttl_seconds: u64,
        branch_key_source: BranchKeySource,
        //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#initialization
        //= type=implication
        //# - MAY provide a [Cache Type](#cache-type)
        cache_type: Option<CacheType>,
        //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#initialization
        //= type=implication
        //# - MAY provide a [Partition ID](#partition-id)
        partition_id: Option<String>,
    ) -> Result<Self, MaterialsError> {
        if ttl_seconds == 0 {
            //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#cache-limit-ttl
            //# This value MUST be greater than zero.
            return Err(MaterialsError::new(
                "HierarchicalKeyring TTL (ttl_seconds) must be greater than zero",
            ));
        }

        //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#initialization
        //# On initialization the Hierarchical Keyring MUST initialize a [cryptographic-materials-cache](../local-cryptographic-materials-cache.md) with the configured cache limit TTL and the max cache size.
        //
        //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#initialization
        //# If the Hierarchical Keyring does NOT get a `Shared` cache on initialization,
        //# it MUST initialize a [cryptographic-materials-cache](../local-cryptographic-materials-cache.md)
        //# with the user provided cache limit TTL and the entry capacity.
        let cache: Arc<dyn Cmc> = match cache_type
            .unwrap_or(CacheType::Default(DefaultCache::default()))
        {
            CacheType::Default(default_cache) => {
                //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#initialization
                //# If no max cache size is provided, the cryptographic materials cache MUST be configured to a
                //# max cache size of 1000.
                //
                //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#initialization
                //# If no `cache` is provided, a `DefaultCache` MUST be configured with entry capacity of 1000.
                let local = LocalCmc::new(
                    default_cache.entry_capacity,
                    default_cache.entry_pruning_tail_size,
                )
                .map_err(|e| {
                    MaterialsError::new(format!(
                        "HierarchicalKeyring: failed to initialize default LocalCmc: {e}",
                    ))
                })?;
                Arc::new(local)
            }
            CacheType::Shared(cache) => cache,
            CacheType::StormTracking(params) => {
                //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#initialization
                //# If the cache to initialize is a [Storm Tracking Cryptographic Materials Cache](../storm-tracking-cryptographic-materials-cache.md#overview)
                //# then the [Grace Period](../storm-tracking-cryptographic-materials-cache.md#grace-period) MUST be less than the [cache limit TTL](#cache-limit-ttl).
                let grace_in_seconds = match params.time_units.unwrap_or_default() {
                    TimeUnits::Seconds => params.grace_period,
                    TimeUnits::Milliseconds => params.grace_period / 1000,
                };
                if grace_in_seconds >= ttl_seconds {
                    return Err(MaterialsError::new(format!(
                        "HierarchicalKeyring: storm-tracking grace period ({} {:?}) must be less than the cache limit TTL ({ttl_seconds} seconds)",
                        params.grace_period,
                        params.time_units.unwrap_or_default(),
                    )));
                }
                let storm = StormTrackingCmc::new(
                    params.entry_capacity,
                    params.entry_pruning_tail_size,
                    params.grace_period,
                    params.grace_interval,
                    params.fan_out,
                    params.inflight_ttl,
                    params.sleep_milli,
                    params.time_units,
                )
                .map_err(|e| {
                    MaterialsError::new(format!(
                        "HierarchicalKeyring: failed to initialize StormTrackingCmc: {e}",
                    ))
                })?;
                Arc::new(storm)
            }
        };

        //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#partition-id-1
        //= type=implication
        //# It can either be a String provided by the user, which MUST be interpreted as the bytes of
        //# UTF-8 Encoding of the String, or a v4 UUID, which SHOULD be interpreted as the 16 byte representation of the UUID.
        let partition_id_bytes = match partition_id {
            //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#partition-id
            //= type=implication
            //# If provided, it MUST be interpreted as UTF8 bytes.
            Some(s) => s.into_bytes(),
            //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#partition-id
            //# If the PartitionId is NOT provided by the user, it MUST be set to the 16 byte representation of a v4 UUID.
            None => generate_v4_uuid_bytes()?,
        };

        Ok(Self {
            keystore,
            ttl_seconds,
            branch_key_source,
            partition_id_bytes,
            cache,
        })
    }

    /// The configured TTL for cached branch-key materials, in seconds.
    pub fn ttl_seconds(&self) -> u64 {
        self.ttl_seconds
    }

    /// The source from which a branch key id is resolved (a static identifier
    /// or a [`BranchKeySupplier`]).
    pub fn branch_key_source(&self) -> &BranchKeySource {
        &self.branch_key_source
    }

    /// The configured keystore.
    pub fn keystore(&self) -> &Arc<dyn Keystore> {
        &self.keystore
    }

    /// The 16-byte partition id of this keyring. Either the UTF-8 bytes of the
    /// caller-provided string, or a freshly-generated v4 UUID.
    ///
    /// Hidden from the public API surface; intended for tests verifying the
    /// v4-UUID variant/version bits and round-tripping of caller-provided
    /// strings.
    #[doc(hidden)]
    pub fn partition_id_bytes(&self) -> &[u8] {
        &self.partition_id_bytes
    }

    /// The configured cache. Hidden from the public API surface;
    /// intended for tests asserting that `CacheType::Shared(...)` round-
    /// trips the supplied `Arc<dyn Cmc>` verbatim.
    #[doc(hidden)]
    pub fn cache(&self) -> &Arc<dyn Cmc> {
        &self.cache
    }
}

/// Generate the 16-byte representation of a fresh v4 UUID using the
/// `aws_lc_rs` CSPRNG, then set the version and variant bits per
/// RFC 4122 §4.4.
fn generate_v4_uuid_bytes() -> Result<Vec<u8>, MaterialsError> {
    let mut bytes = [0u8; 16];
    aws_lc_rs::rand::fill(&mut bytes).map_err(|_| {
        MaterialsError::new(
            "HierarchicalKeyring: failed to obtain entropy for partition-id v4 UUID",
        )
    })?;
    // RFC 4122 §4.4: set the version (top 4 bits of byte 6) to 0b0100 (4).
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    // RFC 4122 §4.4: set the variant (top 2 bits of byte 8) to 0b10.
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    Ok(bytes.to_vec())
}

/// Convert the 16-byte representation of a UUID back to its canonical
/// 36-character hyphenated string form (`8-4-4-4-12`). The output
/// satisfies the `is_valid_uuid_v4` check inside
/// [`BranchKeyMaterials::new`] when the input bytes were produced by a
/// v4 UUID generator (variant + version bits already set).
fn uuid_16_bytes_to_str(bytes: &[u8; CIPHERTEXT_VERSION_LEN]) -> String {
    uuid::Uuid::from_bytes(*bytes).hyphenated().to_string()
}

//= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#interface
//= type=implication
//# MUST implement the [AWS Encryption SDK Keyring interface](../keyring-interface.md#interface)
#[async_trait]
impl Keyring for HierarchicalKeyring {
    //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
    //= type=implication
    //# OnEncrypt MUST take [encryption materials](../structures.md#encryption-materials) as input.
    async fn on_encrypt(
        &self,
        materials: EncryptionMaterials,
    ) -> Result<EncryptionMaterials, MaterialsError> {
        //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
        //# The `branchKeyId` used in this operation is either the configured branchKeyId, if supplied, or the result of the `branchKeySupplier`'s
        //# `getBranchKeyId` operation, using the encryption material's encryption context as input.
        let branch_key_id = self
            .resolve_branch_key_id(materials.encryption_context())
            .await?;

        //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
        //# If the input [encryption materials](../structures.md#encryption-materials) do not contain a plaintext data key,
        //# OnEncrypt MUST generate a random plaintext data key, according to the key length defined in the [algorithm suite](../algorithm-suites.md#encryption-key-length).
        //
        //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
        //# The process used to generate this random plaintext data key MUST use a secure source of randomness.
        let plaintext_dk = match materials.plaintext_data_key() {
            Some(pdk) => pdk.clone(),
            None => generate_random_data_key(materials.algorithm_suite())?,
        };

        // Resolve the keystore's logical name once per operation; the
        // Appendix A formula binds it into the cache identifier.
        let logical_keystore_name = self
            .keystore
            .get_key_store_info()
            .await
            .map_err(|e| {
                MaterialsError::keyring_failed(format!(
                    "HierarchicalKeyring: get_key_store_info failed: {e}",
                ))
            })?
            .logical_keystore_name;

        //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
        //# The hierarchical keyring MUST use the formulas specified in [Appendix A](#appendix-a-cache-entry-identifier-formulas)
        //# to compute the [cache entry identifier](../cryptographic-materials-cache.md#cache-identifier).
        let cache_id = cache_entry_identifier::for_encrypt(
            &self.partition_id_bytes,
            &logical_keystore_name,
            &branch_key_id,
        );

        //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
        //# The hierarchical keyring MUST attempt to find [branch key materials](../structures.md#branch-key-materials)
        //# from the underlying [cryptographic materials cache](../local-cryptographic-materials-cache.md).
        let cached = self.cache.get_cache_entry(&cache_id).await.map_err(|e| {
            MaterialsError::keyring_failed(format!(
                "HierarchicalKeyring: cache get_cache_entry failed: {e}",
            ))
        })?;

        let ciphertext = match cached {
            //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
            //# If a cache entry is found and the entry's TTL has not expired, the hierarchical keyring MUST use those branch key materials for key wrapping.
            //
            //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
            //# There MUST be a check (cacheEntryWithinLimits) to make sure that for the cache entry found, who's TTL has NOT expired,
            //# `time.now() - cacheEntryCreationTime <= ttlSeconds` is true and
            //# valid for TTL of the Hierarchical Keyring getting the cache entry.
            Some(entry) if cache_entry_within_limits(&entry, self.ttl_seconds) => {
                let bkm = unwrap_branch_key_materials(&entry)?;
                //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
                //# - MUST wrap a data key with the branch key materials according to the [branch key wrapping](#branch-key-wrapping) section.
                branch_key_wrap::wrap(bkm, materials.encryption_context(), plaintext_dk.as_bytes())?
            }
            //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
            //# If this is NOT true, then we MUST treat the cache entry as expired.
            //
            //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
            //# If a cache entry is not found or the cache entry is expired, the hierarchical keyring MUST attempt to obtain the branch key materials
            //# by querying the backing branch keystore specified in the [retrieve OnEncrypt branch key materials](#query-branch-keystore-onencrypt) section.
            _ => {
                //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#query-branch-keystore-onencrypt
                //# OnEncrypt MUST call the Keystore's [GetActiveBranchKey](../branch-key-store.md#getactivebranchkey) operation with the following inputs:
                //
                //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#query-branch-keystore-onencrypt
                //# - the `branchKeyId` used in this operation
                let bkm = self
                    .keystore
                    .get_active_branch_key(branch_key_id.clone())
                    .await
                    .map_err(|e| {
                        //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#query-branch-keystore-onencrypt
                        //# Otherwise, OnEncrypt MUST fail.
                        MaterialsError::keyring_failed(format!(
                            "HierarchicalKeyring: get_active_branch_key failed: {e}",
                        ))
                    })?;

                //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#query-branch-keystore-onencrypt
                //# If the Keystore's GetActiveBranchKey operation succeeds
                //# the keyring MUST put the returned branch key materials in the cache using the
                //# formula defined in [Appendix A](#appendix-a-cache-entry-identifier-formulas).
                let now = SystemTime::now();
                let entry = CacheEntry::new(
                    CachedMaterials::BranchKey(bkm.clone()),
                    now,
                    //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#cache-limit-ttl
                    //# The maximum amount of time in seconds that an entry within the cache may be used before it MUST be evicted.
                    now + Duration::from_secs(self.ttl_seconds),
                    UsageMetadata::default(),
                );
                self.cache
                    .put_cache_entry(&cache_id, entry)
                    .await
                    .map_err(|e| {
                        MaterialsError::keyring_failed(format!(
                            "HierarchicalKeyring: cache put_cache_entry failed: {e}",
                        ))
                    })?;

                //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
                //# If the keyring is not able to retrieve [branch key materials](../structures.md#branch-key-materials)
                //# through the underlying cryptographic materials cache or
                //# it no longer has access to them through the backing keystore, OnEncrypt MUST fail.
                branch_key_wrap::wrap(
                    &bkm,
                    materials.encryption_context(),
                    plaintext_dk.as_bytes(),
                )?
            }
        };

        //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
        //# Otherwise, OnEncrypt MUST append a new [encrypted data key](../structures.md#encrypted-data-key)
        //# to the encrypted data key list in the [encryption materials](../structures.md#encryption-materials), constructed as follows:
        let edk = EncryptedDataKey::new(
            //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
            //# - [key provider id](../structures.md#key-provider-id): MUST be UTF8 Encoded "aws-kms-hierarchy"
            KEY_PROVIDER_ID_HIERARCHY.to_string(),
            //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
            //# - [key provider info](../structures.md#key-provider-information): MUST be the UTF8 Encoded AWS DDB response `branch-key-id`
            branch_key_id.into_bytes(),
            //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
            //# - [ciphertext](../structures.md#ciphertext): MUST be serialized as the [hierarchical keyring ciphertext](#ciphertext)
            ciphertext,
        );

        //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
        //# If the keyring is unable to wrap a plaintext data key, OnEncrypt MUST fail
        //# and MUST NOT modify the [decryption materials](structures.md#decryption-materials).
        //
        // Reaching this point means wrap succeeded above (any wrap failure
        // returned via `?`); only at this point does the function build a
        // new EncryptionMaterials value. The input `materials` parameter
        // is owned but never mutated; we construct a fresh value so a
        // caller's failure handling can re-use the original.
        let mut new_edks: Vec<EncryptedDataKey> = materials.encrypted_data_keys().to_vec();
        new_edks.push(edk);
        EncryptionMaterials::new(
            materials.algorithm_suite_id(),
            new_edks,
            materials.encryption_context().clone(),
            materials.required_encryption_context_keys().clone(),
            Some(plaintext_dk),
            materials.signing_key().cloned(),
            materials.symmetric_signing_keys().map(|s| s.to_vec()),
        )
    }

    //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
    //= type=implication
    //# OnDecrypt MUST take [decryption materials](../structures.md#decryption-materials) and a list of [encrypted data keys](../structures.md#encrypted-data-keys) as input.
    async fn on_decrypt(
        &self,
        materials: DecryptionMaterials,
        encrypted_data_keys: &[EncryptedDataKey],
    ) -> Result<DecryptionMaterials, MaterialsError> {
        //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
        //# If the decryption materials already contain a `PlainTextDataKey`, OnDecrypt MUST fail.
        if materials.plaintext_data_key().is_some() {
            return Err(MaterialsError::plaintext_already_present(
                "HierarchicalKeyring::on_decrypt: decryption materials already contain a plaintext data key",
            ));
        }

        //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
        //# The `branchKeyId` used in this operation is either the configured branchKeyId, if supplied, or the result of the `branchKeySupplier`'s
        //# `getBranchKeyId` operation, using the decryption material's encryption context as input.
        let branch_key_id = self
            .resolve_branch_key_id(materials.encryption_context())
            .await?;

        // Resolve the keystore's logical name once per operation; the
        // Appendix A formula binds it into the cache identifier.
        let logical_keystore_name = self
            .keystore
            .get_key_store_info()
            .await
            .map_err(|e| {
                MaterialsError::keyring_failed(format!(
                    "HierarchicalKeyring: get_key_store_info failed: {e}",
                ))
            })?
            .logical_keystore_name;

        //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
        //# For each encrypted data key in the filtered set, one at a time, OnDecrypt MUST attempt to decrypt the encrypted data key.
        //
        //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
        //# The set of encrypted data keys MUST first be filtered to match this keyring’s configuration. For the encrypted data key to match:
        let mut collected_errors: Vec<String> = Vec::new();
        for edk in encrypted_data_keys {
            //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
            //# - Its provider ID MUST match the UTF8 Encoded value of “aws-kms-hierarchy”.
            if edk.key_provider_id != KEY_PROVIDER_ID_HIERARCHY {
                continue;
            }

            //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
            //# - Deserialize the key provider info, if deserialization fails the next EDK in the set MUST be attempted.
            let Ok(edk_branch_key_id) = std::str::from_utf8(&edk.key_provider_info) else {
                continue;
            };

            //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
            //# - The deserialized key provider info MUST be UTF8 Decoded and MUST match this keyring's configured `Branch Key Identifier`.
            //
            //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#getitem-branch-keystore-ondecrypt
            //# - Deserialize the UTF8-Decoded `branch-key-id` from the [key provider info](../structures.md#key-provider-information) of the [encrypted data key](../structures.md#encrypted-data-key)
            //#   and verify this is equal to the configured or supplied `branch-key-id`.
            if edk_branch_key_id != branch_key_id {
                continue;
            }

            match self
                .try_decrypt_edk(&materials, edk, &branch_key_id, &logical_keystore_name)
                .await
            {
                Ok(plaintext_dk_bytes) => {
                    //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
                    //# If a decryption succeeds, this keyring MUST
                    //# add the resulting plaintext data key to the decryption materials and return the modified materials.
                    return DecryptionMaterials::new(
                        materials.algorithm_suite_id(),
                        materials.encryption_context().clone(),
                        materials.required_encryption_context_keys().clone(),
                        Some(PlaintextDataKey::new(plaintext_dk_bytes)),
                        materials.verification_key().cloned(),
                        materials.symmetric_signing_key().cloned(),
                    );
                }
                //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
                //# If this attempt results in an error, then these errors MUST be collected.
                Err(e) => collected_errors.push(e.to_string()),
            }
        }

        //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
        //# If OnDecrypt fails to successfully decrypt any [encrypted data key](../structures.md#encrypted-data-key),
        //# then it MUST yield an error that includes all the collected errors
        //# and MUST NOT modify the [decryption materials](structures.md#decryption-materials).
        //
        // The early-return above on `Ok` is the only path that produces a
        // mutated DecryptionMaterials; reaching this line means no EDK was
        // successfully decrypted, so the input `materials` parameter (owned
        // but never mutated) is dropped without modification.
        Err(MaterialsError::keyring_failed(format!(
            "HierarchicalKeyring::on_decrypt: failed to decrypt any encrypted data key (collected errors: [{}])",
            collected_errors.join("; "),
        )))
    }
}

/// UTF-8-encoded key-provider-id sentinel for EDKs produced by the
/// AWS KMS Hierarchical Keyring. Spec: `#onencrypt` "key provider id:
/// MUST be UTF8 Encoded `aws-kms-hierarchy`".
const KEY_PROVIDER_ID_HIERARCHY: &str = "aws-kms-hierarchy";

/// On-wire byte offset of the 16-byte branch-key version in an EDK
/// ciphertext produced by [`branch_key_wrap::wrap`]. Per spec
/// `#ciphertext`, the layout is
/// `salt(16) || iv(12) || version(16) || encrypted_key(var) || tag(16)`,
/// so the version starts at `salt + iv = 16 + 12 = 28`.
const CIPHERTEXT_VERSION_OFFSET: usize = 16 + 12;

/// On-wire byte length of the branch-key version in an EDK ciphertext.
/// Per spec `#ciphertext` the version is the 16-byte representation of
/// the UUID branch-key version.
const CIPHERTEXT_VERSION_LEN: usize = 16;

impl HierarchicalKeyring {
    /// Resolve the branch-key id for this operation: either the
    /// configured static value or the supplier callback's output bound
    /// to the current encryption context.
    async fn resolve_branch_key_id(
        &self,
        encryption_context: &EncryptionContext,
    ) -> Result<String, MaterialsError> {
        match &self.branch_key_source {
            BranchKeySource::Identifier(id) => Ok(id.clone()),
            BranchKeySource::Supplier(supplier) => {
                supplier.get_branch_key_id(encryption_context).await
            }
        }
    }

    /// Run the OnDecrypt steps for a single (already-filtered) EDK:
    /// parse the version, compute the cache identifier, do the cache
    /// and keystore fallthrough to obtain branch-key materials, and
    /// unwrap the EDK ciphertext. Returns the recovered plaintext
    /// data-key bytes on success.
    ///
    /// The caller (`on_decrypt`) is responsible for filtering the EDK
    /// list and for collecting per-EDK errors into the final error.
    async fn try_decrypt_edk(
        &self,
        materials: &DecryptionMaterials,
        edk: &EncryptedDataKey,
        branch_key_id: &str,
        logical_keystore_name: &str,
    ) -> Result<Vec<u8>, MaterialsError> {
        // Parse the 16-byte branch-key version out of the on-wire layout
        // `salt(16) || iv(12) || version(16) || encrypted_key(var) || tag(16)`
        // (per `#ciphertext`). branch_key_wrap::unwrap re-validates the
        // full layout (including the trailing 16-byte tag) before doing
        // the AES-GCM open; here we only need the slice for the version.
        let ciphertext = &edk.ciphertext;
        if ciphertext.len() < CIPHERTEXT_VERSION_OFFSET + CIPHERTEXT_VERSION_LEN {
            return Err(MaterialsError::keyring_failed(format!(
                "HierarchicalKeyring::on_decrypt: EDK ciphertext too short to contain branch-key version: {} bytes (need at least {})",
                ciphertext.len(),
                CIPHERTEXT_VERSION_OFFSET + CIPHERTEXT_VERSION_LEN,
            )));
        }
        let version_bytes: [u8; CIPHERTEXT_VERSION_LEN] = ciphertext
            [CIPHERTEXT_VERSION_OFFSET..CIPHERTEXT_VERSION_OFFSET + CIPHERTEXT_VERSION_LEN]
            .try_into()
            .expect("16-byte slice into [u8; 16]");

        //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#getitem-branch-keystore-ondecrypt
        //# OnDecrypt MUST calculate the following values:
        //
        //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#getitem-branch-keystore-ondecrypt
        //# - Deserialize the UUID string representation of the `version` from the [encrypted data key](../structures.md#encrypted-data-key) [ciphertext](#ciphertext).
        let branch_key_version = uuid_16_bytes_to_str(&version_bytes);

        //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
        //# The hierarchical keyring MUST use the OnDecrypt formula specified in [Appendix A](#decryption-materials)
        //# in order to compute the [cache entry identifier](cryptographic-materials-cache.md#cache-identifier).
        let cache_id = cache_entry_identifier::for_decrypt(
            &self.partition_id_bytes,
            logical_keystore_name,
            branch_key_id,
            &branch_key_version,
        );

        //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
        //# To decrypt each encrypted data key in the filtered set, the hierarchical keyring MUST attempt
        //# to find the corresponding [branch key materials](../structures.md#branch-key-materials)
        //# from the underlying [cryptographic materials cache](../local-cryptographic-materials-cache.md).
        let cached = self.cache.get_cache_entry(&cache_id).await.map_err(|e| {
            MaterialsError::keyring_failed(format!(
                "HierarchicalKeyring: cache get_cache_entry failed: {e}",
            ))
        })?;

        let bkm = match cached {
            //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
            //# If a cache entry is found and the entry's TTL has not expired, the hierarchical keyring MUST use those branch key materials for key unwrapping.
            //
            //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
            //# There MUST be a check (cacheEntryWithinLimits) to make sure that for the cache entry found, who's TTL has NOT expired,
            //# `time.now() - cacheEntryCreationTime <= ttlSeconds` is true and
            //# valid for TTL of the Hierarchical Keyring getting the cache entry.
            Some(entry) if cache_entry_within_limits(&entry, self.ttl_seconds) => {
                unwrap_branch_key_materials(&entry)?.clone()
            }
            //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
            //# If this is NOT true, then we MUST treat the cache entry as expired.
            //
            //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
            //# If a cache entry is not found or the cache entry is expired, the hierarchical keyring
            //# MUST attempt to obtain the branch key materials by calling the backing branch key
            //# store specified in the [retrieve OnDecrypt branch key materials](#getitem-branch-keystore-ondecrypt) section.
            _ => {
                //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#getitem-branch-keystore-ondecrypt
                //# OnDecrypt MUST call the Keystore's [GetBranchKeyVersion](../branch-key-store.md#getbranchkeyversion) operation with the following inputs:
                //
                //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#getitem-branch-keystore-ondecrypt
                //# - The deserialized, UTF8-Decoded `branch-key-id`
                //
                //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#getitem-branch-keystore-ondecrypt
                //# - The deserialized UUID string representation of the `version`
                let bkm = self
                    .keystore
                    .get_branch_key_version(branch_key_id.to_string(), branch_key_version.clone())
                    .await
                    .map_err(|e| {
                        //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
                        //# If the keyring is not able to retrieve `branch key materials` from the backing keystore then OnDecrypt MUST fail.
                        //
                        //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#getitem-branch-keystore-ondecrypt
                        //# Otherwise, OnDecrypt MUST fail.
                        MaterialsError::keyring_failed(format!(
                            "HierarchicalKeyring: get_branch_key_version failed: {e}",
                        ))
                    })?;

                //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#getitem-branch-keystore-ondecrypt
                //# If the Keystore's GetBranchKeyVersion operation succeeds
                //# the keyring MUST put the returned branch key materials in the cache using the
                //# formula defined in [Appendix A](#appendix-a-cache-entry-identifier-formulas).
                let now = SystemTime::now();
                let entry = CacheEntry::new(
                    CachedMaterials::BranchKey(bkm.clone()),
                    now,
                    now + Duration::from_secs(self.ttl_seconds),
                    UsageMetadata::default(),
                );
                self.cache
                    .put_cache_entry(&cache_id, entry)
                    .await
                    .map_err(|e| {
                        MaterialsError::keyring_failed(format!(
                            "HierarchicalKeyring: cache put_cache_entry failed: {e}",
                        ))
                    })?;
                bkm
            }
        };

        //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
        //# If the keyring is able to retrieve `branch key materials` from the backing keystore, OnDecrypt:
        //
        //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
        //# - MUST unwrap the encrypted data key with the branch key materials according to the [branch key unwrapping](#branch-key-unwrapping) section.
        branch_key_wrap::unwrap(&bkm, materials.encryption_context(), ciphertext)
    }
}

/// Generate a random plaintext data key of the algorithm suite's
/// configured encryption-key length using the `aws_lc_rs` CSPRNG.
fn generate_random_data_key(suite: AlgorithmSuite) -> Result<PlaintextDataKey, MaterialsError> {
    let mut bytes = vec![0u8; suite.encryption_key_length()];
    aws_lc_rs::rand::fill(&mut bytes).map_err(|_| {
        MaterialsError::keyring_failed(
            "HierarchicalKeyring: failed to obtain entropy for random plaintext data key",
        )
    })?;
    Ok(PlaintextDataKey::new(bytes))
}

/// `cacheEntryWithinLimits` per spec `#onencrypt` / `#ondecrypt`:
/// `time.now() - cacheEntryCreationTime <= ttlSeconds`.
fn cache_entry_within_limits(entry: &CacheEntry, ttl_seconds: u64) -> bool {
    let now = SystemTime::now();
    let elapsed = now
        .duration_since(entry.creation_time)
        .unwrap_or(Duration::ZERO);
    elapsed.as_secs() <= ttl_seconds
}

/// Extract a borrowed [`BranchKeyMaterials`] reference from a cache
/// entry, failing if the entry holds non-branch-key materials (which
/// would indicate a cache identifier collision).
fn unwrap_branch_key_materials(entry: &CacheEntry) -> Result<&BranchKeyMaterials, MaterialsError> {
    match &entry.materials {
        CachedMaterials::BranchKey(bkm) => Ok(bkm),
        _ => Err(MaterialsError::keyring_failed(
            "HierarchicalKeyring: cache entry has wrong materials kind (expected BranchKey)",
        )),
    }
}

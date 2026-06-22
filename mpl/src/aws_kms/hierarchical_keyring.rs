// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! AWS KMS Hierarchical Keyring — construction / configuration surface +
//! cache wiring.
//!
//! Implements the static-configuration slice of
//! `spec/framework/aws-kms/aws-kms-hierarchical-keyring.md` plus the
//! cache-initialization clauses of the same `#initialization` section.
//! The [`Keyring`] impl's OnEncrypt / OnDecrypt bodies are still stubs;
//! they wire the cache + the existing branch-key wrap/unwrap helpers
//! into the spec's algorithms in the next cycle.

use std::sync::Arc;

use async_trait::async_trait;

use crate::Keyring;
use crate::cmc::{Cmc, LocalCmc, StormTrackingCmc, TimeUnits};
use crate::keystore::Keystore;
use crate::structures::{
    DecryptionMaterials, EncryptedDataKey, EncryptionContext, EncryptionMaterials, MaterialsError,
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

/// Storm-tracking cache configuration. Mirrors the parameter set
/// accepted by [`StormTrackingCmc::new`]; bundled into a struct so the
/// [`CacheType::StormTracking`] variant stays ergonomic.
pub struct StormTrackingParameters {
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

/// Cache configuration for a [`HierarchicalKeyring`].
///
/// The three variants correspond to the spec's `#cache-type` discussion:
/// a keyring-local default cache, an externally-supplied `Shared` cache
/// that may be reused across multiple Cryptographic Material Providers,
/// and a keyring-local Storm-tracking cache for high-fan-out workloads.
#[non_exhaustive]
pub enum CacheType {
    /// A keyring-local [`LocalCmc`] with entry capacity 1000. Per spec
    /// `#initialization`: "If no max cache size is provided, the
    /// cryptographic materials cache MUST be configured to a max cache
    /// size of 1000." Also: "If no `cache` is provided, a `DefaultCache`
    /// MUST be configured with entry capacity of 1000."
    Default,
    /// Use the caller-supplied [`Cmc`] impl directly. Common when one
    /// cache is shared across multiple Hierarchical Keyrings (or other
    /// CMPs); see `#shared-cache-considerations`.
    Shared(Arc<dyn Cmc>),
    /// Build a keyring-local [`StormTrackingCmc`] with the supplied
    /// parameters. The keyring validates that
    /// `grace_period < cache limit TTL` per spec `#initialization`.
    StormTracking(StormTrackingParameters),
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
/// impl's OnEncrypt / OnDecrypt bodies are still stubs; the cache
/// wiring done in this slice unblocks those bodies.
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
    /// `None`, behaves as `Some(CacheType::Default)`.
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
        let cache: Arc<dyn Cmc> = match cache_type.unwrap_or(CacheType::Default) {
            CacheType::Default => {
                //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#initialization
                //# If no max cache size is provided, the cryptographic materials cache MUST be configured to a
                //# max cache size of 1000.
                //
                //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#initialization
                //# If no `cache` is provided, a `DefaultCache` MUST be configured with entry capacity of 1000.
                let local = LocalCmc::new(
                    DEFAULT_CACHE_ENTRY_CAPACITY,
                    DEFAULT_CACHE_PRUNING_TAIL_SIZE,
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

//= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#interface
//= type=implication
//# MUST implement the [AWS Encryption SDK Keyring interface](../keyring-interface.md#interface)
#[async_trait]
impl Keyring for HierarchicalKeyring {
    async fn on_encrypt(
        &self,
        _materials: EncryptionMaterials,
    ) -> Result<EncryptionMaterials, MaterialsError> {
        // OnEncrypt body lands in cycle 2. Returning an explicit error
        // (rather than panicking via unimplemented!()) so callers fail
        // fast and so that production builds cannot panic on this path.
        Err(MaterialsError::keyring_failed(
            "HierarchicalKeyring::on_encrypt is not yet implemented",
        ))
    }

    async fn on_decrypt(
        &self,
        _materials: DecryptionMaterials,
        _encrypted_data_keys: &[EncryptedDataKey],
    ) -> Result<DecryptionMaterials, MaterialsError> {
        // OnDecrypt body lands in cycle 3.
        Err(MaterialsError::keyring_failed(
            "HierarchicalKeyring::on_decrypt is not yet implemented",
        ))
    }
}

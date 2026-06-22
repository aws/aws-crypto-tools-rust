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

/// UTF-8-encoded key-provider-id sentinel for EDKs produced by the
/// AWS KMS Hierarchical Keyring. Spec: `#onencrypt` "key provider id:
/// MUST be UTF8 Encoded `aws-kms-hierarchy`".
const KEY_PROVIDER_ID_HIERARCHY: &str = "aws-kms-hierarchy";

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

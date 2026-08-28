// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! AWS KMS Hierarchical Keyring.
//!
//! Provides the keyring's construction and configuration surface, its
//! OnEncrypt and OnDecrypt operations, and the keystore- / cache-fallthrough
//! they share. The pure-crypto wrap and unwrap operations live in
//! [`super::branch_key_wrap`] and the cache identifier formulas in
//! [`super::cache_entry_identifier`].

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;

use crate::Keyring;
use crate::aws_kms::branch_key_wrap;
use crate::aws_kms::cache_entry_identifier;
use crate::cmc::cache_config::{
    CACHE_PRUNING_TAIL_SIZE, CacheType, DEFAULT_CACHE_ENTRY_CAPACITY, DefaultCache,
};
use crate::cmc::{
    CacheEntry, CachedMaterials, Cmc, LocalCmc, StormTrackingCmc, TimeUnits, UsageMetadata,
};
use crate::keystore::Keystore;
use crate::structures::{
    AlgorithmSuite, BranchKeyMaterials, DecryptionMaterials, EncryptedDataKey, EncryptionContext,
    EncryptionMaterials, MaterialsError, PlaintextDataKey,
};

/// Input for [`BranchKeySupplier::get_branch_key_id`]. Mirrors the Smithy
/// `GetBranchKeyIdInput`, whose only member is the encryption context.
///
/// A struct rather than a bare `EncryptionContext` parameter so that a member
/// added to the model later does not break every implementor of the trait.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct GetBranchKeyIdInput {
    encryption_context: EncryptionContext,
}

impl GetBranchKeyIdInput {
    /// Construct the input from the encryption context of the operation being
    /// performed.
    #[must_use]
    pub const fn new(encryption_context: EncryptionContext) -> Self {
        Self { encryption_context }
    }

    /// The encryption context used with this encryption or decryption.
    #[must_use]
    pub const fn encryption_context(&self) -> &EncryptionContext {
        &self.encryption_context
    }
}

/// Output of [`BranchKeySupplier::get_branch_key_id`]. Mirrors the Smithy
/// `GetBranchKeyIdOutput`, whose only member is the branch key id.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct GetBranchKeyIdOutput {
    branch_key_id: String,
}

impl GetBranchKeyIdOutput {
    /// Construct the output from the chosen branch key id.
    #[must_use]
    pub const fn new(branch_key_id: String) -> Self {
        Self { branch_key_id }
    }

    /// The identifier of the branch key that should wrap or unwrap the data
    /// key for this operation.
    #[must_use]
    pub fn branch_key_id(&self) -> &str {
        &self.branch_key_id
    }

    /// Consume the output, yielding the branch key id.
    #[must_use]
    pub fn into_branch_key_id(self) -> String {
        self.branch_key_id
    }
}

/// User-supplied callback that maps an encryption context to a branch key id.
///
/// Implementations are typically used by callers running multi-tenant workloads
/// who want to pick the branch key based on encryption-context metadata.
///
/// The decision is made from the encryption context alone, so this method is
/// synchronous. An implementation that must perform IO to reach its answer is
/// responsible for bridging to it itself (for example
/// `tokio::task::block_in_place`).
pub trait BranchKeySupplier: Send + Sync {
    /// Return the branch key id to use for a given encryption context.
    //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-supplier
    //= type=implication
    //# This operation MUST take in an encryption context as input,
    //# and return a branch key id (string) as output.
    fn get_branch_key_id(
        &self,
        input: GetBranchKeyIdInput,
    ) -> Result<GetBranchKeyIdOutput, MaterialsError>;
}

/// AWS KMS Hierarchical Keyring.
///
/// See [`HierarchicalKeyring::new`] for construction. The [`Keyring`]
/// impl wires the configured cache and keystore into the OnEncrypt /
/// OnDecrypt algorithms.
pub struct HierarchicalKeyring {
    keystore: Arc<dyn Keystore>,

    ttl_seconds: u64,

    /// The single branch key id this keyring wraps and unwraps with, when
    /// configured with one. Exactly one of this and `branch_key_id_supplier`
    /// is `Some`, checked in [`HierarchicalKeyring::new`].
    branch_key_id: Option<String>,

    /// The supplier that chooses a branch key id per operation, when
    /// configured with one instead of a static `branch_key_id`.
    branch_key_id_supplier: Option<Arc<dyn BranchKeySupplier>>,

    //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#partition-id
    //= type=implication
    //# The Partition ID MUST NOT be changed after initialization.
    partition_id_bytes: Vec<u8>,

    /// The keystore's logical name, which the cache identifier formulas bind.
    /// Not a construction parameter: it is read from the keystore's own
    /// `get_key_store_info` once in [`HierarchicalKeyring::new`].
    logical_keystore_name: String,

    /// Cryptographic-materials cache for branch-key materials. Either a
    /// keyring-local `LocalCmc`/`StormTrackingCmc` built at construction
    /// time, or a `Shared` cache supplied by the caller.
    cache: Arc<dyn Cmc>,
}

impl HierarchicalKeyring {
    /// Construct a new hierarchical keyring.
    ///
    /// `ttl_seconds` must be greater than zero.
    ///
    /// If `partition_id` is `None`, a fresh v4 UUID is generated and stored
    /// as the 16-byte partition id.
    ///
    /// `cache_type` selects the cache backing — see [`CacheType`]. When
    /// `None`, behaves as `Some(CacheType::Default(DefaultCache::default()))`.
    pub fn new(
        keystore: Arc<dyn Keystore>,
        ttl_seconds: u64,
        branch_key_id: Option<String>,
        branch_key_id_supplier: Option<Arc<dyn BranchKeySupplier>>,
        cache_type: Option<CacheType>,
        partition_id: Option<String>,
    ) -> Result<Self, MaterialsError> {
        //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#initialization
        //# - MUST provide a [cache limit TTL](#cache-limit-ttl)
        //
        //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#cache-limit-ttl
        //# This value MUST be greater than zero.
        if ttl_seconds == 0 {
            return Err(MaterialsError::new(
                "HierarchicalKeyring TTL (ttl_seconds) must be greater than zero",
            ));
        }

        if branch_key_id.is_some() && branch_key_id_supplier.is_some() {
            return Err(MaterialsError::new(
                "Cannot initialize keyring with both a branch_key_id and a branch_key_id_supplier",
            ));
        }
        //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#initialization
        //# - MUST provide either a Branch Key Identifier or a [Branch Key Supplier](#branch-key-supplier)
        if branch_key_id.is_none() && branch_key_id_supplier.is_none() {
            return Err(MaterialsError::new(
                "Must initialize keyring with either a branch_key_id or a branch_key_id_supplier",
            ));
        }

        // An absent `cache_type` is where the 1000-entry default lives: the
        // model requires `DefaultCache.entryCapacity`, and documents this
        // number on the keyring's own `cache` member.
        //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#initialization
        //# - MAY provide a [Cache Type](#cache-type)
        //
        //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#initialization
        //# On initialization the Hierarchical Keyring MUST initialize a [cryptographic-materials-cache](../local-cryptographic-materials-cache.md) with the configured cache limit TTL and the max cache size.
        //
        //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#initialization
        //# If no max cache size is provided, the cryptographic materials cache MUST be configured to a
        //# max cache size of 1000.
        //
        //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#initialization
        //# If no `cache` is provided, a `DefaultCache` MUST be configured with entry capacity of 1000.
        let cache: Arc<dyn Cmc> = match cache_type.unwrap_or(CacheType::Default(DefaultCache::new(
            DEFAULT_CACHE_ENTRY_CAPACITY,
        ))) {
            CacheType::Default(default_cache) => {
                //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#initialization
                //# If the Hierarchical Keyring does NOT get a `Shared` cache on initialization,
                //# it MUST initialize a [cryptographic-materials-cache](../local-cryptographic-materials-cache.md)
                //# with the user provided cache limit TTL and the entry capacity.
                let local = LocalCmc::new(default_cache.entry_capacity, CACHE_PRUNING_TAIL_SIZE)
                    .map_err(|e| {
                        MaterialsError::new(format!(
                            "HierarchicalKeyring: failed to initialize default LocalCmc: {e}",
                        ))
                    })?;
                Arc::new(local)
            }
            CacheType::Shared(cache) => cache,
            CacheType::StormTracking(params) => {
                let grace_in_seconds = match params.time_units.unwrap_or_default() {
                    TimeUnits::Seconds => params.grace_period,
                    TimeUnits::Milliseconds => params.grace_period / 1000,
                };
                //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#initialization
                //# If the cache to initialize is a [Storm Tracking Cryptographic Materials Cache](../storm-tracking-cryptographic-materials-cache.md#overview)
                //# then the [Grace Period](../storm-tracking-cryptographic-materials-cache.md#grace-period) MUST be less than the [cache limit TTL](#cache-limit-ttl).
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

        //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#initialization
        //# - MAY provide a [Partition ID](#partition-id)
        //
        //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#partition-id-1
        //# It can either be a String provided by the user, which MUST be interpreted as the bytes of
        //# UTF-8 Encoding of the String, or a v4 UUID, which SHOULD be interpreted as the 16 byte representation of the UUID.
        //
        //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#partition-id-1
        //# The constructor of the Hierarchical Keyring MUST record these bytes at construction time.
        let partition_id_bytes = match partition_id {
            //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#partition-id
            //# If provided, it MUST be interpreted as UTF8 bytes.
            Some(s) => s.into_bytes(),
            //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#partition-id
            //# If the PartitionId is NOT provided by the user, it MUST be set to the 16 byte representation of a v4 UUID.
            None => generate_partition_id()?,
        };

        // Resolve the keystore's logical name once, here, so the OnEncrypt and
        // OnDecrypt paths can build cache identifiers without re-reading it.
        //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#initialization
        //# - MUST provide a [Keystore](../branch-key-store.md)
        let logical_keystore_name = keystore
            .get_key_store_info()
            .map_err(|e| {
                MaterialsError::new(format!(
                    "HierarchicalKeyring: get_key_store_info failed: {e}",
                ))
            })?
            .logical_keystore_name;

        Ok(Self {
            keystore,
            ttl_seconds,
            branch_key_id,
            branch_key_id_supplier,
            partition_id_bytes,
            logical_keystore_name,
            cache,
        })
    }

    /// The configured TTL for cached branch-key materials, in seconds.
    pub fn ttl_seconds(&self) -> u64 {
        self.ttl_seconds
    }

    /// The configured static branch key id, if this keyring was built with one
    /// rather than with a [`BranchKeySupplier`].
    pub fn branch_key_id(&self) -> Option<&str> {
        self.branch_key_id.as_deref()
    }

    /// The configured branch key id supplier, if this keyring was built with
    /// one rather than with a static branch key id.
    pub fn branch_key_id_supplier(&self) -> Option<&Arc<dyn BranchKeySupplier>> {
        self.branch_key_id_supplier.as_ref()
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

/// Generate a default partition id: the 16-byte representation of a fresh v4
/// UUID, drawing the randomness from the `aws-mpl-primitives` CSPRNG rather
/// than the `uuid` crate's own entropy source, so all randomness in this crate
/// comes from one audited primitive. `Builder::from_random_bytes` sets the
/// version and variant bits.
fn generate_partition_id() -> Result<Vec<u8>, MaterialsError> {
    let mut bytes = [0u8; 16];
    aws_mpl_primitives::generate_random_bytes(&mut bytes).map_err(|_| {
        MaterialsError::new(
            "HierarchicalKeyring: failed to obtain entropy for partition-id v4 UUID",
        )
    })?;
    Ok(uuid::Builder::from_random_bytes(bytes)
        .into_uuid()
        .as_bytes()
        .to_vec())
}

/// Convert the 16-byte representation of a UUID back to its canonical
/// 36-character hyphenated string form (`8-4-4-4-12`). The output is a
/// well-formed UUIDv4 string suitable for passing to
/// [`BranchKeyMaterials::new`] and the wrap/unwrap machinery when the
/// input bytes were produced by a v4 UUID generator (variant + version
/// bits already set).
fn uuid_16_bytes_to_str(bytes: &[u8; CIPHERTEXT_VERSION_LEN]) -> String {
    uuid::Uuid::from_bytes(*bytes).hyphenated().to_string()
}

#[async_trait]
//= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#interface
//= type=implication
//# MUST implement the [AWS Encryption SDK Keyring interface](../keyring-interface.md#interface)
impl Keyring for HierarchicalKeyring {
    async fn on_encrypt(
        &self,
        materials: EncryptionMaterials,
    ) -> Result<EncryptionMaterials, MaterialsError> {
        //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
        //# OnEncrypt MUST take [encryption materials](../structures.md#encryption-materials) as input.
        //
        //= spec/framework/keyring-interface.md#onencrypt
        //# This interface MUST take [encryption materials](structures.md#encryption-materials) as input.
        let branch_key_id = self.resolve_branch_key_id(materials.encryption_context())?;

        let plaintext_dk = match materials.plaintext_data_key() {
            //= spec/framework/keyring-interface.md#generate-data-key
            //# If the encryption materials contain a plaintext data key, OnEncrypt MUST NOT generate a data key.
            Some(pdk) => pdk.clone(),
            //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
            //# If the input [encryption materials](../structures.md#encryption-materials) do not contain a plaintext data key,
            //# OnEncrypt MUST generate a random plaintext data key, according to the key length defined in the [algorithm suite](../algorithm-suites.md#encryption-key-length).
            //
            //= spec/framework/keyring-interface.md#generate-data-key
            //# If the [encryption materials](structures.md#encryption-materials) do not contain a plaintext data key,
            //# OnEncrypt MUST generate a data key.
            None => generate_random_data_key(materials.algorithm_suite())?,
        };

        //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
        //# The hierarchical keyring MUST use the formulas specified in [Appendix A](#appendix-a-cache-entry-identifier-formulas)
        //# to compute the [cache entry identifier](../cryptographic-materials-cache.md#cache-identifier).
        let cache_id = cache_entry_identifier::build_cache_identifier(
            SCOPE_ID_ENCRYPT,
            &self.partition_id_bytes,
            &self.logical_keystore_name,
            &branch_key_id,
            None,
        );

        //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
        //# The hierarchical keyring MUST attempt to find [branch key materials](../structures.md#branch-key-materials)
        //# from the underlying [cryptographic materials cache](../local-cryptographic-materials-cache.md).
        let cached = self.cache.get_cache_entry(&cache_id).await.map_err(|e| {
            MaterialsError::keyring_failed(format!(
                "HierarchicalKeyring: cache get_cache_entry failed: {e}",
            ))
        })?;

        let ciphertext = match cached {
            //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
            //# If a cache entry is found and the entry's TTL has not expired, the hierarchical keyring MUST use those branch key materials for key wrapping.
            Some(entry) if cache_entry_within_limits(&entry, self.ttl_seconds) => {
                let bkm = as_branch_key_materials(&entry)?;
                //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
                //# - MUST wrap a data key with the branch key materials according to the [branch key wrapping](#branch-key-wrapping) section.
                //
                //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
                //# If the keyring is unable to wrap a plaintext data key, OnEncrypt MUST fail
                //# and MUST NOT modify the [decryption materials](structures.md#decryption-materials).
                //
                //= spec/framework/keyring-interface.md#encrypt-data-key
                //# If the [encryption materials](structures.md#encryption-materials) contain a plaintext data key,
                //# OnEncrypt MUST encrypt a data key.
                //
                //= spec/framework/keyring-interface.md#encrypt-data-key
                //# The [encrypted data keys](structures.md#encrypted-data-key) produced by this keyring MUST
                //# have [ciphertexts](structures.md#ciphertext) that can be decrypted to the plaintext data key in the
                //# [encryption materials](structures.md#encryption-materials).
                branch_key_wrap::wrap(bkm, materials.encryption_context(), plaintext_dk.as_bytes())?
            }
            //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
            //# If this is NOT true, then we MUST treat the cache entry as expired.
            //
            //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
            //# If a cache entry is not found or the cache entry is expired, the hierarchical keyring MUST attempt to obtain the branch key materials
            //# by querying the backing branch keystore specified in the [retrieve OnEncrypt branch key materials](#query-branch-keystore-onencrypt) section.
            _ => {
                //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#query-branch-keystore-onencrypt
                //# OnEncrypt MUST call the Keystore's [GetActiveBranchKey](../branch-key-store.md#getactivebranchkey) operation with the following inputs:
                let bkm = self
                    .keystore
                    .get_active_branch_key(branch_key_id.clone())
                    .await
                    //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#query-branch-keystore-onencrypt
                    //# Otherwise, OnEncrypt MUST fail.
                    //
                    //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
                    //# If the keyring is not able to retrieve [branch key materials](../structures.md#branch-key-materials)
                    //# through the underlying cryptographic materials cache or
                    //# it no longer has access to them through the backing keystore, OnEncrypt MUST fail.
                    .map_err(|e| {
                        MaterialsError::keyring_failed(format!(
                            "HierarchicalKeyring: get_active_branch_key failed: {e}",
                        ))
                    })?;

                let now = SystemTime::now();
                //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#cache-limit-ttl
                //# The client MUST set a time-to-live (TTL) for [branch key materials](../structures.md#branch-key-materials) in the underlying cache.
                let entry = CacheEntry::new(
                    CachedMaterials::BranchKey(bkm.clone()),
                    now,
                    now + Duration::from_secs(self.ttl_seconds),
                    UsageMetadata::default(),
                );
                //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#query-branch-keystore-onencrypt
                //# If the Keystore's GetActiveBranchKey operation succeeds
                //# the keyring MUST put the returned branch key materials in the cache using the
                //# formula defined in [Appendix A](#appendix-a-cache-entry-identifier-formulas).
                self.cache
                    .put_cache_entry(&cache_id, entry)
                    .await
                    .map_err(|e| {
                        MaterialsError::keyring_failed(format!(
                            "HierarchicalKeyring: cache put_cache_entry failed: {e}",
                        ))
                    })?;

                branch_key_wrap::wrap(
                    &bkm,
                    materials.encryption_context(),
                    plaintext_dk.as_bytes(),
                )?
            }
        };

        let edk = EncryptedDataKey::new(
            //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
            //# - [key provider id](../structures.md#key-provider-id): MUST be UTF8 Encoded "aws-kms-hierarchy"
            //
            //= spec/framework/keyring-interface.md#key-provider-id
            //# The key provider ID MUST be a binary value
            //# and SHOULD be equal to a UTF-8 encoding of the key namespace.
            //
            //= spec/framework/keyring-interface.md#key-provider-id
            //# This value MUST NOT be or start with "aws-kms"
            //# unless this encrypted data key was produced by one of the [AWS KMS Keyrings](./aws-kms/).
            KEY_PROVIDER_ID_HIERARCHY.to_string(),
            //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
            //# - [key provider info](../structures.md#key-provider-information): MUST be the UTF8 Encoded AWS DDB response `branch-key-id`
            //
            //= spec/framework/keyring-interface.md#key-provider-info
            //# The key provider info MUST be a binary value
            //# and SHOULD be equal to a UTF-8 encoding of the key name.
            branch_key_id.into_bytes(),
            //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
            //# - [ciphertext](../structures.md#ciphertext): MUST be serialized as the [hierarchical keyring ciphertext](#ciphertext)
            ciphertext,
        );

        // Reaching this point means wrap succeeded above (any wrap failure
        // returned via `?`); only at this point does the function build a
        // new EncryptionMaterials value. The input `materials` parameter
        // is owned but never mutated; we construct a fresh value so a
        // caller's failure handling can re-use the original.
        let mut new_edks: Vec<EncryptedDataKey> = materials.encrypted_data_keys().to_vec();
        //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
        //# Otherwise, OnEncrypt MUST append a new [encrypted data key](../structures.md#encrypted-data-key)
        //# to the encrypted data key list in the [encryption materials](../structures.md#encryption-materials), constructed as follows:
        //
        //= spec/framework/keyring-interface.md#encrypt-data-key
        //# Encrypt Data Key MUST modify the following fields in the [encryption materials](structures.md#encryption-materials):
        new_edks.push(edk);
        //= spec/framework/keyring-interface.md#onencrypt
        //# If this keyring attempted any of the above behaviors, and successfully completed those behaviors,
        //# it MUST output the modified [encryption materials](structures.md#encryption-materials).
        //
        //= spec/framework/keyring-interface.md#onencrypt
        //# It MUST modify it with at least one of the following behaviors:
        //
        //= spec/framework/keyring-interface.md#generate-data-key
        //# Generate Data Key MUST modify the following fields in the [encryption materials](structures.md#encryption-materials):
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
        materials: DecryptionMaterials,
        encrypted_data_keys: &[EncryptedDataKey],
    ) -> Result<DecryptionMaterials, MaterialsError> {
        //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
        //# OnDecrypt MUST take [decryption materials](../structures.md#decryption-materials) and a list of [encrypted data keys](../structures.md#encrypted-data-keys) as input.
        //
        //= spec/framework/keyring-interface.md#ondecrypt
        //# This interface MUST take [decryption materials](structures.md#decryption-materials) and
        //# a list of [encrypted data keys](structures.md#encrypted-data-key) as input.
        //
        //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
        //# If the decryption materials already contain a `PlainTextDataKey`, OnDecrypt MUST fail.
        //
        //= spec/framework/keyring-interface.md#ondecrypt
        //# If the decryption materials already contain a plaintext data key,
        //# the keyring MUST fail
        //# and MUST NOT modify the [decryption materials](structures.md#decryption-materials).
        //
        //= spec/framework/keyring-interface.md#decrypt-data-key
        //# If the encryption materials do contain a plaintext data key, OnDecrypt MUST NOT decrypt a data key.
        if materials.plaintext_data_key().is_some() {
            return Err(MaterialsError::plaintext_data_key_already_present(
                "HierarchicalKeyring::on_decrypt: decryption materials already contain a plaintext data key",
            ));
        }

        let branch_key_id = self.resolve_branch_key_id(materials.encryption_context())?;

        let mut collected_errors: Vec<String> = Vec::new();
        //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
        //# The set of encrypted data keys MUST first be filtered to match this keyring’s configuration.
        //
        //= spec/framework/keyring-interface.md#decrypt-data-key
        //# If the [decryption materials](structures.md#decryption-materials) do not include a plaintext data key,
        //# OnDecrypt MUST decrypt a data key.
        for edk in encrypted_data_keys {
            //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
            //# - Its provider ID MUST match the UTF8 Encoded value of “aws-kms-hierarchy”.
            if edk.key_provider_id != KEY_PROVIDER_ID_HIERARCHY {
                continue;
            }

            //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
            //# - Deserialize the key provider info, if deserialization fails the next EDK in the set MUST be attempted.
            let Ok(edk_branch_key_id) = std::str::from_utf8(&edk.key_provider_info) else {
                continue;
            };

            //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
            //# - The deserialized key provider info MUST be UTF8 Decoded and MUST match this keyring's configured `Branch Key Identifier`.
            if edk_branch_key_id != branch_key_id {
                continue;
            }

            //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
            //# For each encrypted data key in the filtered set, one at a time, OnDecrypt MUST attempt to decrypt the encrypted data key.
            match self.try_decrypt_edk(&materials, edk, &branch_key_id).await {
                Ok(plaintext_dk_bytes) => {
                    //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
                    //# If a decryption succeeds, this keyring MUST
                    //# add the resulting plaintext data key to the decryption materials and return the modified materials.
                    //
                    //= spec/framework/keyring-interface.md#ondecrypt
                    //# If this keyring attempted the above behavior, and succeeded, it MUST output the modified [decryption materials](structures.md#decryption-materials).
                    //
                    //= spec/framework/keyring-interface.md#ondecrypt
                    //# It MUST modify it with the following behavior:
                    //
                    //= spec/framework/keyring-interface.md#decrypt-data-key
                    //# The decrypt data key MUST modify the following fields in the [decryption materials](structures.md#decryption-materials):
                    //
                    //= spec/framework/keyring-interface.md#decrypt-data-key
                    //# If the keyring is able to successfully get at least one plaintext data key from any [encrypted data key](structures.md#encrypted-data-key)
                    //# and the [decryption materials](structures.md#decryption-materials) still do not include a plaintext data key,
                    //# it SHOULD set one resulting plaintext data key on the [decryption materials](structures.md#decryption-materials).
                    return DecryptionMaterials::new(
                        materials.algorithm_suite_id(),
                        materials.encryption_context().clone(),
                        materials.required_encryption_context_keys().clone(),
                        Some(PlaintextDataKey::new(plaintext_dk_bytes)),
                        materials.verification_key().cloned(),
                        materials.symmetric_signing_key().cloned(),
                    );
                }
                //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
                //# If this attempt results in an error, then these errors MUST be collected.
                Err(e) => collected_errors.push(e.to_string()),
            }
        }

        // The early-return above on `Ok` is the only path that produces a
        // mutated DecryptionMaterials; reaching this line means no EDK was
        // successfully decrypted, so the input `materials` parameter (owned
        // but never mutated) is dropped without modification.
        //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
        //# If OnDecrypt fails to successfully decrypt any [encrypted data key](../structures.md#encrypted-data-key),
        //# then it MUST yield an error that includes all the collected errors
        //# and MUST NOT modify the [decryption materials](structures.md#decryption-materials).
        //
        //= spec/framework/keyring-interface.md#ondecrypt
        //# If the keyring did not attempt the above behavior,
        //# the keyring MUST fail
        //# and MUST NOT modify the [decryption materials](structures.md#decryption-materials).
        //
        //= spec/framework/keyring-interface.md#decrypt-data-key
        //# If the keyring is unable to get any plaintext data key using the input [encrypted data keys](structures.md#encrypted-data-key),
        //# the keyring MUST NOT not update the [decryption materials](structures.md#decryption-materials) and MUST return failure.
        Err(MaterialsError::keyring_failed(format!(
            "HierarchicalKeyring::on_decrypt: failed to decrypt any encrypted data key (collected errors: [{}])",
            collected_errors.join("; "),
        )))
    }
}

/// UTF-8-encoded key-provider-id sentinel for EDKs produced by the
/// AWS KMS Hierarchical Keyring.
const KEY_PROVIDER_ID_HIERARCHY: &str = "aws-kms-hierarchy";

/// On-wire byte offset of the 16-byte branch-key version in an EDK
/// ciphertext produced by [`branch_key_wrap::wrap`].
// The layout is `salt(16) || iv(12) || version(16) || encrypted_key(var) ||
// tag(16)`, so the version starts at `salt + iv = 16 + 12 = 28`.
const CIPHERTEXT_VERSION_OFFSET: usize = 16 + 12;

/// On-wire byte length of the branch-key version in an EDK ciphertext: the
/// 16-byte representation of the UUID branch-key version.
const CIPHERTEXT_VERSION_LEN: usize = 16;

/// Cache-identifier scope byte for OnEncrypt, passed to
/// `cache_entry_identifier::build_cache_identifier`.
///
/// Hidden from the public API surface; intended for tests that recompute the
/// identifier independently of the keyring.
#[doc(hidden)]
//= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#encryption-materials
//# - MUST be the Scope ID for Encrypt (0x01)
pub const SCOPE_ID_ENCRYPT: u8 = 0x01;

/// Cache-identifier scope byte for OnDecrypt, passed to
/// `cache_entry_identifier::build_cache_identifier`.
///
/// Hidden from the public API surface; intended for tests that recompute the
/// identifier independently of the keyring.
#[doc(hidden)]
//= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#decryption-materials
//# - MUST be the Scope ID for Decrypt (0x02)
pub const SCOPE_ID_DECRYPT: u8 = 0x02;

impl HierarchicalKeyring {
    /// Resolve the branch-key id for this operation: either the
    /// configured static value or the supplier callback's output bound
    /// to the current encryption context.
    fn resolve_branch_key_id(
        &self,
        encryption_context: &EncryptionContext,
    ) -> Result<String, MaterialsError> {
        if let Some(id) = &self.branch_key_id {
            return Ok(id.clone());
        }

        // `new` rejects the configuration where neither is set, so reaching
        // here means the supplier is present.
        let Some(supplier) = &self.branch_key_id_supplier else {
            return Err(MaterialsError::new(
                "HierarchicalKeyring: neither a branch_key_id nor a branch_key_id_supplier is configured",
            ));
        };

        // The input owns its encryption context, so the clone happens only on
        // the supplier path — a static branch key id never pays for it.
        let input = GetBranchKeyIdInput::new(encryption_context.clone());
        Ok(supplier.get_branch_key_id(input)?.into_branch_key_id())
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
    ) -> Result<Vec<u8>, MaterialsError> {
        // Parse the 16-byte branch-key version out of the on-wire layout
        // `salt(16) || iv(12) || version(16) || encrypted_key(var) || tag(16)`.
        // branch_key_wrap::unwrap re-validates the full layout (including the
        // trailing 16-byte tag) before doing the AES-GCM open; here we only
        // need the slice for the version.
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

        let branch_key_version = uuid_16_bytes_to_str(&version_bytes);

        //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#getitem-branch-keystore-ondecrypt
        //# OnDecrypt MUST calculate the following values:
        //
        //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
        //# The hierarchical keyring MUST use the OnDecrypt formula specified in [Appendix A](#decryption-materials)
        //# in order to compute the [cache entry identifier](cryptographic-materials-cache.md#cache-identifier).
        let cache_id = cache_entry_identifier::build_cache_identifier(
            SCOPE_ID_DECRYPT,
            &self.partition_id_bytes,
            &self.logical_keystore_name,
            branch_key_id,
            Some(&branch_key_version),
        );

        //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
        //# To decrypt each encrypted data key in the filtered set, the hierarchical keyring MUST attempt
        //# to find the corresponding [branch key materials](../structures.md#branch-key-materials)
        //# from the underlying [cryptographic materials cache](../local-cryptographic-materials-cache.md).
        let cached = self.cache.get_cache_entry(&cache_id).await.map_err(|e| {
            MaterialsError::keyring_failed(format!(
                "HierarchicalKeyring: cache get_cache_entry failed: {e}",
            ))
        })?;

        let bkm = match cached {
            //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
            //# If a cache entry is found and the entry's TTL has not expired, the hierarchical keyring MUST use those branch key materials for key unwrapping.
            Some(entry) if cache_entry_within_limits(&entry, self.ttl_seconds) => {
                as_branch_key_materials(&entry)?.clone()
            }
            //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
            //# If this is NOT true, then we MUST treat the cache entry as expired.
            //
            //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
            //# If a cache entry is not found or the cache entry is expired, the hierarchical keyring
            //# MUST attempt to obtain the branch key materials by calling the backing branch key
            //# store specified in the [retrieve OnDecrypt branch key materials](#getitem-branch-keystore-ondecrypt) section.
            _ => {
                //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#getitem-branch-keystore-ondecrypt
                //# OnDecrypt MUST call the Keystore's [GetBranchKeyVersion](../branch-key-store.md#getbranchkeyversion) operation with the following inputs:
                let bkm = self
                    .keystore
                    .get_branch_key_version(branch_key_id.to_string(), branch_key_version.clone())
                    .await
                    //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#getitem-branch-keystore-ondecrypt
                    //# Otherwise, OnDecrypt MUST fail.
                    //
                    //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
                    //# If the keyring is not able to retrieve `branch key materials` from the backing keystore then OnDecrypt MUST fail.
                    .map_err(|e| {
                        MaterialsError::keyring_failed(format!(
                            "HierarchicalKeyring: get_branch_key_version failed: {e}",
                        ))
                    })?;

                let now = SystemTime::now();
                let entry = CacheEntry::new(
                    CachedMaterials::BranchKey(bkm.clone()),
                    now,
                    now + Duration::from_secs(self.ttl_seconds),
                    UsageMetadata::default(),
                );
                //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#getitem-branch-keystore-ondecrypt
                //# If the Keystore's GetBranchKeyVersion operation succeeds
                //# the keyring MUST put the returned branch key materials in the cache using the
                //# formula defined in [Appendix A](#appendix-a-cache-entry-identifier-formulas).
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

        //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
        //# - MUST unwrap the encrypted data key with the branch key materials according to the [branch key unwrapping](#branch-key-unwrapping) section.
        branch_key_wrap::unwrap(&bkm, materials.encryption_context(), ciphertext)
    }
}

/// Generate a random plaintext data key of the algorithm suite's
/// configured encryption-key length using the `aws-mpl-primitives` CSPRNG.
fn generate_random_data_key(suite: AlgorithmSuite) -> Result<PlaintextDataKey, MaterialsError> {
    //= spec/framework/keyring-interface.md#generate-data-key
    //# The length of the output plaintext data key MUST be equal to the KDF input length of the [algorithm suite](algorithm-suites.md)
    //# specified in the [encryption materials](structures.md#encryption-materials).
    let mut bytes = vec![0u8; suite.encryption_key_length()];
    //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
    //# The process used to generate this random plaintext data key MUST use a secure source of randomness.
    //
    //= spec/framework/keyring-interface.md#generate-data-key
    //# The value of the plaintext data key MUST consist of cryptographically secure (pseudo-)random bits.
    aws_mpl_primitives::generate_random_bytes(&mut bytes).map_err(|_| {
        MaterialsError::keyring_failed(
            "HierarchicalKeyring: failed to obtain entropy for random plaintext data key",
        )
    })?;
    Ok(PlaintextDataKey::new(bytes))
}

/// Whether a cache entry is still within its TTL:
/// `time.now() - cacheEntryCreationTime <= ttlSeconds`.
fn cache_entry_within_limits(entry: &CacheEntry, ttl_seconds: u64) -> bool {
    //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#cache-limit-ttl
    //# The maximum amount of time in seconds that an entry within the cache may be used before it MUST be evicted.
    //
    //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
    //# There MUST be a check (cacheEntryWithinLimits) to make sure that for the cache entry found, who's TTL has NOT expired,
    //# `time.now() - cacheEntryCreationTime <= ttlSeconds` is true and
    //# valid for TTL of the Hierarchical Keyring getting the cache entry.
    //
    //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
    //# There MUST be a check (cacheEntryWithinLimits) to make sure that for the cache entry found, who's TTL has NOT expired,
    //# `time.now() - cacheEntryCreationTime <= ttlSeconds` is true and
    //# valid for TTL of the Hierarchical Keyring getting the cache entry.
    let now = SystemTime::now();
    let elapsed = now
        .duration_since(entry.creation_time)
        .unwrap_or(Duration::ZERO);
    elapsed.as_secs() <= ttl_seconds
}

/// Extract a borrowed [`BranchKeyMaterials`] reference from a cache
/// entry, failing if the entry holds non-branch-key materials (which
/// would indicate a cache identifier collision).
fn as_branch_key_materials(entry: &CacheEntry) -> Result<&BranchKeyMaterials, MaterialsError> {
    match &entry.materials {
        CachedMaterials::BranchKey(bkm) => Ok(bkm),
        _ => Err(MaterialsError::keyring_failed(
            "HierarchicalKeyring: cache entry has wrong materials kind (expected BranchKey)",
        )),
    }
}

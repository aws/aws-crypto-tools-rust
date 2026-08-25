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
        if branch_key_id.is_none() && branch_key_id_supplier.is_none() {
            return Err(MaterialsError::new(
                "Must initialize keyring with either a branch_key_id or a branch_key_id_supplier",
            ));
        }

        // An absent `cache_type` is where the 1000-entry default lives: the
        // model requires `DefaultCache.entryCapacity`, and documents this
        // number on the keyring's own `cache` member.
        let cache: Arc<dyn Cmc> = match cache_type.unwrap_or(CacheType::Default(DefaultCache::new(
            DEFAULT_CACHE_ENTRY_CAPACITY,
        ))) {
            CacheType::Default(default_cache) => {
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

        let partition_id_bytes = match partition_id {
            Some(s) => s.into_bytes(),
            None => generate_partition_id()?,
        };

        // Resolve the keystore's logical name once, here, so the OnEncrypt and
        // OnDecrypt paths can build cache identifiers without re-reading it.
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
impl Keyring for HierarchicalKeyring {
    async fn on_encrypt(
        &self,
        materials: EncryptionMaterials,
    ) -> Result<EncryptionMaterials, MaterialsError> {
        let branch_key_id = self.resolve_branch_key_id(materials.encryption_context())?;

        let plaintext_dk = match materials.plaintext_data_key() {
            Some(pdk) => pdk.clone(),
            None => generate_random_data_key(materials.algorithm_suite())?,
        };

        let cache_id = cache_entry_identifier::build_cache_identifier(
            SCOPE_ID_ENCRYPT,
            &self.partition_id_bytes,
            &self.logical_keystore_name,
            &branch_key_id,
            None,
        );

        let cached = self.cache.get_cache_entry(&cache_id).await.map_err(|e| {
            MaterialsError::keyring_failed_with_cause(
                format!("HierarchicalKeyring: cache get_cache_entry failed: {e}"),
                e,
            )
        })?;

        let ciphertext = match cached {
            Some(entry) if cache_entry_within_limits(&entry, self.ttl_seconds) => {
                let bkm = as_branch_key_materials(&entry)?;
                branch_key_wrap::wrap(bkm, materials.encryption_context(), plaintext_dk.as_bytes())?
            }
            _ => {
                let bkm = self
                    .keystore
                    .get_active_branch_key(branch_key_id.clone())
                    .await
                    .map_err(|e| {
                        MaterialsError::keyring_failed_with_cause(
                            format!("HierarchicalKeyring: get_active_branch_key failed: {e}"),
                            e,
                        )
                    })?;

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
                        MaterialsError::keyring_failed_with_cause(
                            format!("HierarchicalKeyring: cache put_cache_entry failed: {e}"),
                            e,
                        )
                    })?;

                branch_key_wrap::wrap(
                    &bkm,
                    materials.encryption_context(),
                    plaintext_dk.as_bytes(),
                )?
            }
        };

        let edk = EncryptedDataKey::new(
            KEY_PROVIDER_ID_HIERARCHY.to_string(),
            branch_key_id.into_bytes(),
            ciphertext,
        );

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
        materials: DecryptionMaterials,
        encrypted_data_keys: &[EncryptedDataKey],
    ) -> Result<DecryptionMaterials, MaterialsError> {
        if materials.plaintext_data_key().is_some() {
            return Err(MaterialsError::plaintext_data_key_already_present(
                "HierarchicalKeyring::on_decrypt: decryption materials already contain a plaintext data key",
            ));
        }

        let branch_key_id = self.resolve_branch_key_id(materials.encryption_context())?;

        let mut collected_errors: Vec<MaterialsError> = Vec::new();
        for edk in encrypted_data_keys {
            if edk.key_provider_id != KEY_PROVIDER_ID_HIERARCHY {
                continue;
            }

            let Ok(edk_branch_key_id) = std::str::from_utf8(&edk.key_provider_info) else {
                continue;
            };

            if edk_branch_key_id != branch_key_id {
                continue;
            }

            match self.try_decrypt_edk(&materials, edk, &branch_key_id).await {
                Ok(plaintext_dk_bytes) => {
                    return DecryptionMaterials::new(
                        materials.algorithm_suite_id(),
                        materials.encryption_context().clone(),
                        materials.required_encryption_context_keys().clone(),
                        Some(PlaintextDataKey::new(plaintext_dk_bytes)),
                        materials.verification_key().cloned(),
                        materials.symmetric_signing_key().cloned(),
                    );
                }
                Err(e) => collected_errors.push(e),
            }
        }

        // The early-return above on `Ok` is the only path that produces a
        // mutated DecryptionMaterials; reaching this line means no EDK was
        // successfully decrypted, so the input `materials` parameter (owned
        // but never mutated) is dropped without modification.
        const FAILURE_PREFIX: &str =
            "HierarchicalKeyring::on_decrypt: failed to decrypt any encrypted data key";

        // Every collected failure is carried typed on the returned error, which
        // is what the specification requires:
        //
        //   "If OnDecrypt fails to successfully decrypt any encrypted data key,
        //    then it MUST yield an error that includes all the collected
        //    errors."
        //
        // https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
        //
        // Formatting them into the message alone would satisfy the letter of
        // that but leave a caller parsing prose to find out why any given
        // attempt failed. The Dafny implementation makes the same choice with
        // its `CollectionOfErrors(list, message)` error variant.
        //
        // `keyring_failed_collection` also attaches the single failure as the
        // `cause` when exactly one candidate was attempted, so `source()`
        // reaches it in the common single-key case. The message is unchanged
        // either way: a one-element join renders identically to the single
        // error on its own.
        Err(MaterialsError::keyring_failed_collection(
            format!(
                "{FAILURE_PREFIX} (collected errors: [{}])",
                collected_errors
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; "),
            ),
            collected_errors,
        ))
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
pub const SCOPE_ID_ENCRYPT: u8 = 0x01;

/// Cache-identifier scope byte for OnDecrypt, passed to
/// `cache_entry_identifier::build_cache_identifier`.
///
/// Hidden from the public API surface; intended for tests that recompute the
/// identifier independently of the keyring.
#[doc(hidden)]
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

        let cache_id = cache_entry_identifier::build_cache_identifier(
            SCOPE_ID_DECRYPT,
            &self.partition_id_bytes,
            &self.logical_keystore_name,
            branch_key_id,
            Some(&branch_key_version),
        );

        let cached = self.cache.get_cache_entry(&cache_id).await.map_err(|e| {
            MaterialsError::keyring_failed_with_cause(
                format!("HierarchicalKeyring: cache get_cache_entry failed: {e}"),
                e,
            )
        })?;

        let bkm = match cached {
            Some(entry) if cache_entry_within_limits(&entry, self.ttl_seconds) => {
                as_branch_key_materials(&entry)?.clone()
            }
            _ => {
                let bkm = self
                    .keystore
                    .get_branch_key_version(branch_key_id.to_string(), branch_key_version.clone())
                    .await
                    .map_err(|e| {
                        MaterialsError::keyring_failed_with_cause(
                            format!("HierarchicalKeyring: get_branch_key_version failed: {e}"),
                            e,
                        )
                    })?;

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
                        MaterialsError::keyring_failed_with_cause(
                            format!("HierarchicalKeyring: cache put_cache_entry failed: {e}"),
                            e,
                        )
                    })?;
                bkm
            }
        };

        branch_key_wrap::unwrap(&bkm, materials.encryption_context(), ciphertext)
    }
}

/// Generate a random plaintext data key of the algorithm suite's
/// configured encryption-key length using the `aws-mpl-primitives` CSPRNG.
fn generate_random_data_key(suite: AlgorithmSuite) -> Result<PlaintextDataKey, MaterialsError> {
    let mut bytes = vec![0u8; suite.encryption_key_length()];
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

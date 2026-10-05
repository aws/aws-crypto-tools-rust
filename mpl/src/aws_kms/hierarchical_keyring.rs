// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! AWS KMS Hierarchical Keyring.
//!
//! Provides the keyring's construction and configuration surface, its
//! OnEncrypt and OnDecrypt operations, and the keystore- / cache-fallthrough
//! they share. The pure-crypto wrap and unwrap operations live in
//! [`super::branch_key_wrap`] and the cache identifier formulas in
//! [`super::cache_entry_identifier`].

use crate::Error;
use crate::error::{Cache, Kind, Resource};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;

use crate::Keyring;
use crate::aws_kms::branch_key_wrap;
use crate::aws_kms::cache_entry_identifier;
use crate::cmc::cache_config::{
    CacheType, DEFAULT_CACHE_ENTRY_CAPACITY, DefaultCache, create_cryptographic_materials_cache,
};
use crate::cmc::{CacheEntry, CachedMaterials, Cmc, SharedCmc, UsageMetadata};
use crate::keystore::{Keystore, SharedKeystore};
use crate::shared::IntoShared;
use crate::structures::{
    AlgorithmSuite, BranchKeyMaterials, DecryptionMaterials, EncryptedDataKey, EncryptionContext,
    EncryptionMaterials, PlaintextDataKey,
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
///
/// To hold a supplier whose concrete type is chosen at runtime, use [`SharedBranchKeySupplier`].
pub trait BranchKeySupplier: Send + Sync {
    /// Return the branch key id to use for a given encryption context.
    fn get_branch_key_id(&self, input: GetBranchKeyIdInput) -> Result<GetBranchKeyIdOutput, Error>;
}

crate::shared::shared_handle!(
    /// A branch key supplier whose concrete type is chosen at runtime.
    ///
    /// It implements [`BranchKeySupplier`], so it can be passed anywhere a branch key supplier is accepted.
    /// Callers that know their branch key supplier's type pass it directly and never need this one.
    SharedBranchKeySupplier,
    BranchKeySupplier
);

impl BranchKeySupplier for SharedBranchKeySupplier {
    fn get_branch_key_id(&self, input: GetBranchKeyIdInput) -> Result<GetBranchKeyIdOutput, Error> {
        self.0.get_branch_key_id(input)
    }
}

/// AWS KMS Hierarchical Keyring.
///
/// Construct with [`HierarchicalKeyring::builder`].
/// The [`Keyring`] impl wires the configured cache and keystore into the
/// OnEncrypt / OnDecrypt algorithms.
#[derive(Clone)]
pub struct HierarchicalKeyring {
    inner: Arc<HierarchicalKeyringInner>,
}

struct HierarchicalKeyringInner {
    keystore: SharedKeystore,

    ttl: Duration,

    /// The single branch key id this keyring wraps and unwraps with, when
    /// configured with one. Exactly one of this and `branch_key_id_supplier`
    /// is `Some`, checked in [`HierarchicalKeyringBuilder::build`].
    branch_key_id: Option<String>,

    /// The supplier that chooses a branch key id per operation, when
    /// configured with one instead of a static `branch_key_id`.
    branch_key_id_supplier: Option<SharedBranchKeySupplier>,

    partition_id_bytes: Vec<u8>,

    /// The keystore's logical name, which the cache identifier formulas bind.
    /// Not a construction parameter: it is read from the keystore's own
    /// `get_key_store_info` once in [`HierarchicalKeyringBuilder::build`].
    logical_keystore_name: String,

    /// Cryptographic-materials cache for branch-key materials. Either a
    /// keyring-local `LocalCmc`/`StormTrackingCmc` built at construction
    /// time, or a `Shared` cache supplied by the caller.
    cache: SharedCmc,
}

impl HierarchicalKeyring {
    /// Start a builder for `HierarchicalKeyring`.
    #[must_use]
    pub fn builder() -> HierarchicalKeyringBuilder {
        HierarchicalKeyringBuilder::default()
    }

    /// The configured TTL for cached branch-key materials.
    pub fn ttl(&self) -> Duration {
        self.inner.ttl
    }

    /// The configured static branch key id, if this keyring was built with one
    /// rather than with a [`BranchKeySupplier`].
    pub fn branch_key_id(&self) -> Option<&str> {
        self.inner.branch_key_id.as_deref()
    }

    /// The configured branch key id supplier, if this keyring was built with
    /// one rather than with a static branch key id.
    pub fn branch_key_id_supplier(&self) -> Option<&SharedBranchKeySupplier> {
        self.inner.branch_key_id_supplier.as_ref()
    }

    /// The configured keystore.
    pub fn keystore(&self) -> &SharedKeystore {
        &self.inner.keystore
    }

    /// The partition id: the UTF-8 bytes of the caller's string,
    /// or the 16 bytes of a v4 UUID the keyring generated.
    ///
    /// Not part of the public API; exposed for tests.
    #[doc(hidden)]
    pub fn partition_id_bytes(&self) -> &[u8] {
        &self.inner.partition_id_bytes
    }

    /// The configured cache.
    ///
    /// Not part of the public API; exposed for tests.
    #[doc(hidden)]
    pub fn cache(&self) -> &SharedCmc {
        &self.inner.cache
    }
}

/// Builder for [`HierarchicalKeyring`], returned by
/// [`HierarchicalKeyring::builder`].
#[derive(Default)]
pub struct HierarchicalKeyringBuilder {
    key_store: Option<SharedKeystore>,
    ttl: Option<Duration>,
    branch_key_id: Option<String>,
    branch_key_id_supplier: Option<SharedBranchKeySupplier>,
    cache: Option<CacheType>,
    partition_id: Option<String>,
}

impl std::fmt::Debug for HierarchicalKeyringBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HierarchicalKeyringBuilder")
            .field("ttl", &self.ttl)
            .field("branch_key_id", &self.branch_key_id)
            .field("partition_id", &self.partition_id)
            .finish_non_exhaustive()
    }
}

impl HierarchicalKeyringBuilder {
    /// The keystore. Required.
    #[must_use]
    pub fn key_store(mut self, key_store: impl Keystore + 'static) -> Self {
        self.key_store = Some(key_store.into_shared());
        self
    }

    /// The TTL for cached branch-key materials.
    /// Required, and must be greater than zero.
    #[must_use]
    pub fn ttl(mut self, ttl: Duration) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// A static branch key id.
    /// Set this or [`branch_key_id_supplier`](Self::branch_key_id_supplier), not both.
    #[must_use]
    pub fn branch_key_id(mut self, branch_key_id: impl Into<String>) -> Self {
        self.branch_key_id = Some(branch_key_id.into());
        self
    }

    /// A [`BranchKeySupplier`].
    /// Set this or [`branch_key_id`](Self::branch_key_id), not both.
    #[must_use]
    pub fn branch_key_id_supplier(mut self, supplier: impl BranchKeySupplier + 'static) -> Self {
        self.branch_key_id_supplier = Some(supplier.into_shared());
        self
    }

    /// The cache for branch key materials; see [`CacheType`].
    /// When unset, behaves as `CacheType::Default(DefaultCache::new(1000))`.
    #[must_use]
    pub fn cache(mut self, cache: CacheType) -> Self {
        self.cache = Some(cache);
        self
    }

    /// The partition id.
    /// When unset, the keyring generates a fresh v4 UUID and stores it as the 16-byte partition id.
    #[must_use]
    pub fn partition_id(mut self, partition_id: impl Into<String>) -> Self {
        self.partition_id = Some(partition_id.into());
        self
    }

    /// Construct a new hierarchical keyring.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): no key store or TTL is set, the TTL is zero, both or neither of a branch key id and a branch key id supplier are set, a storm-tracking grace period is not less than the TTL, or the materials cache rejects its parameters.
    /// - [`Cryptographic`](crate::Error::Cryptographic): obtaining entropy for the default partition id failed.
    ///
    /// Any error the configured key store returns while reporting its info is propagated with its variant unchanged; the built-in [`BranchKeyStore`](crate::BranchKeyStore) returns none.
    pub fn build(self) -> Result<HierarchicalKeyring, Error> {
        let Self {
            key_store,
            ttl,
            branch_key_id,
            branch_key_id_supplier,
            cache,
            partition_id,
        } = self;

        let Some(keystore) = key_store else {
            return Err(Error::new(Kind::Validation, "a key store is required"));
        };

        let Some(ttl) = ttl else {
            return Err(Error::new(Kind::Validation, "a TTL is required"));
        };
        if ttl.is_zero() {
            return Err(Error::new(
                Kind::Validation,
                "TTL must be greater than zero",
            ));
        }

        if branch_key_id.is_some() && branch_key_id_supplier.is_some() {
            return Err(Error::new(
                Kind::Validation,
                "cannot initialize keyring with both a branch_key_id and a branch_key_id_supplier",
            ));
        }
        if branch_key_id.is_none() && branch_key_id_supplier.is_none() {
            return Err(Error::new(
                Kind::Validation,
                "must initialize keyring with either a branch_key_id or a branch_key_id_supplier",
            ));
        }

        // An absent `cache` is where the 1000-entry default lives: the model
        // requires `DefaultCache.entryCapacity`, and documents this number on
        // the keyring's own `cache` member.
        let cache_type = cache.unwrap_or(CacheType::Default(DefaultCache::new(
            DEFAULT_CACHE_ENTRY_CAPACITY,
        )));

        // The grace-period bound relates a storm-tracking parameter to this
        // keyring's TTL, so it is checked here rather than inside
        // `create_cryptographic_materials_cache`, which has no TTL to compare
        // against when a cache is built standalone.
        if let CacheType::StormTracking(params) = &cache_type
            && params.grace_period() >= ttl
        {
            return Err(Error::new(
                Kind::Validation,
                format!(
                    "storm-tracking grace period ({:?}) must be less than the cache limit TTL ({ttl:?})",
                    params.grace_period(),
                ),
            ));
        }

        let cache = create_cryptographic_materials_cache(cache_type).map_err(|e| {
            Error::with_cause(Kind::Validation, "could not create the materials cache", e)
        })?;

        let partition_id_bytes = match partition_id {
            Some(s) => s.into_bytes(),
            None => generate_partition_id()?,
        };

        // Resolve the keystore's logical name once, here, so the OnEncrypt and
        // OnDecrypt paths can build cache identifiers without re-reading it.
        let logical_keystore_name = keystore
            .get_key_store_info()
            .map_err(|e| Error::wrap("could not read the key store info", e))?
            .logical_keystore_name;

        Ok(HierarchicalKeyring {
            inner: Arc::new(HierarchicalKeyringInner {
                keystore,
                ttl,
                branch_key_id,
                branch_key_id_supplier,
                partition_id_bytes,
                logical_keystore_name,
                cache,
            }),
        })
    }
}

/// Generate a default partition id: the 16-byte representation of a fresh v4
/// UUID, drawing the randomness from the `aws-mpl-primitives` CSPRNG rather
/// than the `uuid` crate's own entropy source, so all randomness in this crate
/// comes from one audited primitive. `Builder::from_random_bytes` sets the
/// version and variant bits.
fn generate_partition_id() -> Result<Vec<u8>, Error> {
    let mut bytes = [0u8; 16];
    aws_mpl_primitives::generate_random_bytes(&mut bytes).map_err(|e| {
        Error::with_cause(
            Kind::Cryptographic,
            "failed to obtain entropy for partition-id v4 UUID",
            e,
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
    /// The configured branch key ID, or `"supplier"` when a branch key ID supplier chooses it.
    fn name(&self) -> &str {
        self.inner.branch_key_id.as_deref().unwrap_or("supplier")
    }

    async fn on_encrypt(
        &self,
        materials: EncryptionMaterials,
    ) -> Result<EncryptionMaterials, Error> {
        let branch_key_id = self.resolve_branch_key_id(materials.encryption_context())?;

        let plaintext_dk = match materials.plaintext_data_key() {
            Some(pdk) => pdk.clone(),
            None => generate_random_data_key(materials.algorithm_suite())?,
        };

        let cache_id = cache_entry_identifier::build_cache_identifier(
            SCOPE_ID_ENCRYPT,
            &self.inner.partition_id_bytes,
            &self.inner.logical_keystore_name,
            &branch_key_id,
            None,
        );

        let cached = self
            .inner
            .cache
            .get_cache_entry(&cache_id)
            .await
            .map_err(|e| name_branch_key_in_cache_wait(e, &branch_key_id))?;

        let ciphertext = match cached {
            Some(entry) if cache_entry_within_limits(&entry, self.inner.ttl) => {
                let bkm = as_branch_key_materials(&entry)?;
                branch_key_wrap::wrap(bkm, materials.encryption_context(), plaintext_dk.as_bytes())?
            }
            _ => {
                let bkm = self
                    .inner
                    .keystore
                    .get_active_branch_key(branch_key_id.clone())
                    .await?;

                let now = SystemTime::now();
                let entry = CacheEntry::new(
                    CachedMaterials::BranchKey(bkm.clone()),
                    now,
                    now + self.inner.ttl,
                    UsageMetadata::default(),
                );
                self.inner.cache.put_cache_entry(&cache_id, entry).await?;

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
    ) -> Result<DecryptionMaterials, Error> {
        if materials.plaintext_data_key().is_some() {
            return Err(Error::new(
                Kind::InvalidMaterials,
                "decryption materials already contain a plaintext data key",
            ));
        }

        let branch_key_id = self.resolve_branch_key_id(materials.encryption_context())?;

        let mut collected_errors: Vec<Error> = Vec::new();
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

        // Nothing was attempted: every supplied EDK was filtered out before
        // the keystore was consulted, so this is not an aggregate of failures
        // but a distinct one — no encrypted data key matched this keyring.
        if collected_errors.is_empty() {
            return Err(Error::new(
                Kind::NoMatchingDataKey,
                "no encrypted data key matched",
            ));
        }

        // At least one candidate was attempted and every one failed. The
        // per-attempt errors are carried typed on the returned error, which is
        // what the specification requires:
        //
        //   "If OnDecrypt fails to successfully decrypt any encrypted data key,
        //    then it MUST yield an error that includes all the collected
        //    errors."
        //
        // https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
        // With exactly one candidate, its error is the one returned.
        Err(Error::all_failed(
            "failed to decrypt any encrypted data key",
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
    ) -> Result<String, Error> {
        if let Some(id) = &self.inner.branch_key_id {
            return Ok(id.clone());
        }

        // `new` rejects the configuration where neither is set, so reaching
        // here means the supplier is present.
        let Some(supplier) = &self.inner.branch_key_id_supplier else {
            return Err(Error::new(
                Kind::Internal,
                "neither a branch_key_id nor a branch_key_id_supplier is configured",
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
    ) -> Result<Vec<u8>, Error> {
        // Parse the 16-byte branch-key version out of the on-wire layout
        // `salt(16) || iv(12) || version(16) || encrypted_key(var) || tag(16)`.
        // branch_key_wrap::unwrap re-validates the full layout (including the
        // trailing 16-byte tag) before doing the AES-GCM open; here we only
        // need the slice for the version.
        let ciphertext = &edk.ciphertext;
        if ciphertext.len() < CIPHERTEXT_VERSION_OFFSET + CIPHERTEXT_VERSION_LEN {
            return Err(Error::new(
                Kind::Cryptographic,
                format!(
                    "encrypted data key ciphertext too short to contain the branch key version: {} bytes (need at least {})",
                    ciphertext.len(),
                    CIPHERTEXT_VERSION_OFFSET + CIPHERTEXT_VERSION_LEN,
                ),
            ));
        }
        let version_bytes: [u8; CIPHERTEXT_VERSION_LEN] = ciphertext
            [CIPHERTEXT_VERSION_OFFSET..CIPHERTEXT_VERSION_OFFSET + CIPHERTEXT_VERSION_LEN]
            .try_into()
            .expect("16-byte slice into [u8; 16]");

        let branch_key_version = uuid_16_bytes_to_str(&version_bytes);

        let cache_id = cache_entry_identifier::build_cache_identifier(
            SCOPE_ID_DECRYPT,
            &self.inner.partition_id_bytes,
            &self.inner.logical_keystore_name,
            branch_key_id,
            Some(&branch_key_version),
        );

        let cached = self
            .inner
            .cache
            .get_cache_entry(&cache_id)
            .await
            .map_err(|e| name_branch_key_in_cache_wait(e, branch_key_id))?;

        let bkm = match cached {
            Some(entry) if cache_entry_within_limits(&entry, self.inner.ttl) => {
                as_branch_key_materials(&entry)?.clone()
            }
            _ => {
                let bkm = self
                    .inner
                    .keystore
                    .get_branch_key_version(branch_key_id.to_string(), branch_key_version.clone())
                    .await?;

                let now = SystemTime::now();
                let entry = CacheEntry::new(
                    CachedMaterials::BranchKey(bkm.clone()),
                    now,
                    now + self.inner.ttl,
                    UsageMetadata::default(),
                );
                self.inner.cache.put_cache_entry(&cache_id, entry).await?;
                bkm
            }
        };

        branch_key_wrap::unwrap(&bkm, materials.encryption_context(), ciphertext)
    }
}

/// Name the branch key in a cache throttling error,
/// which names only the cache because the cache's keys are opaque.
fn name_branch_key_in_cache_wait(mut e: Error, branch_key_id: &str) -> Error {
    if e.is_throttling() && e.resource() == Some(&Resource::Cache(Cache::new())) {
        e.set_message(format!(
            "timed out waiting for another caller to fetch branch key {branch_key_id}"
        ));
    }
    e
}

/// Generate a random plaintext data key of the algorithm suite's
/// configured encryption-key length using the `aws-mpl-primitives` CSPRNG.
fn generate_random_data_key(suite: AlgorithmSuite) -> Result<PlaintextDataKey, Error> {
    let mut bytes = vec![0u8; suite.encryption_key_length()];
    aws_mpl_primitives::generate_random_bytes(&mut bytes).map_err(|e| {
        Error::with_cause(
            Kind::Cryptographic,
            "failed to obtain entropy for random plaintext data key",
            e,
        )
    })?;
    Ok(PlaintextDataKey::new(bytes))
}

/// Whether a cache entry is still within its TTL:
/// `time.now() - cacheEntryCreationTime <= ttlSeconds`.
fn cache_entry_within_limits(entry: &CacheEntry, ttl: Duration) -> bool {
    let now = SystemTime::now();
    let elapsed = now
        .duration_since(entry.creation_time)
        .unwrap_or(Duration::ZERO);
    elapsed <= ttl
}

/// Extract a borrowed [`BranchKeyMaterials`] reference from a cache
/// entry, failing if the entry holds non-branch-key materials (which
/// would indicate a cache identifier collision).
fn as_branch_key_materials(entry: &CacheEntry) -> Result<&BranchKeyMaterials, Error> {
    match &entry.materials {
        CachedMaterials::BranchKey(bkm) => Ok(bkm),
        _ => Err(Error::new(
            Kind::Validation,
            "cache entry has wrong materials kind (expected BranchKey)",
        )),
    }
}

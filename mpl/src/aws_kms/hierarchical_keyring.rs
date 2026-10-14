// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! AWS KMS Hierarchical Keyring.
//!
//! The keyring's builder, its OnEncrypt and OnDecrypt operations,
//! and the branch key lookup they share: the cache first, then the key store.

use crate::Error;
use crate::builder::required;
use crate::error::{Cache, DataKeyInfo, Kind, Resource};
use std::borrow::Cow;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;

use crate::Keyring;
use crate::aws_kms::branch_key_wrap;
use crate::aws_kms::cache_entry_identifier;
use crate::cmc::{CacheEntry, CachedMaterials, Cmc, DefaultCmc, SharedCmc};
use crate::key_store::KeyStoreClient;
use crate::keyring::{OnDecryptInput, OnDecryptOutput, OnEncryptInput, OnEncryptOutput};
use crate::shared::IntoShared;
use crate::structures::{
    AlgorithmSuite, BranchKeyMaterials, DecryptionMaterials, EncryptedDataKey, EncryptionContext,
    PlaintextDataKey,
};

/// Input for [`BranchKeySupplier::get_branch_key_id`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct GetBranchKeyIdInput {
    encryption_context: EncryptionContext,
}

impl GetBranchKeyIdInput {
    /// Start a builder for `GetBranchKeyIdInput`.
    #[must_use]
    pub fn builder() -> GetBranchKeyIdInputBuilder {
        GetBranchKeyIdInputBuilder::default()
    }

    /// The encryption context of the message being encrypted or decrypted.
    #[must_use]
    pub const fn encryption_context(&self) -> &EncryptionContext {
        &self.encryption_context
    }
}

/// Builder for [`GetBranchKeyIdInput`].
#[derive(Debug, Clone, Default)]
pub struct GetBranchKeyIdInputBuilder {
    encryption_context: Option<EncryptionContext>,
}

impl GetBranchKeyIdInputBuilder {
    /// Adds a key-value pair to the encryption context of the message being encrypted or decrypted.
    ///
    /// To override the contents of this collection use [`set_encryption_context`](Self::set_encryption_context).
    /// Required.
    #[must_use]
    pub fn encryption_context(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.encryption_context
            .get_or_insert_with(Default::default)
            .insert(k, v);
        self
    }

    /// Set or clear the encryption context from an `Option`.
    /// To add one entry, use [`Self::encryption_context`].
    #[must_use]
    pub fn set_encryption_context(mut self, encryption_context: Option<EncryptionContext>) -> Self {
        self.encryption_context = encryption_context;
        self
    }

    /// The encryption context, if set.
    #[must_use]
    pub const fn get_encryption_context(&self) -> &Option<EncryptionContext> {
        &self.encryption_context
    }

    /// Build the `GetBranchKeyIdInput`.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): `encryption_context` is unset.
    pub fn build(self) -> Result<GetBranchKeyIdInput, Error> {
        Ok(GetBranchKeyIdInput {
            encryption_context: required(self.encryption_context, "encryption_context")?,
        })
    }
}

/// Output of [`BranchKeySupplier::get_branch_key_id`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct GetBranchKeyIdOutput {
    branch_key_id: String,
}

impl GetBranchKeyIdOutput {
    /// Start a builder for `GetBranchKeyIdOutput`.
    #[must_use]
    pub fn builder() -> GetBranchKeyIdOutputBuilder {
        GetBranchKeyIdOutputBuilder::default()
    }

    /// The identifier of the branch key that wraps or unwraps the data key.
    #[must_use]
    pub fn branch_key_id(&self) -> &str {
        &self.branch_key_id
    }

    /// The branch key identifier, consuming the output.
    #[must_use]
    pub fn into_branch_key_id(self) -> String {
        self.branch_key_id
    }
}

/// Builder for [`GetBranchKeyIdOutput`].
#[derive(Debug, Clone, Default)]
pub struct GetBranchKeyIdOutputBuilder {
    branch_key_id: Option<String>,
}

impl GetBranchKeyIdOutputBuilder {
    /// Set the identifier of the branch key that wraps or unwraps the data key.
    /// Required.
    #[must_use]
    pub fn branch_key_id(mut self, branch_key_id: impl Into<String>) -> Self {
        self.branch_key_id = Some(branch_key_id.into());
        self
    }

    /// Set or clear the branch key identifier from an `Option`.
    /// To add one entry, use [`Self::branch_key_id`].
    #[must_use]
    pub fn set_branch_key_id(mut self, branch_key_id: Option<String>) -> Self {
        self.branch_key_id = branch_key_id;
        self
    }

    /// The branch key ID, if set.
    #[must_use]
    pub const fn get_branch_key_id(&self) -> &Option<String> {
        &self.branch_key_id
    }

    /// Build the `GetBranchKeyIdOutput`.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): `branch_key_id` is unset.
    pub fn build(self) -> Result<GetBranchKeyIdOutput, Error> {
        Ok(GetBranchKeyIdOutput {
            branch_key_id: required(self.branch_key_id, "branch_key_id")?,
        })
    }
}

impl From<String> for GetBranchKeyIdOutput {
    fn from(branch_key_id: String) -> Self {
        Self { branch_key_id }
    }
}

impl From<&str> for GetBranchKeyIdOutput {
    fn from(branch_key_id: &str) -> Self {
        Self {
            branch_key_id: branch_key_id.to_owned(),
        }
    }
}

/// User-supplied callback that maps an encryption context to a branch key id.
///
/// Implementations are typically used by callers running multi-tenant workloads
/// who want to pick the branch key based on encryption-context metadata.
///
/// To hold a supplier whose concrete type is chosen at runtime, use [`SharedBranchKeySupplier`].
#[async_trait::async_trait]
pub trait BranchKeySupplier: Send + Sync {
    /// Return the branch key id to use for a given encryption context.
    async fn get_branch_key_id(
        &self,
        input: GetBranchKeyIdInput,
    ) -> Result<GetBranchKeyIdOutput, Error>;
}

crate::shared::shared_handle!(
    /// A branch key supplier whose concrete type is chosen at runtime.
    ///
    /// It implements [`BranchKeySupplier`], so it can be passed anywhere a branch key supplier is accepted.
    /// Callers that know their branch key supplier's type pass it directly and never need this one.
    ///
    /// Its operation returns a fluent builder: set the input, then call `send`.
    SharedBranchKeySupplier,
    BranchKeySupplier
);

#[async_trait::async_trait]
impl BranchKeySupplier for SharedBranchKeySupplier {
    async fn get_branch_key_id(
        &self,
        input: GetBranchKeyIdInput,
    ) -> Result<GetBranchKeyIdOutput, Error> {
        BranchKeySupplier::get_branch_key_id(&*self.0, input).await
    }
}

impl SharedBranchKeySupplier {
    /// Start a [`BranchKeySupplier::get_branch_key_id`] call.
    pub fn get_branch_key_id(&self) -> GetBranchKeyIdFluentBuilder {
        GetBranchKeyIdFluentBuilder {
            handle: self.clone(),
            inner: GetBranchKeyIdInput::builder(),
        }
    }
}

/// Fluent builder for [`SharedBranchKeySupplier::get_branch_key_id`].
#[derive(Debug, Clone)]
#[must_use = "does nothing until `send` is called"]
pub struct GetBranchKeyIdFluentBuilder {
    handle: SharedBranchKeySupplier,
    inner: GetBranchKeyIdInputBuilder,
}

impl GetBranchKeyIdFluentBuilder {
    /// The input set so far.
    #[must_use]
    pub const fn as_input(&self) -> &GetBranchKeyIdInputBuilder {
        &self.inner
    }

    /// Adds a key-value pair to the encryption context of the message being encrypted or decrypted.
    ///
    /// To override the contents of this collection use [`set_encryption_context`](Self::set_encryption_context).
    /// Required.
    pub fn encryption_context(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.inner = self.inner.encryption_context(k, v);
        self
    }

    /// Set or clear the encryption context from an `Option`.
    /// To add one entry, use [`Self::encryption_context`].
    pub fn set_encryption_context(mut self, encryption_context: Option<EncryptionContext>) -> Self {
        self.inner = self.inner.set_encryption_context(encryption_context);
        self
    }

    /// The encryption context, if set.
    #[must_use]
    pub const fn get_encryption_context(&self) -> &Option<EncryptionContext> {
        self.inner.get_encryption_context()
    }

    /// Send the request.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): `encryption_context` is unset.
    ///
    /// Otherwise, the errors [`BranchKeySupplier::get_branch_key_id`] documents.
    pub async fn send(self) -> Result<GetBranchKeyIdOutput, Error> {
        let input = self.inner.build()?;
        BranchKeySupplier::get_branch_key_id(&*self.handle.0, input).await
    }
}

/// AWS KMS Hierarchical Keyring.
///
/// Construct with [`HierarchicalKeyring::builder`].
#[derive(Clone)]
pub struct HierarchicalKeyring {
    inner: Arc<HierarchicalKeyringInner>,
}

struct HierarchicalKeyringInner {
    key_store: KeyStoreClient,

    ttl: Duration,

    /// The single branch key id this keyring wraps and unwraps with, when
    /// configured with one. Exactly one of this and `branch_key_id_supplier`
    /// is `Some`, checked in [`HierarchicalKeyringBuilder::build`].
    branch_key_id: Option<String>,

    /// The supplier that chooses a branch key id per operation, when
    /// configured with one instead of a static `branch_key_id`.
    branch_key_id_supplier: Option<SharedBranchKeySupplier>,

    partition_id_bytes: Vec<u8>,

    /// The key store's logical name, which the cache identifier formulas bind.
    /// [`HierarchicalKeyringBuilder::build`] reads it once from the key store's `get_key_store_info`.
    logical_key_store_name: String,

    /// The cache for branch key materials:
    /// the caller's, or a `DefaultCmc` the builder creates when none is set.
    cache: SharedCmc,
}

impl HierarchicalKeyring {
    /// Start a builder for `HierarchicalKeyring`.
    #[must_use]
    pub fn builder() -> HierarchicalKeyringBuilder {
        HierarchicalKeyringBuilder::default()
    }

    /// The configured TTL for cached branch-key materials.
    #[must_use]
    pub fn ttl(&self) -> Duration {
        self.inner.ttl
    }

    /// The configured static branch key id, if this keyring was built with one
    /// rather than with a [`BranchKeySupplier`].
    #[must_use]
    pub fn branch_key_id(&self) -> Option<&str> {
        self.inner.branch_key_id.as_deref()
    }

    /// The configured branch key id supplier, if this keyring was built with
    /// one rather than with a static branch key id.
    #[must_use]
    pub fn branch_key_id_supplier(&self) -> Option<&SharedBranchKeySupplier> {
        self.inner.branch_key_id_supplier.as_ref()
    }

    /// The configured key store.
    #[must_use]
    pub fn key_store(&self) -> &KeyStoreClient {
        &self.inner.key_store
    }

    /// The partition id: the UTF-8 bytes of the caller's string,
    /// or the 16 bytes of a v4 UUID the keyring generated.
    #[cfg(feature = "test-utils")]
    pub(crate) fn partition_id_bytes(&self) -> &[u8] {
        &self.inner.partition_id_bytes
    }

    /// The configured cache.
    #[cfg(feature = "test-utils")]
    pub(crate) fn cache(&self) -> &SharedCmc {
        &self.inner.cache
    }
}

/// Entry capacity of the [`DefaultCmc`] a keyring builds when no cache is set.
const DEFAULT_CACHE_ENTRY_CAPACITY: usize = 1000;

/// Builder for [`HierarchicalKeyring`], returned by
/// [`HierarchicalKeyring::builder`].
#[derive(Default)]
pub struct HierarchicalKeyringBuilder {
    key_store: Option<KeyStoreClient>,
    ttl: Option<Duration>,
    branch_key_id: Option<String>,
    branch_key_id_supplier: Option<SharedBranchKeySupplier>,
    cache: Option<SharedCmc>,
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
    /// The key store.
    /// Required.
    ///
    /// Pass the [`KeyStoreClient`] that [`KeyStoreClient::builder`] builds, or any [`KeyStore`](crate::KeyStore).
    #[must_use]
    pub fn key_store(mut self, key_store: impl Into<KeyStoreClient>) -> Self {
        self.key_store = Some(key_store.into());
        self
    }

    /// Set or clear the key store from an `Option`.
    /// To add one entry, use [`Self::key_store`].
    #[must_use]
    pub fn set_key_store(mut self, key_store: Option<KeyStoreClient>) -> Self {
        self.key_store = key_store;
        self
    }

    /// The key store, if set.
    #[must_use]
    pub const fn get_key_store(&self) -> &Option<KeyStoreClient> {
        &self.key_store
    }

    /// The TTL for cached branch-key materials.
    /// Required, and must be greater than zero.
    #[must_use]
    pub fn ttl(mut self, ttl: Duration) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Set or clear the TTL from an `Option`.
    /// To add one entry, use [`Self::ttl`].
    #[must_use]
    pub fn set_ttl(mut self, ttl: Option<Duration>) -> Self {
        self.ttl = ttl;
        self
    }

    /// The TTL, if set.
    #[must_use]
    pub const fn get_ttl(&self) -> &Option<Duration> {
        &self.ttl
    }

    /// A static branch key id.
    /// Set this or [`branch_key_id_supplier`](Self::branch_key_id_supplier), not both.
    #[must_use]
    pub fn branch_key_id(mut self, branch_key_id: impl Into<String>) -> Self {
        self.branch_key_id = Some(branch_key_id.into());
        self
    }

    /// Set or clear the static branch key id from an `Option`.
    /// To add one entry, use [`Self::branch_key_id`].
    #[must_use]
    pub fn set_branch_key_id(mut self, branch_key_id: Option<String>) -> Self {
        self.branch_key_id = branch_key_id;
        self
    }

    /// The branch key ID, if set.
    #[must_use]
    pub const fn get_branch_key_id(&self) -> &Option<String> {
        &self.branch_key_id
    }

    /// A [`BranchKeySupplier`].
    /// Set this or [`branch_key_id`](Self::branch_key_id), not both.
    #[must_use]
    pub fn branch_key_id_supplier(mut self, supplier: impl BranchKeySupplier + 'static) -> Self {
        self.branch_key_id_supplier = Some(supplier.into_shared());
        self
    }

    /// Set or clear the branch key id supplier from an `Option`.
    /// To add one entry, use [`Self::branch_key_id_supplier`].
    #[must_use]
    pub fn set_branch_key_id_supplier(mut self, supplier: Option<SharedBranchKeySupplier>) -> Self {
        self.branch_key_id_supplier = supplier;
        self
    }

    /// The branch key ID supplier, if set.
    #[must_use]
    pub const fn get_branch_key_id_supplier(&self) -> &Option<SharedBranchKeySupplier> {
        &self.branch_key_id_supplier
    }

    /// The cache for branch key materials.
    /// Pass clones of one cache to several keyrings to share its entries.
    /// When unset, the keyring builds its own [`DefaultCmc`] with an entry capacity of 1000.
    ///
    /// The cache's [grace period](Cmc::grace_period), if it has one, must be less than the [TTL](Self::ttl).
    /// The default cache's grace period is 10 seconds.
    #[must_use]
    pub fn cache(mut self, cache: impl Cmc + 'static) -> Self {
        self.cache = Some(cache.into_shared());
        self
    }

    /// Set or clear the cache from an `Option`.
    /// To add one entry, use [`Self::cache`].
    #[must_use]
    pub fn set_cache(mut self, cache: Option<SharedCmc>) -> Self {
        self.cache = cache;
        self
    }

    /// The cache, if set.
    #[must_use]
    pub const fn get_cache(&self) -> &Option<SharedCmc> {
        &self.cache
    }

    /// The partition id.
    /// When unset, the keyring generates a fresh v4 UUID and stores it as the 16-byte partition id.
    #[must_use]
    pub fn partition_id(mut self, partition_id: impl Into<String>) -> Self {
        self.partition_id = Some(partition_id.into());
        self
    }

    /// Set or clear the partition id from an `Option`.
    /// To add one entry, use [`Self::partition_id`].
    #[must_use]
    pub fn set_partition_id(mut self, partition_id: Option<String>) -> Self {
        self.partition_id = partition_id;
        self
    }

    /// The partition ID, if set.
    #[must_use]
    pub const fn get_partition_id(&self) -> &Option<String> {
        &self.partition_id
    }

    /// Construct a new hierarchical keyring.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): no key store or TTL is set, the TTL is zero, both or neither of a branch key id and a branch key id supplier are set, a storm-tracking grace period is not less than the TTL, or the materials cache rejects its parameters.
    /// - [`Cryptographic`](crate::Error::Cryptographic): the random number generator failed while creating the default partition id.
    ///
    /// If the key store's [`get_key_store_info`](crate::KeyStore::get_key_store_info) fails, returns that error unchanged.
    /// The key store [`KeyStoreClient::builder`] builds does not fail it.
    pub fn build(self) -> Result<HierarchicalKeyring, Error> {
        let Self {
            key_store,
            ttl,
            branch_key_id,
            branch_key_id_supplier,
            cache,
            partition_id,
        } = self;

        let key_store = required(key_store, "key_store")?;
        let ttl = required(ttl, "ttl")?;
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

        let cache = match cache {
            Some(cache) => cache,
            None => SharedCmc::new(
                DefaultCmc::builder()
                    .entry_capacity(DEFAULT_CACHE_ENTRY_CAPACITY)
                    .build()
                    .map_err(|e| Error::wrap("could not create the default materials cache", e))?,
            ),
        };

        if let Some(grace_period) = cache.grace_period()
            && grace_period >= ttl
        {
            return Err(Error::new(
                Kind::Validation,
                format!(
                    "storm-tracking grace period ({grace_period:?}) must be less than the cache limit TTL ({ttl:?})",
                ),
            ));
        }

        let partition_id_bytes = match partition_id {
            Some(s) => s.into_bytes(),
            None => generate_partition_id()?,
        };

        let logical_key_store_name = key_store
            .get_key_store_info()
            .send()
            .map_err(|e| Error::wrap("could not read the key store info", e))?
            .logical_key_store_name;

        Ok(HierarchicalKeyring {
            inner: Arc::new(HierarchicalKeyringInner {
                key_store,
                ttl,
                branch_key_id,
                branch_key_id_supplier,
                partition_id_bytes,
                logical_key_store_name,
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
/// 36-character hyphenated string form (`8-4-4-4-12`), the form the key store
/// takes as a branch key version.
fn uuid_16_bytes_to_str(bytes: &[u8; CIPHERTEXT_VERSION_LEN]) -> String {
    uuid::Uuid::from_bytes(*bytes).hyphenated().to_string()
}

#[async_trait]
impl Keyring for HierarchicalKeyring {
    /// The configured branch key ID, or `"supplier"` when a branch key ID supplier chooses it.
    fn name(&self) -> Cow<'_, str> {
        Cow::Borrowed(self.inner.branch_key_id.as_deref().unwrap_or("supplier"))
    }

    async fn on_encrypt(&self, input: OnEncryptInput) -> Result<OnEncryptOutput, Error> {
        let materials = input.materials;
        let branch_key_id = self
            .resolve_branch_key_id(materials.encryption_context())
            .await?;

        let (plaintext_dk, generated) = match materials.plaintext_data_key() {
            Some(pdk) => (pdk.clone(), false),
            None => (generate_random_data_key(materials.algorithm_suite())?, true),
        };

        let cache_id = cache_entry_identifier::build_cache_identifier(
            SCOPE_ID_ENCRYPT,
            &self.inner.partition_id_bytes,
            &self.inner.logical_key_store_name,
            &branch_key_id,
            None,
        );

        let cached = self
            .inner
            .cache
            .get_cache_entry()
            .identifier(cache_id)
            .send()
            .await
            .map_err(|e| name_branch_key_in_cache_wait(e, &branch_key_id))?
            .into_entry();

        let ciphertext = match cached {
            Some(entry) if cache_entry_within_limits(&entry, self.inner.ttl) => {
                let bkm = as_branch_key_materials(&entry)?;
                branch_key_wrap::wrap(bkm, materials.encryption_context(), plaintext_dk.as_bytes())?
            }
            _ => {
                let bkm = self
                    .inner
                    .key_store
                    .get_active_branch_key()
                    .branch_key_id(&branch_key_id)
                    .send()
                    .await?
                    .branch_key_materials;

                let now = SystemTime::now();
                let entry = CacheEntry::builder()
                    .materials(CachedMaterials::BranchKey(bkm.clone()))
                    .creation_time(now)
                    .expiry_time(now + self.inner.ttl)
                    .build()?;
                self.inner
                    .cache
                    .put_cache_entry()
                    .identifier(cache_id)
                    .entry(entry)
                    .send()
                    .await?;

                branch_key_wrap::wrap(
                    &bkm,
                    materials.encryption_context(),
                    plaintext_dk.as_bytes(),
                )?
            }
        };

        let edk = EncryptedDataKey::builder()
            .key_provider_id(KEY_PROVIDER_ID_HIERARCHY)
            .key_provider_info(branch_key_id.into_bytes())
            .ciphertext(ciphertext)
            .build()?;

        let materials = if generated {
            materials.add_data_key(plaintext_dk, edk)?
        } else {
            materials.add_encrypted_data_key(edk)?
        };
        OnEncryptOutput::builder().materials(materials).build()
    }

    async fn on_decrypt(&self, input: OnDecryptInput) -> Result<OnDecryptOutput, Error> {
        let OnDecryptInput {
            materials,
            encrypted_data_keys,
        } = input;
        if materials.plaintext_data_key().is_some() {
            return Err(Error::new(
                Kind::InvalidMaterials,
                "decryption materials already contain a plaintext data key",
            ));
        }

        let branch_key_id = self
            .resolve_branch_key_id(materials.encryption_context())
            .await?;

        let mut collected_errors: Vec<Error> = Vec::new();
        for edk in &encrypted_data_keys {
            if edk.key_provider_id() != KEY_PROVIDER_ID_HIERARCHY {
                continue;
            }

            let Ok(edk_branch_key_id) = std::str::from_utf8(edk.key_provider_info()) else {
                continue;
            };

            if edk_branch_key_id != branch_key_id {
                continue;
            }

            match self.try_decrypt_edk(&materials, edk, &branch_key_id).await {
                Ok(plaintext_dk_bytes) => {
                    let materials =
                        materials.add_data_key(PlaintextDataKey::new(plaintext_dk_bytes))?;
                    return OnDecryptOutput::builder().materials(materials).build();
                }
                Err(e) => collected_errors.push(e),
            }
        }

        // The early-return above on `Ok` is the only path that produces a
        // mutated DecryptionMaterials; reaching this line means no EDK was
        // successfully decrypted, so the input `materials` parameter (owned
        // but never mutated) is dropped without modification.

        // Every EDK was filtered out before the key store was called,
        // so the error is that no encrypted data key matched, not an aggregate of failures.
        if collected_errors.is_empty() {
            return Err(
                Error::new(Kind::NoMatchingDataKey, "no encrypted data key matched")
                    .with_encrypted_data_keys(encrypted_data_keys.iter().map(DataKeyInfo::from)),
            );
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
        // With one candidate, `all_failed` returns that candidate's error itself.
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
pub(crate) const SCOPE_ID_ENCRYPT: u8 = 0x01;

/// Cache-identifier scope byte for OnDecrypt, passed to
/// `cache_entry_identifier::build_cache_identifier`.
pub(crate) const SCOPE_ID_DECRYPT: u8 = 0x02;

impl HierarchicalKeyring {
    /// Resolve the branch-key id for this operation: either the
    /// configured static value or the supplier callback's output bound
    /// to the current encryption context.
    async fn resolve_branch_key_id(
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
        Ok(supplier
            .get_branch_key_id()
            .set_encryption_context(Some(encryption_context.clone()))
            .send()
            .await?
            .into_branch_key_id())
    }

    /// Run the OnDecrypt steps for one EDK that passed filtering:
    /// parse the version,
    /// compute the cache identifier,
    /// get the branch key materials from the cache or else the key store,
    /// and unwrap the EDK ciphertext.
    /// Returns the recovered plaintext data key bytes.
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
        let ciphertext = edk.ciphertext();
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
        self.decrypt_edk_at_version(materials, edk, branch_key_id, &branch_key_version)
            .await
            .map_err(|e| e.at_branch_key_version(branch_key_id, &branch_key_version))
    }

    /// Unwrap `edk` with version `branch_key_version` of the branch key, from the cache or the key store.
    async fn decrypt_edk_at_version(
        &self,
        materials: &DecryptionMaterials,
        edk: &EncryptedDataKey,
        branch_key_id: &str,
        branch_key_version: &str,
    ) -> Result<Vec<u8>, Error> {
        let cache_id = cache_entry_identifier::build_cache_identifier(
            SCOPE_ID_DECRYPT,
            &self.inner.partition_id_bytes,
            &self.inner.logical_key_store_name,
            branch_key_id,
            Some(branch_key_version),
        );

        let cached = self
            .inner
            .cache
            .get_cache_entry()
            .identifier(cache_id)
            .send()
            .await
            .map_err(|e| name_branch_key_in_cache_wait(e, branch_key_id))?
            .into_entry();

        let bkm = match cached {
            Some(entry) if cache_entry_within_limits(&entry, self.inner.ttl) => {
                as_branch_key_materials(&entry)?.clone()
            }
            _ => {
                let bkm = self
                    .inner
                    .key_store
                    .get_branch_key_version()
                    .branch_key_id(branch_key_id)
                    .branch_key_version(branch_key_version)
                    .send()
                    .await?
                    .branch_key_materials;

                let now = SystemTime::now();
                let entry = CacheEntry::builder()
                    .materials(CachedMaterials::BranchKey(bkm.clone()))
                    .creation_time(now)
                    .expiry_time(now + self.inner.ttl)
                    .build()?;
                self.inner
                    .cache
                    .put_cache_entry()
                    .identifier(cache_id)
                    .entry(entry)
                    .send()
                    .await?;
                bkm
            }
        };

        branch_key_wrap::unwrap(&bkm, materials.encryption_context(), edk.ciphertext())
    }
}

/// Name the branch key in the message of a cache throttling error.
/// The cache names only itself, because its keys are opaque.
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
        .duration_since(entry.creation_time())
        .unwrap_or(Duration::ZERO);
    elapsed <= ttl
}

/// Extract a borrowed [`BranchKeyMaterials`] reference from a cache
/// entry, failing if the entry holds non-branch-key materials (which
/// would indicate a cache identifier collision).
fn as_branch_key_materials(entry: &CacheEntry) -> Result<&BranchKeyMaterials, Error> {
    match entry.materials() {
        CachedMaterials::BranchKey(bkm) => Ok(bkm),
        _ => Err(Error::new(
            Kind::Validation,
            "cache entry has wrong materials kind (expected BranchKey)",
        )),
    }
}

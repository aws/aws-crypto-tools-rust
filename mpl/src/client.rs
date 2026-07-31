// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Top-level Material Providers Library client and its factory builders.
//!
//! [`MaterialProviders`] is the entry-point developers compose against.
//! It carries a [`MaterialProvidersConfig`] and exposes fluent
//! `create_*` factory methods that build the concrete primitives:
//!
//! - [`MaterialProviders::create_cryptographic_materials_cache`] →
//!   `Arc<dyn Cmc>` for use as a [`CacheType::Shared`] across keyrings.
//! - [`MaterialProviders::create_branch_key_store`] → `Arc<BranchKeyStore>`
//!   wired to the supplied AWS clients.
//! - [`MaterialProviders::create_aws_kms_hierarchical_keyring`] →
//!   [`HierarchicalKeyring`] composed of a keystore, a TTL, a branch-key
//!   identifier or supplier, and an optional cache.
//!
//! Every fluent builder's `.send()` is **synchronous and infallible
//! w.r.t. I/O** — none of these factories perform AWS calls. The blueprint
//! example uses `.send().await?` because the underlying ESDK operations
//! really do I/O; our `.send()` is just sugar over the existing
//! constructors. Direct constructors (`HierarchicalKeyring::new`,
//! `BranchKeyStore::new`, `LocalCmc::new`, `StormTrackingCmc::new`)
//! remain public and behave identically.

use std::sync::Arc;

use aws_sdk_dynamodb::Client as DynamoDbClient;
use aws_sdk_kms::Client as KmsClient;

use crate::aws_kms::hierarchical_keyring::{
    BranchKeySource, BranchKeySupplier, CacheType, HierarchicalKeyring,
};
use crate::cmc::{Cmc, LocalCmc, StormTrackingCmc};
use crate::keystore::{BranchKeyStore, KeyStoreConfig, Keystore, KeystoreError};
use crate::structures::MaterialsError;

/// Configuration carried by a [`MaterialProviders`] client.
///
/// Empty today; reserved for future client-level knobs (telemetry
/// hooks, default partition-id strategy, etc.). The struct is
/// `#[non_exhaustive]` so adding fields later is non-breaking.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct MaterialProvidersConfig {}

/// Material Providers Library client. Holds a [`MaterialProvidersConfig`]
/// and serves as the fluent entry point for constructing keystores,
/// caches, and keyrings via `create_*` methods.
///
/// `MaterialProviders` is `Clone` and `&self`-only, so a single instance
/// can be reused to build many primitives.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct MaterialProviders {
    pub(crate) config: MaterialProvidersConfig,
}

impl MaterialProviders {
    /// Construct a `MaterialProviders` client with the given config.
    #[must_use]
    pub const fn new(config: MaterialProvidersConfig) -> Self {
        Self { config }
    }

    /// Start a fluent builder for `MaterialProviders`.
    #[must_use]
    pub fn builder() -> MaterialProvidersBuilder {
        MaterialProvidersBuilder::default()
    }

    /// Borrow this client's configuration.
    #[must_use]
    pub const fn config(&self) -> &MaterialProvidersConfig {
        &self.config
    }

    /// Begin constructing a Cryptographic Materials Cache through this
    /// client. See [`CreateCryptographicMaterialsCacheFluentBuilder`].
    ///
    /// Requires the `keystore` Cargo feature (the [`CacheType`] enum
    /// itself lives behind that flag).
    #[must_use]
    pub fn create_cryptographic_materials_cache(
        &self,
    ) -> CreateCryptographicMaterialsCacheFluentBuilder {
        CreateCryptographicMaterialsCacheFluentBuilder::default()
    }

    /// Begin constructing a [`BranchKeyStore`] through this client.
    /// See [`CreateBranchKeyStoreFluentBuilder`].
    ///
    /// Requires the `keystore` Cargo feature.
    #[must_use]
    pub fn create_branch_key_store(&self) -> CreateBranchKeyStoreFluentBuilder {
        CreateBranchKeyStoreFluentBuilder::default()
    }

    /// Begin constructing an [`HierarchicalKeyring`] through this client.
    /// See [`CreateAwsKmsHierarchicalKeyringFluentBuilder`].
    ///
    /// Requires the `keystore` Cargo feature.
    #[must_use]
    pub fn create_aws_kms_hierarchical_keyring(
        &self,
    ) -> CreateAwsKmsHierarchicalKeyringFluentBuilder {
        CreateAwsKmsHierarchicalKeyringFluentBuilder::default()
    }
}

/// Fluent builder for [`MaterialProviders`]. Today only the config is
/// configurable; `build` is infallible.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct MaterialProvidersBuilder {
    config: MaterialProvidersConfig,
}

impl MaterialProvidersBuilder {
    /// Override the client configuration.
    #[must_use]
    pub fn config(mut self, config: MaterialProvidersConfig) -> Self {
        self.config = config;
        self
    }

    /// Build the `MaterialProviders` client.
    #[must_use]
    pub fn build(self) -> MaterialProviders {
        MaterialProviders {
            config: self.config,
        }
    }
}

// ─── create_cryptographic_materials_cache ───────────────────────────────────

/// Fluent builder produced by
/// [`MaterialProviders::create_cryptographic_materials_cache`].
///
/// Set the desired backing cache via [`Self::cache`], then call
/// [`Self::send`]. The returned `Arc<dyn Cmc>` is suitable for sharing
/// across multiple keyrings via [`CacheType::Shared`].
#[derive(Default)]
pub struct CreateCryptographicMaterialsCacheFluentBuilder {
    cache: Option<CacheType>,
}

impl CreateCryptographicMaterialsCacheFluentBuilder {
    /// Set the [`CacheType`] backing for the constructed cache.
    #[must_use]
    pub fn cache(mut self, cache: CacheType) -> Self {
        self.cache = Some(cache);
        self
    }

    /// Build the cache.
    ///
    /// - [`CacheType::Default`] → a fresh `Arc<LocalCmc>`.
    /// - [`CacheType::Shared`] → returns the supplied `Arc<dyn Cmc>` verbatim.
    /// - [`CacheType::StormTracking`] → a fresh `Arc<StormTrackingCmc>`.
    ///
    /// Returns [`MaterialsError`] if no `cache` was supplied or if the
    /// underlying cache constructor rejects the parameters
    /// (e.g., zero `sleep_milli` for storm tracking).
    pub fn send(self) -> Result<Arc<dyn Cmc>, MaterialsError> {
        let cache = self.cache.ok_or_else(|| {
            MaterialsError::new(
                "create_cryptographic_materials_cache: cache is required (call .cache(...))",
            )
        })?;
        match cache {
            CacheType::Default(default_cache) => {
                let local = LocalCmc::new(
                    default_cache.entry_capacity,
                    default_cache.entry_pruning_tail_size,
                )
                .map_err(|e| {
                    MaterialsError::new(format!(
                        "create_cryptographic_materials_cache: failed to initialize LocalCmc: {e}",
                    ))
                })?;
                Ok(Arc::new(local))
            }
            CacheType::Shared(arc) => Ok(arc),
            CacheType::StormTracking(params) => {
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
                        "create_cryptographic_materials_cache: failed to initialize StormTrackingCmc: {e}",
                    ))
                })?;
                Ok(Arc::new(storm))
            }
        }
    }
}

// ─── create_branch_key_store ────────────────────────────────────────────────

/// Fluent builder produced by [`MaterialProviders::create_branch_key_store`].
///
/// [`Self::key_store_config`] is required; [`Self::kms_client`] and
/// [`Self::ddb_client`] are optional and, when set, populate the config's
/// client fields. When a client is left unset, [`BranchKeyStore::new`]
/// builds a default client from the Region in the configured KMS ARN.
#[derive(Default)]
pub struct CreateBranchKeyStoreFluentBuilder {
    key_store_config: Option<KeyStoreConfig>,
    kms_client: Option<KmsClient>,
    ddb_client: Option<DynamoDbClient>,
}

impl CreateBranchKeyStoreFluentBuilder {
    /// Set the [`KeyStoreConfig`].
    #[must_use]
    pub fn key_store_config(mut self, config: KeyStoreConfig) -> Self {
        self.key_store_config = Some(config);
        self
    }

    /// Set the AWS KMS client used by the keystore for `Decrypt` /
    /// `ReEncrypt` / `GenerateDataKeyWithoutPlaintext`.
    #[must_use]
    pub fn kms_client(mut self, client: KmsClient) -> Self {
        self.kms_client = Some(client);
        self
    }

    /// Set the Amazon DynamoDB client used by the keystore for
    /// `GetItem` / `TransactWriteItems`.
    #[must_use]
    pub fn ddb_client(mut self, client: DynamoDbClient) -> Self {
        self.ddb_client = Some(client);
        self
    }

    /// Build the [`BranchKeyStore`] and wrap it in an `Arc` for direct
    /// use as `Arc<dyn Keystore>` via unsized coercion.
    ///
    /// Returns [`KeystoreError`] when [`Self::key_store_config`] was not
    /// invoked, or when the underlying [`BranchKeyStore::new`] rejects the
    /// configuration (e.g., malformed KMS ARN).
    pub async fn send(self) -> Result<Arc<BranchKeyStore>, KeystoreError> {
        use crate::keystore::error::KeystoreErrorKind;
        let mut key_store_config = self.key_store_config.ok_or_else(|| {
            KeystoreError::new(
                KeystoreErrorKind::Configuration,
                "create_branch_key_store: key_store_config is required (call .key_store_config(...))",
            )
        })?;
        // Builder-level client setters override the config's clients when
        // provided; otherwise the config's own (possibly `None`) clients
        // stand, and `BranchKeyStore::new` defaults any `None`.
        if self.kms_client.is_some() {
            key_store_config.kms_client = self.kms_client;
        }
        if self.ddb_client.is_some() {
            key_store_config.ddb_client = self.ddb_client;
        }
        Ok(Arc::new(BranchKeyStore::new(key_store_config).await?))
    }
}

// ─── create_aws_kms_hierarchical_keyring ────────────────────────────────────

/// Fluent builder produced by
/// [`MaterialProviders::create_aws_kms_hierarchical_keyring`].
///
/// Required setters: [`Self::key_store`], [`Self::ttl_seconds`], and
/// **exactly one** of [`Self::branch_key_id`] or
/// [`Self::branch_key_id_supplier`]. Optional setters: [`Self::cache`]
/// (defaults to [`CacheType::Default`] with spec defaults) and
/// [`Self::partition_id`] (defaults to a fresh v4 UUID).
#[derive(Default)]
pub struct CreateAwsKmsHierarchicalKeyringFluentBuilder {
    key_store: Option<Arc<dyn Keystore>>,
    ttl_seconds: Option<u64>,
    branch_key_id: Option<String>,
    branch_key_id_supplier: Option<Arc<dyn BranchKeySupplier>>,
    cache: Option<CacheType>,
    partition_id: Option<String>,
}

impl CreateAwsKmsHierarchicalKeyringFluentBuilder {
    /// Set the keystore the keyring will resolve branch keys against.
    #[must_use]
    pub fn key_store(mut self, keystore: Arc<dyn Keystore>) -> Self {
        self.key_store = Some(keystore);
        self
    }

    /// Set the cache TTL in seconds. MUST be greater than zero per spec.
    #[must_use]
    pub const fn ttl_seconds(mut self, ttl: u64) -> Self {
        self.ttl_seconds = Some(ttl);
        self
    }

    /// Set a static branch key id. Mutually exclusive with
    /// [`Self::branch_key_id_supplier`].
    #[must_use]
    pub fn branch_key_id(mut self, id: impl Into<String>) -> Self {
        self.branch_key_id = Some(id.into());
        self
    }

    /// Set a [`BranchKeySupplier`] that resolves the branch key id at
    /// encrypt / decrypt time. Mutually exclusive with
    /// [`Self::branch_key_id`].
    #[must_use]
    pub fn branch_key_id_supplier(mut self, supplier: Arc<dyn BranchKeySupplier>) -> Self {
        self.branch_key_id_supplier = Some(supplier);
        self
    }

    /// Set the cache backing the keyring. Defaults to
    /// [`CacheType::Default`] with spec defaults when unset.
    #[must_use]
    pub fn cache(mut self, cache: CacheType) -> Self {
        self.cache = Some(cache);
        self
    }

    /// Set the partition id. Defaults to a fresh v4 UUID when unset.
    #[must_use]
    pub fn partition_id(mut self, id: impl Into<String>) -> Self {
        self.partition_id = Some(id.into());
        self
    }

    /// Build the [`HierarchicalKeyring`].
    ///
    /// Returns [`MaterialsError`] when:
    /// - `key_store` or `ttl_seconds` was not set,
    /// - both or neither of `branch_key_id` / `branch_key_id_supplier` were set,
    /// - or [`HierarchicalKeyring::new`] rejects the parameters.
    pub fn send(self) -> Result<HierarchicalKeyring, MaterialsError> {
        let key_store = self.key_store.ok_or_else(|| {
            MaterialsError::new(
                "create_aws_kms_hierarchical_keyring: key_store is required (call .key_store(...))",
            )
        })?;
        let ttl_seconds = self.ttl_seconds.ok_or_else(|| {
            MaterialsError::new(
                "create_aws_kms_hierarchical_keyring: ttl_seconds is required (call .ttl_seconds(...))",
            )
        })?;
        let branch_key_source = match (self.branch_key_id, self.branch_key_id_supplier) {
            (Some(_), Some(_)) => {
                return Err(MaterialsError::new(
                    "create_aws_kms_hierarchical_keyring: only one of branch_key_id or branch_key_id_supplier may be set",
                ));
            }
            (Some(id), None) => BranchKeySource::Identifier(id),
            (None, Some(supplier)) => BranchKeySource::Supplier(supplier),
            (None, None) => {
                return Err(MaterialsError::new(
                    "create_aws_kms_hierarchical_keyring: one of branch_key_id or branch_key_id_supplier must be set",
                ));
            }
        };
        HierarchicalKeyring::new(
            key_store,
            ttl_seconds,
            branch_key_source,
            self.cache,
            self.partition_id,
        )
    }
}

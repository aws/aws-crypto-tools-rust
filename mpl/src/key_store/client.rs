// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use crate::Error;
use crate::key_store::KeyStore;
use crate::key_store::types::{
    CreateKeyInput, CreateKeyInputBuilder, CreateKeyOutput, CreateKeyStoreInput,
    CreateKeyStoreInputBuilder, CreateKeyStoreOutput, GetActiveBranchKeyInput,
    GetActiveBranchKeyInputBuilder, GetActiveBranchKeyOutput, GetBeaconKeyInput,
    GetBeaconKeyInputBuilder, GetBeaconKeyOutput, GetBranchKeyVersionInput,
    GetBranchKeyVersionInputBuilder, GetBranchKeyVersionOutput, GetKeyStoreInfoInput,
    GetKeyStoreInfoInputBuilder, GetKeyStoreInfoOutput, VersionKeyInput, VersionKeyInputBuilder,
    VersionKeyOutput,
};
use crate::structures::EncryptionContext;

/// A handle to a key store, with one method per key store operation.
///
/// Each method returns a fluent builder: set the input, then call `send`.
///
/// ```no_run
/// # async fn example(key_store: aws_crypto_mpl::KeyStoreClient) -> Result<(), aws_crypto_mpl::Error> {
/// let materials = key_store
///     .get_active_branch_key()
///     .branch_key_id("my-branch-key")
///     .send()
///     .await?
///     .into_branch_key_materials();
/// # Ok(())
/// # }
/// ```
///
/// Cloning is cheap: clones share one key store.
#[derive(Clone)]
pub struct KeyStoreClient {
    inner: Arc<dyn KeyStore>,
}

impl KeyStoreClient {
    /// Wrap `key_store` in a client.
    pub fn new(key_store: impl KeyStore + 'static) -> Self {
        Self {
            inner: Arc::new(key_store),
        }
    }

    /// Start a [`KeyStore::get_key_store_info`] call.
    pub fn get_key_store_info(&self) -> GetKeyStoreInfoFluentBuilder {
        GetKeyStoreInfoFluentBuilder {
            client: self.clone(),
            inner: GetKeyStoreInfoInput::builder(),
        }
    }

    /// Start a [`KeyStore::create_key_store`] call.
    pub fn create_key_store(&self) -> CreateKeyStoreFluentBuilder {
        CreateKeyStoreFluentBuilder {
            client: self.clone(),
            inner: CreateKeyStoreInput::builder(),
        }
    }

    /// Start a [`KeyStore::create_key`] call.
    pub fn create_key(&self) -> CreateKeyFluentBuilder {
        CreateKeyFluentBuilder {
            client: self.clone(),
            inner: CreateKeyInput::builder(),
        }
    }

    /// Start a [`KeyStore::version_key`] call.
    pub fn version_key(&self) -> VersionKeyFluentBuilder {
        VersionKeyFluentBuilder {
            client: self.clone(),
            inner: VersionKeyInput::builder(),
        }
    }

    /// Start a [`KeyStore::get_active_branch_key`] call.
    pub fn get_active_branch_key(&self) -> GetActiveBranchKeyFluentBuilder {
        GetActiveBranchKeyFluentBuilder {
            client: self.clone(),
            inner: GetActiveBranchKeyInput::builder(),
        }
    }

    /// Start a [`KeyStore::get_branch_key_version`] call.
    pub fn get_branch_key_version(&self) -> GetBranchKeyVersionFluentBuilder {
        GetBranchKeyVersionFluentBuilder {
            client: self.clone(),
            inner: GetBranchKeyVersionInput::builder(),
        }
    }

    /// Start a [`KeyStore::get_beacon_key`] call.
    pub fn get_beacon_key(&self) -> GetBeaconKeyFluentBuilder {
        GetBeaconKeyFluentBuilder {
            client: self.clone(),
            inner: GetBeaconKeyInput::builder(),
        }
    }
}

impl<T: KeyStore + 'static> From<T> for KeyStoreClient {
    fn from(key_store: T) -> Self {
        Self::new(key_store)
    }
}

impl std::fmt::Debug for KeyStoreClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyStoreClient").finish_non_exhaustive()
    }
}

/// Fluent builder for [`KeyStoreClient::get_key_store_info`].
#[derive(Debug, Clone)]
#[must_use = "does nothing until `send` is called"]
pub struct GetKeyStoreInfoFluentBuilder {
    client: KeyStoreClient,
    inner: GetKeyStoreInfoInputBuilder,
}

impl GetKeyStoreInfoFluentBuilder {
    /// The input set so far.
    #[must_use]
    pub const fn as_input(&self) -> &GetKeyStoreInfoInputBuilder {
        &self.inner
    }

    /// Send the request.
    ///
    /// # Errors
    ///
    /// The errors [`KeyStore::get_key_store_info`] documents.
    pub async fn send(self) -> Result<GetKeyStoreInfoOutput, Error> {
        let input = self.inner.build()?;
        self.client.inner.get_key_store_info(input).await
    }
}

/// Fluent builder for [`KeyStoreClient::create_key_store`].
#[derive(Debug, Clone)]
#[must_use = "does nothing until `send` is called"]
pub struct CreateKeyStoreFluentBuilder {
    client: KeyStoreClient,
    inner: CreateKeyStoreInputBuilder,
}

impl CreateKeyStoreFluentBuilder {
    /// The input set so far.
    #[must_use]
    pub const fn as_input(&self) -> &CreateKeyStoreInputBuilder {
        &self.inner
    }

    /// Send the request.
    ///
    /// # Errors
    ///
    /// The errors [`KeyStore::create_key_store`] documents.
    pub async fn send(self) -> Result<CreateKeyStoreOutput, Error> {
        let input = self.inner.build()?;
        self.client.inner.create_key_store(input).await
    }
}

/// Fluent builder for [`KeyStoreClient::create_key`].
#[derive(Debug, Clone)]
#[must_use = "does nothing until `send` is called"]
pub struct CreateKeyFluentBuilder {
    client: KeyStoreClient,
    inner: CreateKeyInputBuilder,
}

impl CreateKeyFluentBuilder {
    /// The input set so far.
    #[must_use]
    pub const fn as_input(&self) -> &CreateKeyInputBuilder {
        &self.inner
    }

    /// Set the identifier for the new branch key.
    /// When unset, the key store generates one.
    pub fn branch_key_id(mut self, branch_key_id: impl Into<String>) -> Self {
        self.inner = self.inner.branch_key_id(branch_key_id);
        self
    }

    /// Set or clear the branch key identifier from an `Option`.
    /// To add one entry, use [`Self::branch_key_id`].
    pub fn set_branch_key_id(mut self, branch_key_id: Option<String>) -> Self {
        self.inner = self.inner.set_branch_key_id(branch_key_id);
        self
    }

    /// The branch key id, if set.
    #[must_use]
    pub const fn get_branch_key_id(&self) -> &Option<String> {
        self.inner.get_branch_key_id()
    }

    /// Add one key-value pair to the custom encryption context for the new branch key.
    /// Required when `branch_key_id` is set.
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
    /// The errors [`KeyStore::create_key`] documents.
    pub async fn send(self) -> Result<CreateKeyOutput, Error> {
        let input = self.inner.build()?;
        self.client.inner.create_key(input).await
    }
}

/// Fluent builder for [`KeyStoreClient::version_key`].
#[derive(Debug, Clone)]
#[must_use = "does nothing until `send` is called"]
pub struct VersionKeyFluentBuilder {
    client: KeyStoreClient,
    inner: VersionKeyInputBuilder,
}

impl VersionKeyFluentBuilder {
    /// The input set so far.
    #[must_use]
    pub const fn as_input(&self) -> &VersionKeyInputBuilder {
        &self.inner
    }

    /// Set the identifier of the branch key to rotate.
    /// Required.
    pub fn branch_key_id(mut self, branch_key_id: impl Into<String>) -> Self {
        self.inner = self.inner.branch_key_id(branch_key_id);
        self
    }

    /// Set or clear the branch key identifier from an `Option`.
    /// To set a value, use [`Self::branch_key_id`].
    pub fn set_branch_key_id(mut self, branch_key_id: Option<String>) -> Self {
        self.inner = self.inner.set_branch_key_id(branch_key_id);
        self
    }

    /// The branch key id, if set.
    #[must_use]
    pub const fn get_branch_key_id(&self) -> &Option<String> {
        self.inner.get_branch_key_id()
    }

    /// Send the request.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): `branch_key_id` is unset.
    ///
    /// Otherwise, the errors [`KeyStore::version_key`] documents.
    pub async fn send(self) -> Result<VersionKeyOutput, Error> {
        let input = self.inner.build()?;
        self.client.inner.version_key(input).await
    }
}

/// Fluent builder for [`KeyStoreClient::get_active_branch_key`].
#[derive(Debug, Clone)]
#[must_use = "does nothing until `send` is called"]
pub struct GetActiveBranchKeyFluentBuilder {
    client: KeyStoreClient,
    inner: GetActiveBranchKeyInputBuilder,
}

impl GetActiveBranchKeyFluentBuilder {
    /// The input set so far.
    #[must_use]
    pub const fn as_input(&self) -> &GetActiveBranchKeyInputBuilder {
        &self.inner
    }

    /// Set the branch key identifier.
    /// Required.
    pub fn branch_key_id(mut self, branch_key_id: impl Into<String>) -> Self {
        self.inner = self.inner.branch_key_id(branch_key_id);
        self
    }

    /// Set or clear the branch key identifier from an `Option`.
    /// To set a value, use [`Self::branch_key_id`].
    pub fn set_branch_key_id(mut self, branch_key_id: Option<String>) -> Self {
        self.inner = self.inner.set_branch_key_id(branch_key_id);
        self
    }

    /// The branch key id, if set.
    #[must_use]
    pub const fn get_branch_key_id(&self) -> &Option<String> {
        self.inner.get_branch_key_id()
    }

    /// Send the request.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): `branch_key_id` is unset.
    ///
    /// Otherwise, the errors [`KeyStore::get_active_branch_key`] documents.
    pub async fn send(self) -> Result<GetActiveBranchKeyOutput, Error> {
        let input = self.inner.build()?;
        self.client.inner.get_active_branch_key(input).await
    }
}

/// Fluent builder for [`KeyStoreClient::get_branch_key_version`].
#[derive(Debug, Clone)]
#[must_use = "does nothing until `send` is called"]
pub struct GetBranchKeyVersionFluentBuilder {
    client: KeyStoreClient,
    inner: GetBranchKeyVersionInputBuilder,
}

impl GetBranchKeyVersionFluentBuilder {
    /// The input set so far.
    #[must_use]
    pub const fn as_input(&self) -> &GetBranchKeyVersionInputBuilder {
        &self.inner
    }

    /// Set the branch key identifier.
    /// Required.
    pub fn branch_key_id(mut self, branch_key_id: impl Into<String>) -> Self {
        self.inner = self.inner.branch_key_id(branch_key_id);
        self
    }

    /// Set or clear the branch key identifier from an `Option`.
    /// To set a value, use [`Self::branch_key_id`].
    pub fn set_branch_key_id(mut self, branch_key_id: Option<String>) -> Self {
        self.inner = self.inner.set_branch_key_id(branch_key_id);
        self
    }

    /// The branch key id, if set.
    #[must_use]
    pub const fn get_branch_key_id(&self) -> &Option<String> {
        self.inner.get_branch_key_id()
    }

    /// Set the branch key version.
    /// Required.
    pub fn branch_key_version(mut self, branch_key_version: impl Into<String>) -> Self {
        self.inner = self.inner.branch_key_version(branch_key_version);
        self
    }

    /// Set or clear the branch key version from an `Option`.
    /// To set a value, use [`Self::branch_key_version`].
    pub fn set_branch_key_version(mut self, branch_key_version: Option<String>) -> Self {
        self.inner = self.inner.set_branch_key_version(branch_key_version);
        self
    }

    /// The branch key version, if set.
    #[must_use]
    pub const fn get_branch_key_version(&self) -> &Option<String> {
        self.inner.get_branch_key_version()
    }

    /// Send the request.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): `branch_key_id` or `branch_key_version` is unset.
    ///
    /// Otherwise, the errors [`KeyStore::get_branch_key_version`] documents.
    pub async fn send(self) -> Result<GetBranchKeyVersionOutput, Error> {
        let input = self.inner.build()?;
        self.client.inner.get_branch_key_version(input).await
    }
}

/// Fluent builder for [`KeyStoreClient::get_beacon_key`].
#[derive(Debug, Clone)]
#[must_use = "does nothing until `send` is called"]
pub struct GetBeaconKeyFluentBuilder {
    client: KeyStoreClient,
    inner: GetBeaconKeyInputBuilder,
}

impl GetBeaconKeyFluentBuilder {
    /// The input set so far.
    #[must_use]
    pub const fn as_input(&self) -> &GetBeaconKeyInputBuilder {
        &self.inner
    }

    /// Set the branch key identifier.
    /// Required.
    pub fn branch_key_id(mut self, branch_key_id: impl Into<String>) -> Self {
        self.inner = self.inner.branch_key_id(branch_key_id);
        self
    }

    /// Set or clear the branch key identifier from an `Option`.
    /// To set a value, use [`Self::branch_key_id`].
    pub fn set_branch_key_id(mut self, branch_key_id: Option<String>) -> Self {
        self.inner = self.inner.set_branch_key_id(branch_key_id);
        self
    }

    /// The branch key id, if set.
    #[must_use]
    pub const fn get_branch_key_id(&self) -> &Option<String> {
        self.inner.get_branch_key_id()
    }

    /// Send the request.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): `branch_key_id` is unset.
    ///
    /// Otherwise, the errors [`KeyStore::get_beacon_key`] documents.
    pub async fn send(self) -> Result<GetBeaconKeyOutput, Error> {
        let input = self.inner.build()?;
        self.client.inner.get_beacon_key(input).await
    }
}

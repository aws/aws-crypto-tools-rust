// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Inputs and outputs of the [`KeyStore`](super::KeyStore) operations.

use crate::Error;
use crate::builder::required;
use crate::key_store::KmsConfiguration;
use crate::structures::{BeaconKeyMaterials, BranchKeyMaterials, EncryptionContext};

/// Input for [`KeyStore::get_key_store_info`](super::KeyStore::get_key_store_info).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct GetKeyStoreInfoInput {}

impl GetKeyStoreInfoInput {
    /// Start a builder for `GetKeyStoreInfoInput`.
    #[must_use]
    pub fn builder() -> GetKeyStoreInfoInputBuilder {
        GetKeyStoreInfoInputBuilder::default()
    }
}

/// Builder for [`GetKeyStoreInfoInput`].
#[derive(Debug, Clone, Default)]
pub struct GetKeyStoreInfoInputBuilder {}

impl GetKeyStoreInfoInputBuilder {
    /// Build the `GetKeyStoreInfoInput`.
    ///
    /// # Errors
    ///
    /// Never returns an error.
    pub fn build(self) -> Result<GetKeyStoreInfoInput, Error> {
        Ok(GetKeyStoreInfoInput {})
    }
}

/// Output of [`KeyStore::get_key_store_info`](super::KeyStore::get_key_store_info).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct GetKeyStoreInfoOutput {
    pub(crate) key_store_id: String,
    pub(crate) key_store_name: String,
    pub(crate) logical_key_store_name: String,
    pub(crate) grant_tokens: Vec<String>,
    pub(crate) kms_configuration: KmsConfiguration,
}

impl GetKeyStoreInfoOutput {
    /// Start a builder for `GetKeyStoreInfoOutput`.
    #[must_use]
    pub fn builder() -> GetKeyStoreInfoOutputBuilder {
        GetKeyStoreInfoOutputBuilder::default()
    }

    /// The key store identifier.
    #[must_use]
    pub fn key_store_id(&self) -> &str {
        &self.key_store_id
    }

    /// The DynamoDB table name that backs the key store.
    #[must_use]
    pub fn key_store_name(&self) -> &str {
        &self.key_store_name
    }

    /// The logical key store name, which is cryptographically bound to the keys it holds.
    #[must_use]
    pub fn logical_key_store_name(&self) -> &str {
        &self.logical_key_store_name
    }

    /// The AWS KMS grant tokens the key store uses.
    #[must_use]
    pub fn grant_tokens(&self) -> &[String] {
        &self.grant_tokens
    }

    /// The KMS configuration of the key store.
    #[must_use]
    pub const fn kms_configuration(&self) -> &KmsConfiguration {
        &self.kms_configuration
    }
}

/// Builder for [`GetKeyStoreInfoOutput`].
#[derive(Debug, Clone, Default)]
pub struct GetKeyStoreInfoOutputBuilder {
    key_store_id: Option<String>,
    key_store_name: Option<String>,
    logical_key_store_name: Option<String>,
    grant_tokens: Option<Vec<String>>,
    kms_configuration: Option<KmsConfiguration>,
}

impl GetKeyStoreInfoOutputBuilder {
    /// Set the key store identifier.
    /// Required.
    #[must_use]
    pub fn key_store_id(mut self, key_store_id: impl Into<String>) -> Self {
        self.key_store_id = Some(key_store_id.into());
        self
    }

    /// Set or clear the key store identifier from an `Option`.
    /// To set a value, use [`Self::key_store_id`].
    #[must_use]
    pub fn set_key_store_id(mut self, key_store_id: Option<String>) -> Self {
        self.key_store_id = key_store_id;
        self
    }

    /// The key store ID, if set.
    #[must_use]
    pub const fn get_key_store_id(&self) -> &Option<String> {
        &self.key_store_id
    }

    /// Set the DynamoDB table name that backs the key store.
    /// Required.
    #[must_use]
    pub fn key_store_name(mut self, key_store_name: impl Into<String>) -> Self {
        self.key_store_name = Some(key_store_name.into());
        self
    }

    /// Set or clear the DynamoDB table name from an `Option`.
    /// To set a value, use [`Self::key_store_name`].
    #[must_use]
    pub fn set_key_store_name(mut self, key_store_name: Option<String>) -> Self {
        self.key_store_name = key_store_name;
        self
    }

    /// The key store name, if set.
    #[must_use]
    pub const fn get_key_store_name(&self) -> &Option<String> {
        &self.key_store_name
    }

    /// Set the logical key store name, which is cryptographically bound to the keys it holds.
    /// Required.
    #[must_use]
    pub fn logical_key_store_name(mut self, logical_key_store_name: impl Into<String>) -> Self {
        self.logical_key_store_name = Some(logical_key_store_name.into());
        self
    }

    /// Set or clear the logical key store name from an `Option`.
    /// To set a value, use [`Self::logical_key_store_name`].
    #[must_use]
    pub fn set_logical_key_store_name(mut self, logical_key_store_name: Option<String>) -> Self {
        self.logical_key_store_name = logical_key_store_name;
        self
    }

    /// The logical key store name, if set.
    #[must_use]
    pub const fn get_logical_key_store_name(&self) -> &Option<String> {
        &self.logical_key_store_name
    }

    /// Appends an item to the AWS KMS grant tokens the key store uses.
    ///
    /// To override the contents of this collection use [`set_grant_tokens`](Self::set_grant_tokens).
    /// Required.
    #[must_use]
    pub fn grant_tokens(mut self, input: impl Into<String>) -> Self {
        self.grant_tokens
            .get_or_insert_with(Default::default)
            .push(input.into());
        self
    }

    /// Set or clear the grant tokens from an `Option`.
    /// To add one entry, use [`Self::grant_tokens`].
    #[must_use]
    pub fn set_grant_tokens(mut self, grant_tokens: Option<Vec<String>>) -> Self {
        self.grant_tokens = grant_tokens;
        self
    }

    /// The grant tokens, if set.
    #[must_use]
    pub const fn get_grant_tokens(&self) -> &Option<Vec<String>> {
        &self.grant_tokens
    }

    /// Set the KMS configuration of the key store.
    /// Required.
    #[must_use]
    pub fn kms_configuration(mut self, kms_configuration: impl Into<KmsConfiguration>) -> Self {
        self.kms_configuration = Some(kms_configuration.into());
        self
    }

    /// Set or clear the KMS configuration from an `Option`.
    /// To set a value, use [`Self::kms_configuration`].
    #[must_use]
    pub fn set_kms_configuration(mut self, kms_configuration: Option<KmsConfiguration>) -> Self {
        self.kms_configuration = kms_configuration;
        self
    }

    /// The KMS configuration, if set.
    #[must_use]
    pub const fn get_kms_configuration(&self) -> &Option<KmsConfiguration> {
        &self.kms_configuration
    }

    /// Build the `GetKeyStoreInfoOutput`.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): `key_store_id`, `key_store_name`, `logical_key_store_name`, `grant_tokens` or `kms_configuration` is unset.
    pub fn build(self) -> Result<GetKeyStoreInfoOutput, Error> {
        Ok(GetKeyStoreInfoOutput {
            key_store_id: required(self.key_store_id, "key_store_id")?,
            key_store_name: required(self.key_store_name, "key_store_name")?,
            logical_key_store_name: required(
                self.logical_key_store_name,
                "logical_key_store_name",
            )?,
            grant_tokens: required(self.grant_tokens, "grant_tokens")?,
            kms_configuration: required(self.kms_configuration, "kms_configuration")?,
        })
    }
}

/// Input for [`KeyStore::create_key_store`](super::KeyStore::create_key_store).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CreateKeyStoreInput {}

impl CreateKeyStoreInput {
    /// Start a builder for `CreateKeyStoreInput`.
    #[must_use]
    pub fn builder() -> CreateKeyStoreInputBuilder {
        CreateKeyStoreInputBuilder::default()
    }
}

/// Builder for [`CreateKeyStoreInput`].
#[derive(Debug, Clone, Default)]
pub struct CreateKeyStoreInputBuilder {}

impl CreateKeyStoreInputBuilder {
    /// Build the `CreateKeyStoreInput`.
    ///
    /// # Errors
    ///
    /// Never returns an error.
    pub fn build(self) -> Result<CreateKeyStoreInput, Error> {
        Ok(CreateKeyStoreInput {})
    }
}

/// Output of [`KeyStore::create_key_store`](super::KeyStore::create_key_store).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CreateKeyStoreOutput {
    pub(crate) table_arn: String,
}

impl CreateKeyStoreOutput {
    /// Start a builder for `CreateKeyStoreOutput`.
    #[must_use]
    pub fn builder() -> CreateKeyStoreOutputBuilder {
        CreateKeyStoreOutputBuilder::default()
    }

    /// The ARN of the DynamoDB table that backs the key store.
    #[must_use]
    pub fn table_arn(&self) -> &str {
        &self.table_arn
    }

    /// The table ARN, consuming the output.
    #[must_use]
    pub fn into_table_arn(self) -> String {
        self.table_arn
    }
}

/// Builder for [`CreateKeyStoreOutput`].
#[derive(Debug, Clone, Default)]
pub struct CreateKeyStoreOutputBuilder {
    table_arn: Option<String>,
}

impl CreateKeyStoreOutputBuilder {
    /// Set the ARN of the DynamoDB table that backs the key store.
    /// Required.
    #[must_use]
    pub fn table_arn(mut self, table_arn: impl Into<String>) -> Self {
        self.table_arn = Some(table_arn.into());
        self
    }

    /// Set or clear the table ARN from an `Option`.
    /// To set a value, use [`Self::table_arn`].
    #[must_use]
    pub fn set_table_arn(mut self, table_arn: Option<String>) -> Self {
        self.table_arn = table_arn;
        self
    }

    /// The table ARN, if set.
    #[must_use]
    pub const fn get_table_arn(&self) -> &Option<String> {
        &self.table_arn
    }

    /// Build the `CreateKeyStoreOutput`.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): `table_arn` is unset.
    pub fn build(self) -> Result<CreateKeyStoreOutput, Error> {
        Ok(CreateKeyStoreOutput {
            table_arn: required(self.table_arn, "table_arn")?,
        })
    }
}

/// Input for [`KeyStore::create_key`](super::KeyStore::create_key).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CreateKeyInput {
    pub(crate) branch_key_id: Option<String>,
    pub(crate) encryption_context: Option<EncryptionContext>,
}

impl CreateKeyInput {
    /// Start a builder for `CreateKeyInput`.
    #[must_use]
    pub fn builder() -> CreateKeyInputBuilder {
        CreateKeyInputBuilder::default()
    }

    /// The identifier for the new branch key.
    /// When unset, the key store generates one.
    #[must_use]
    pub fn branch_key_id(&self) -> Option<&str> {
        self.branch_key_id.as_deref()
    }

    /// The custom encryption context for the new branch key.
    /// Required when `branch_key_id` is set.
    #[must_use]
    pub fn encryption_context(&self) -> Option<&EncryptionContext> {
        self.encryption_context.as_ref()
    }
}

/// Builder for [`CreateKeyInput`].
#[derive(Debug, Clone, Default)]
pub struct CreateKeyInputBuilder {
    branch_key_id: Option<String>,
    encryption_context: Option<EncryptionContext>,
}

impl CreateKeyInputBuilder {
    /// Set the identifier for the new branch key.
    /// When unset, the key store generates one.
    #[must_use]
    pub fn branch_key_id(mut self, branch_key_id: impl Into<String>) -> Self {
        self.branch_key_id = Some(branch_key_id.into());
        self
    }

    /// Set or clear the branch key identifier from an `Option`.
    /// To set a value, use [`Self::branch_key_id`].
    #[must_use]
    pub fn set_branch_key_id(mut self, branch_key_id: Option<String>) -> Self {
        self.branch_key_id = branch_key_id;
        self
    }

    /// The branch key identifier, if set.
    #[must_use]
    pub const fn get_branch_key_id(&self) -> &Option<String> {
        &self.branch_key_id
    }

    /// Adds a key-value pair to the custom encryption context for the new branch key.
    ///
    /// To override the contents of this collection use [`set_encryption_context`](Self::set_encryption_context).
    /// Required when `branch_key_id` is set.
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

    /// Build the `CreateKeyInput`.
    ///
    /// # Errors
    ///
    /// Never returns an error.
    pub fn build(self) -> Result<CreateKeyInput, Error> {
        Ok(CreateKeyInput {
            branch_key_id: self.branch_key_id,
            encryption_context: self.encryption_context,
        })
    }
}

/// Output of [`KeyStore::create_key`](super::KeyStore::create_key).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CreateKeyOutput {
    pub(crate) branch_key_id: String,
}

impl CreateKeyOutput {
    /// Start a builder for `CreateKeyOutput`.
    #[must_use]
    pub fn builder() -> CreateKeyOutputBuilder {
        CreateKeyOutputBuilder::default()
    }

    /// The identifier of the created branch key.
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

/// Builder for [`CreateKeyOutput`].
#[derive(Debug, Clone, Default)]
pub struct CreateKeyOutputBuilder {
    branch_key_id: Option<String>,
}

impl CreateKeyOutputBuilder {
    /// Set the identifier of the created branch key.
    /// Required.
    #[must_use]
    pub fn branch_key_id(mut self, branch_key_id: impl Into<String>) -> Self {
        self.branch_key_id = Some(branch_key_id.into());
        self
    }

    /// Set or clear the branch key identifier from an `Option`.
    /// To set a value, use [`Self::branch_key_id`].
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

    /// Build the `CreateKeyOutput`.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): `branch_key_id` is unset.
    pub fn build(self) -> Result<CreateKeyOutput, Error> {
        Ok(CreateKeyOutput {
            branch_key_id: required(self.branch_key_id, "branch_key_id")?,
        })
    }
}

/// Input for [`KeyStore::version_key`](super::KeyStore::version_key).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VersionKeyInput {
    pub(crate) branch_key_id: String,
}

impl VersionKeyInput {
    /// Start a builder for `VersionKeyInput`.
    #[must_use]
    pub fn builder() -> VersionKeyInputBuilder {
        VersionKeyInputBuilder::default()
    }

    /// The identifier of the branch key to rotate.
    #[must_use]
    pub fn branch_key_id(&self) -> &str {
        &self.branch_key_id
    }
}

/// Builder for [`VersionKeyInput`].
#[derive(Debug, Clone, Default)]
pub struct VersionKeyInputBuilder {
    branch_key_id: Option<String>,
}

impl VersionKeyInputBuilder {
    /// Set the identifier of the branch key to rotate.
    /// Required.
    #[must_use]
    pub fn branch_key_id(mut self, branch_key_id: impl Into<String>) -> Self {
        self.branch_key_id = Some(branch_key_id.into());
        self
    }

    /// Set or clear the branch key identifier from an `Option`.
    /// To set a value, use [`Self::branch_key_id`].
    #[must_use]
    pub fn set_branch_key_id(mut self, branch_key_id: Option<String>) -> Self {
        self.branch_key_id = branch_key_id;
        self
    }

    /// The branch key identifier, if set.
    #[must_use]
    pub const fn get_branch_key_id(&self) -> &Option<String> {
        &self.branch_key_id
    }

    /// Build the `VersionKeyInput`.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): `branch_key_id` is unset.
    pub fn build(self) -> Result<VersionKeyInput, Error> {
        Ok(VersionKeyInput {
            branch_key_id: required(self.branch_key_id, "branch_key_id")?,
        })
    }
}

/// Output of [`KeyStore::version_key`](super::KeyStore::version_key).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VersionKeyOutput {}

impl VersionKeyOutput {
    /// Start a builder for `VersionKeyOutput`.
    #[must_use]
    pub fn builder() -> VersionKeyOutputBuilder {
        VersionKeyOutputBuilder::default()
    }
}

/// Builder for [`VersionKeyOutput`].
#[derive(Debug, Clone, Default)]
pub struct VersionKeyOutputBuilder {}

impl VersionKeyOutputBuilder {
    /// Build the `VersionKeyOutput`.
    ///
    /// # Errors
    ///
    /// Never returns an error.
    pub fn build(self) -> Result<VersionKeyOutput, Error> {
        Ok(VersionKeyOutput {})
    }
}

/// Input for [`KeyStore::get_active_branch_key`](super::KeyStore::get_active_branch_key).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct GetActiveBranchKeyInput {
    pub(crate) branch_key_id: String,
}

impl GetActiveBranchKeyInput {
    /// Start a builder for `GetActiveBranchKeyInput`.
    #[must_use]
    pub fn builder() -> GetActiveBranchKeyInputBuilder {
        GetActiveBranchKeyInputBuilder::default()
    }

    /// The branch key identifier.
    #[must_use]
    pub fn branch_key_id(&self) -> &str {
        &self.branch_key_id
    }
}

/// Builder for [`GetActiveBranchKeyInput`].
#[derive(Debug, Clone, Default)]
pub struct GetActiveBranchKeyInputBuilder {
    branch_key_id: Option<String>,
}

impl GetActiveBranchKeyInputBuilder {
    /// Set the branch key identifier.
    /// Required.
    #[must_use]
    pub fn branch_key_id(mut self, branch_key_id: impl Into<String>) -> Self {
        self.branch_key_id = Some(branch_key_id.into());
        self
    }

    /// Set or clear the branch key identifier from an `Option`.
    /// To set a value, use [`Self::branch_key_id`].
    #[must_use]
    pub fn set_branch_key_id(mut self, branch_key_id: Option<String>) -> Self {
        self.branch_key_id = branch_key_id;
        self
    }

    /// The branch key identifier, if set.
    #[must_use]
    pub const fn get_branch_key_id(&self) -> &Option<String> {
        &self.branch_key_id
    }

    /// Build the `GetActiveBranchKeyInput`.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): `branch_key_id` is unset.
    pub fn build(self) -> Result<GetActiveBranchKeyInput, Error> {
        Ok(GetActiveBranchKeyInput {
            branch_key_id: required(self.branch_key_id, "branch_key_id")?,
        })
    }
}

/// Output of [`KeyStore::get_active_branch_key`](super::KeyStore::get_active_branch_key).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct GetActiveBranchKeyOutput {
    pub(crate) branch_key_materials: BranchKeyMaterials,
}

impl GetActiveBranchKeyOutput {
    /// Start a builder for `GetActiveBranchKeyOutput`.
    #[must_use]
    pub fn builder() -> GetActiveBranchKeyOutputBuilder {
        GetActiveBranchKeyOutputBuilder::default()
    }

    /// The ACTIVE branch key materials.
    #[must_use]
    pub const fn branch_key_materials(&self) -> &BranchKeyMaterials {
        &self.branch_key_materials
    }

    /// The branch key materials, consuming the output.
    #[must_use]
    pub fn into_branch_key_materials(self) -> BranchKeyMaterials {
        self.branch_key_materials
    }
}

/// Builder for [`GetActiveBranchKeyOutput`].
#[derive(Debug, Clone, Default)]
pub struct GetActiveBranchKeyOutputBuilder {
    branch_key_materials: Option<BranchKeyMaterials>,
}

impl GetActiveBranchKeyOutputBuilder {
    /// Set the ACTIVE branch key materials.
    /// Required.
    #[must_use]
    pub fn branch_key_materials(
        mut self,
        branch_key_materials: impl Into<BranchKeyMaterials>,
    ) -> Self {
        self.branch_key_materials = Some(branch_key_materials.into());
        self
    }

    /// Set or clear the branch key materials from an `Option`.
    /// To set a value, use [`Self::branch_key_materials`].
    #[must_use]
    pub fn set_branch_key_materials(
        mut self,
        branch_key_materials: Option<BranchKeyMaterials>,
    ) -> Self {
        self.branch_key_materials = branch_key_materials;
        self
    }

    /// The branch key materials, if set.
    #[must_use]
    pub const fn get_branch_key_materials(&self) -> &Option<BranchKeyMaterials> {
        &self.branch_key_materials
    }

    /// Build the `GetActiveBranchKeyOutput`.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): `branch_key_materials` is unset.
    pub fn build(self) -> Result<GetActiveBranchKeyOutput, Error> {
        Ok(GetActiveBranchKeyOutput {
            branch_key_materials: required(self.branch_key_materials, "branch_key_materials")?,
        })
    }
}

/// Input for [`KeyStore::get_branch_key_version`](super::KeyStore::get_branch_key_version).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct GetBranchKeyVersionInput {
    pub(crate) branch_key_id: String,
    pub(crate) branch_key_version: String,
}

impl GetBranchKeyVersionInput {
    /// Start a builder for `GetBranchKeyVersionInput`.
    #[must_use]
    pub fn builder() -> GetBranchKeyVersionInputBuilder {
        GetBranchKeyVersionInputBuilder::default()
    }

    /// The branch key identifier.
    #[must_use]
    pub fn branch_key_id(&self) -> &str {
        &self.branch_key_id
    }

    /// The branch key version.
    #[must_use]
    pub fn branch_key_version(&self) -> &str {
        &self.branch_key_version
    }
}

/// Builder for [`GetBranchKeyVersionInput`].
#[derive(Debug, Clone, Default)]
pub struct GetBranchKeyVersionInputBuilder {
    branch_key_id: Option<String>,
    branch_key_version: Option<String>,
}

impl GetBranchKeyVersionInputBuilder {
    /// Set the branch key identifier.
    /// Required.
    #[must_use]
    pub fn branch_key_id(mut self, branch_key_id: impl Into<String>) -> Self {
        self.branch_key_id = Some(branch_key_id.into());
        self
    }

    /// Set or clear the branch key identifier from an `Option`.
    /// To set a value, use [`Self::branch_key_id`].
    #[must_use]
    pub fn set_branch_key_id(mut self, branch_key_id: Option<String>) -> Self {
        self.branch_key_id = branch_key_id;
        self
    }

    /// The branch key identifier, if set.
    #[must_use]
    pub const fn get_branch_key_id(&self) -> &Option<String> {
        &self.branch_key_id
    }

    /// Set the branch key version.
    /// Required.
    #[must_use]
    pub fn branch_key_version(mut self, branch_key_version: impl Into<String>) -> Self {
        self.branch_key_version = Some(branch_key_version.into());
        self
    }

    /// Set or clear the branch key version from an `Option`.
    /// To set a value, use [`Self::branch_key_version`].
    #[must_use]
    pub fn set_branch_key_version(mut self, branch_key_version: Option<String>) -> Self {
        self.branch_key_version = branch_key_version;
        self
    }

    /// The branch key version, if set.
    #[must_use]
    pub const fn get_branch_key_version(&self) -> &Option<String> {
        &self.branch_key_version
    }

    /// Build the `GetBranchKeyVersionInput`.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): `branch_key_id` or `branch_key_version` is unset.
    pub fn build(self) -> Result<GetBranchKeyVersionInput, Error> {
        Ok(GetBranchKeyVersionInput {
            branch_key_id: required(self.branch_key_id, "branch_key_id")?,
            branch_key_version: required(self.branch_key_version, "branch_key_version")?,
        })
    }
}

/// Output of [`KeyStore::get_branch_key_version`](super::KeyStore::get_branch_key_version).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct GetBranchKeyVersionOutput {
    pub(crate) branch_key_materials: BranchKeyMaterials,
}

impl GetBranchKeyVersionOutput {
    /// Start a builder for `GetBranchKeyVersionOutput`.
    #[must_use]
    pub fn builder() -> GetBranchKeyVersionOutputBuilder {
        GetBranchKeyVersionOutputBuilder::default()
    }

    /// The branch key materials for the requested version.
    #[must_use]
    pub const fn branch_key_materials(&self) -> &BranchKeyMaterials {
        &self.branch_key_materials
    }

    /// The branch key materials, consuming the output.
    #[must_use]
    pub fn into_branch_key_materials(self) -> BranchKeyMaterials {
        self.branch_key_materials
    }
}

/// Builder for [`GetBranchKeyVersionOutput`].
#[derive(Debug, Clone, Default)]
pub struct GetBranchKeyVersionOutputBuilder {
    branch_key_materials: Option<BranchKeyMaterials>,
}

impl GetBranchKeyVersionOutputBuilder {
    /// Set the branch key materials for the requested version.
    /// Required.
    #[must_use]
    pub fn branch_key_materials(
        mut self,
        branch_key_materials: impl Into<BranchKeyMaterials>,
    ) -> Self {
        self.branch_key_materials = Some(branch_key_materials.into());
        self
    }

    /// Set or clear the branch key materials from an `Option`.
    /// To set a value, use [`Self::branch_key_materials`].
    #[must_use]
    pub fn set_branch_key_materials(
        mut self,
        branch_key_materials: Option<BranchKeyMaterials>,
    ) -> Self {
        self.branch_key_materials = branch_key_materials;
        self
    }

    /// The branch key materials, if set.
    #[must_use]
    pub const fn get_branch_key_materials(&self) -> &Option<BranchKeyMaterials> {
        &self.branch_key_materials
    }

    /// Build the `GetBranchKeyVersionOutput`.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): `branch_key_materials` is unset.
    pub fn build(self) -> Result<GetBranchKeyVersionOutput, Error> {
        Ok(GetBranchKeyVersionOutput {
            branch_key_materials: required(self.branch_key_materials, "branch_key_materials")?,
        })
    }
}

/// Input for [`KeyStore::get_beacon_key`](super::KeyStore::get_beacon_key).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct GetBeaconKeyInput {
    pub(crate) branch_key_id: String,
}

impl GetBeaconKeyInput {
    /// Start a builder for `GetBeaconKeyInput`.
    #[must_use]
    pub fn builder() -> GetBeaconKeyInputBuilder {
        GetBeaconKeyInputBuilder::default()
    }

    /// The branch key identifier.
    #[must_use]
    pub fn branch_key_id(&self) -> &str {
        &self.branch_key_id
    }
}

/// Builder for [`GetBeaconKeyInput`].
#[derive(Debug, Clone, Default)]
pub struct GetBeaconKeyInputBuilder {
    branch_key_id: Option<String>,
}

impl GetBeaconKeyInputBuilder {
    /// Set the branch key identifier.
    /// Required.
    #[must_use]
    pub fn branch_key_id(mut self, branch_key_id: impl Into<String>) -> Self {
        self.branch_key_id = Some(branch_key_id.into());
        self
    }

    /// Set or clear the branch key identifier from an `Option`.
    /// To set a value, use [`Self::branch_key_id`].
    #[must_use]
    pub fn set_branch_key_id(mut self, branch_key_id: Option<String>) -> Self {
        self.branch_key_id = branch_key_id;
        self
    }

    /// The branch key identifier, if set.
    #[must_use]
    pub const fn get_branch_key_id(&self) -> &Option<String> {
        &self.branch_key_id
    }

    /// Build the `GetBeaconKeyInput`.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): `branch_key_id` is unset.
    pub fn build(self) -> Result<GetBeaconKeyInput, Error> {
        Ok(GetBeaconKeyInput {
            branch_key_id: required(self.branch_key_id, "branch_key_id")?,
        })
    }
}

/// Output of [`KeyStore::get_beacon_key`](super::KeyStore::get_beacon_key).
#[derive(Debug)]
#[non_exhaustive]
pub struct GetBeaconKeyOutput {
    pub(crate) beacon_key_materials: BeaconKeyMaterials,
}

impl GetBeaconKeyOutput {
    /// Start a builder for `GetBeaconKeyOutput`.
    #[must_use]
    pub fn builder() -> GetBeaconKeyOutputBuilder {
        GetBeaconKeyOutputBuilder::default()
    }

    /// The beacon key materials.
    #[must_use]
    pub const fn beacon_key_materials(&self) -> &BeaconKeyMaterials {
        &self.beacon_key_materials
    }

    /// The beacon key materials, consuming the output.
    #[must_use]
    pub fn into_beacon_key_materials(self) -> BeaconKeyMaterials {
        self.beacon_key_materials
    }
}

/// Builder for [`GetBeaconKeyOutput`].
#[derive(Debug, Default)]
pub struct GetBeaconKeyOutputBuilder {
    beacon_key_materials: Option<BeaconKeyMaterials>,
}

impl GetBeaconKeyOutputBuilder {
    /// Set the beacon key materials.
    /// Required.
    #[must_use]
    pub fn beacon_key_materials(
        mut self,
        beacon_key_materials: impl Into<BeaconKeyMaterials>,
    ) -> Self {
        self.beacon_key_materials = Some(beacon_key_materials.into());
        self
    }

    /// Set or clear the beacon key materials from an `Option`.
    /// To set a value, use [`Self::beacon_key_materials`].
    #[must_use]
    pub fn set_beacon_key_materials(
        mut self,
        beacon_key_materials: Option<BeaconKeyMaterials>,
    ) -> Self {
        self.beacon_key_materials = beacon_key_materials;
        self
    }

    /// The beacon key materials, if set.
    #[must_use]
    pub const fn get_beacon_key_materials(&self) -> &Option<BeaconKeyMaterials> {
        &self.beacon_key_materials
    }

    /// Build the `GetBeaconKeyOutput`.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): `beacon_key_materials` is unset.
    pub fn build(self) -> Result<GetBeaconKeyOutput, Error> {
        Ok(GetBeaconKeyOutput {
            beacon_key_materials: required(self.beacon_key_materials, "beacon_key_materials")?,
        })
    }
}

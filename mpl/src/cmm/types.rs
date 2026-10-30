// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Inputs and outputs of the [`Cmm`](super::Cmm) operations.

use std::collections::BTreeSet;

use crate::Error;
use crate::builder::required;
use crate::structures::{
    AlgorithmSuiteId, CommitmentPolicy, DecryptionMaterials, EncryptedDataKey, EncryptionContext,
    EncryptionMaterials,
};

/// Input for [`Cmm::get_encryption_materials`](super::Cmm::get_encryption_materials).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct GetEncryptionMaterialsInput {
    pub(crate) encryption_context: EncryptionContext,
    pub(crate) commitment_policy: CommitmentPolicy,
    pub(crate) algorithm_suite_id: Option<AlgorithmSuiteId>,
    pub(crate) required_encryption_context_keys: Option<BTreeSet<String>>,
    pub(crate) max_plaintext_length: Option<u64>,
}

impl GetEncryptionMaterialsInput {
    /// Start a builder for `GetEncryptionMaterialsInput`.
    #[must_use]
    pub fn builder() -> GetEncryptionMaterialsInputBuilder {
        GetEncryptionMaterialsInputBuilder::default()
    }

    /// The encryption context the caller supplied.
    /// May be empty.
    #[must_use]
    pub const fn encryption_context(&self) -> &EncryptionContext {
        &self.encryption_context
    }

    /// The commitment policy the algorithm suite must satisfy.
    #[must_use]
    pub const fn commitment_policy(&self) -> CommitmentPolicy {
        self.commitment_policy
    }

    /// The algorithm suite to use.
    /// When unset, the CMM picks one from the commitment policy.
    #[must_use]
    pub const fn algorithm_suite_id(&self) -> Option<AlgorithmSuiteId> {
        self.algorithm_suite_id
    }

    /// The encryption context keys that must be supplied again at decrypt time.
    /// Empty when unset.
    #[must_use]
    pub fn required_encryption_context_keys(&self) -> &BTreeSet<String> {
        static EMPTY: BTreeSet<String> = BTreeSet::new();
        self.required_encryption_context_keys
            .as_ref()
            .unwrap_or(&EMPTY)
    }

    /// The maximum plaintext length the materials are for.
    /// When unset, there is no bound.
    #[must_use]
    pub const fn max_plaintext_length(&self) -> Option<u64> {
        self.max_plaintext_length
    }
}

/// Builder for [`GetEncryptionMaterialsInput`].
#[derive(Debug, Clone, Default)]
pub struct GetEncryptionMaterialsInputBuilder {
    encryption_context: Option<EncryptionContext>,
    commitment_policy: Option<CommitmentPolicy>,
    algorithm_suite_id: Option<AlgorithmSuiteId>,
    required_encryption_context_keys: Option<BTreeSet<String>>,
    max_plaintext_length: Option<u64>,
}

impl GetEncryptionMaterialsInputBuilder {
    /// Adds a key-value pair to the encryption context the caller supplied.
    ///
    /// To override the contents of this collection use [`set_encryption_context`](Self::set_encryption_context).
    /// Required, and may be empty.
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

    /// Set the commitment policy the algorithm suite must satisfy.
    /// Required.
    #[must_use]
    pub fn commitment_policy(mut self, commitment_policy: impl Into<CommitmentPolicy>) -> Self {
        self.commitment_policy = Some(commitment_policy.into());
        self
    }

    /// Set or clear the commitment policy from an `Option`.
    /// To set a value, use [`Self::commitment_policy`].
    #[must_use]
    pub fn set_commitment_policy(mut self, commitment_policy: Option<CommitmentPolicy>) -> Self {
        self.commitment_policy = commitment_policy;
        self
    }

    /// The commitment policy, if set.
    #[must_use]
    pub const fn get_commitment_policy(&self) -> &Option<CommitmentPolicy> {
        &self.commitment_policy
    }

    /// Set the algorithm suite to use.
    /// When unset, the CMM picks one from the commitment policy.
    #[must_use]
    pub fn algorithm_suite_id(mut self, algorithm_suite_id: impl Into<AlgorithmSuiteId>) -> Self {
        self.algorithm_suite_id = Some(algorithm_suite_id.into());
        self
    }

    /// Set or clear the algorithm suite from an `Option`.
    /// To set a value, use [`Self::algorithm_suite_id`].
    #[must_use]
    pub fn set_algorithm_suite_id(mut self, algorithm_suite_id: Option<AlgorithmSuiteId>) -> Self {
        self.algorithm_suite_id = algorithm_suite_id;
        self
    }

    /// The algorithm suite ID, if set.
    #[must_use]
    pub const fn get_algorithm_suite_id(&self) -> &Option<AlgorithmSuiteId> {
        &self.algorithm_suite_id
    }

    /// Appends an item to the encryption context keys that must be supplied again at decrypt time.
    ///
    /// To override the contents of this collection use [`set_required_encryption_context_keys`](Self::set_required_encryption_context_keys).
    #[must_use]
    pub fn required_encryption_context_keys(mut self, input: impl Into<String>) -> Self {
        self.required_encryption_context_keys
            .get_or_insert_with(Default::default)
            .insert(input.into());
        self
    }

    /// Set or clear the required encryption context keys from an `Option`.
    /// To add one entry, use [`Self::required_encryption_context_keys`].
    #[must_use]
    pub fn set_required_encryption_context_keys(
        mut self,
        required_encryption_context_keys: Option<BTreeSet<String>>,
    ) -> Self {
        self.required_encryption_context_keys = required_encryption_context_keys;
        self
    }

    /// The required encryption context keys, if set.
    #[must_use]
    pub const fn get_required_encryption_context_keys(&self) -> &Option<BTreeSet<String>> {
        &self.required_encryption_context_keys
    }

    /// Set the maximum plaintext length the materials are for.
    /// When unset, there is no bound.
    #[must_use]
    pub fn max_plaintext_length(mut self, max_plaintext_length: impl Into<u64>) -> Self {
        self.max_plaintext_length = Some(max_plaintext_length.into());
        self
    }

    /// Set or clear the maximum plaintext length from an `Option`.
    /// To set a value, use [`Self::max_plaintext_length`].
    #[must_use]
    pub fn set_max_plaintext_length(mut self, max_plaintext_length: Option<u64>) -> Self {
        self.max_plaintext_length = max_plaintext_length;
        self
    }

    /// The max plaintext length, if set.
    #[must_use]
    pub const fn get_max_plaintext_length(&self) -> &Option<u64> {
        &self.max_plaintext_length
    }

    /// Build the `GetEncryptionMaterialsInput`.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): `encryption_context` or `commitment_policy` is unset.
    pub fn build(self) -> Result<GetEncryptionMaterialsInput, Error> {
        Ok(GetEncryptionMaterialsInput {
            encryption_context: required(self.encryption_context, "encryption_context")?,
            commitment_policy: required(self.commitment_policy, "commitment_policy")?,
            algorithm_suite_id: self.algorithm_suite_id,
            required_encryption_context_keys: self.required_encryption_context_keys,
            max_plaintext_length: self.max_plaintext_length,
        })
    }
}

/// Output of [`Cmm::get_encryption_materials`](super::Cmm::get_encryption_materials).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct GetEncryptionMaterialsOutput {
    pub(crate) encryption_materials: EncryptionMaterials,
}

impl GetEncryptionMaterialsOutput {
    /// Start a builder for `GetEncryptionMaterialsOutput`.
    #[must_use]
    pub fn builder() -> GetEncryptionMaterialsOutputBuilder {
        GetEncryptionMaterialsOutputBuilder::default()
    }

    /// The encryption materials.
    #[must_use]
    pub const fn encryption_materials(&self) -> &EncryptionMaterials {
        &self.encryption_materials
    }

    /// The encryption materials, consuming the output.
    #[must_use]
    pub fn into_encryption_materials(self) -> EncryptionMaterials {
        self.encryption_materials
    }
}

/// Builder for [`GetEncryptionMaterialsOutput`].
#[derive(Debug, Clone, Default)]
pub struct GetEncryptionMaterialsOutputBuilder {
    encryption_materials: Option<EncryptionMaterials>,
}

impl GetEncryptionMaterialsOutputBuilder {
    /// Set the encryption materials.
    /// Required.
    #[must_use]
    pub fn encryption_materials(
        mut self,
        encryption_materials: impl Into<EncryptionMaterials>,
    ) -> Self {
        self.encryption_materials = Some(encryption_materials.into());
        self
    }

    /// Set or clear the encryption materials from an `Option`.
    /// To set a value, use [`Self::encryption_materials`].
    #[must_use]
    pub fn set_encryption_materials(
        mut self,
        encryption_materials: Option<EncryptionMaterials>,
    ) -> Self {
        self.encryption_materials = encryption_materials;
        self
    }

    /// The encryption materials, if set.
    #[must_use]
    pub const fn get_encryption_materials(&self) -> &Option<EncryptionMaterials> {
        &self.encryption_materials
    }

    /// Build the `GetEncryptionMaterialsOutput`.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): `encryption_materials` is unset.
    pub fn build(self) -> Result<GetEncryptionMaterialsOutput, Error> {
        Ok(GetEncryptionMaterialsOutput {
            encryption_materials: required(self.encryption_materials, "encryption_materials")?,
        })
    }
}

/// Input for [`Cmm::decrypt_materials`](super::Cmm::decrypt_materials).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DecryptMaterialsInput {
    pub(crate) algorithm_suite_id: AlgorithmSuiteId,
    pub(crate) commitment_policy: CommitmentPolicy,
    pub(crate) encrypted_data_keys: Vec<EncryptedDataKey>,
    pub(crate) encryption_context: EncryptionContext,
    pub(crate) reproduced_encryption_context: Option<EncryptionContext>,
}

impl DecryptMaterialsInput {
    /// Start a builder for `DecryptMaterialsInput`.
    #[must_use]
    pub fn builder() -> DecryptMaterialsInputBuilder {
        DecryptMaterialsInputBuilder::default()
    }

    /// The algorithm suite in the message header.
    #[must_use]
    pub const fn algorithm_suite_id(&self) -> AlgorithmSuiteId {
        self.algorithm_suite_id
    }

    /// The commitment policy the algorithm suite must satisfy.
    #[must_use]
    pub const fn commitment_policy(&self) -> CommitmentPolicy {
        self.commitment_policy
    }

    /// The encrypted data keys in the message header.
    #[must_use]
    pub fn encrypted_data_keys(&self) -> &[EncryptedDataKey] {
        &self.encrypted_data_keys
    }

    /// The encryption context in the message header.
    /// May be empty.
    #[must_use]
    pub const fn encryption_context(&self) -> &EncryptionContext {
        &self.encryption_context
    }

    /// The encryption context the caller expects the message to have.
    #[must_use]
    pub fn reproduced_encryption_context(&self) -> Option<&EncryptionContext> {
        self.reproduced_encryption_context.as_ref()
    }
}

/// Builder for [`DecryptMaterialsInput`].
#[derive(Debug, Clone, Default)]
pub struct DecryptMaterialsInputBuilder {
    algorithm_suite_id: Option<AlgorithmSuiteId>,
    commitment_policy: Option<CommitmentPolicy>,
    encrypted_data_keys: Option<Vec<EncryptedDataKey>>,
    encryption_context: Option<EncryptionContext>,
    reproduced_encryption_context: Option<EncryptionContext>,
}

impl DecryptMaterialsInputBuilder {
    /// Set the algorithm suite in the message header.
    /// Required.
    #[must_use]
    pub fn algorithm_suite_id(mut self, algorithm_suite_id: impl Into<AlgorithmSuiteId>) -> Self {
        self.algorithm_suite_id = Some(algorithm_suite_id.into());
        self
    }

    /// Set or clear the algorithm suite from an `Option`.
    /// To set a value, use [`Self::algorithm_suite_id`].
    #[must_use]
    pub fn set_algorithm_suite_id(mut self, algorithm_suite_id: Option<AlgorithmSuiteId>) -> Self {
        self.algorithm_suite_id = algorithm_suite_id;
        self
    }

    /// The algorithm suite ID, if set.
    #[must_use]
    pub const fn get_algorithm_suite_id(&self) -> &Option<AlgorithmSuiteId> {
        &self.algorithm_suite_id
    }

    /// Set the commitment policy the algorithm suite must satisfy.
    /// Required.
    #[must_use]
    pub fn commitment_policy(mut self, commitment_policy: impl Into<CommitmentPolicy>) -> Self {
        self.commitment_policy = Some(commitment_policy.into());
        self
    }

    /// Set or clear the commitment policy from an `Option`.
    /// To set a value, use [`Self::commitment_policy`].
    #[must_use]
    pub fn set_commitment_policy(mut self, commitment_policy: Option<CommitmentPolicy>) -> Self {
        self.commitment_policy = commitment_policy;
        self
    }

    /// The commitment policy, if set.
    #[must_use]
    pub const fn get_commitment_policy(&self) -> &Option<CommitmentPolicy> {
        &self.commitment_policy
    }

    /// Appends an item to the encrypted data keys in the message header.
    ///
    /// To override the contents of this collection use [`set_encrypted_data_keys`](Self::set_encrypted_data_keys).
    /// Required.
    #[must_use]
    pub fn encrypted_data_keys(mut self, input: EncryptedDataKey) -> Self {
        self.encrypted_data_keys
            .get_or_insert_with(Default::default)
            .push(input);
        self
    }

    /// Set or clear the encrypted data keys from an `Option`.
    /// To add one entry, use [`Self::encrypted_data_keys`].
    #[must_use]
    pub fn set_encrypted_data_keys(
        mut self,
        encrypted_data_keys: Option<Vec<EncryptedDataKey>>,
    ) -> Self {
        self.encrypted_data_keys = encrypted_data_keys;
        self
    }

    /// The encrypted data keys, if set.
    #[must_use]
    pub const fn get_encrypted_data_keys(&self) -> &Option<Vec<EncryptedDataKey>> {
        &self.encrypted_data_keys
    }

    /// Adds a key-value pair to the encryption context in the message header.
    ///
    /// To override the contents of this collection use [`set_encryption_context`](Self::set_encryption_context).
    /// Required, and may be empty.
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

    /// Add one pair to the encryption context the caller expects the message to have.
    #[must_use]
    pub fn reproduced_encryption_context(
        mut self,
        k: impl Into<String>,
        v: impl Into<String>,
    ) -> Self {
        self.reproduced_encryption_context
            .get_or_insert_with(Default::default)
            .insert(k, v);
        self
    }

    /// Set or clear the reproduced encryption context from an `Option`.
    /// To add one entry, use [`Self::reproduced_encryption_context`].
    #[must_use]
    pub fn set_reproduced_encryption_context(
        mut self,
        reproduced_encryption_context: Option<EncryptionContext>,
    ) -> Self {
        self.reproduced_encryption_context = reproduced_encryption_context;
        self
    }

    /// The reproduced encryption context, if set.
    #[must_use]
    pub const fn get_reproduced_encryption_context(&self) -> &Option<EncryptionContext> {
        &self.reproduced_encryption_context
    }

    /// Build the `DecryptMaterialsInput`.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): `algorithm_suite_id`, `commitment_policy`, `encrypted_data_keys` or `encryption_context` is unset.
    pub fn build(self) -> Result<DecryptMaterialsInput, Error> {
        Ok(DecryptMaterialsInput {
            algorithm_suite_id: required(self.algorithm_suite_id, "algorithm_suite_id")?,
            commitment_policy: required(self.commitment_policy, "commitment_policy")?,
            encrypted_data_keys: required(self.encrypted_data_keys, "encrypted_data_keys")?,
            encryption_context: required(self.encryption_context, "encryption_context")?,
            reproduced_encryption_context: self.reproduced_encryption_context,
        })
    }
}

/// Output of [`Cmm::decrypt_materials`](super::Cmm::decrypt_materials).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DecryptMaterialsOutput {
    pub(crate) decryption_materials: DecryptionMaterials,
}

impl DecryptMaterialsOutput {
    /// Start a builder for `DecryptMaterialsOutput`.
    #[must_use]
    pub fn builder() -> DecryptMaterialsOutputBuilder {
        DecryptMaterialsOutputBuilder::default()
    }

    /// The decryption materials.
    #[must_use]
    pub const fn decryption_materials(&self) -> &DecryptionMaterials {
        &self.decryption_materials
    }

    /// The decryption materials, consuming the output.
    #[must_use]
    pub fn into_decryption_materials(self) -> DecryptionMaterials {
        self.decryption_materials
    }
}

/// Builder for [`DecryptMaterialsOutput`].
#[derive(Debug, Clone, Default)]
pub struct DecryptMaterialsOutputBuilder {
    decryption_materials: Option<DecryptionMaterials>,
}

impl DecryptMaterialsOutputBuilder {
    /// Set the decryption materials.
    /// Required.
    #[must_use]
    pub fn decryption_materials(
        mut self,
        decryption_materials: impl Into<DecryptionMaterials>,
    ) -> Self {
        self.decryption_materials = Some(decryption_materials.into());
        self
    }

    /// Set or clear the decryption materials from an `Option`.
    /// To set a value, use [`Self::decryption_materials`].
    #[must_use]
    pub fn set_decryption_materials(
        mut self,
        decryption_materials: Option<DecryptionMaterials>,
    ) -> Self {
        self.decryption_materials = decryption_materials;
        self
    }

    /// The decryption materials, if set.
    #[must_use]
    pub const fn get_decryption_materials(&self) -> &Option<DecryptionMaterials> {
        &self.decryption_materials
    }

    /// Build the `DecryptMaterialsOutput`.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): `decryption_materials` is unset.
    pub fn build(self) -> Result<DecryptMaterialsOutput, Error> {
        Ok(DecryptMaterialsOutput {
            decryption_materials: required(self.decryption_materials, "decryption_materials")?,
        })
    }
}

impl From<EncryptionMaterials> for GetEncryptionMaterialsOutput {
    fn from(encryption_materials: EncryptionMaterials) -> Self {
        Self {
            encryption_materials,
        }
    }
}

impl From<DecryptionMaterials> for DecryptMaterialsOutput {
    fn from(decryption_materials: DecryptionMaterials) -> Self {
        Self {
            decryption_materials,
        }
    }
}

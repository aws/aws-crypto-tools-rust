// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Fluent builders for the [`SharedCmm`] operations.

use std::collections::BTreeSet;

use super::{
    Cmm, DecryptMaterialsInput, DecryptMaterialsInputBuilder, DecryptMaterialsOutput,
    GetEncryptionMaterialsInput, GetEncryptionMaterialsInputBuilder, GetEncryptionMaterialsOutput,
    SharedCmm,
};
use crate::Error;
use crate::structures::{AlgorithmSuiteId, CommitmentPolicy, EncryptedDataKey, EncryptionContext};

impl SharedCmm {
    /// Start a [`Cmm::get_encryption_materials`] call.
    pub fn get_encryption_materials(&self) -> GetEncryptionMaterialsFluentBuilder {
        GetEncryptionMaterialsFluentBuilder {
            handle: self.clone(),
            inner: GetEncryptionMaterialsInput::builder(),
        }
    }

    /// Start a [`Cmm::decrypt_materials`] call.
    pub fn decrypt_materials(&self) -> DecryptMaterialsFluentBuilder {
        DecryptMaterialsFluentBuilder {
            handle: self.clone(),
            inner: DecryptMaterialsInput::builder(),
        }
    }
}

/// Fluent builder for [`SharedCmm::get_encryption_materials`].
#[derive(Debug, Clone)]
#[must_use = "does nothing until `send` is called"]
pub struct GetEncryptionMaterialsFluentBuilder {
    handle: SharedCmm,
    inner: GetEncryptionMaterialsInputBuilder,
}

impl GetEncryptionMaterialsFluentBuilder {
    /// The input set so far.
    #[must_use]
    pub const fn as_input(&self) -> &GetEncryptionMaterialsInputBuilder {
        &self.inner
    }

    /// Adds a key-value pair to the encryption context the caller supplied.
    ///
    /// To override the contents of this collection use [`set_encryption_context`](Self::set_encryption_context).
    /// Required, and may be empty.
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

    /// Set the commitment policy the algorithm suite must satisfy.
    /// Required.
    pub fn commitment_policy(mut self, commitment_policy: impl Into<CommitmentPolicy>) -> Self {
        self.inner = self.inner.commitment_policy(commitment_policy);
        self
    }

    /// Set or clear the commitment policy from an `Option`.
    /// To set a value, use [`Self::commitment_policy`].
    pub fn set_commitment_policy(mut self, commitment_policy: Option<CommitmentPolicy>) -> Self {
        self.inner = self.inner.set_commitment_policy(commitment_policy);
        self
    }

    /// The commitment policy, if set.
    #[must_use]
    pub const fn get_commitment_policy(&self) -> &Option<CommitmentPolicy> {
        self.inner.get_commitment_policy()
    }

    /// Set the algorithm suite to use.
    /// When unset, the CMM picks one from the commitment policy.
    pub fn algorithm_suite_id(mut self, algorithm_suite_id: impl Into<AlgorithmSuiteId>) -> Self {
        self.inner = self.inner.algorithm_suite_id(algorithm_suite_id);
        self
    }

    /// Set or clear the algorithm suite from an `Option`.
    /// To set a value, use [`Self::algorithm_suite_id`].
    pub fn set_algorithm_suite_id(mut self, algorithm_suite_id: Option<AlgorithmSuiteId>) -> Self {
        self.inner = self.inner.set_algorithm_suite_id(algorithm_suite_id);
        self
    }

    /// The algorithm suite ID, if set.
    #[must_use]
    pub const fn get_algorithm_suite_id(&self) -> &Option<AlgorithmSuiteId> {
        self.inner.get_algorithm_suite_id()
    }

    /// Appends an item to the encryption context keys that must be supplied again at decrypt time.
    ///
    /// To override the contents of this collection use [`set_required_encryption_context_keys`](Self::set_required_encryption_context_keys).
    pub fn required_encryption_context_keys(mut self, input: impl Into<String>) -> Self {
        self.inner = self.inner.required_encryption_context_keys(input);
        self
    }

    /// Set or clear the required encryption context keys from an `Option`.
    /// To add one entry, use [`Self::required_encryption_context_keys`].
    pub fn set_required_encryption_context_keys(
        mut self,
        required_encryption_context_keys: Option<BTreeSet<String>>,
    ) -> Self {
        self.inner = self
            .inner
            .set_required_encryption_context_keys(required_encryption_context_keys);
        self
    }

    /// The required encryption context keys, if set.
    #[must_use]
    pub const fn get_required_encryption_context_keys(&self) -> &Option<BTreeSet<String>> {
        self.inner.get_required_encryption_context_keys()
    }

    /// Set the maximum plaintext length the materials are for.
    /// When unset, there is no bound.
    pub fn max_plaintext_length(mut self, max_plaintext_length: u64) -> Self {
        self.inner = self.inner.max_plaintext_length(max_plaintext_length);
        self
    }

    /// Set or clear the maximum plaintext length from an `Option`.
    /// To set a value, use [`Self::max_plaintext_length`].
    pub fn set_max_plaintext_length(mut self, max_plaintext_length: Option<u64>) -> Self {
        self.inner = self.inner.set_max_plaintext_length(max_plaintext_length);
        self
    }

    /// The max plaintext length, if set.
    #[must_use]
    pub const fn get_max_plaintext_length(&self) -> &Option<u64> {
        self.inner.get_max_plaintext_length()
    }

    /// Send the request.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): `encryption_context` or `commitment_policy` is unset.
    ///
    /// Otherwise, the errors [`Cmm::get_encryption_materials`] documents.
    pub async fn send(self) -> Result<GetEncryptionMaterialsOutput, Error> {
        let input = self.inner.build()?;
        Cmm::get_encryption_materials(&*self.handle.0, input).await
    }
}

/// Fluent builder for [`SharedCmm::decrypt_materials`].
#[derive(Debug, Clone)]
#[must_use = "does nothing until `send` is called"]
pub struct DecryptMaterialsFluentBuilder {
    handle: SharedCmm,
    inner: DecryptMaterialsInputBuilder,
}

impl DecryptMaterialsFluentBuilder {
    /// The input set so far.
    #[must_use]
    pub const fn as_input(&self) -> &DecryptMaterialsInputBuilder {
        &self.inner
    }

    /// Set the algorithm suite in the message header.
    /// Required.
    pub fn algorithm_suite_id(mut self, algorithm_suite_id: impl Into<AlgorithmSuiteId>) -> Self {
        self.inner = self.inner.algorithm_suite_id(algorithm_suite_id);
        self
    }

    /// Set or clear the algorithm suite from an `Option`.
    /// To set a value, use [`Self::algorithm_suite_id`].
    pub fn set_algorithm_suite_id(mut self, algorithm_suite_id: Option<AlgorithmSuiteId>) -> Self {
        self.inner = self.inner.set_algorithm_suite_id(algorithm_suite_id);
        self
    }

    /// The algorithm suite ID, if set.
    #[must_use]
    pub const fn get_algorithm_suite_id(&self) -> &Option<AlgorithmSuiteId> {
        self.inner.get_algorithm_suite_id()
    }

    /// Set the commitment policy the algorithm suite must satisfy.
    /// Required.
    pub fn commitment_policy(mut self, commitment_policy: impl Into<CommitmentPolicy>) -> Self {
        self.inner = self.inner.commitment_policy(commitment_policy);
        self
    }

    /// Set or clear the commitment policy from an `Option`.
    /// To set a value, use [`Self::commitment_policy`].
    pub fn set_commitment_policy(mut self, commitment_policy: Option<CommitmentPolicy>) -> Self {
        self.inner = self.inner.set_commitment_policy(commitment_policy);
        self
    }

    /// The commitment policy, if set.
    #[must_use]
    pub const fn get_commitment_policy(&self) -> &Option<CommitmentPolicy> {
        self.inner.get_commitment_policy()
    }

    /// Appends an item to the encrypted data keys in the message header.
    ///
    /// To override the contents of this collection use [`set_encrypted_data_keys`](Self::set_encrypted_data_keys).
    /// Required.
    pub fn encrypted_data_keys(mut self, input: EncryptedDataKey) -> Self {
        self.inner = self.inner.encrypted_data_keys(input);
        self
    }

    /// Set or clear the encrypted data keys from an `Option`.
    /// To add one entry, use [`Self::encrypted_data_keys`].
    pub fn set_encrypted_data_keys(
        mut self,
        encrypted_data_keys: Option<Vec<EncryptedDataKey>>,
    ) -> Self {
        self.inner = self.inner.set_encrypted_data_keys(encrypted_data_keys);
        self
    }

    /// The encrypted data keys, if set.
    #[must_use]
    pub const fn get_encrypted_data_keys(&self) -> &Option<Vec<EncryptedDataKey>> {
        self.inner.get_encrypted_data_keys()
    }

    /// Adds a key-value pair to the encryption context in the message header.
    ///
    /// To override the contents of this collection use [`set_encryption_context`](Self::set_encryption_context).
    /// Required, and may be empty.
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

    /// Add one pair to the encryption context the caller expects the message to have.
    pub fn reproduced_encryption_context(
        mut self,
        k: impl Into<String>,
        v: impl Into<String>,
    ) -> Self {
        self.inner = self.inner.reproduced_encryption_context(k, v);
        self
    }

    /// Set or clear the reproduced encryption context from an `Option`.
    /// To add one entry, use [`Self::reproduced_encryption_context`].
    pub fn set_reproduced_encryption_context(
        mut self,
        reproduced_encryption_context: Option<EncryptionContext>,
    ) -> Self {
        self.inner = self
            .inner
            .set_reproduced_encryption_context(reproduced_encryption_context);
        self
    }

    /// The reproduced encryption context, if set.
    #[must_use]
    pub const fn get_reproduced_encryption_context(&self) -> &Option<EncryptionContext> {
        self.inner.get_reproduced_encryption_context()
    }

    /// Send the request.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): `algorithm_suite_id`, `commitment_policy`, `encrypted_data_keys` or `encryption_context` is unset.
    ///
    /// Otherwise, the errors [`Cmm::decrypt_materials`] documents.
    pub async fn send(self) -> Result<DecryptMaterialsOutput, Error> {
        let input = self.inner.build()?;
        Cmm::decrypt_materials(&*self.handle.0, input).await
    }
}

/// Add the [`SharedCmm`] fluent calls to a built-in CMM.
macro_rules! fluent_cmm {
    ($($ty:ty),+) => {$(
        impl $ty {
            /// Start a [`Cmm::get_encryption_materials`] call.
            pub fn get_encryption_materials(&self) -> GetEncryptionMaterialsFluentBuilder {
                SharedCmm::new(crate::shared::Builtin(self.clone())).get_encryption_materials()
            }

            /// Start a [`Cmm::decrypt_materials`] call.
            pub fn decrypt_materials(&self) -> DecryptMaterialsFluentBuilder {
                SharedCmm::new(crate::shared::Builtin(self.clone())).decrypt_materials()
            }
        }

        impl crate::shared::FromUnshared<$ty> for SharedCmm {
            fn from_unshared(value: $ty) -> Self {
                SharedCmm::new(crate::shared::Builtin(value))
            }
        }
    )+};
}

fluent_cmm!(super::DefaultCmm);

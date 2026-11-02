// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Decryption materials structure.

use crate::Error;
use crate::builder::required;
use crate::error::Kind;
use std::collections::BTreeSet;

use super::algorithm_suite::{
    AlgorithmSuite, AlgorithmSuiteId, PlaintextDataKey, SymmetricSigningKey, VerificationKey,
    check_data_key_length,
};
use super::encryption_context::EncryptionContext;

/// Materials needed for decryption.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DecryptionMaterials {
    algorithm_suite_id: AlgorithmSuiteId,
    encryption_context: EncryptionContext,
    required_encryption_context_keys: BTreeSet<String>,
    plaintext_data_key: Option<PlaintextDataKey>,
    verification_key: Option<VerificationKey>,
    symmetric_signing_key: Option<SymmetricSigningKey>,
}

impl DecryptionMaterials {
    /// Start a builder for `DecryptionMaterials`.
    ///
    /// A CMM builds the initial materials.
    /// A keyring changes them only through [`add_data_key`](Self::add_data_key).
    #[must_use]
    pub fn builder() -> DecryptionMaterialsBuilder {
        DecryptionMaterialsBuilder::default()
    }

    /// Add the plaintext data key a keyring recovered.
    ///
    /// # Errors
    ///
    /// - [`InvalidMaterials`](crate::Error::InvalidMaterials): these materials already have a plaintext data key,
    ///   or `plaintext_data_key` is not the algorithm suite's encryption key length.
    pub fn add_data_key(
        mut self,
        plaintext_data_key: impl Into<PlaintextDataKey>,
    ) -> Result<Self, Error> {
        let plaintext_data_key = plaintext_data_key.into();
        if self.plaintext_data_key.is_some() {
            return Err(Error::new(
                Kind::InvalidMaterials,
                "the materials already have a plaintext data key",
            ));
        }
        check_data_key_length(&self.algorithm_suite(), &plaintext_data_key)?;
        self.plaintext_data_key = Some(plaintext_data_key);
        Ok(self)
    }

    /// The algorithm suite.
    #[must_use]
    pub fn algorithm_suite_id(&self) -> AlgorithmSuiteId {
        self.algorithm_suite_id
    }

    /// The specification of the algorithm suite.
    #[must_use]
    pub fn algorithm_suite(&self) -> AlgorithmSuite {
        self.algorithm_suite_id.specification()
    }

    /// The encryption context.
    #[must_use]
    pub fn encryption_context(&self) -> &EncryptionContext {
        &self.encryption_context
    }

    /// The encryption context keys the caller had to supply again.
    #[must_use]
    pub fn required_encryption_context_keys(&self) -> &BTreeSet<String> {
        &self.required_encryption_context_keys
    }

    /// The plaintext data key, once a keyring has added one.
    #[must_use]
    pub fn plaintext_data_key(&self) -> Option<&PlaintextDataKey> {
        self.plaintext_data_key.as_ref()
    }

    /// The verification key, for an algorithm suite with asymmetric signing.
    #[must_use]
    pub fn verification_key(&self) -> Option<&VerificationKey> {
        self.verification_key.as_ref()
    }

    /// The symmetric signing key, for an algorithm suite with symmetric signing.
    #[must_use]
    pub fn symmetric_signing_key(&self) -> Option<&SymmetricSigningKey> {
        self.symmetric_signing_key.as_ref()
    }

    /// Validate the aws-crypto-public-key convention for decryption materials.
    pub fn validate_aws_crypto_public_key(&self) -> Result<(), Error> {
        let has_key = self
            .encryption_context
            .contains_key("aws-crypto-public-key");
        if self.verification_key.is_some() && !has_key {
            return Err(Error::new(
                Kind::InvalidMaterials,
                "encryption context MUST include 'aws-crypto-public-key' when verification key is present",
            ));
        }
        if self.verification_key.is_none() && has_key {
            return Err(Error::new(
                Kind::InvalidMaterials,
                "encryption context MUST NOT include 'aws-crypto-public-key' when verification key is absent",
            ));
        }
        Ok(())
    }
}

/// Builder for [`DecryptionMaterials`].
///
/// `algorithm_suite_id` is required.
/// The encryption context and required encryption context keys default to empty.
#[derive(Debug, Clone, Default)]
pub struct DecryptionMaterialsBuilder {
    algorithm_suite_id: Option<AlgorithmSuiteId>,
    encryption_context: Option<EncryptionContext>,
    required_encryption_context_keys: Option<BTreeSet<String>>,
    plaintext_data_key: Option<PlaintextDataKey>,
    verification_key: Option<VerificationKey>,
    symmetric_signing_key: Option<SymmetricSigningKey>,
}

impl DecryptionMaterialsBuilder {
    /// Set the algorithm suite.
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
    pub fn get_algorithm_suite_id(&self) -> &Option<AlgorithmSuiteId> {
        &self.algorithm_suite_id
    }

    /// Adds a key-value pair to the encryption context.
    ///
    /// To override the contents of this collection use [`set_encryption_context`](Self::set_encryption_context).
    /// Defaults to empty.
    #[must_use]
    pub fn encryption_context(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.encryption_context
            .get_or_insert_with(EncryptionContext::new)
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

    /// The encryption context set so far.
    #[must_use]
    #[allow(clippy::ref_option)] // AWS SDK for Rust getter shape
    pub fn get_encryption_context(&self) -> &Option<EncryptionContext> {
        &self.encryption_context
    }

    /// Appends an item to the required encryption context keys.
    ///
    /// To override the contents of this collection use [`set_required_encryption_context_keys`](Self::set_required_encryption_context_keys).
    /// Defaults to none.
    #[must_use]
    pub fn required_encryption_context_keys(mut self, input: impl Into<String>) -> Self {
        self.required_encryption_context_keys
            .get_or_insert_with(BTreeSet::new)
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

    /// The required encryption context keys set so far.
    #[must_use]
    #[allow(clippy::ref_option)] // AWS SDK for Rust getter shape
    pub fn get_required_encryption_context_keys(&self) -> &Option<BTreeSet<String>> {
        &self.required_encryption_context_keys
    }

    /// Set the plaintext data key.
    #[must_use]
    pub fn plaintext_data_key(mut self, plaintext_data_key: impl Into<PlaintextDataKey>) -> Self {
        self.plaintext_data_key = Some(plaintext_data_key.into());
        self
    }

    /// Set or clear the plaintext data key from an `Option`.
    /// To set a value, use [`Self::plaintext_data_key`].
    #[must_use]
    pub fn set_plaintext_data_key(mut self, plaintext_data_key: Option<PlaintextDataKey>) -> Self {
        self.plaintext_data_key = plaintext_data_key;
        self
    }

    /// The plaintext data key, if set.
    #[must_use]
    pub fn get_plaintext_data_key(&self) -> &Option<PlaintextDataKey> {
        &self.plaintext_data_key
    }

    /// Set the verification key.
    #[must_use]
    pub fn verification_key(mut self, verification_key: impl Into<VerificationKey>) -> Self {
        self.verification_key = Some(verification_key.into());
        self
    }

    /// Set or clear the verification key from an `Option`.
    /// To set a value, use [`Self::verification_key`].
    #[must_use]
    pub fn set_verification_key(mut self, verification_key: Option<VerificationKey>) -> Self {
        self.verification_key = verification_key;
        self
    }

    /// The verification key, if set.
    #[must_use]
    pub fn get_verification_key(&self) -> &Option<VerificationKey> {
        &self.verification_key
    }

    /// Set the symmetric signing key.
    #[must_use]
    pub fn symmetric_signing_key(
        mut self,
        symmetric_signing_key: impl Into<SymmetricSigningKey>,
    ) -> Self {
        self.symmetric_signing_key = Some(symmetric_signing_key.into());
        self
    }

    /// Set or clear the symmetric signing key from an `Option`.
    /// To set a value, use [`Self::symmetric_signing_key`].
    #[must_use]
    pub fn set_symmetric_signing_key(
        mut self,
        symmetric_signing_key: Option<SymmetricSigningKey>,
    ) -> Self {
        self.symmetric_signing_key = symmetric_signing_key;
        self
    }

    /// The symmetric signing key, if set.
    #[must_use]
    pub fn get_symmetric_signing_key(&self) -> &Option<SymmetricSigningKey> {
        &self.symmetric_signing_key
    }

    /// Build the `DecryptionMaterials`.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): `algorithm_suite_id` is unset.
    /// - [`EncryptionContextMismatch`](crate::Error::EncryptionContextMismatch): a required encryption context key is not in the encryption context.
    /// - [`InvalidMaterials`](crate::Error::InvalidMaterials): the plaintext data key is not the algorithm suite's encryption key length,
    ///   or the verification key or symmetric signing key does not suit the algorithm suite.
    pub fn build(self) -> Result<DecryptionMaterials, Error> {
        let algorithm_suite_id = required(self.algorithm_suite_id, "algorithm_suite_id")?;
        let encryption_context = self.encryption_context.unwrap_or_default();
        let required_encryption_context_keys =
            self.required_encryption_context_keys.unwrap_or_default();
        let suite = algorithm_suite_id.specification();

        if let Some(key) = &self.plaintext_data_key {
            check_data_key_length(&algorithm_suite_id.specification(), key)?;
        }

        // Required encryption context keys must be a subset of encryption context keys
        for key in &required_encryption_context_keys {
            if !encryption_context.contains_key(key) {
                return Err(Error::new(
                    Kind::EncryptionContextMismatch,
                    format!(
                        "required encryption context key {key:?} not found in encryption context"
                    ),
                ));
            }
        }

        // If no asymmetric signing, verification key must not be present.
        if !algorithm_suite_id.has_asymmetric_signing() && self.verification_key.is_some() {
            return Err(Error::new(
                Kind::InvalidMaterials,
                "verification key must not be present when algorithm suite has no asymmetric signing",
            ));
        }

        // If asymmetric signing, the verification key (when present) MUST match
        // the suite's asymmetric signature algorithm SEC1-compressed length.
        if let Some(vk) = &self.verification_key
            && let Some(expected_len) = suite.verification_key_length()
            && vk.len() != expected_len
        {
            return Err(Error::new(
                Kind::InvalidMaterials,
                format!(
                    "verification key length ({}) does not match expected length ({expected_len}) for algorithm suite",
                    vk.len(),
                ),
            ));
        }

        // If no symmetric signing, symmetric signing key must not be included
        if !algorithm_suite_id.has_symmetric_signing() && self.symmetric_signing_key.is_some() {
            return Err(Error::new(
                Kind::InvalidMaterials,
                "symmetric signing key must not be present when algorithm suite has no symmetric signing",
            ));
        }

        Ok(DecryptionMaterials {
            algorithm_suite_id,
            encryption_context,
            required_encryption_context_keys,
            plaintext_data_key: self.plaintext_data_key,
            verification_key: self.verification_key,
            symmetric_signing_key: self.symmetric_signing_key,
        })
    }
}

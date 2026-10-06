// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Decryption materials structure.

use crate::Error;
use crate::error::Kind;
use std::collections::BTreeSet;

use super::algorithm_suite::{
    AlgorithmSuite, AlgorithmSuiteId, PlaintextDataKey, SymmetricSigningKey, VerificationKey,
};
use super::encryption_context::EncryptionContext;

/// Materials needed for decryption.
#[derive(Debug)]
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
    pub fn add_data_key(mut self, plaintext_data_key: PlaintextDataKey) -> Result<Self, Error> {
        if self.plaintext_data_key.is_some() {
            return Err(Error::new(
                Kind::InvalidMaterials,
                "the materials already have a plaintext data key",
            ));
        }
        let expected_len = self.algorithm_suite().encryption_key_length();
        if plaintext_data_key.len() != expected_len {
            return Err(Error::new(
                Kind::InvalidMaterials,
                format!(
                    "plaintext data key is {} bytes, expected {expected_len} for the algorithm suite",
                    plaintext_data_key.len(),
                ),
            ));
        }
        self.plaintext_data_key = Some(plaintext_data_key);
        Ok(self)
    }

    pub fn algorithm_suite_id(&self) -> AlgorithmSuiteId {
        self.algorithm_suite_id
    }

    pub fn algorithm_suite(&self) -> AlgorithmSuite {
        self.algorithm_suite_id.specification()
    }

    pub fn encryption_context(&self) -> &EncryptionContext {
        &self.encryption_context
    }

    pub fn required_encryption_context_keys(&self) -> &BTreeSet<String> {
        &self.required_encryption_context_keys
    }

    pub fn plaintext_data_key(&self) -> Option<&PlaintextDataKey> {
        self.plaintext_data_key.as_ref()
    }

    pub fn verification_key(&self) -> Option<&VerificationKey> {
        self.verification_key.as_ref()
    }

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
#[derive(Debug, Default)]
pub struct DecryptionMaterialsBuilder {
    algorithm_suite_id: Option<AlgorithmSuiteId>,
    encryption_context: EncryptionContext,
    required_encryption_context_keys: BTreeSet<String>,
    plaintext_data_key: Option<PlaintextDataKey>,
    verification_key: Option<VerificationKey>,
    symmetric_signing_key: Option<SymmetricSigningKey>,
}

impl DecryptionMaterialsBuilder {
    /// Set the algorithm suite.
    /// Required.
    #[must_use]
    pub const fn algorithm_suite_id(mut self, algorithm_suite_id: AlgorithmSuiteId) -> Self {
        self.algorithm_suite_id = Some(algorithm_suite_id);
        self
    }

    /// Set the encryption context.
    #[must_use]
    pub fn encryption_context(mut self, encryption_context: EncryptionContext) -> Self {
        self.encryption_context = encryption_context;
        self
    }

    /// Set the required encryption context keys.
    #[must_use]
    pub fn required_encryption_context_keys(
        mut self,
        required_encryption_context_keys: BTreeSet<String>,
    ) -> Self {
        self.required_encryption_context_keys = required_encryption_context_keys;
        self
    }

    /// Set the plaintext data key.
    #[must_use]
    pub fn plaintext_data_key(mut self, plaintext_data_key: PlaintextDataKey) -> Self {
        self.plaintext_data_key = Some(plaintext_data_key);
        self
    }

    /// Set or clear the plaintext data key from an `Option`.
    /// To set a value, use [`Self::plaintext_data_key`].
    #[must_use]
    pub fn set_plaintext_data_key(mut self, plaintext_data_key: Option<PlaintextDataKey>) -> Self {
        self.plaintext_data_key = plaintext_data_key;
        self
    }

    /// Set the verification key.
    #[must_use]
    pub fn verification_key(mut self, verification_key: VerificationKey) -> Self {
        self.verification_key = Some(verification_key);
        self
    }

    /// Set or clear the verification key from an `Option`.
    /// To set a value, use [`Self::verification_key`].
    #[must_use]
    pub fn set_verification_key(mut self, verification_key: Option<VerificationKey>) -> Self {
        self.verification_key = verification_key;
        self
    }

    /// Set the symmetric signing key.
    #[must_use]
    pub fn symmetric_signing_key(mut self, symmetric_signing_key: SymmetricSigningKey) -> Self {
        self.symmetric_signing_key = Some(symmetric_signing_key);
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

    /// Build the `DecryptionMaterials`.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): `algorithm_suite_id` is unset.
    /// - [`EncryptionContextMismatch`](crate::Error::EncryptionContextMismatch): a required encryption context key is not in the encryption context.
    /// - [`InvalidMaterials`](crate::Error::InvalidMaterials): the verification key or symmetric signing key does not suit the algorithm suite.
    pub fn build(self) -> Result<DecryptionMaterials, Error> {
        let Some(algorithm_suite_id) = self.algorithm_suite_id else {
            return Err(Error::new(
                Kind::Validation,
                "an algorithm suite is required",
            ));
        };
        let suite = algorithm_suite_id.specification();

        // Required encryption context keys must be a subset of encryption context keys
        for key in &self.required_encryption_context_keys {
            if !self.encryption_context.contains_key(key) {
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
            encryption_context: self.encryption_context,
            required_encryption_context_keys: self.required_encryption_context_keys,
            plaintext_data_key: self.plaintext_data_key,
            verification_key: self.verification_key,
            symmetric_signing_key: self.symmetric_signing_key,
        })
    }
}

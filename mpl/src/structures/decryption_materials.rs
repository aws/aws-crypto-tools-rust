// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Decryption materials structure.

use std::collections::BTreeSet;

use super::algorithm_suite::{
    AlgorithmSuite, AlgorithmSuiteId, PlaintextDataKey, SymmetricSigningKey, VerificationKey,
};
use super::encryption_context::EncryptionContext;
use super::error::MaterialsError;

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
    /// A CMM builds the initial materials. A keyring changes them only through
    /// [`add_data_key`](Self::add_data_key).
    #[must_use]
    pub fn builder() -> DecryptionMaterialsBuilder {
        DecryptionMaterialsBuilder::default()
    }

    /// Add the plaintext data key a keyring recovered.
    ///
    /// # Errors
    ///
    /// Returns a [`MaterialsErrorKind::Validation`](super::MaterialsErrorKind::Validation)
    /// error if these materials already have a plaintext data key, or if
    /// `plaintext_data_key` is not the algorithm suite's encryption key length.
    pub fn add_data_key(
        mut self,
        plaintext_data_key: PlaintextDataKey,
    ) -> Result<Self, MaterialsError> {
        if self.plaintext_data_key.is_some() {
            return Err(MaterialsError::new(
                "DecryptionMaterials::add_data_key: the materials already have a plaintext data key",
            ));
        }
        let expected_len = self.algorithm_suite().encryption_key_length();
        if plaintext_data_key.len() != expected_len {
            return Err(MaterialsError::new(format!(
                "DecryptionMaterials::add_data_key: plaintext data key is {} bytes, expected {expected_len} for the algorithm suite",
                plaintext_data_key.len(),
            )));
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
    pub fn validate_aws_crypto_public_key(&self) -> Result<(), MaterialsError> {
        let has_key = self
            .encryption_context
            .contains_key("aws-crypto-public-key");
        if self.verification_key.is_some() && !has_key {
            return Err(MaterialsError::new(
                "Encryption context MUST include 'aws-crypto-public-key' when verification key is present",
            ));
        }
        if self.verification_key.is_none() && has_key {
            return Err(MaterialsError::new(
                "Encryption context MUST NOT include 'aws-crypto-public-key' when verification key is absent",
            ));
        }
        Ok(())
    }
}

/// Builder for [`DecryptionMaterials`].
///
/// `algorithm_suite_id` is required. The encryption context and required
/// encryption context keys default to empty.
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
    /// Set the algorithm suite. Required.
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

    /// Set the plaintext data key from an `Option`. `None` leaves it unset.
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

    /// Set the verification key from an `Option`. `None` leaves it unset.
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

    /// Set the symmetric signing key from an `Option`. `None` leaves it unset.
    #[must_use]
    pub fn set_symmetric_signing_key(
        mut self,
        symmetric_signing_key: Option<SymmetricSigningKey>,
    ) -> Self {
        self.symmetric_signing_key = symmetric_signing_key;
        self
    }

    /// Build the `DecryptionMaterials`, enforcing all spec invariants.
    ///
    /// # Errors
    ///
    /// Returns a [`MaterialsErrorKind::Validation`](super::MaterialsErrorKind::Validation)
    /// error if no algorithm suite was set or the fields violate a spec invariant.
    pub fn build(self) -> Result<DecryptionMaterials, MaterialsError> {
        let Some(algorithm_suite_id) = self.algorithm_suite_id else {
            return Err(MaterialsError::new(
                "DecryptionMaterials: an algorithm suite is required",
            ));
        };
        let suite = algorithm_suite_id.specification();

        // Required encryption context keys must be a subset of encryption context keys
        for key in &self.required_encryption_context_keys {
            if !self.encryption_context.contains_key(key) {
                return Err(MaterialsError::new(format!(
                    "Required encryption context key {:?} not found in encryption context",
                    key
                )));
            }
        }

        // If no asymmetric signing, verification key must not be present.
        if !algorithm_suite_id.has_asymmetric_signing() && self.verification_key.is_some() {
            return Err(MaterialsError::new(
                "Verification key must not be present when algorithm suite has no asymmetric signing",
            ));
        }

        // If asymmetric signing, the verification key (when present) MUST match
        // the suite's asymmetric signature algorithm SEC1-compressed length.
        if let Some(vk) = &self.verification_key
            && let Some(expected_len) = suite.verification_key_length()
            && vk.len() != expected_len
        {
            return Err(MaterialsError::new(format!(
                "Verification key length ({}) does not match expected length ({}) for algorithm suite",
                vk.len(),
                expected_len
            )));
        }

        // If no symmetric signing, symmetric signing key must not be included
        if !algorithm_suite_id.has_symmetric_signing() && self.symmetric_signing_key.is_some() {
            return Err(MaterialsError::new(
                "Symmetric signing key must not be present when algorithm suite has no symmetric signing",
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

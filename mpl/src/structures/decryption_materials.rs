// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Decryption materials structure.

use std::collections::BTreeSet;

use super::algorithm_suite::{
    AlgorithmSuite, PlaintextDataKey, SymmetricSigningKey, VerificationKey,
};
use super::encryption_context::EncryptionContext;
use super::error::MaterialsError;

/// Materials needed for decryption.
///
pub struct DecryptionMaterials {
    algorithm_suite: AlgorithmSuite,
    encryption_context: EncryptionContext,
    required_encryption_context_keys: BTreeSet<Vec<u8>>,
    plaintext_data_key: Option<PlaintextDataKey>,
    verification_key: Option<VerificationKey>,
    symmetric_signing_key: Option<SymmetricSigningKey>,
}

impl DecryptionMaterials {
    /// Construct decryption materials, enforcing all spec invariants.
    pub fn new(
        algorithm_suite: AlgorithmSuite,
        encryption_context: EncryptionContext,
        required_encryption_context_keys: BTreeSet<Vec<u8>>,
        plaintext_data_key: Option<PlaintextDataKey>,
        verification_key: Option<VerificationKey>,
        symmetric_signing_key: Option<SymmetricSigningKey>,
    ) -> Result<Self, MaterialsError> {
        // Required encryption context keys must be a subset of encryption context keys
        for key in &required_encryption_context_keys {
            if !encryption_context.contains_key(key) {
                return Err(MaterialsError::new(format!(
                    "Required encryption context key {:?} not found in encryption context",
                    key
                )));
            }
        }

        // If no symmetric signing, symmetric signing key must not be included
        if !algorithm_suite.has_symmetric_signing() && symmetric_signing_key.is_some() {
            return Err(MaterialsError::new(
                "Symmetric signing key must not be present when algorithm suite has no symmetric signing",
            ));
        }

        // If symmetric signing, symmetric signing key must be present iff plaintext data key is present
        if algorithm_suite.has_symmetric_signing()
            && plaintext_data_key.is_some() != symmetric_signing_key.is_some()
        {
            return Err(MaterialsError::new(
                "Symmetric signing key must be present if and only if plaintext data key is present (when algorithm suite has symmetric signing)",
            ));
        }

        Ok(Self {
            algorithm_suite,
            encryption_context,
            required_encryption_context_keys,
            plaintext_data_key,
            verification_key,
            symmetric_signing_key,
        })
    }

    pub fn algorithm_suite(&self) -> &AlgorithmSuite {
        &self.algorithm_suite
    }

    pub fn encryption_context(&self) -> &EncryptionContext {
        &self.encryption_context
    }

    pub fn required_encryption_context_keys(&self) -> &BTreeSet<Vec<u8>> {
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
            .contains_key(b"aws-crypto-public-key");
        if self.verification_key.is_some() && !has_key {
            return Err(MaterialsError::new(
                "Encryption context SHOULD include 'aws-crypto-public-key' when verification key is present",
            ));
        }
        if self.verification_key.is_none() && has_key {
            return Err(MaterialsError::new(
                "Encryption context SHOULD NOT include 'aws-crypto-public-key' when verification key is absent",
            ));
        }
        Ok(())
    }
}

impl std::fmt::Debug for DecryptionMaterials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecryptionMaterials")
            .field("algorithm_suite", &self.algorithm_suite)
            .field("encryption_context", &self.encryption_context)
            .field(
                "required_encryption_context_keys",
                &self.required_encryption_context_keys,
            )
            .field("plaintext_data_key", &self.plaintext_data_key)
            .field("verification_key", &self.verification_key)
            .field("symmetric_signing_key", &self.symmetric_signing_key)
            .finish()
    }
}

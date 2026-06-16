// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Encryption materials structure.

use std::collections::BTreeSet;

use super::algorithm_suite::{AlgorithmSuite, PlaintextDataKey, SigningKey, SymmetricSigningKey};
use super::encrypted_data_key::EncryptedDataKey;
use super::encryption_context::EncryptionContext;
use super::error::MaterialsError;

/// Materials needed for encryption.
///
#[derive(Debug)]
pub struct EncryptionMaterials {
    algorithm_suite: AlgorithmSuite,
    encrypted_data_keys: Vec<EncryptedDataKey>,
    encryption_context: EncryptionContext,
    required_encryption_context_keys: BTreeSet<Vec<u8>>,
    plaintext_data_key: Option<PlaintextDataKey>,
    signing_key: Option<SigningKey>,
    symmetric_signing_keys: Option<Vec<SymmetricSigningKey>>,
}

impl EncryptionMaterials {
    /// Construct encryption materials, enforcing all spec invariants.
    pub fn new(
        algorithm_suite: AlgorithmSuite,
        encrypted_data_keys: Vec<EncryptedDataKey>,
        encryption_context: EncryptionContext,
        required_encryption_context_keys: BTreeSet<Vec<u8>>,
        plaintext_data_key: Option<PlaintextDataKey>,
        signing_key: Option<SigningKey>,
        symmetric_signing_keys: Option<Vec<SymmetricSigningKey>>,
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

        // If no plaintext data key, encrypted data keys must be empty
        if plaintext_data_key.is_none() && !encrypted_data_keys.is_empty() {
            return Err(MaterialsError::new(
                "Encrypted data keys must be empty when plaintext data key is not present",
            ));
        }

        // If no asymmetric signing, signing key must not be present
        if !algorithm_suite.has_asymmetric_signing() && signing_key.is_some() {
            return Err(MaterialsError::new(
                "Signing key must not be present when algorithm suite has no asymmetric signing",
            ));
        }

        // If no symmetric signing, symmetric signing keys must not be included
        if !algorithm_suite.has_symmetric_signing() && symmetric_signing_keys.is_some() {
            return Err(MaterialsError::new(
                "Symmetric signing keys must not be present when algorithm suite has no symmetric signing",
            ));
        }

        // If symmetric signing, list length must equal encrypted data keys length
        if algorithm_suite.has_symmetric_signing()
            && let Some(ref keys) = symmetric_signing_keys
            && keys.len() != encrypted_data_keys.len()
        {
            return Err(MaterialsError::new(format!(
                "Symmetric signing keys length ({}) must equal encrypted data keys length ({})",
                keys.len(),
                encrypted_data_keys.len()
            )));
        }

        Ok(Self {
            algorithm_suite,
            encrypted_data_keys,
            encryption_context,
            required_encryption_context_keys,
            plaintext_data_key,
            signing_key,
            symmetric_signing_keys,
        })
    }

    pub fn algorithm_suite(&self) -> &AlgorithmSuite {
        &self.algorithm_suite
    }

    pub fn encrypted_data_keys(&self) -> &[EncryptedDataKey] {
        &self.encrypted_data_keys
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

    pub fn signing_key(&self) -> Option<&SigningKey> {
        self.signing_key.as_ref()
    }

    pub fn symmetric_signing_keys(&self) -> Option<&[SymmetricSigningKey]> {
        self.symmetric_signing_keys.as_deref()
    }

    /// Validate the aws-crypto-public-key convention for encryption materials.
    pub fn validate_aws_crypto_public_key(&self) -> Result<(), MaterialsError> {
        let has_key = self
            .encryption_context
            .contains_key(b"aws-crypto-public-key");
        if self.signing_key.is_some() && !has_key {
            return Err(MaterialsError::new(
                "Encryption context SHOULD include 'aws-crypto-public-key' when signing key is present",
            ));
        }
        if self.signing_key.is_none() && has_key {
            return Err(MaterialsError::new(
                "Encryption context SHOULD NOT include 'aws-crypto-public-key' when signing key is absent",
            ));
        }
        Ok(())
    }
}

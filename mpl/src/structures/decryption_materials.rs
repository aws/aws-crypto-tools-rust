// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Decryption materials structure.

use crate::{Error, ErrorKind};
use std::collections::BTreeSet;

use super::algorithm_suite::{
    AlgorithmSuite, AlgorithmSuiteId, PlaintextDataKey, SymmetricSigningKey, VerificationKey,
};
use super::encryption_context::EncryptionContext;

/// Materials needed for decryption.
///
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
    /// Construct decryption materials, enforcing all spec invariants.
    pub fn new(
        algorithm_suite_id: AlgorithmSuiteId,
        encryption_context: EncryptionContext,
        required_encryption_context_keys: BTreeSet<String>,
        plaintext_data_key: Option<PlaintextDataKey>,
        verification_key: Option<VerificationKey>,
        symmetric_signing_key: Option<SymmetricSigningKey>,
    ) -> Result<Self, Error> {
        let suite = algorithm_suite_id.specification();

        // Required encryption context keys must be a subset of encryption context keys
        for key in &required_encryption_context_keys {
            if !encryption_context.contains_key(key) {
                return Err(Error::new(
                    ErrorKind::EncryptionContextMismatch,
                    format!(
                        "required encryption context key {:?} not found in encryption context",
                        key
                    ),
                ));
            }
        }

        // If no asymmetric signing, verification key must not be present.
        if !algorithm_suite_id.has_asymmetric_signing() && verification_key.is_some() {
            return Err(Error::new(
                ErrorKind::InvalidMaterials,
                "verification key must not be present when algorithm suite has no asymmetric signing",
            ));
        }

        // If asymmetric signing, the verification key (when present) MUST match
        // the suite's asymmetric signature algorithm SEC1-compressed length.
        if let Some(ref vk) = verification_key
            && let Some(expected_len) = suite.verification_key_length()
            && vk.len() != expected_len
        {
            return Err(Error::new(
                ErrorKind::InvalidMaterials,
                format!(
                    "verification key length ({}) does not match expected length ({}) for algorithm suite",
                    vk.len(),
                    expected_len
                ),
            ));
        }

        // If no symmetric signing, symmetric signing key must not be included
        if !algorithm_suite_id.has_symmetric_signing() && symmetric_signing_key.is_some() {
            return Err(Error::new(
                ErrorKind::InvalidMaterials,
                "symmetric signing key must not be present when algorithm suite has no symmetric signing",
            ));
        }

        Ok(Self {
            algorithm_suite_id,
            encryption_context,
            required_encryption_context_keys,
            plaintext_data_key,
            verification_key,
            symmetric_signing_key,
        })
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
                ErrorKind::InvalidMaterials,
                "encryption context MUST include 'aws-crypto-public-key' when verification key is present",
            ));
        }
        if self.verification_key.is_none() && has_key {
            return Err(Error::new(
                ErrorKind::InvalidMaterials,
                "encryption context MUST NOT include 'aws-crypto-public-key' when verification key is absent",
            ));
        }
        Ok(())
    }
}

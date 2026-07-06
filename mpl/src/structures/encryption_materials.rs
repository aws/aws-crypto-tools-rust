// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Encryption materials structure.

use std::collections::BTreeSet;

use super::algorithm_suite::{
    AlgorithmSuite, AlgorithmSuiteId, PlaintextDataKey, SigningKey, SymmetricSigningKey,
};
use super::encrypted_data_key::EncryptedDataKey;
use super::encryption_context::EncryptionContext;
use super::error::MaterialsError;

/// Materials needed for encryption.
///
#[derive(Debug)]
pub struct EncryptionMaterials {
    algorithm_suite_id: AlgorithmSuiteId,
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
        algorithm_suite_id: AlgorithmSuiteId,
        encrypted_data_keys: Vec<EncryptedDataKey>,
        encryption_context: EncryptionContext,
        required_encryption_context_keys: BTreeSet<Vec<u8>>,
        plaintext_data_key: Option<PlaintextDataKey>,
        signing_key: Option<SigningKey>,
        symmetric_signing_keys: Option<Vec<SymmetricSigningKey>>,
    ) -> Result<Self, MaterialsError> {
        let suite = algorithm_suite_id.specification();

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
        if !algorithm_suite_id.has_asymmetric_signing() && signing_key.is_some() {
            return Err(MaterialsError::new(
                "Signing key must not be present when algorithm suite has no asymmetric signing",
            ));
        }

        // If asymmetric signing, the signing key (when present) MUST match the
        // suite's asymmetric signature algorithm scalar length.
        if let Some(ref sk) = signing_key
            && let Some(expected_len) = suite.signing_key_length()
            && sk.len() != expected_len
        {
            return Err(MaterialsError::new(format!(
                "Signing key length ({}) does not match expected length ({}) for algorithm suite",
                sk.len(),
                expected_len
            )));
        }

        // If no symmetric signing, symmetric signing keys must not be included
        if !algorithm_suite_id.has_symmetric_signing() && symmetric_signing_keys.is_some() {
            return Err(MaterialsError::new(
                "Symmetric signing keys must not be present when algorithm suite has no symmetric signing",
            ));
        }

        // Defensive invariant ported from `aws-crypto-rust/structures-review`
        // (commit `715c0a0`), which closed Copilot review feedback on PR #11:
        // when the suite HAS symmetric signing and callers already provide
        // EDKs, they MUST also provide a `symmetric_signing_keys` list. The
        // spec carve-out — the list MAY be omitted when the EDK list is empty
        // — is preserved by the `!encrypted_data_keys.is_empty()` clause.
        //
        // Currently unreachable on `unreviewed`: no `AlgorithmSuiteId`
        // variant returns `true` from `has_symmetric_signing()` (every ESDK
        // suite in `algorithm_suite.rs` sets `symmetric_signature_algorithm:
        // None`). We bring the check over anyway so the moment a symmetric-
        // signing suite (e.g. a DBE variant) lands in the enum, callers are
        // held to the same invariant as slice 2's review snapshot without
        // relying on anyone remembering to re-port this guard. When such a
        // suite is added, add a companion `test_symmetric_keys_required_
        // when_edks_present` test (mirroring the one on structures-review)
        // to exercise this branch — until then the branch is uncovered.
        if algorithm_suite_id.has_symmetric_signing()
            && symmetric_signing_keys.is_none()
            && !encrypted_data_keys.is_empty()
        {
            return Err(MaterialsError::new(
                "Symmetric signing keys must be present when algorithm suite has symmetric signing and encrypted data keys are non-empty",
            ));
        }

        Ok(Self {
            algorithm_suite_id,
            encrypted_data_keys,
            encryption_context,
            required_encryption_context_keys,
            plaintext_data_key,
            signing_key,
            symmetric_signing_keys,
        })
    }

    pub fn algorithm_suite_id(&self) -> AlgorithmSuiteId {
        self.algorithm_suite_id
    }

    pub fn algorithm_suite(&self) -> AlgorithmSuite {
        self.algorithm_suite_id.specification()
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

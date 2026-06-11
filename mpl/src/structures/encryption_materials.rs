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
//= ../spec/framework/structures.md#structure-2
//= type=implication
//# This structure MUST include the following fields:
//
//= ../spec/framework/structures.md#structure-2
//= type=implication
//# This structure MAY include any of the following fields:
//
//= ../spec/framework/cmm-interface.md#get-encryption-materials
//= type=implication
//# The encryption materials returned MUST include the following:
#[derive(Clone)]
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
    //= ../spec/framework/structures.md#plaintext-data-key
    //= type=exception
    //= reason=Plaintext data key length is constrained by the algorithm suite's encryption key length, validated when materials are consumed by encrypt; see #encryption-algorithm in algorithm-suites.md.
    //# The plaintext data key MUST:
    //
    //= ../spec/framework/structures.md#encrypted-data-keys
    //= type=exception
    //= reason=Opaque ciphertext; determinism is the key provider's responsibility, not the holder type.
    //# The [ciphertext](#ciphertext) of each encrypted data key in this list MUST be an opaque form of the
    //# plaintext data key from this set of encryption materials.
    //
    //= ../spec/framework/structures.md#symmetric-signing-keys
    //= type=exception
    //= reason=ESDK algorithm suites never include a symmetric signature algorithm; this clause is vacuously satisfied for every variant of AlgorithmSuiteId in this MPL implementation.
    //# The symmetric signature keys MUST adhere to the specification for [symmetric signature algorithms](./algorithm-suites.md#symmetric-signature-algorithm)
    //# included in this encryption material's [algorithm suite](#algorithm-suite).
    //
    //= ../spec/framework/structures.md#symmetric-signing-keys
    //= type=exception
    //= reason=ESDK algorithm suites never include a symmetric signature algorithm; this clause is vacuously satisfied for every variant of AlgorithmSuiteId in this MPL implementation.
    //# If the algorithm suite does contain a symmetric signing algorithm, this list MUST have length equal to the [encrypted data key list](#encrypted-data-keys).
    //
    //= ../spec/framework/structures.md#symmetric-signing-keys
    //# Since the symmetric signing keys value is optional,
    //# if the [encrypted data key list](#encrypted-data-keys) is empty
    //# the symmetric signing algorithm MAY be omitted.
    //
    //= ../spec/framework/structures.md#encryption-context-1
    //= type=exception
    //= reason=Cannot validate cryptographic correspondence without the keypair generation context; documented invariant.
    //# The mapped value from the reserved key `aws-crypto-public-key` SHOULD be the signature verification key
    //# corresponding to the [signing key](#signing-key) stored on the [encryption material](#encryption-materials).
    //
    //= ../spec/framework/cmm-interface.md#get-encryption-materials
    //= type=implication
    //# - The encryption materials returned MUST follow the specification for [encryption-materials](structures.md#encryption-materials).
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
        //= ../spec/framework/structures.md#required-encryption-context-keys
        //# Every key in Required Encryption Context Keys
        //# MUST be a key in the [encryption context](#encryption-context-1).
        //
        //= ../spec/framework/cmm-interface.md#get-encryption-materials
        //= type=implication
        //# - For every key in [Required Encryption Context Keys](structures.md#required-encryption-context-keys)
        //# there MUST be a matching key in the [Encryption Context](structures.md#encryption-context-1).
        for key in &required_encryption_context_keys {
            if !encryption_context.contains_key(key) {
                return Err(MaterialsError::new(format!(
                    "Required encryption context key {:?} not found in encryption context",
                    key
                )));
            }
        }

        // If no plaintext data key, encrypted data keys must be empty
        //= ../spec/framework/structures.md#encrypted-data-keys
        //# If the plaintext data key is not included in this set of encryption materials, this list MUST be empty.
        if plaintext_data_key.is_none() && !encrypted_data_keys.is_empty() {
            return Err(MaterialsError::new(
                "Encrypted data keys must be empty when plaintext data key is not present",
            ));
        }

        // If no asymmetric signing, signing key must not be present
        //= ../spec/framework/structures.md#signing-key
        //# If the algorithm suite does not contain an asymmetric signing algorithm, the signing key MUST NOT be present.
        if !algorithm_suite_id.has_asymmetric_signing() && signing_key.is_some() {
            //= ../spec/framework/algorithm-suites.md#asymmetric-signature-algorithm
            //# - Asymmetric signatures MUST NOT be generated.
            return Err(MaterialsError::new(
                "Signing key must not be present when algorithm suite has no asymmetric signing",
            ));
        }

        // If asymmetric signing, the signing key (when present) MUST match the
        // suite's asymmetric signature algorithm scalar length.
        //= ../spec/framework/structures.md#signing-key
        //# The signing key MUST fit the specification described by the [asymmetric signature algorithm](algorithm-suites.md#asymmetric-signature-algorithm)
        //# included in this encryption material's [algorithm suite](#algorithm-suite).
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
        //= ../spec/framework/structures.md#symmetric-signing-keys
        //# If the algorithm suite does not contain a symmetric signing algorithm, this list MUST NOT be included in the materials.
        if !algorithm_suite_id.has_symmetric_signing() && symmetric_signing_keys.is_some() {
            //= ../spec/framework/algorithm-suites.md#symmetric-signature-algorithm
            //# - Symmetric signatures MUST NOT be generated.
            return Err(MaterialsError::new(
                "Symmetric signing keys must not be present when algorithm suite has no symmetric signing",
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

    //= ../spec/framework/structures.md#plaintext-data-key
    //= type=implication
    //# The plaintext data key SHOULD be stored as immutable data.
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
    //= ../spec/framework/structures.md#encryption-context-1
    //# If an [encryption material](#encryption-materials) contains a [signing key](#signing-key),
    //# the [encryption context](#encryption-context) SHOULD include the reserved key `aws-crypto-public-key`.
    //
    //= ../spec/framework/structures.md#encryption-context-1
    //# If an [encryption material](#encryption-materials) does not contains a [signing key](#signing-key),
    //# the [encryption context](#encryption-context) SHOULD NOT include the reserved key `aws-crypto-public-key`.
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

impl std::fmt::Debug for EncryptionMaterials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptionMaterials")
            .field("algorithm_suite_id", &self.algorithm_suite_id)
            .field("encrypted_data_keys", &self.encrypted_data_keys)
            .field("encryption_context", &self.encryption_context)
            .field(
                "required_encryption_context_keys",
                &self.required_encryption_context_keys,
            )
            .field("plaintext_data_key", &self.plaintext_data_key)
            .field("signing_key", &self.signing_key)
            .field("symmetric_signing_keys", &self.symmetric_signing_keys)
            .finish()
    }
}

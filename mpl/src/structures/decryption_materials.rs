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
///
//= ../spec/framework/structures.md#fields
//= type=implication
//# This structure MUST include the following fields:
//
//= ../spec/framework/structures.md#fields
//= type=implication
//# This structure MAY include any of the following fields:
//
//= ../spec/framework/cmm-interface.md#decrypt-materials
//= type=implication
//# The decryption materials returned MUST include the following:
#[derive(Clone)]
pub struct DecryptionMaterials {
    algorithm_suite_id: AlgorithmSuiteId,
    encryption_context: EncryptionContext,
    required_encryption_context_keys: BTreeSet<Vec<u8>>,
    plaintext_data_key: Option<PlaintextDataKey>,
    verification_key: Option<VerificationKey>,
    symmetric_signing_key: Option<SymmetricSigningKey>,
}

impl DecryptionMaterials {
    /// Construct decryption materials, enforcing all spec invariants.
    //= ../spec/framework/structures.md#plaintext-data-key-1
    //= type=exception
    //= reason=Plaintext data key length is constrained by the algorithm suite's encryption key length, validated when materials are consumed by decrypt; see #encryption-algorithm in algorithm-suites.md.
    //# The plaintext data key MUST:
    //
    //= ../spec/framework/structures.md#symmetric-signing-key
    //= type=exception
    //= reason=ESDK algorithm suites never include a symmetric signature algorithm; this clause is vacuously satisfied for every variant of AlgorithmSuiteId in this MPL implementation.
    //# If included, the symmetric signature key MUST fit the specification for the [symmetric signature algorithm](algorithm-suites.md#symmetric-signature-algorithm)
    //# included in this decryption material's [algorithm suite](#algorithm-suite-1).
    //
    //= ../spec/framework/structures.md#symmetric-signing-key
    //= type=exception
    //= reason=ESDK algorithm suites never include a symmetric signature algorithm; this clause is vacuously satisfied for every variant of AlgorithmSuiteId in this MPL implementation.
    //# If the algorithm suite does contain a symmetric signing algorithm,
    //# the symmetric signing key MUST also be included in the materials
    //# if and only if the materials also include a [plaintext data key](#plaintext-data-key-1).
    //
    //= ../spec/framework/structures.md#encryption-context-2
    //= type=exception
    //= reason=Cannot validate cryptographic correspondence without the keypair generation context; documented invariant.
    //# The mapped value from the reserved key `aws-crypto-public-key`
    //# SHOULD be the signature verification key stored on the [decryption materials](#decryption-materials).
    //
    //= ../spec/framework/cmm-interface.md#decrypt-materials
    //= type=implication
    //# - The decryption materials returned MUST follow the specification for [decryption-materials](structures.md#decryption-materials).
    pub fn new(
        algorithm_suite_id: AlgorithmSuiteId,
        encryption_context: EncryptionContext,
        required_encryption_context_keys: BTreeSet<Vec<u8>>,
        plaintext_data_key: Option<PlaintextDataKey>,
        verification_key: Option<VerificationKey>,
        symmetric_signing_key: Option<SymmetricSigningKey>,
    ) -> Result<Self, MaterialsError> {
        let suite = algorithm_suite_id.specification();

        // Required encryption context keys must be a subset of encryption context keys
        //= ../spec/framework/structures.md#required-encryption-context-keys-1
        //# Every key in Required Encryption Context Keys
        //# MUST be a key in the [encryption context](#encryption-context-2).
        //
        //= ../spec/framework/cmm-interface.md#decrypt-materials
        //= type=implication
        //# - All keys in this set MUST exist in the decryption materials encryption context.
        for key in &required_encryption_context_keys {
            if !encryption_context.contains_key(key) {
                return Err(MaterialsError::new(format!(
                    "Required encryption context key {:?} not found in encryption context",
                    key
                )));
            }
        }

        // If no asymmetric signing, verification key must not be present.
        if !algorithm_suite_id.has_asymmetric_signing() && verification_key.is_some() {
            //= ../spec/framework/algorithm-suites.md#asymmetric-signature-algorithm
            //# - Asymmetric signatures MUST NOT be verified.
            return Err(MaterialsError::new(
                "Verification key must not be present when algorithm suite has no asymmetric signing",
            ));
        }

        // If asymmetric signing, the verification key (when present) MUST match
        // the suite's asymmetric signature algorithm SEC1-uncompressed length.
        //= ../spec/framework/structures.md#verification-key
        //# The verification key MUST fit the specification for the [asymmetric signature algorithm](algorithm-suites.md#asymmetric-signature-algorithm)
        //# included in this decryption material's [algorithm suite](#algorithm-suite-1).
        if let Some(ref vk) = verification_key
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
        //= ../spec/framework/structures.md#symmetric-signing-key
        //# If the algorithm suite does not contain a symmetric signing algorithm,
        //# the symmetric signing key MUST NOT be included in the materials.
        if !algorithm_suite_id.has_symmetric_signing() && symmetric_signing_key.is_some() {
            //= ../spec/framework/algorithm-suites.md#symmetric-signature-algorithm
            //# - Symmetric signatures MUST NOT be verified.
            return Err(MaterialsError::new(
                "Symmetric signing key must not be present when algorithm suite has no symmetric signing",
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

    pub fn required_encryption_context_keys(&self) -> &BTreeSet<Vec<u8>> {
        &self.required_encryption_context_keys
    }

    //= ../spec/framework/structures.md#plaintext-data-key-1
    //= type=implication
    //# The plaintext data key SHOULD be stored as immutable data.
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
    //= ../spec/framework/structures.md#encryption-context-2
    //# If a [decryption materials](#decryption-materials) contains a [verification key](#verification-key),
    //# the [encryption context](#encryption-context) SHOULD include the reserved key `aws-crypto-public-key`.
    //
    //= ../spec/framework/structures.md#encryption-context-2
    //# If a [decryption materials](#decryption-materials) does not contain a [verification key](#verification-key),
    //# the [encryption context](#encryption-context) SHOULD NOT include the reserved key `aws-crypto-public-key`.
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
            .field("algorithm_suite_id", &self.algorithm_suite_id)
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

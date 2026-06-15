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
//= ../spec/framework/structures.md#fields
//= type=implication
//# This structure MUST include the following fields:
//
//= ../spec/framework/structures.md#fields
//= type=implication
//# This structure MAY include any of the following fields:
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
    //= ../spec/framework/structures.md#plaintext-data-key-1
    //= type=exception
    //= reason=Algorithm-suite-defined property, validated when materials are consumed by decrypt; out of scope for this crate.
    //# The plaintext data key MUST:
    //
    //= ../spec/framework/structures.md#verification-key
    //= type=exception
    //= reason=Algorithm suite property; cross-references algorithm-suites.md.
    //# The verification key MUST fit the specification for the [asymmetric signature algorithm](algorithm-suites.md#asymmetric-signature-algorithm)
    //# included in this decryption material's [algorithm suite](#algorithm-suite-1).
    //
    //= ../spec/framework/structures.md#symmetric-signing-key
    //= type=exception
    //= reason=Algorithm suite property; cross-references algorithm-suites.md.
    //# If included, the symmetric signature key MUST fit the specification for the [symmetric signature algorithm](algorithm-suites.md#symmetric-signature-algorithm)
    //# included in this decryption material's [algorithm suite](#algorithm-suite-1).
    //
    //= ../spec/framework/structures.md#encryption-context-2
    //= type=exception
    //= reason=Cannot validate cryptographic correspondence without the keypair generation context; documented invariant.
    //# The mapped value from the reserved key `aws-crypto-public-key`
    //# SHOULD be the signature verification key stored on the [decryption materials](#decryption-materials).
    pub fn new(
        algorithm_suite: AlgorithmSuite,
        encryption_context: EncryptionContext,
        required_encryption_context_keys: BTreeSet<Vec<u8>>,
        plaintext_data_key: Option<PlaintextDataKey>,
        verification_key: Option<VerificationKey>,
        symmetric_signing_key: Option<SymmetricSigningKey>,
    ) -> Result<Self, MaterialsError> {
        // Required encryption context keys must be a subset of encryption context keys
        //= ../spec/framework/structures.md#required-encryption-context-keys-1
        //# Every key in Required Encryption Context Keys
        //# MUST be a key in the [encryption context](#encryption-context-2).
        for key in &required_encryption_context_keys {
            if !encryption_context.contains_key(key) {
                return Err(MaterialsError::new(format!(
                    "Required encryption context key {:?} not found in encryption context",
                    key
                )));
            }
        }

        // If no symmetric signing, symmetric signing key must not be included
        //= ../spec/framework/structures.md#symmetric-signing-key
        //# If the algorithm suite does not contain a symmetric signing algorithm,
        //# the symmetric signing key MUST NOT be included in the materials.
        if !algorithm_suite.has_symmetric_signing() && symmetric_signing_key.is_some() {
            return Err(MaterialsError::new(
                "Symmetric signing key must not be present when algorithm suite has no symmetric signing",
            ));
        }

        // If symmetric signing, symmetric signing key must be present iff plaintext data key is present
        //= ../spec/framework/structures.md#symmetric-signing-key
        //# If the algorithm suite does contain a symmetric signing algorithm,
        //# the symmetric signing key MUST also be included in the materials
        //# if and only if the materials also include a [plaintext data key](#plaintext-data-key-1).
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

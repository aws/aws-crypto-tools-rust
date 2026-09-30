// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Encryption materials structure.

use crate::{Error, ErrorKind};
use std::collections::BTreeSet;

use super::algorithm_suite::{
    AlgorithmSuite, AlgorithmSuiteId, PlaintextDataKey, SigningKey, SymmetricSigningKey,
};
use super::encrypted_data_key::EncryptedDataKey;
use super::encryption_context::EncryptionContext;

/// Materials needed for encryption.
///
#[derive(Debug)]
pub struct EncryptionMaterials {
    algorithm_suite_id: AlgorithmSuiteId,
    encrypted_data_keys: Vec<EncryptedDataKey>,
    encryption_context: EncryptionContext,
    required_encryption_context_keys: BTreeSet<String>,
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
        required_encryption_context_keys: BTreeSet<String>,
        plaintext_data_key: Option<PlaintextDataKey>,
        signing_key: Option<SigningKey>,
        symmetric_signing_keys: Option<Vec<SymmetricSigningKey>>,
    ) -> Result<Self, Error> {
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

        // If no plaintext data key, encrypted data keys must be empty
        if plaintext_data_key.is_none() && !encrypted_data_keys.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidMaterials,
                "encrypted data keys must be empty when plaintext data key is not present",
            ));
        }

        // If no asymmetric signing, signing key must not be present
        if !algorithm_suite_id.has_asymmetric_signing() && signing_key.is_some() {
            return Err(Error::new(
                ErrorKind::InvalidMaterials,
                "signing key must not be present when algorithm suite has no asymmetric signing",
            ));
        }

        // The signing key's byte length is deliberately NOT validated. The
        // spec constrains only its presence and the algorithm it must suit
        // (`structures.md#signing-key`,
        // `algorithm-suites.md#asymmetric-signature-algorithm`); it defines no
        // length. The Dafny MPL matches that — `Materials.dfy` constrains
        // `signingKey` by presence only, and `Signature.dfy`'s `KeyGen` checks
        // `|verificationKey| == FieldSize` while passing `signingKey` through
        // unchecked. The key is an opaque blob whose encoding belongs to the
        // signer: `aws-mpl-primitives` emits and consumes it DER-encoded, so
        // asserting the raw-scalar length here would reject exactly the keys
        // that can actually be signed with.

        // If no symmetric signing, symmetric signing keys must not be included
        if !algorithm_suite_id.has_symmetric_signing() && symmetric_signing_keys.is_some() {
            return Err(Error::new(
                ErrorKind::InvalidMaterials,
                "symmetric signing keys must not be present when algorithm suite has no symmetric signing",
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

    pub fn required_encryption_context_keys(&self) -> &BTreeSet<String> {
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
    pub fn validate_aws_crypto_public_key(&self) -> Result<(), Error> {
        let has_key = self
            .encryption_context
            .contains_key("aws-crypto-public-key");
        if self.signing_key.is_some() && !has_key {
            return Err(Error::new(
                ErrorKind::InvalidMaterials,
                "encryption context MUST include 'aws-crypto-public-key' when signing key is present",
            ));
        }
        if self.signing_key.is_none() && has_key {
            return Err(Error::new(
                ErrorKind::InvalidMaterials,
                "encryption context MUST NOT include 'aws-crypto-public-key' when signing key is absent",
            ));
        }
        Ok(())
    }
}

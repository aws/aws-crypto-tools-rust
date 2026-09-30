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
    /// Start a builder for `EncryptionMaterials`.
    ///
    /// A CMM builds the initial materials. A keyring changes them only through
    /// [`add_data_key`](Self::add_data_key) and
    /// [`add_encrypted_data_key`](Self::add_encrypted_data_key).
    #[must_use]
    pub fn builder() -> EncryptionMaterialsBuilder {
        EncryptionMaterialsBuilder::default()
    }

    /// Add a plaintext data key and the encrypted data key that wraps it.
    ///
    /// # Errors
    ///
    /// Returns an [`ErrorKind::InvalidMaterials`](crate::ErrorKind::InvalidMaterials)
    /// error if these materials already have a plaintext data key, or if
    /// `plaintext_data_key` is not the algorithm suite's encryption key length.
    pub fn add_data_key(
        mut self,
        plaintext_data_key: PlaintextDataKey,
        encrypted_data_key: EncryptedDataKey,
    ) -> Result<Self, Error> {
        if self.plaintext_data_key.is_some() {
            return Err(Error::new(
                ErrorKind::InvalidMaterials,
                "the materials already have a plaintext data key",
            ));
        }
        let expected_len = self.algorithm_suite().encryption_key_length();
        if plaintext_data_key.len() != expected_len {
            return Err(Error::new(
                ErrorKind::InvalidMaterials,
                format!(
                    "plaintext data key is {} bytes, expected {expected_len} for the algorithm suite",
                    plaintext_data_key.len(),
                ),
            ));
        }
        self.plaintext_data_key = Some(plaintext_data_key);
        self.encrypted_data_keys.push(encrypted_data_key);
        Ok(self)
    }

    /// Add an encrypted data key that wraps the existing plaintext data key.
    ///
    /// # Errors
    ///
    /// Returns an [`ErrorKind::InvalidMaterials`](crate::ErrorKind::InvalidMaterials)
    /// error if these materials have no plaintext data key.
    pub fn add_encrypted_data_key(
        mut self,
        encrypted_data_key: EncryptedDataKey,
    ) -> Result<Self, Error> {
        if self.plaintext_data_key.is_none() {
            return Err(Error::new(
                ErrorKind::InvalidMaterials,
                "the materials have no plaintext data key",
            ));
        }
        self.encrypted_data_keys.push(encrypted_data_key);
        Ok(self)
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

/// Builder for [`EncryptionMaterials`].
///
/// `algorithm_suite_id` is required. The encryption context, required
/// encryption context keys, and encrypted data keys default to empty.
#[derive(Debug, Default)]
pub struct EncryptionMaterialsBuilder {
    algorithm_suite_id: Option<AlgorithmSuiteId>,
    encrypted_data_keys: Vec<EncryptedDataKey>,
    encryption_context: EncryptionContext,
    required_encryption_context_keys: BTreeSet<String>,
    plaintext_data_key: Option<PlaintextDataKey>,
    signing_key: Option<SigningKey>,
    symmetric_signing_keys: Option<Vec<SymmetricSigningKey>>,
}

impl EncryptionMaterialsBuilder {
    /// Set the algorithm suite. Required.
    #[must_use]
    pub const fn algorithm_suite_id(mut self, algorithm_suite_id: AlgorithmSuiteId) -> Self {
        self.algorithm_suite_id = Some(algorithm_suite_id);
        self
    }

    /// Set the encrypted data keys.
    #[must_use]
    pub fn encrypted_data_keys(mut self, encrypted_data_keys: Vec<EncryptedDataKey>) -> Self {
        self.encrypted_data_keys = encrypted_data_keys;
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

    /// Set the signing key.
    #[must_use]
    pub fn signing_key(mut self, signing_key: SigningKey) -> Self {
        self.signing_key = Some(signing_key);
        self
    }

    /// Set the signing key from an `Option`. `None` leaves it unset.
    #[must_use]
    pub fn set_signing_key(mut self, signing_key: Option<SigningKey>) -> Self {
        self.signing_key = signing_key;
        self
    }

    /// Set the symmetric signing keys.
    #[must_use]
    pub fn symmetric_signing_keys(
        mut self,
        symmetric_signing_keys: Vec<SymmetricSigningKey>,
    ) -> Self {
        self.symmetric_signing_keys = Some(symmetric_signing_keys);
        self
    }

    /// Set the symmetric signing keys from an `Option`. `None` leaves them unset.
    #[must_use]
    pub fn set_symmetric_signing_keys(
        mut self,
        symmetric_signing_keys: Option<Vec<SymmetricSigningKey>>,
    ) -> Self {
        self.symmetric_signing_keys = symmetric_signing_keys;
        self
    }

    /// Build the `EncryptionMaterials`, enforcing all spec invariants.
    ///
    /// # Errors
    ///
    /// Returns a [`ErrorKind::Validation`](crate::ErrorKind::Validation) error if no
    /// algorithm suite was set, an
    /// [`ErrorKind::EncryptionContextMismatch`](crate::ErrorKind::EncryptionContextMismatch)
    /// error if a required encryption context key is missing, or an
    /// [`ErrorKind::InvalidMaterials`](crate::ErrorKind::InvalidMaterials) error if the fields
    /// violate another spec invariant.
    pub fn build(self) -> Result<EncryptionMaterials, Error> {
        let Some(algorithm_suite_id) = self.algorithm_suite_id else {
            return Err(Error::new(
                ErrorKind::Validation,
                "an algorithm suite is required",
            ));
        };

        // Required encryption context keys must be a subset of encryption context keys
        for key in &self.required_encryption_context_keys {
            if !self.encryption_context.contains_key(key) {
                return Err(Error::new(
                    ErrorKind::EncryptionContextMismatch,
                    format!(
                        "required encryption context key {key:?} not found in encryption context"
                    ),
                ));
            }
        }

        // If no plaintext data key, encrypted data keys must be empty
        if self.plaintext_data_key.is_none() && !self.encrypted_data_keys.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidMaterials,
                "encrypted data keys must be empty when plaintext data key is not present",
            ));
        }

        // If no asymmetric signing, signing key must not be present
        if !algorithm_suite_id.has_asymmetric_signing() && self.signing_key.is_some() {
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
        if !algorithm_suite_id.has_symmetric_signing() && self.symmetric_signing_keys.is_some() {
            return Err(Error::new(
                ErrorKind::InvalidMaterials,
                "symmetric signing keys must not be present when algorithm suite has no symmetric signing",
            ));
        }

        Ok(EncryptionMaterials {
            algorithm_suite_id,
            encrypted_data_keys: self.encrypted_data_keys,
            encryption_context: self.encryption_context,
            required_encryption_context_keys: self.required_encryption_context_keys,
            plaintext_data_key: self.plaintext_data_key,
            signing_key: self.signing_key,
            symmetric_signing_keys: self.symmetric_signing_keys,
        })
    }
}

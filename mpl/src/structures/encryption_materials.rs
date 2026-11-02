// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Encryption materials structure.

use crate::Error;
use crate::builder::required;
use crate::error::Kind;
use std::collections::BTreeSet;

use super::algorithm_suite::{
    AlgorithmSuite, AlgorithmSuiteId, PlaintextDataKey, SigningKey, SymmetricSigningKey,
    check_data_key_length,
};
use super::encrypted_data_key::EncryptedDataKey;
use super::encryption_context::EncryptionContext;

/// Materials needed for encryption.
#[derive(Debug, Clone)]
#[non_exhaustive]
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
    /// A CMM builds the initial materials.
    /// A keyring changes them only through [`add_data_key`](Self::add_data_key)
    /// and [`add_encrypted_data_key`](Self::add_encrypted_data_key).
    #[must_use]
    pub fn builder() -> EncryptionMaterialsBuilder {
        EncryptionMaterialsBuilder::default()
    }

    /// Add a plaintext data key and the encrypted data key that wraps it.
    ///
    /// # Errors
    ///
    /// - [`InvalidMaterials`](crate::Error::InvalidMaterials): these materials already have a plaintext data key,
    ///   or `plaintext_data_key` is not the algorithm suite's encryption key length.
    pub fn add_data_key(
        mut self,
        plaintext_data_key: impl Into<PlaintextDataKey>,
        encrypted_data_key: EncryptedDataKey,
    ) -> Result<Self, Error> {
        let plaintext_data_key = plaintext_data_key.into();
        if self.plaintext_data_key.is_some() {
            return Err(Error::new(
                Kind::InvalidMaterials,
                "the materials already have a plaintext data key",
            ));
        }
        check_data_key_length(&self.algorithm_suite(), &plaintext_data_key)?;
        self.plaintext_data_key = Some(plaintext_data_key);
        self.encrypted_data_keys.push(encrypted_data_key);
        Ok(self)
    }

    /// Add an encrypted data key that wraps the existing plaintext data key.
    ///
    /// # Errors
    ///
    /// - [`InvalidMaterials`](crate::Error::InvalidMaterials): these materials have no plaintext data key.
    pub fn add_encrypted_data_key(
        mut self,
        encrypted_data_key: EncryptedDataKey,
    ) -> Result<Self, Error> {
        if self.plaintext_data_key.is_none() {
            return Err(Error::new(
                Kind::InvalidMaterials,
                "the materials have no plaintext data key",
            ));
        }
        self.encrypted_data_keys.push(encrypted_data_key);
        Ok(self)
    }

    /// The algorithm suite.
    #[must_use]
    pub const fn algorithm_suite_id(&self) -> AlgorithmSuiteId {
        self.algorithm_suite_id
    }

    /// The specification of the algorithm suite.
    #[must_use]
    pub fn algorithm_suite(&self) -> AlgorithmSuite {
        self.algorithm_suite_id.specification()
    }

    /// The encrypted data keys, in the order keyrings added them.
    #[must_use]
    pub fn encrypted_data_keys(&self) -> &[EncryptedDataKey] {
        &self.encrypted_data_keys
    }

    /// The encryption context.
    #[must_use]
    pub const fn encryption_context(&self) -> &EncryptionContext {
        &self.encryption_context
    }

    /// The encryption context keys that must be supplied again at decrypt time.
    #[must_use]
    pub const fn required_encryption_context_keys(&self) -> &BTreeSet<String> {
        &self.required_encryption_context_keys
    }

    /// The plaintext data key, once a keyring has added one.
    #[must_use]
    pub const fn plaintext_data_key(&self) -> Option<&PlaintextDataKey> {
        self.plaintext_data_key.as_ref()
    }

    /// The signing key, for an algorithm suite with asymmetric signing.
    #[must_use]
    pub const fn signing_key(&self) -> Option<&SigningKey> {
        self.signing_key.as_ref()
    }

    /// The symmetric signing keys, for an algorithm suite with symmetric signing.
    /// Empty for any other suite.
    #[must_use]
    pub fn symmetric_signing_keys(&self) -> &[SymmetricSigningKey] {
        self.symmetric_signing_keys.as_deref().unwrap_or_default()
    }

    /// Validate the aws-crypto-public-key convention for encryption materials.
    pub fn validate_aws_crypto_public_key(&self) -> Result<(), Error> {
        let has_key = self
            .encryption_context
            .contains_key("aws-crypto-public-key");
        if self.signing_key.is_some() && !has_key {
            return Err(Error::new(
                Kind::InvalidMaterials,
                "encryption context MUST include 'aws-crypto-public-key' when signing key is present",
            ));
        }
        if self.signing_key.is_none() && has_key {
            return Err(Error::new(
                Kind::InvalidMaterials,
                "encryption context MUST NOT include 'aws-crypto-public-key' when signing key is absent",
            ));
        }
        Ok(())
    }
}

/// Builder for [`EncryptionMaterials`].
///
/// `algorithm_suite_id` is required.
/// The encryption context, required encryption context keys, and encrypted data keys default to empty.
#[derive(Debug, Clone, Default)]
pub struct EncryptionMaterialsBuilder {
    algorithm_suite_id: Option<AlgorithmSuiteId>,
    encrypted_data_keys: Option<Vec<EncryptedDataKey>>,
    encryption_context: Option<EncryptionContext>,
    required_encryption_context_keys: Option<BTreeSet<String>>,
    plaintext_data_key: Option<PlaintextDataKey>,
    signing_key: Option<SigningKey>,
    symmetric_signing_keys: Option<Vec<SymmetricSigningKey>>,
}

impl EncryptionMaterialsBuilder {
    /// Set the algorithm suite.
    /// Required.
    #[must_use]
    pub fn algorithm_suite_id(mut self, algorithm_suite_id: impl Into<AlgorithmSuiteId>) -> Self {
        self.algorithm_suite_id = Some(algorithm_suite_id.into());
        self
    }

    /// Set or clear the algorithm suite from an `Option`.
    /// To set a value, use [`Self::algorithm_suite_id`].
    #[must_use]
    pub const fn set_algorithm_suite_id(
        mut self,
        algorithm_suite_id: Option<AlgorithmSuiteId>,
    ) -> Self {
        self.algorithm_suite_id = algorithm_suite_id;
        self
    }

    /// The algorithm suite ID, if set.
    #[must_use]
    pub const fn get_algorithm_suite_id(&self) -> &Option<AlgorithmSuiteId> {
        &self.algorithm_suite_id
    }

    /// Appends an item to the encrypted data keys.
    ///
    /// To override the contents of this collection use [`set_encrypted_data_keys`](Self::set_encrypted_data_keys).
    /// Defaults to none.
    #[must_use]
    pub fn encrypted_data_keys(mut self, input: EncryptedDataKey) -> Self {
        self.encrypted_data_keys
            .get_or_insert_with(Vec::new)
            .push(input);
        self
    }

    /// Set or clear the encrypted data keys from an `Option`.
    /// To add one entry, use [`Self::encrypted_data_keys`].
    #[must_use]
    pub fn set_encrypted_data_keys(
        mut self,
        encrypted_data_keys: Option<Vec<EncryptedDataKey>>,
    ) -> Self {
        self.encrypted_data_keys = encrypted_data_keys;
        self
    }

    /// The encrypted data keys set so far.
    #[must_use]
    pub const fn get_encrypted_data_keys(&self) -> &Option<Vec<EncryptedDataKey>> {
        &self.encrypted_data_keys
    }

    /// Adds a key-value pair to the encryption context.
    ///
    /// To override the contents of this collection use [`set_encryption_context`](Self::set_encryption_context).
    /// Defaults to empty.
    #[must_use]
    pub fn encryption_context(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.encryption_context
            .get_or_insert_with(EncryptionContext::new)
            .insert(k, v);
        self
    }

    /// Set or clear the encryption context from an `Option`.
    /// To add one entry, use [`Self::encryption_context`].
    #[must_use]
    pub fn set_encryption_context(mut self, encryption_context: Option<EncryptionContext>) -> Self {
        self.encryption_context = encryption_context;
        self
    }

    /// The encryption context set so far.
    #[must_use]
    #[allow(clippy::ref_option)] // AWS SDK for Rust getter shape
    pub const fn get_encryption_context(&self) -> &Option<EncryptionContext> {
        &self.encryption_context
    }

    /// Appends an item to the required encryption context keys.
    ///
    /// To override the contents of this collection use [`set_required_encryption_context_keys`](Self::set_required_encryption_context_keys).
    /// Defaults to none.
    #[must_use]
    pub fn required_encryption_context_keys(mut self, input: impl Into<String>) -> Self {
        self.required_encryption_context_keys
            .get_or_insert_with(BTreeSet::new)
            .insert(input.into());
        self
    }

    /// Set or clear the required encryption context keys from an `Option`.
    /// To add one entry, use [`Self::required_encryption_context_keys`].
    #[must_use]
    pub fn set_required_encryption_context_keys(
        mut self,
        required_encryption_context_keys: Option<BTreeSet<String>>,
    ) -> Self {
        self.required_encryption_context_keys = required_encryption_context_keys;
        self
    }

    /// The required encryption context keys set so far.
    #[must_use]
    #[allow(clippy::ref_option)] // AWS SDK for Rust getter shape
    pub const fn get_required_encryption_context_keys(&self) -> &Option<BTreeSet<String>> {
        &self.required_encryption_context_keys
    }

    /// Set the plaintext data key.
    #[must_use]
    pub fn plaintext_data_key(mut self, plaintext_data_key: impl Into<PlaintextDataKey>) -> Self {
        self.plaintext_data_key = Some(plaintext_data_key.into());
        self
    }

    /// Set or clear the plaintext data key from an `Option`.
    /// To set a value, use [`Self::plaintext_data_key`].
    #[must_use]
    pub fn set_plaintext_data_key(mut self, plaintext_data_key: Option<PlaintextDataKey>) -> Self {
        self.plaintext_data_key = plaintext_data_key;
        self
    }

    /// The plaintext data key, if set.
    #[must_use]
    pub const fn get_plaintext_data_key(&self) -> &Option<PlaintextDataKey> {
        &self.plaintext_data_key
    }

    /// Set the signing key.
    #[must_use]
    pub fn signing_key(mut self, signing_key: impl Into<SigningKey>) -> Self {
        self.signing_key = Some(signing_key.into());
        self
    }

    /// Set or clear the signing key from an `Option`.
    /// To set a value, use [`Self::signing_key`].
    #[must_use]
    pub fn set_signing_key(mut self, signing_key: Option<SigningKey>) -> Self {
        self.signing_key = signing_key;
        self
    }

    /// The signing key, if set.
    #[must_use]
    pub const fn get_signing_key(&self) -> &Option<SigningKey> {
        &self.signing_key
    }

    /// Appends an item to the symmetric signing keys.
    ///
    /// To override the contents of this collection use [`set_symmetric_signing_keys`](Self::set_symmetric_signing_keys).
    #[must_use]
    pub fn symmetric_signing_keys(mut self, input: SymmetricSigningKey) -> Self {
        self.symmetric_signing_keys
            .get_or_insert_with(Default::default)
            .push(input);
        self
    }

    /// Set or clear the symmetric signing keys from an `Option`.
    /// To add one entry, use [`Self::symmetric_signing_keys`].
    #[must_use]
    pub fn set_symmetric_signing_keys(
        mut self,
        symmetric_signing_keys: Option<Vec<SymmetricSigningKey>>,
    ) -> Self {
        self.symmetric_signing_keys = symmetric_signing_keys;
        self
    }

    /// The symmetric signing keys, if set.
    #[must_use]
    pub const fn get_symmetric_signing_keys(&self) -> &Option<Vec<SymmetricSigningKey>> {
        &self.symmetric_signing_keys
    }

    /// Build the `EncryptionMaterials`.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): `algorithm_suite_id` is unset.
    /// - [`EncryptionContextMismatch`](crate::Error::EncryptionContextMismatch): a required encryption context key is not in the encryption context.
    /// - [`InvalidMaterials`](crate::Error::InvalidMaterials): the plaintext data key is not the algorithm suite's encryption key length,
    ///   encrypted data keys are set without a plaintext data key,
    ///   or the signing key or symmetric signing keys do not suit the algorithm suite.
    pub fn build(self) -> Result<EncryptionMaterials, Error> {
        let algorithm_suite_id = required(self.algorithm_suite_id, "algorithm_suite_id")?;
        let encryption_context = self.encryption_context.unwrap_or_default();
        let required_encryption_context_keys =
            self.required_encryption_context_keys.unwrap_or_default();

        if let Some(key) = &self.plaintext_data_key {
            check_data_key_length(&algorithm_suite_id.specification(), key)?;
        }

        // Required encryption context keys must be a subset of encryption context keys
        for key in &required_encryption_context_keys {
            if !encryption_context.contains_key(key) {
                return Err(Error::new(
                    Kind::EncryptionContextMismatch,
                    format!(
                        "required encryption context key {key:?} not found in encryption context"
                    ),
                ));
            }
        }

        // If no plaintext data key, encrypted data keys must be empty
        if self.plaintext_data_key.is_none()
            && self
                .encrypted_data_keys
                .as_ref()
                .is_some_and(|k| !k.is_empty())
        {
            return Err(Error::new(
                Kind::InvalidMaterials,
                "encrypted data keys must be empty when plaintext data key is not present",
            ));
        }

        // If no asymmetric signing, signing key must not be present
        if !algorithm_suite_id.has_asymmetric_signing() && self.signing_key.is_some() {
            return Err(Error::new(
                Kind::InvalidMaterials,
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

        // If no symmetric signing, symmetric signing keys must not be included.
        // An empty list includes none, matching the getter, which returns an empty slice.
        if !algorithm_suite_id.has_symmetric_signing()
            && self
                .symmetric_signing_keys
                .as_ref()
                .is_some_and(|k| !k.is_empty())
        {
            return Err(Error::new(
                Kind::InvalidMaterials,
                "symmetric signing keys must not be present when algorithm suite has no symmetric signing",
            ));
        }

        Ok(EncryptionMaterials {
            algorithm_suite_id,
            encrypted_data_keys: self.encrypted_data_keys.unwrap_or_default(),
            encryption_context,
            required_encryption_context_keys,
            plaintext_data_key: self.plaintext_data_key,
            signing_key: self.signing_key,
            symmetric_signing_keys: self.symmetric_signing_keys,
        })
    }
}

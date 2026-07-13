// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Input request types for the [`Cmm`](super::Cmm) trait.

use std::collections::BTreeSet;

use crate::structures::{AlgorithmSuiteId, CommitmentPolicy, EncryptedDataKey, EncryptionContext};

/// Input to [`Cmm::get_encryption_materials`](super::Cmm::get_encryption_materials).
///
/// The request carries the customer-supplied encryption context and
/// commitment policy plus, optionally, an explicit algorithm suite, a set of
/// encryption-context keys that MUST be reproduced at decrypt time, and the
/// maximum plaintext length the returned materials are valid for.
#[derive(Debug, Clone)]
pub struct EncryptionMaterialsRequest {
    /// Encryption context provided by the customer. MAY be empty.
    encryption_context: EncryptionContext,
    /// Commitment policy to enforce when selecting the algorithm suite.
    commitment_policy: CommitmentPolicy,
    /// Optional explicit algorithm suite. If `None`, the CMM picks based on
    /// the commitment policy.
    algorithm_suite_id: Option<AlgorithmSuiteId>,
    /// Optional set of encryption context keys that MUST be reproducible at
    /// decrypt time.
    required_encryption_context_keys: Option<BTreeSet<Vec<u8>>>,
    /// Maximum plaintext length the returned materials are valid for. `None`
    /// means unbounded.
    max_plaintext_length: Option<u64>,
}

impl EncryptionMaterialsRequest {
    /// Construct an `EncryptionMaterialsRequest` with the two required
    /// fields. Optional fields default to `None`; chain `with_*` setters to
    /// supply them.
    pub fn new(encryption_context: EncryptionContext, commitment_policy: CommitmentPolicy) -> Self {
        Self {
            encryption_context,
            commitment_policy,
            algorithm_suite_id: None,
            required_encryption_context_keys: None,
            max_plaintext_length: None,
        }
    }

    /// Set the optional explicit algorithm suite ID on this request.
    pub fn with_algorithm_suite_id(mut self, id: AlgorithmSuiteId) -> Self {
        self.algorithm_suite_id = Some(id);
        self
    }

    /// Set the optional Required Encryption Context Keys set on this request.
    pub fn with_required_encryption_context_keys(mut self, keys: BTreeSet<Vec<u8>>) -> Self {
        self.required_encryption_context_keys = Some(keys);
        self
    }

    /// Set the optional maximum plaintext length on this request.
    pub fn with_max_plaintext_length(mut self, len: u64) -> Self {
        self.max_plaintext_length = Some(len);
        self
    }

    /// Borrow the customer-supplied encryption context.
    pub fn encryption_context(&self) -> &EncryptionContext {
        &self.encryption_context
    }

    /// Returns the commitment policy this request will be evaluated against.
    pub fn commitment_policy(&self) -> CommitmentPolicy {
        self.commitment_policy
    }

    /// Returns the optional explicit algorithm suite ID.
    pub fn algorithm_suite_id(&self) -> Option<AlgorithmSuiteId> {
        self.algorithm_suite_id
    }

    /// Borrow the optional Required Encryption Context Keys set.
    pub fn required_encryption_context_keys(&self) -> Option<&BTreeSet<Vec<u8>>> {
        self.required_encryption_context_keys.as_ref()
    }

    /// Returns the optional maximum plaintext length.
    pub fn max_plaintext_length(&self) -> Option<u64> {
        self.max_plaintext_length
    }
}

/// Input to [`Cmm::decrypt_materials`](super::Cmm::decrypt_materials).
///
/// The request carries the algorithm suite advertised in the message header,
/// the commitment policy in effect at the call site, the encrypted data
/// keys parsed from the header, and the encryption context parsed from the
/// header. It MAY also include a customer-supplied reproduced encryption
/// context to validate against the message's.
#[derive(Debug, Clone)]
pub struct DecryptMaterialsRequest {
    /// Algorithm suite advertised in the message header.
    algorithm_suite_id: AlgorithmSuiteId,
    /// Commitment policy to enforce when accepting the algorithm suite.
    commitment_policy: CommitmentPolicy,
    /// Encrypted data keys parsed from the message header.
    encrypted_data_keys: Vec<EncryptedDataKey>,
    /// Encryption context parsed from the message header. MAY be empty.
    encryption_context: EncryptionContext,
    /// Optional reproduced encryption context the customer expects to match
    /// the message's.
    reproduced_encryption_context: Option<EncryptionContext>,
}

impl DecryptMaterialsRequest {
    /// Construct a `DecryptMaterialsRequest` with the four required fields.
    /// `reproduced_encryption_context` defaults to `None`; chain
    /// [`Self::with_reproduced_encryption_context`] to supply it.
    pub fn new(
        algorithm_suite_id: AlgorithmSuiteId,
        commitment_policy: CommitmentPolicy,
        encrypted_data_keys: Vec<EncryptedDataKey>,
        encryption_context: EncryptionContext,
    ) -> Self {
        Self {
            algorithm_suite_id,
            commitment_policy,
            encrypted_data_keys,
            encryption_context,
            reproduced_encryption_context: None,
        }
    }

    /// Set the optional Reproduced Encryption Context on this request.
    pub fn with_reproduced_encryption_context(mut self, reproduced: EncryptionContext) -> Self {
        self.reproduced_encryption_context = Some(reproduced);
        self
    }

    /// Returns the algorithm suite advertised in the message header.
    pub fn algorithm_suite_id(&self) -> AlgorithmSuiteId {
        self.algorithm_suite_id
    }

    /// Returns the commitment policy this request will be evaluated against.
    pub fn commitment_policy(&self) -> CommitmentPolicy {
        self.commitment_policy
    }

    /// Borrow the encrypted data keys parsed from the message header.
    pub fn encrypted_data_keys(&self) -> &[EncryptedDataKey] {
        &self.encrypted_data_keys
    }

    /// Borrow the encryption context parsed from the message header.
    pub fn encryption_context(&self) -> &EncryptionContext {
        &self.encryption_context
    }

    /// Borrow the optional Reproduced Encryption Context.
    pub fn reproduced_encryption_context(&self) -> Option<&EncryptionContext> {
        self.reproduced_encryption_context.as_ref()
    }
}

// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Framework structures for cryptographic materials.

pub mod algorithm_suite;
pub mod beacon_key_materials;
pub mod branch_key_materials;
pub mod commitment_policy;
pub mod decryption_materials;
pub mod encrypted_data_key;
pub mod encryption_context;
pub mod encryption_materials;
pub mod error;

pub use algorithm_suite::{
    AlgorithmSuite, AlgorithmSuiteId, AsymmetricSignatureAlgorithm, EncryptionAlgorithm,
    EncryptionAlgorithmMode, EsdkAlgorithmSuiteId, Format, KeyDerivationAlgorithm,
    PlaintextDataKey, SigningKey, SymmetricSignatureAlgorithm, SymmetricSigningKey,
    VerificationKey,
};
pub use beacon_key_materials::BeaconKeyMaterials;
pub use branch_key_materials::BranchKeyMaterials;
pub use commitment_policy::{CommitmentPolicy, Esdk};
pub use decryption_materials::DecryptionMaterials;
pub use encrypted_data_key::EncryptedDataKey;
pub use encryption_context::EncryptionContext;
pub use encryption_materials::EncryptionMaterials;
pub use error::{MaterialsError, MaterialsErrorKind};

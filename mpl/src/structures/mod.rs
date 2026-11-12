// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Framework structures for cryptographic materials.

mod aes_wrapping_alg;
pub mod algorithm_suite;
pub mod beacon_key_materials;
pub mod branch_key_materials;
pub mod commitment_policy;
pub mod decryption_materials;
pub mod encrypted_data_key;
pub mod encryption_context;
pub mod encryption_materials;
pub(crate) mod materials_checks;
pub mod required_encryption_context_keys;

pub use aes_wrapping_alg::AesWrappingAlg;
pub use algorithm_suite::{
    AlgorithmSuite, AlgorithmSuiteId, AsymmetricSignatureAlgorithm, EncryptionAlgorithm,
    EncryptionAlgorithmMode, EsdkAlgorithmSuiteId, KeyDerivationAlgorithm, PlaintextDataKey,
    SigningKey, SymmetricSignatureAlgorithm, SymmetricSigningKey, VerificationKey,
};
pub use beacon_key_materials::{BeaconKeyMaterials, BeaconKeyMaterialsBuilder};
pub use branch_key_materials::{BranchKeyMaterials, BranchKeyMaterialsBuilder};
pub use commitment_policy::{CommitmentPolicy, EsdkCommitmentPolicy};
pub use decryption_materials::{DecryptionMaterials, DecryptionMaterialsBuilder};
pub use encrypted_data_key::{EncryptedDataKey, EncryptedDataKeyBuilder};
pub use encryption_context::EncryptionContext;
pub use encryption_materials::{EncryptionMaterials, EncryptionMaterialsBuilder};
pub use required_encryption_context_keys::RequiredEncryptionContextKeys;

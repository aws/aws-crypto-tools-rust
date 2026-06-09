// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Framework structures for cryptographic materials.

//= ../spec/framework/structures.md#overview
//= type=implication
//# These structures define a group of related fields that MUST hold certain properties.
//
//= ../spec/framework/structures.md#overview
//= type=implication
//# Wherever these structures are referenced in this specification,
//# implementations MUST ensure that all properties of a structure's fields are upheld.
//
//= ../spec/framework/structures.md#overview
//= type=implication
//# While these structures will usually be represented as objects, lower level languages MAY represent
//# these fields in a less strictly defined way as long as all field properties are still upheld.

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
    EncryptionAlgorithmMode, Format, KeyDerivationAlgorithm, PlaintextDataKey, SigningKey,
    SymmetricSignatureAlgorithm, SymmetricSigningKey, VerificationKey,
};
pub use beacon_key_materials::BeaconKeyMaterials;
pub use branch_key_materials::BranchKeyMaterials;
pub use commitment_policy::CommitmentPolicy;
pub use decryption_materials::DecryptionMaterials;
pub use encrypted_data_key::EncryptedDataKey;
pub use encryption_context::EncryptionContext;
pub use encryption_materials::EncryptionMaterials;
pub use error::{MaterialsError, MaterialsErrorKind};

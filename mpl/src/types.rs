// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The data shapes the keyrings, CMMs, caches, and key store take and return.

pub use crate::cmc::entry::{BytesUsage, CacheEntry, CachedMaterials, MessageUsage, UsageMetadata};
pub use crate::structures::{
    AesWrappingAlg, AlgorithmSuite, AlgorithmSuiteId, AsymmetricSignatureAlgorithm,
    BeaconKeyMaterials, BranchKeyMaterials, CommitmentPolicy, DecryptionMaterials,
    EncryptedDataKey, EncryptionAlgorithm, EncryptionAlgorithmMode, EncryptionContext,
    EncryptionMaterials, EsdkAlgorithmSuiteId, EsdkCommitmentPolicy, Format,
    KeyDerivationAlgorithm, PlaintextDataKey, SigningKey, SymmetricSignatureAlgorithm,
    SymmetricSigningKey, VerificationKey,
};

pub mod builders {
    //! Builders for the shapes in [`types`](crate::types).

    pub use crate::cmc::entry::{CacheEntryBuilder, UsageMetadataBuilder};
    pub use crate::structures::{
        BeaconKeyMaterialsBuilder, BranchKeyMaterialsBuilder, DecryptionMaterialsBuilder,
        EncryptedDataKeyBuilder, EncryptionMaterialsBuilder,
    };
}

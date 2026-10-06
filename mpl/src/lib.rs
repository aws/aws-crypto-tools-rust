// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod aws_kms;
mod builder;
pub mod cmc;
pub mod cmm;
pub mod error;
pub mod error_chain;
pub mod key_store;
pub mod keyring;
pub mod shared;
pub mod structures;

pub use error::Error;
pub use shared::IntoShared;
// Re-exported because `RawAesKeyringBuilder::wrapping_alg` takes an `AesGcm`,
// so callers can name the wrapping algorithm without depending on `aws-mpl-primitives`.
pub use aws_mpl_primitives::AesGcm;

pub use aws_config;
pub use aws_kms::hierarchical_keyring::{
    BranchKeySupplier, HierarchicalKeyring, HierarchicalKeyringBuilder, SharedBranchKeySupplier,
};

// Both SDK clients appear in `BranchKeyStoreBuilder`'s public signature,
// and a key store `Error` carries their SDK errors as its source.
// Downcasting to one needs the exact crate version this crate uses,
// which a consumer's own dependency might not resolve to.
pub use aws_sdk_dynamodb;
pub use aws_sdk_kms;

pub use cmc::{
    BytesUsage, CacheEntry, CachedMaterials, Cmc, DefaultCmc, DefaultCmcBuilder, LocalCmc,
    LocalCmcBuilder, MessageUsage, SharedCmc, StormTrackingCmc, StormTrackingCmcBuilder,
    UsageMetadata,
};
pub use cmm::{Cmm, DefaultCmm, SharedCmm};
pub use key_store::{
    BranchKeyStore, BranchKeyStoreBuilder, KeyStore, KeyStoreClient, KmsConfiguration,
};
pub use keyring::{Keyring, RawAesKeyring, RawAesKeyringBuilder, SharedKeyring};

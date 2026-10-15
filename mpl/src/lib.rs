// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod aws_kms;
mod builder;
pub mod cmc;
pub mod cmm;
pub mod error;
#[cfg(feature = "test-utils")]
mod error_chain;
pub mod key_store;
pub mod keyring;
pub mod shared;
pub mod structures;

pub use error::Error;

/// Put `#[async_trait]` on an `impl` of [`Keyring`], [`Cmm`], [`Cmc`], [`KeyStore`], or [`BranchKeySupplier`].
pub use async_trait::async_trait;
pub use shared::IntoShared;
// Re-exported because `RawAesKeyringBuilder::wrapping_alg` takes an `AesGcm`,
// so callers can name the wrapping algorithm without depending on `aws-mpl-primitives`.
pub use aws_mpl_primitives::AesGcm;

#[cfg(feature = "default-config")]
pub use aws_config;
pub use aws_kms::hierarchical_keyring::{
    BranchKeySupplier, GetBranchKeyIdInput, GetBranchKeyIdOutput, HierarchicalKeyring,
    HierarchicalKeyringBuilder, SharedBranchKeySupplier,
};

// Both SDK clients appear in `KeyStoreClientBuilder`'s public signature,
// and a key store `Error` carries their SDK errors as its source.
// Downcasting that source needs the exact SDK version this crate uses,
// which the consumer's own dependency might not resolve to.
#[cfg(feature = "ddb")]
pub use aws_sdk_dynamodb;
#[cfg(feature = "kms")]
pub use aws_sdk_kms;

pub use cmc::{
    BytesUsage, CacheEntry, CachedMaterials, Cmc, LocalCmc, LocalCmcBuilder, MessageUsage,
    SharedCmc, UsageMetadata,
};
#[cfg(feature = "rt-tokio")]
pub use cmc::{DefaultCmc, DefaultCmcBuilder, StormTrackingCmc, StormTrackingCmcBuilder};
pub use cmm::{Cmm, DefaultCmm, SharedCmm};
#[cfg(all(feature = "kms", feature = "ddb"))]
pub use key_store::KeyStoreClientBuilder;
pub use key_store::{Discovery, KeyStore, KeyStoreClient, KmsConfiguration, MrDiscovery};
pub use keyring::{Keyring, RawAesKeyring, RawAesKeyringBuilder, SharedKeyring};

#[cfg(feature = "test-utils")]
#[doc(hidden)]
pub mod __test_internals {
    pub mod error_chain {
        pub use crate::error_chain::*;
    }
}

// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// TODO: give every operation an input type, for consistency with the Dafny MPL
// and the Smithy model it is generated from. `Cmm` and `BranchKeySupplier`
// already take one (`EncryptionMaterialsRequest`, `DecryptMaterialsRequest`,
// `GetBranchKeyIdInput`); `Keystore`, `Keyring` and `Cmc` still take their
// members as positional parameters, so a member added to a model structure
// upstream is a breaking change here rather than an additive one. These are
// customer-implementable traits, so the conversion is breaking and should land
// in one change rather than trait by trait.

pub mod aws_kms;
mod client;
pub mod cmc;
pub mod cmm;
pub mod error;
pub mod error_chain;
pub mod keyring;
pub mod keystore;
pub mod shared;
pub mod structures;

pub use client::*;
pub use error::{Error, ErrorKind};
pub use shared::IntoShared;
// Re-exported because `AesGcm` appears in the public signature of
// `RawAesKeyring::new`; without this a caller would have to depend on
// `aws-mpl-primitives` directly just to name the wrapping algorithm.
pub use aws_mpl_primitives::AesGcm;

pub use aws_config;
pub use aws_kms::hierarchical_keyring::{
    BranchKeySupplier, HierarchicalKeyring, HierarchicalKeyringBuilder, SharedBranchKeySupplier,
};

// Re-exported because both SDK clients appear in the public signature of
// `BranchKeyStoreBuilder`, and because an `Error` from the key store carries these crates' SDK
// errors as its cause: downcasting to one requires the exact same crate
// version, which a consumer declaring its own dependency may not resolve.
pub use aws_sdk_dynamodb;
pub use aws_sdk_kms;

pub use cmc::{
    BytesUsage, CacheEntry, CacheType, CachedMaterials, Cmc, DefaultCache, LocalCmc, MessageUsage,
    SharedCmc, StormTrackingCache, StormTrackingCacheBuilder, StormTrackingCmc, UsageMetadata,
};
pub use cmm::{Cmm, DecryptMaterialsRequest, DefaultCmm, EncryptionMaterialsRequest, SharedCmm};
pub use keyring::{Keyring, RawAesKeyring, SharedKeyring};
pub use keystore::{
    BranchKeyStore, BranchKeyStoreBuilder, KeyStoreInfo, Keystore, KmsConfiguration,
    SharedKeystore, encryption_context, kms_config, record,
};

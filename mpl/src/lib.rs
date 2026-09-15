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
pub mod error_chain;
pub mod keyring;
pub mod keystore;
pub mod structures;

pub use client::*;
// Re-exported because `AesGcm` appears in the public signature of
// `RawAesKeyring::new`; without this a caller would have to depend on
// `aws-mpl-primitives` directly just to name the wrapping algorithm.
pub use aws_mpl_primitives::AesGcm;
// Re-exported because both SDK clients appear in the public signature of
// `KeyStoreConfig`, and because a `KeystoreError` carries these crates' SDK
// errors as its cause: downcasting to one requires the exact same crate
// version, which a consumer declaring its own dependency may not resolve.
pub use aws_sdk_dynamodb;
pub use aws_sdk_kms;
// Re-exported for the same version-matching reason as the SDK clients above: a
// caller that builds its own `SdkConfig` to construct those clients must use the
// `aws-config` this crate resolved, or the `Client::new` argument types differ.
pub use aws_config;
pub use aws_kms::hierarchical_keyring::HierarchicalKeyring;
pub use cmc::{
    BytesUsage, CacheEntry, CacheType, CachedMaterials, Cmc, CmcError, CmcErrorKind, DefaultCache,
    LocalCmc, MessageUsage, StormTrackingCache, StormTrackingCacheBuilder, StormTrackingCmc,
    TimeUnits, UsageMetadata,
};
pub use cmm::{Cmm, DecryptMaterialsRequest, DefaultCmm, EncryptionMaterialsRequest};
pub use keyring::{Keyring, RawAesKeyring};
pub use keystore::{
    BranchKeyStore, KeyStoreConfig, KeyStoreInfo, Keystore, KeystoreError, KmsConfiguration,
    encryption_context, kms_config, record,
};

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
// `KeyStoreConfig`, and because the SDK errors these crates define are
// carried as the `cause` of a `KeystoreError`. Downcasting to an SDK error
// requires naming its exact type from the exact same crate version, so a
// consumer resolving a different `aws-sdk-kms` would silently get `None`;
// re-exporting removes the need for them to declare the dependency at all.
// `aws_sdk_kms::error` also re-exports `DisplayErrorContext`,
// `ProvideErrorMetadata`, and `ErrorMetadata`, which is the full toolkit for
// walking the chain.
pub use aws_sdk_dynamodb;
pub use aws_sdk_kms;
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

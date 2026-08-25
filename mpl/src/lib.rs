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
pub mod keyring;
pub mod keystore;
pub mod structures;

pub use client::*;
// Re-exported because `AesGcm` appears in the public signature of
// `RawAesKeyring::new`; without this a caller would have to depend on
// `aws-mpl-primitives` directly just to name the wrapping algorithm.
pub use aws_mpl_primitives::AesGcm;
pub use cmc::{
    BytesUsage, CacheEntry, CacheType, CachedMaterials, Cmc, CmcError, CmcErrorKind, DefaultCache,
    LocalCmc, MessageUsage, MultiThreadedCache, SingleThreadedCache, StormTrackingCache,
    StormTrackingCacheBuilder, StormTrackingCmc, TimeUnits, UsageMetadata,
};
pub use cmm::{Cmm, DecryptMaterialsRequest, DefaultCmm, EncryptionMaterialsRequest};
pub use keyring::{Keyring, RawAesKeyring};
pub use keystore::{
    BranchKeyStore, KeyStoreConfig, KeyStoreInfo, Keystore, KeystoreError, KmsConfiguration,
    encryption_context, kms_config, record,
};

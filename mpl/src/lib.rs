// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod aws_kms;
mod client;
pub mod cmc;
pub mod cmm;
pub mod keyring;
pub mod keystore;
pub mod structures;

pub use client::*;
// Re-exported so callers of `create_raw_aes_keyring().wrapping_alg(..)` and
// `RawAesKeyring::new` need not depend on `aws-mpl-primitives` directly.
pub use aws_mpl_primitives::AesGcm;
pub use cmc::{
    BytesUsage, CacheEntry, CachedMaterials, Cmc, CmcError, CmcErrorKind, LocalCmc, MessageUsage,
    StormTrackingCmc, TimeUnits, UsageMetadata,
};
pub use cmm::{Cmm, DecryptMaterialsRequest, DefaultCmm, EncryptionMaterialsRequest};
pub use keyring::{Keyring, RawAesKeyring};
pub use keystore::{
    BranchKeyStore, KeyStoreConfig, KeyStoreInfo, Keystore, KeystoreError, KmsConfiguration,
    encryption_context, kms_config, record,
};

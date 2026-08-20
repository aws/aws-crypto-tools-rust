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
// Re-exported because `AesGcm` appears in the public signature of
// `RawAesKeyring::new`; without this a caller would have to depend on
// `aws-mpl-primitives` directly just to name the wrapping algorithm.
pub use aws_mpl_primitives::AesGcm;
pub use cmc::{
    BytesUsage, CacheEntry, CachedMaterials, Cmc, CmcError, CmcErrorKind, LocalCmc, MessageUsage,
    UsageMetadata,
};
pub use cmm::{Cmm, DecryptMaterialsRequest, DefaultCmm, EncryptionMaterialsRequest};
pub use keyring::{Keyring, RawAesKeyring};
pub use keystore::{
    BranchKeyStore, KeyStoreConfig, KeyStoreInfo, Keystore, KeystoreError, KmsConfiguration,
    encryption_context, kms_config, record,
};

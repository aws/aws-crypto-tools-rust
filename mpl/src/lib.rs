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
pub use cmc::{
    BytesUsage, CacheEntry, CacheType, CachedMaterials, Cmc, CmcError, CmcErrorKind, DefaultCache,
    DefaultCacheBuilder, LocalCmc, MessageUsage, StormTrackingCache, StormTrackingCacheBuilder,
    StormTrackingCmc, TimeUnits, UsageMetadata,
};
pub use cmm::{Cmm, DecryptMaterialsRequest, DefaultCmm, EncryptionMaterialsRequest};
pub use keyring::Keyring;
pub use keystore::{
    BranchKeyStore, KeyStoreConfig, KeyStoreInfo, Keystore, KeystoreError, KmsConfiguration,
    encryption_context, kms_config, record,
};

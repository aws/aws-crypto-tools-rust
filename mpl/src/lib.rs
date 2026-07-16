// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod aws_kms;
mod client;
pub mod cmc;
pub mod cmm;
pub mod keyring;
pub mod structures;

pub use client::*;
pub use cmc::{
    BytesUsage, CacheEntry, CachedMaterials, Cmc, CmcError, CmcErrorKind, LocalCmc, MessageUsage,
    UsageMetadata,
};
pub use cmm::{Cmm, DecryptMaterialsRequest, DefaultCmm, EncryptionMaterialsRequest};
pub use keyring::Keyring;

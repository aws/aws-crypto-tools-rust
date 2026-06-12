// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod aws_kms;
mod client;
pub mod cmm;
pub mod keyring;
#[cfg(feature = "keystore")]
pub mod keystore;
pub mod structures;

pub use client::*;
pub use cmm::{Cmm, DecryptMaterialsRequest, DefaultCmm, EncryptionMaterialsRequest};
pub use keyring::Keyring;
#[cfg(feature = "keystore")]
pub use keystore::{
    KeyStoreConfig, KeyStoreInfo, Keystore, KeystoreError, KmsConfiguration, encryption_context,
    kms_config, record,
};

// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The `Keyring` trait — the abstract contract every keyring MUST implement.
//!
//! # Why `async_trait` and not native AFIT
//!
//! Rust 1.75 stabilised `async fn` in traits ("AFIT"), but AFIT traits are NOT
//! dyn-compatible on stable — `dyn_compatible_async` is still nightly-only as
//! of Rust 1.85. The MPL needs `Box<dyn Keyring>` and `&dyn Keyring` plug-in
//! shapes so that a CMM can hold an arbitrary, runtime-configured keyring
//! (KMS endpoint, raw key bytes, multi-keyring composition, …). The
//! [`async_trait`] proc-macro rewrites each `async fn` into a method
//! returning `Pin<Box<dyn Future + Send>>`, which IS dyn-compatible. The one
//! heap allocation per call is the price of the plug-in shape.
//!
use async_trait::async_trait;

pub mod raw_aes_keyring;

pub use raw_aes_keyring::RawAesKeyring;

use crate::structures::{
    DecryptionMaterials, EncryptedDataKey, EncryptionMaterials, MaterialsError,
};

#[async_trait]
pub trait Keyring: Send + Sync {
    /// Modify the supplied [`EncryptionMaterials`] by generating and/or
    /// encrypting a data key. See the
    /// [OnEncrypt](../../../spec/framework/keyring-interface.md#onencrypt)
    /// section of the keyring interface specification.
    async fn on_encrypt(
        &self,
        materials: EncryptionMaterials,
    ) -> Result<EncryptionMaterials, MaterialsError>;

    /// Modify the supplied [`DecryptionMaterials`] by deriving the plaintext
    /// data key from one of the supplied encrypted data keys. See the
    /// [OnDecrypt](../../../spec/framework/keyring-interface.md#ondecrypt)
    /// section of the keyring interface specification.
    async fn on_decrypt(
        &self,
        materials: DecryptionMaterials,
        encrypted_data_keys: &[EncryptedDataKey],
    ) -> Result<DecryptionMaterials, MaterialsError>;
}

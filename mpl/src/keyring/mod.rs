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
//! # Concrete-keyring-deferred clauses (`type=exception`)
//!
//! This commit introduces the abstract `Keyring` trait scaffolding only — no
//! concrete keyring (Raw AES, Raw RSA, AWS KMS, multi-keyring, …) is
//! implemented yet. Two classes of spec clause are therefore annotated as
//! `type=exception` here:
//!
//! 1. Configuration / value-selection / cryptographic-property clauses
//!    (`#key-namespace`, `#key-name`, `#key-provider-id`,
//!    `#security-considerations`, the CSPRNG randomness clause of
//!    `#generate-data-key`) describe properties of CONCRETE keyrings — value
//!    selection, configuration shape, cryptographic boundary, randomness
//!    source — that the abstract trait cannot satisfy.
//! 2. Behavioral MUSTs on `OnEncrypt` / `OnDecrypt` /
//!    `Generate Data Key` / `Encrypt Data Key` / `Decrypt Data Key` describe
//!    runtime conduct that only a concrete keyring can fulfill. These are
//!    exercised TODAY by the mock-driven contract harness in
//!    `tests/test_keyring_contract.rs`, but those tests intentionally carry
//!    no `type=test` annotations: when each concrete keyring is added in a
//!    future commit, the matching exception below will be replaced with
//!    `type=implementation` on the concrete method, and `type=test` will be
//!    placed on the contract test that proves it.

use async_trait::async_trait;

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

// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The `Cmm` trait — the abstract contract every Cryptographic Materials
//! Manager MUST implement.
//!
//! Uses #[async_trait] so that the CMM can hold any runtime defined
//! CMM. The macro makes this work by rewriting each `async fn`
//! to return a boxed future.

pub mod default_cmm;
pub mod request;

use async_trait::async_trait;

pub use default_cmm::DefaultCmm;
pub use request::{DecryptMaterialsRequest, EncryptionMaterialsRequest};

use crate::structures::{DecryptionMaterials, EncryptionMaterials, MaterialsError};

/// The interface every CMM implements.
///
/// To hold a CMM whose concrete type is chosen at runtime, use [`SharedCmm`].
#[async_trait]
pub trait Cmm: Send + Sync {
    /// Assemble encryption materials for an encrypt request. Mirrors the
    /// `Get Encryption Materials` behavior of the
    /// [CMM interface specification](../../../spec/framework/cmm-interface.md#get-encryption-materials).
    async fn get_encryption_materials(
        &self,
        request: EncryptionMaterialsRequest,
    ) -> Result<EncryptionMaterials, MaterialsError>;

    /// Assemble decryption materials for a decrypt request. Mirrors the
    /// `Decrypt Materials` behavior of the
    /// [CMM interface specification](../../../spec/framework/cmm-interface.md#decrypt-materials).
    async fn decrypt_materials(
        &self,
        request: DecryptMaterialsRequest,
    ) -> Result<DecryptionMaterials, MaterialsError>;
}

crate::shared::shared_handle!(
    /// A CMM whose concrete type is not known at compile time.
    ///
    /// [`Cmm`] is the trait a CMM implements.
    /// `SharedCmm` holds any value that implements it.
    /// APIs that accept a CMM take `impl Into<SharedCmm>`,
    /// so callers usually pass the concrete CMM and never name this type.
    ///
    /// Name it when your own variable, field, or collection must hold
    /// a CMM chosen at runtime, e.g. from configuration.
    SharedCmm,
    Cmm
);

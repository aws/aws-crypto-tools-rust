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
    /// A shared handle to any [`Cmm`].
    ///
    /// Every API that accepts a CMM takes `impl Into<SharedCmm>`.
    /// Pass a concrete CMM, an `Arc` of one, or an existing handle.
    /// Cloning is cheap: the clone shares the same CMM instance.
    SharedCmm,
    Cmm
);

// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The `Cmm` trait — the abstract contract every Cryptographic Materials
//! Manager MUST implement.
//!
//! Uses #[async_trait] so that the CMM can hold any runtime defined
//! CMM. The macro makes this work by rewriting each `async fn`
//! to return a boxed future.
//!
//! See [Errors for keyring and CMM authors](crate::keyring#errors-for-keyring-and-cmm-authors)
//! for which error to return.

pub mod default_cmm;
pub mod request;

use crate::Error;
use async_trait::async_trait;

pub use default_cmm::DefaultCmm;
pub use request::{DecryptMaterialsRequest, EncryptionMaterialsRequest};

use crate::structures::{DecryptionMaterials, EncryptionMaterials};

/// To hold a CMM whose concrete type is chosen at runtime, use [`SharedCmm`].
#[async_trait]
pub trait Cmm: Send + Sync {
    /// A short name for this CMM, which errors show.
    ///
    /// The ESDK reports a failure of a caller's CMM with
    /// `resource()` set to [`Resource::Cmm`](crate::error::Resource::Cmm) and this name.
    /// It should be stable and short, and must not contain secrets.
    /// The default is the type's name.
    fn name(&self) -> &str {
        std::any::type_name::<Self>()
    }

    /// Assemble encryption materials for an encrypt request. Mirrors the
    /// `Get Encryption Materials` behavior of the
    /// [CMM interface specification](../../../spec/framework/cmm-interface.md#get-encryption-materials).
    async fn get_encryption_materials(
        &self,
        request: EncryptionMaterialsRequest,
    ) -> Result<EncryptionMaterials, Error>;

    /// Assemble decryption materials for a decrypt request. Mirrors the
    /// `Decrypt Materials` behavior of the
    /// [CMM interface specification](../../../spec/framework/cmm-interface.md#decrypt-materials).
    async fn decrypt_materials(
        &self,
        request: DecryptMaterialsRequest,
    ) -> Result<DecryptionMaterials, Error>;
}

crate::shared::shared_handle!(
    /// A CMM whose concrete type is chosen at runtime.
    ///
    /// It implements [`Cmm`], so it can be passed anywhere a CMM is accepted.
    /// Callers that know their CMM's type pass it directly and never need this one.
    SharedCmm,
    Cmm
);

#[async_trait]
impl Cmm for SharedCmm {
    fn name(&self) -> &str {
        self.0.name()
    }

    async fn get_encryption_materials(
        &self,
        request: EncryptionMaterialsRequest,
    ) -> Result<EncryptionMaterials, Error> {
        self.0.get_encryption_materials(request).await
    }

    async fn decrypt_materials(
        &self,
        request: DecryptMaterialsRequest,
    ) -> Result<DecryptionMaterials, Error> {
        self.0.decrypt_materials(request).await
    }
}

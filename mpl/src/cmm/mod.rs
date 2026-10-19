// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The `Cmm` trait — the abstract contract every Cryptographic Materials
//! Manager MUST implement.
//!
//! Implement it with [`#[async_trait]`](macro@crate::async_trait).
//! The macro rewrites each `async fn` to return a boxed future,
//! so a caller can hold a CMM whose type is chosen at runtime.
//!
//! See [Errors for keyring and CMM authors](crate::keyring#errors-for-keyring-and-cmm-authors)
//! for which error variant to return.

mod default_cmm;
mod fluent_builders;
mod types;

use crate::Error;
use std::borrow::Cow;

use async_trait::async_trait;

pub use default_cmm::DefaultCmm;
pub use fluent_builders::{DecryptMaterialsFluentBuilder, GetEncryptionMaterialsFluentBuilder};
pub use types::{
    DecryptMaterialsInput, DecryptMaterialsInputBuilder, DecryptMaterialsOutput,
    DecryptMaterialsOutputBuilder, GetEncryptionMaterialsInput, GetEncryptionMaterialsInputBuilder,
    GetEncryptionMaterialsOutput, GetEncryptionMaterialsOutputBuilder,
};

/// To hold a CMM whose concrete type is chosen at runtime, use [`SharedCmm`].
#[async_trait]
pub trait Cmm: Send + Sync {
    /// A short name for this CMM, which errors show.
    ///
    /// When the ESDK attributes an error to this CMM, it sets `resource()` to
    /// [`Resource::Cmm`](crate::error::Resource::Cmm) with this name.
    /// Keep it stable and short, and never put secrets in it.
    /// Return `Cow::Owned` for a name built at runtime.
    /// The default is the type's name.
    fn name(&self) -> Cow<'_, str> {
        Cow::Borrowed(std::any::type_name::<Self>())
    }

    /// Assemble encryption materials for an encrypt request. Mirrors the
    /// `Get Encryption Materials` behavior of the
    /// [CMM interface specification](../../../spec/framework/cmm-interface.md#get-encryption-materials).
    async fn get_encryption_materials(
        &self,
        input: GetEncryptionMaterialsInput,
    ) -> Result<GetEncryptionMaterialsOutput, Error>;

    /// Assemble decryption materials for a decrypt request. Mirrors the
    /// `Decrypt Materials` behavior of the
    /// [CMM interface specification](../../../spec/framework/cmm-interface.md#decrypt-materials).
    async fn decrypt_materials(
        &self,
        input: DecryptMaterialsInput,
    ) -> Result<DecryptMaterialsOutput, Error>;
}

crate::shared::shared_handle!(
    /// A CMM whose concrete type is chosen at runtime.
    ///
    /// It implements [`Cmm`], so it can be passed anywhere a CMM is accepted.
    /// Callers that know their CMM's type pass it directly and never need this one.
    ///
    /// Each operation returns a fluent builder: set the input, then call `send`.
    SharedCmm,
    Cmm
);

#[async_trait]
impl Cmm for SharedCmm {
    fn name(&self) -> Cow<'_, str> {
        self.0.name()
    }

    async fn get_encryption_materials(
        &self,
        input: GetEncryptionMaterialsInput,
    ) -> Result<GetEncryptionMaterialsOutput, Error> {
        Cmm::get_encryption_materials(&*self.0, input).await
    }

    async fn decrypt_materials(
        &self,
        input: DecryptMaterialsInput,
    ) -> Result<DecryptMaterialsOutput, Error> {
        Cmm::decrypt_materials(&*self.0, input).await
    }
}

/// A CMM behind an `Arc` is a CMM, so one instance can be shared without being `Clone`.
#[async_trait]
impl<T: Cmm + ?Sized> Cmm for std::sync::Arc<T> {
    fn name(&self) -> Cow<'_, str> {
        (**self).name()
    }

    async fn get_encryption_materials(
        &self,
        input: GetEncryptionMaterialsInput,
    ) -> Result<GetEncryptionMaterialsOutput, Error> {
        (**self).get_encryption_materials(input).await
    }

    async fn decrypt_materials(
        &self,
        input: DecryptMaterialsInput,
    ) -> Result<DecryptMaterialsOutput, Error> {
        (**self).decrypt_materials(input).await
    }
}

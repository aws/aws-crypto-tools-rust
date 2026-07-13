// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The `Cmm` trait — the abstract contract every Cryptographic Materials
//! Manager MUST implement.
//!
//! # Why `async_trait` and not native AFIT
//!
//! The same dyn-compatibility rationale recorded in [`crate::keyring`] applies
//! here: AFIT traits are not stable-dyn-compatible, the MPL needs `dyn Cmm`
//! and `Box<dyn Cmm>` for plug-in CMMs (Default CMM, Caching CMM, Required EC
//! CMM, custom user CMMs that wrap one or more keyrings), and `async_trait`
//! boxes the future to make `dyn Cmm` work today. See `src/keyring/mod.rs`
//! for the full discussion.
//!
//! # Concrete-CMM-deferred clauses (`type=exception`)
//!
//! This commit introduces the abstract `Cmm` trait scaffolding plus the two
//! request input types only — no concrete CMM (Default CMM, Caching CMM,
//! Required EC CMM, …) is implemented yet. Behavioral MUSTs on
//! `get_encryption_materials` and `decrypt_materials` (validity checks,
//! `aws-crypto-public-key` handling, encryption-context validation, etc.) are
//! therefore annotated `type=exception` here. They are exercised TODAY by the
//! mock-driven contract harness in `tests/test_cmm_contract.rs`, but those
//! tests intentionally carry no `type=test` annotations: when each concrete
//! CMM is added in a future commit, the matching exception below will be
//! replaced with `type=implementation` on the concrete method, and
//! `type=test` will be placed on the contract test that proves it.

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

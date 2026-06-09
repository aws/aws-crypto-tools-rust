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

//= ../spec/framework/cmm-interface.md#overview
//= type=implication
//# The CMM interface describes the interface that all CMMs MUST implement.
//
//= ../spec/framework/cmm-interface.md#supported-cmms
//= type=implication
//# Note: A user MAY create their own custom CMM.
#[async_trait]
//= ../spec/framework/cmm-interface.md#behaviors
//= type=implication
//# The CMM Interface MUST support the following behaviors:
pub trait Cmm: Send + Sync {
    /// Assemble encryption materials for an encrypt request. Mirrors the
    /// `Get Encryption Materials` behavior of the
    /// [CMM interface specification](../../../spec/framework/cmm-interface.md#get-encryption-materials).
    //= ../spec/framework/cmm-interface.md#get-encryption-materials
    //= type=exception
    //= reason=Abstract trait contract; no concrete CMM exists in this commit. Behavior is exercised today by mock-driven contract tests in tests/test_cmm_contract.rs. When a concrete CMM (Default CMM, Caching CMM, etc.) is added, this exception will be replaced with `type=implementation` on the concrete method and `type=test` on the contract test that proves it.
    //# When the CMM gets an [encryption materials request](#encryption-materials-request),
    //# it MUST return [encryption materials](structures.md#encryption-materials) appropriate for the request.
    //
    //= ../spec/framework/cmm-interface.md#get-encryption-materials
    //= type=exception
    //= reason=Abstract trait contract; no concrete CMM exists in this commit. Behavior is exercised today by mock-driven contract tests in tests/test_cmm_contract.rs. When a concrete CMM (Default CMM, Caching CMM, etc.) is added, this exception will be replaced with `type=implementation` on the concrete method and `type=test` on the contract test that proves it.
    //# - If the encryption materials request contains an algorithm suite, the encryption materials returned SHOULD contain the same algorithm suite.
    //
    //= ../spec/framework/cmm-interface.md#get-encryption-materials
    //= type=exception
    //= reason=Abstract trait contract; no concrete CMM exists in this commit. Behavior is exercised today by mock-driven contract tests in tests/test_cmm_contract.rs. When a concrete CMM (Default CMM, Caching CMM, etc.) is added, this exception will be replaced with `type=implementation` on the concrete method and `type=test` on the contract test that proves it.
    //# - Every encrypted data key in this list MUST correspond to the above plaintext data key.
    //
    //= ../spec/framework/cmm-interface.md#get-encryption-materials
    //= type=exception
    //= reason=Permission, not mandate. Concrete CMMs (e.g., Required EC CMM) may add or remove EC entries; the abstract trait imposes no policy.
    //# - The CMM MAY modify the encryption context.
    //
    //= ../spec/framework/cmm-interface.md#get-encryption-materials
    //= type=exception
    //= reason=Abstract trait contract; no concrete CMM exists in this commit. Behavior is exercised today by mock-driven contract tests in tests/test_cmm_contract.rs. When a concrete CMM (Default CMM, Caching CMM, etc.) is added, this exception will be replaced with `type=implementation` on the concrete method and `type=test` on the contract test that proves it.
    //# - The CMM MUST include a [signing key](structures.md#signing-key).
    //
    //= ../spec/framework/cmm-interface.md#get-encryption-materials
    //= type=exception
    //= reason=Abstract trait contract; no concrete CMM exists in this commit. Behavior is exercised today by mock-driven contract tests in tests/test_cmm_contract.rs. When a concrete CMM (Default CMM, Caching CMM, etc.) is added, this exception will be replaced with `type=implementation` on the concrete method and `type=test` on the contract test that proves it.
    //# - The CMM SHOULD also add a key-value pair using the reserved key `aws-crypto-public-key` to the encryption context.
    //
    //= ../spec/framework/cmm-interface.md#get-encryption-materials
    //= type=exception
    //= reason=Abstract trait contract; no concrete CMM exists in this commit. Behavior is exercised today by mock-driven contract tests in tests/test_cmm_contract.rs. When a concrete CMM (Default CMM, Caching CMM, etc.) is added, this exception will be replaced with `type=implementation` on the concrete method and `type=test` on the contract test that proves it.
    //# If it does, the mapped value SHOULD be the signature verification key corresponding to the signing key.
    //
    //= ../spec/framework/cmm-interface.md#get-encryption-materials
    //= type=exception
    //= reason=Abstract trait contract; no concrete CMM exists in this commit. Behavior is exercised today by mock-driven contract tests in tests/test_cmm_contract.rs. When a concrete CMM (Default CMM, Caching CMM, etc.) is added, this exception will be replaced with `type=implementation` on the concrete method and `type=test` on the contract test that proves it.
    //# - The CMM SHOULD NOT add a key-value pair using the reserved key `aws-crypto-public-key` to the encryption context.
    //
    //= ../spec/framework/cmm-interface.md#get-encryption-materials
    //= type=exception
    //= reason=Abstract trait contract; no concrete CMM exists in this commit. Behavior is exercised today by mock-driven contract tests in tests/test_cmm_contract.rs. When a concrete CMM (Default CMM, Caching CMM, etc.) is added, this exception will be replaced with `type=implementation` on the concrete method and `type=test` on the contract test that proves it.
    //# The CMM MUST ensure that the encryption materials returned are valid.
    //
    //= ../spec/framework/cmm-interface.md#get-encryption-materials
    //= type=exception
    //= reason=Cannot enforce a non-NULL PDK at the trait level — a concrete CMM has not been added. EncryptionMaterials::plaintext_data_key() returns Option<&PlaintextDataKey> to express the materials shape; the concrete CMM is responsible for ensuring Some(_) on the encrypt path.
    //# - The value of the plaintext data key MUST be non-NULL.
    //
    //= ../spec/framework/cmm-interface.md#get-encryption-materials
    //= type=exception
    //= reason=Abstract trait contract; no concrete CMM exists in this commit. The mock contract test asserts the suite-derived PDK length; concrete CMMs (Default CMM via keyring) will enforce when added.
    //# - The plaintext data key length MUST be equal to the [key derivation input length](algorithm-suites.md#key-derivation-input-length).
    //
    //= ../spec/framework/cmm-interface.md#get-encryption-materials
    //= type=exception
    //= reason=Abstract trait contract; no concrete CMM exists in this commit. EncryptionMaterials::new only enforces the converse (EDK list MUST be empty when PDK absent); the at-least-one rule for the success path is concrete-CMM scope.
    //# - The encrypted data keys list MUST contain at least one encrypted data key.
    //
    //= ../spec/framework/cmm-interface.md#get-encryption-materials
    //= type=exception
    //= reason=Abstract trait contract; no concrete CMM exists in this commit. Behavior is exercised today by mock-driven contract tests in tests/test_cmm_contract.rs. When a concrete CMM (Default CMM, Caching CMM, etc.) is added, this exception will be replaced with `type=implementation` on the concrete method and `type=test` on the contract test that proves it.
    //# - If the algorithm suite contains a signing algorithm, the encryption materials returned MUST include the generated signing key.
    //
    //= ../spec/framework/cmm-interface.md#get-encryption-materials
    //= type=exception
    //= reason=Abstract trait contract; no concrete CMM exists in this commit. The super-set rule maps from request RECK to materials RECK; concrete CMM ensures.
    //# - The [Required Encryption Context Keys](structures.md#required-encryption-context-keys) MUST be
    //# a super set of the Required Encryption Context Keys in the [encryption materials request](#encryption-materials-request).
    async fn get_encryption_materials(
        &self,
        request: EncryptionMaterialsRequest,
    ) -> Result<EncryptionMaterials, MaterialsError>;

    /// Assemble decryption materials for a decrypt request. Mirrors the
    /// `Decrypt Materials` behavior of the
    /// [CMM interface specification](../../../spec/framework/cmm-interface.md#decrypt-materials).
    //= ../spec/framework/cmm-interface.md#decrypt-materials
    //= type=exception
    //= reason=Abstract trait contract; no concrete CMM exists in this commit. Behavior is exercised today by mock-driven contract tests in tests/test_cmm_contract.rs. When a concrete CMM (Default CMM, Caching CMM, etc.) is added, this exception will be replaced with `type=implementation` on the concrete method and `type=test` on the contract test that proves it.
    //# When the CMM gets a [decrypt materials request](#decrypt-materials-request),
    //# it MUST return [decryption materials](structures.md#decryption-materials) appropriate for the request.
    //
    //= ../spec/framework/cmm-interface.md#decrypt-materials
    //= type=exception
    //= reason=Abstract trait contract; no concrete CMM exists in this commit. Behavior is exercised today by mock-driven contract tests in tests/test_cmm_contract.rs (AwsCryptoPublicKeyUnexpected error kind). When a concrete CMM is added, this exception will be replaced with `type=implementation` on the concrete method and `type=test` on the contract test that proves it.
    //# If the requested algorithm suite does not include a signing algorithm but the encryption context includes the reserved `aws-crypto-public-key` key, the operation SHOULD fail.
    //
    //= ../spec/framework/cmm-interface.md#decrypt-materials
    //= type=exception
    //= reason=Abstract trait contract; no concrete CMM exists in this commit. Behavior is exercised today by mock-driven contract tests in tests/test_cmm_contract.rs (AwsCryptoPublicKeyMissing error kind). When a concrete CMM is added, this exception will be replaced with `type=implementation` on the concrete method and `type=test` on the contract test that proves it.
    //# Likewise, if the requested algorithm suite includes a signing algorithm but the encryption context does not include the reserved `aws-crypto-public-key` key, the operation SHOULD fail.
    //
    //= ../spec/framework/cmm-interface.md#decrypt-materials
    //= type=exception
    //= reason=Abstract trait contract; no concrete CMM exists in this commit. Behavior is exercised today by mock-driven contract tests in tests/test_cmm_contract.rs. When a concrete CMM is added, this exception will be replaced with `type=implementation` on the concrete method and `type=test` on the contract test that proves it.
    //# The CMM MUST validate the [Encryption Context](structures.md#encryption-context)
    //# by comparing it to the customer supplied [Reproduced Encryption Context](structures.md#encryption-context)
    //# in [decrypt materials request](#decrypt-materials-request).
    //
    //= ../spec/framework/cmm-interface.md#decrypt-materials
    //= type=exception
    //= reason=Abstract trait contract; no concrete CMM exists in this commit. Behavior is exercised today by mock-driven contract tests in tests/test_cmm_contract.rs (EncryptionContextValueMismatch error kind). When a concrete CMM is added, this exception will be replaced with `type=implementation` on the concrete method and `type=test` on the contract test that proves it.
    //# For every key that exists in both [Reproduced Encryption Context](structures.md#encryption-context)
    //# and [Encryption Context](structures.md#encryption-context),
    //# the values MUST be equal or the operation MUST fail.
    //
    //= ../spec/framework/cmm-interface.md#decrypt-materials
    //= type=exception
    //= reason=Permission, not mandate. Concrete CMMs (e.g., Required EC CMM) may fail on missing reproduced keys; the abstract trait imposes no policy.
    //# The CMM MAY fail if it expects key-value pairs
    //# that do not exist in [Reproduced Encryption Context](structures.md#encryption-context)
    //# on the [decrypt materials request](#decrypt-materials-request).
    //
    //= ../spec/framework/cmm-interface.md#decrypt-materials
    //= type=exception
    //= reason=Permission, not mandate. Concrete CMMs (Default CMM, Required EC CMM) may add or remove EC entries; the abstract trait imposes no policy.
    //# - The CMM MAY modify the encryption context.
    //
    //= ../spec/framework/cmm-interface.md#decrypt-materials
    //= type=exception
    //= reason=Abstract trait contract; no concrete CMM exists in this commit. The Default CMM will invert encrypt-side EC operations on the decrypt path when added.
    //# - The operations made on the encryption context on the Get Encryption Materials call
    //# SHOULD be inverted on the Decrypt Materials call.
    //
    //= ../spec/framework/cmm-interface.md#decrypt-materials
    //= type=exception
    //= reason=Abstract trait contract; no concrete CMM exists in this commit. Concrete CMMs (Required EC CMM) will append-from-reproduced-only when added.
    //# - All key-value pairs that exist in [Reproduced Encryption Context](structures.md#encryption-context)
    //# but do not exist in encryption context on the [decrypt materials request](#decrypt-materials-request)
    //# SHOULD be appended to the decryption materials.
    //
    //= ../spec/framework/cmm-interface.md#decrypt-materials
    //= type=exception
    //= reason=Abstract trait contract; no concrete CMM exists in this commit. Behavior is exercised today by mock-driven contract tests in tests/test_cmm_contract.rs. When a concrete CMM is added, this exception will be replaced with `type=implementation` on the concrete method and `type=test` on the contract test that proves it.
    //# - If the decrypt materials request contains an algorithm suite,
    //# the decryption materials returned SHOULD contain the same algorithm suite.
    //
    //= ../spec/framework/cmm-interface.md#decrypt-materials
    //= type=exception
    //= reason=Abstract trait contract; no concrete CMM exists in this commit. Concrete CMMs (Required EC CMM) will populate this set from the reproduced-only keys when added.
    //# - This set MUST include all keys added to the decryption materials encryption context
    //# that existed in the [decrypt materials request's](#decrypt-materials-request) reproduced encryption context
    //# but did not exist in the [decrypt materials request's](#decrypt-materials-request) encryption context.
    //
    //= ../spec/framework/cmm-interface.md#decrypt-materials
    //= type=exception
    //= reason=Abstract trait contract; no concrete CMM exists in this commit. Behavior is exercised today by mock-driven contract tests in tests/test_cmm_contract.rs. When a concrete CMM is added, this exception will be replaced with `type=implementation` on the concrete method and `type=test` on the contract test that proves it.
    //# If the algorithm suite obtained from the decryption request contains a [signing algorithm](algorithm-suites.md#signature-algorithm),
    //# the decryption materials MUST include the [signature verification key](structures.md#verification-key).
    //
    //= ../spec/framework/cmm-interface.md#decrypt-materials
    //= type=exception
    //= reason=Abstract trait contract; no concrete CMM exists in this commit. Behavior is exercised today by mock-driven contract tests in tests/test_cmm_contract.rs. When a concrete CMM is added, this exception will be replaced with `type=implementation` on the concrete method and `type=test` on the contract test that proves it.
    //# The CMM MUST ensure that the decryption materials returned are valid.
    //
    //= ../spec/framework/cmm-interface.md#decrypt-materials
    //= type=exception
    //= reason=Cannot enforce a non-NULL PDK at the trait level — a concrete CMM has not been added. DecryptionMaterials::plaintext_data_key() returns Option<&PlaintextDataKey>; the concrete CMM is responsible for ensuring Some(_) on the decrypt success path.
    //# - The value of the plaintext data key MUST be non-NULL.
    //
    //= ../spec/framework/cmm-interface.md#decrypt-materials
    //= type=exception
    //= reason=Abstract trait contract; no concrete CMM exists in this commit. Concrete CMM (Default CMM via keyring) will recover the PDK from one of the EDKs when added.
    //# - The plaintext data key returned MUST correspond with at least one of the encrypted data keys.
    async fn decrypt_materials(
        &self,
        request: DecryptMaterialsRequest,
    ) -> Result<DecryptionMaterials, MaterialsError>;
}

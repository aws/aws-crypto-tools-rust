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

//= ../spec/framework/keyring-interface.md#overview
//= type=implication
//# The keyring interface specified in this document describes the interface all keyrings MUST implement.
//
//= ../spec/framework/keyring-interface.md#why-should-i-use-keyrings-instead-of-master-key-providers-and-master-keys
//= type=implication
//# Due to this simplified architecture, master keys and master key providers are going to be deprecated in the future,
//# and new implementations SHOULD use keyrings.
//
//= ../spec/framework/keyring-interface.md#key-namespace
//= type=exception
//= reason=Per-concrete-keyring configuration. The abstract trait imposes no field shape; each concrete keyring (Raw AES, Raw RSA, KMS) declares its own String-typed namespace when added.
//# The key namespace MUST be a string value.
//
//= ../spec/framework/keyring-interface.md#key-name
//= type=exception
//= reason=Per-concrete-keyring configuration. The abstract trait imposes no field shape; each concrete keyring declares its own String-typed name when added.
//# The key name MUST be a string value.
//
//= ../spec/framework/keyring-interface.md#key-provider-id
//= type=exception
//= reason=Value-selection rule applies when a concrete keyring constructs an EncryptedDataKey; the trait does not produce EDKs. Enforced per concrete keyring (only AWS KMS keyrings will use "aws-kms" provider IDs).
//# This value MUST NOT be or start with "aws-kms"
//# unless this encrypted data key was produced by one of the [AWS KMS Keyrings](./aws-kms/).
//
//= ../spec/framework/keyring-interface.md#onencrypt
//= type=exception
//= reason=Abstract trait contract; no concrete keyring exists in this commit. The "MUST modify with at least one behavior" mutation is exercised today by mock-driven contract tests in tests/test_keyring_contract.rs. When a concrete keyring (Raw AES, AWS KMS, etc.) is added, this exception will be replaced with `type=implementation` on the concrete method and `type=test` on the contract test that proves it.
//# It MUST modify it with at least one of the following behaviors:
//
//= ../spec/framework/keyring-interface.md#onencrypt
//= type=exception
//= reason=Abstract trait contract; no concrete keyring exists in this commit. The success-path "MUST output modified materials" behavior is exercised today by mock-driven contract tests in tests/test_keyring_contract.rs. When a concrete keyring (Raw AES, AWS KMS, etc.) is added, this exception will be replaced with `type=implementation` on the concrete method and `type=test` on the contract test that proves it.
//# If this keyring attempted any of the above behaviors, and successfully completed those behaviors,
//# it MUST output the modified [encryption materials](structures.md#encryption-materials).
//
//= ../spec/framework/keyring-interface.md#onencrypt
//= type=exception
//= reason=Abstract trait contract; no concrete keyring exists in this commit. The "no behaviors attempted MUST fail without mutation" behavior is exercised today by mock-driven contract tests in tests/test_keyring_contract.rs. When a concrete keyring (Raw AES, AWS KMS, etc.) is added, this exception will be replaced with `type=implementation` on the concrete method and `type=test` on the contract test that proves it.
//# If the keyring did not attempt any of the above behaviors, it MUST fail
//# and it MUST NOT modify the [encryption materials](structures.md#encryption-materials).
//
//= ../spec/framework/keyring-interface.md#onencrypt
//= type=exception
//= reason=Concrete-keyring conduct; the abstract trait does not produce EDKs. Each concrete keyring (Raw AES, KMS) honors this when constructing EDK fields.
//# The keyring SHOULD NOT attempt to store the encryption context
//# in the [encrypted data key's](structures.md#encrypted-data-key) properties.
//
//= ../spec/framework/keyring-interface.md#generate-data-key
//= type=exception
//= reason=Abstract trait contract; no concrete keyring exists in this commit. The "MUST generate a data key when materials lack one" behavior is exercised today by mock-driven contract tests in tests/test_keyring_contract.rs. When a concrete keyring (Raw AES, AWS KMS, etc.) is added, this exception will be replaced with `type=implementation` on the concrete method and `type=test` on the contract test that proves it.
//# If the [encryption materials](structures.md#encryption-materials) do not contain a plaintext data key,
//# OnEncrypt MUST generate a data key.
//
//= ../spec/framework/keyring-interface.md#generate-data-key
//= type=exception
//= reason=Abstract trait contract; no concrete keyring exists in this commit. The "MUST NOT generate when a PDK is already present" behavior is exercised today by mock-driven contract tests in tests/test_keyring_contract.rs. When a concrete keyring (Raw AES, AWS KMS, etc.) is added, this exception will be replaced with `type=implementation` on the concrete method and `type=test` on the contract test that proves it.
//# If the encryption materials contain a plaintext data key, OnEncrypt MUST NOT generate a data key.
//
//= ../spec/framework/keyring-interface.md#generate-data-key
//= type=exception
//= reason=Abstract trait contract; no concrete keyring exists in this commit. The "MUST modify the plaintext-data-key field on generate" behavior is exercised today by mock-driven contract tests in tests/test_keyring_contract.rs. When a concrete keyring (Raw AES, AWS KMS, etc.) is added, this exception will be replaced with `type=implementation` on the concrete method and `type=test` on the contract test that proves it.
//# Generate Data Key MUST modify the following fields in the [encryption materials](structures.md#encryption-materials):
//
//= ../spec/framework/keyring-interface.md#generate-data-key
//= type=exception
//= reason=Abstract trait contract; no concrete keyring exists in this commit. The "generated PDK length MUST equal the suite KDF input length" behavior is exercised today by mock-driven contract tests in tests/test_keyring_contract.rs. When a concrete keyring (Raw AES, AWS KMS, etc.) is added, this exception will be replaced with `type=implementation` on the concrete method and `type=test` on the contract test that proves it.
//# The length of the output plaintext data key MUST be equal to the KDF input length of the [algorithm suite](algorithm-suites.md)
//# specified in the [encryption materials](structures.md#encryption-materials).
//
//= ../spec/framework/keyring-interface.md#generate-data-key
//= type=exception
//= reason=Concrete-keyring randomness source. Mock keyring uses deterministic bytes for testability; concrete keyrings (Raw AES, KMS) will source from a CSPRNG (rand::rngs::OsRng or KMS-side randomness) when implemented.
//# The value of the plaintext data key MUST consist of cryptographically secure (pseudo-)random bits.
//
//= ../spec/framework/keyring-interface.md#generate-data-key
//= type=exception
//= reason=Abstract trait contract; no concrete keyring exists in this commit. The "MAY chain encrypt-data-key after generate" behavior is exercised today by mock-driven contract tests in tests/test_keyring_contract.rs. When a concrete keyring (Raw AES, AWS KMS, etc.) is added, this exception will be replaced with `type=implementation` on the concrete method and `type=test` on the contract test that proves it.
//# Note: If the keyring successfully performs this behavior, this means that the keyring MAY then
//# perform the [Encrypt Data Key](#encrypt-data-key) behavior.
//
//= ../spec/framework/keyring-interface.md#encrypt-data-key
//= type=exception
//= reason=Abstract trait contract; no concrete keyring exists in this commit. The "MUST encrypt a data key when materials contain a PDK" behavior is exercised today by mock-driven contract tests in tests/test_keyring_contract.rs. When a concrete keyring (Raw AES, AWS KMS, etc.) is added, this exception will be replaced with `type=implementation` on the concrete method and `type=test` on the contract test that proves it.
//# If the [encryption materials](structures.md#encryption-materials) contain a plaintext data key,
//# OnEncrypt MUST encrypt a data key.
//
//= ../spec/framework/keyring-interface.md#encrypt-data-key
//= type=exception
//= reason=Abstract trait contract; no concrete keyring exists in this commit. The "MUST NOT encrypt when materials lack a PDK" behavior is exercised today by mock-driven contract tests in tests/test_keyring_contract.rs. When a concrete keyring (Raw AES, AWS KMS, etc.) is added, this exception will be replaced with `type=implementation` on the concrete method and `type=test` on the contract test that proves it.
//# If the encryption materials do not contain a plaintext data key, OnEncrypt MUST NOT encrypt a data key.
//
//= ../spec/framework/keyring-interface.md#encrypt-data-key
//= type=exception
//= reason=Abstract trait contract; no concrete keyring exists in this commit. The "MUST modify the encrypted-data-keys field on encrypt" behavior is exercised today by mock-driven contract tests in tests/test_keyring_contract.rs. When a concrete keyring (Raw AES, AWS KMS, etc.) is added, this exception will be replaced with `type=implementation` on the concrete method and `type=test` on the contract test that proves it.
//# Encrypt Data Key MUST modify the following fields in the [encryption materials](structures.md#encryption-materials):
//
//= ../spec/framework/keyring-interface.md#encrypt-data-key
//= type=exception
//= reason=Abstract trait contract; no concrete keyring exists in this commit. The "EDK ciphertexts MUST be decryptable to the plaintext data key" round-trip behavior is exercised today by mock-driven contract tests in tests/test_keyring_contract.rs. When a concrete keyring (Raw AES, AWS KMS, etc.) is added, this exception will be replaced with `type=implementation` on the concrete method and `type=test` on the contract test that proves it.
//# The [encrypted data keys](structures.md#encrypted-data-key) produced by this keyring MUST
//# have [ciphertexts](structures.md#ciphertext) that can be decrypted to the plaintext data key in the
//# [encryption materials](structures.md#encryption-materials).
//
//= ../spec/framework/keyring-interface.md#ondecrypt
//= type=exception
//= reason=Abstract trait contract; no concrete keyring exists in this commit. The "MUST modify with the decrypt-data-key behavior" mutation is exercised today by mock-driven contract tests in tests/test_keyring_contract.rs. When a concrete keyring (Raw AES, AWS KMS, etc.) is added, this exception will be replaced with `type=implementation` on the concrete method and `type=test` on the contract test that proves it.
//# It MUST modify it with the following behavior:
//
//= ../spec/framework/keyring-interface.md#ondecrypt
//= type=exception
//= reason=Abstract trait contract; no concrete keyring exists in this commit. The "MUST fail without mutation if a PDK is already present" behavior is exercised today by mock-driven contract tests in tests/test_keyring_contract.rs. When a concrete keyring (Raw AES, AWS KMS, etc.) is added, this exception will be replaced with `type=implementation` on the concrete method and `type=test` on the contract test that proves it.
//# If the decryption materials already contain a plaintext data key,
//# the keyring MUST fail
//# and MUST NOT modify the [decryption materials](structures.md#decryption-materials).
//
//= ../spec/framework/keyring-interface.md#ondecrypt
//= type=exception
//= reason=Abstract trait contract; no concrete keyring exists in this commit. The success-path "MUST output modified decryption materials" behavior is exercised today by mock-driven contract tests in tests/test_keyring_contract.rs. When a concrete keyring (Raw AES, AWS KMS, etc.) is added, this exception will be replaced with `type=implementation` on the concrete method and `type=test` on the contract test that proves it.
//# If this keyring attempted the above behavior, and succeeded, it MUST output the modified [decryption materials](structures.md#decryption-materials).
//
//= ../spec/framework/keyring-interface.md#ondecrypt
//= type=exception
//= reason=Abstract trait contract; no concrete keyring exists in this commit. The "MUST fail without mutation if no decrypt behavior was attempted" path is exercised today by mock-driven contract tests in tests/test_keyring_contract.rs. When a concrete keyring (Raw AES, AWS KMS, etc.) is added, this exception will be replaced with `type=implementation` on the concrete method and `type=test` on the contract test that proves it.
//# If the keyring did not attempt the above behavior,
//# the keyring MUST fail
//# and MUST NOT modify the [decryption materials](structures.md#decryption-materials).
//
//= ../spec/framework/keyring-interface.md#decrypt-data-key
//= type=exception
//= reason=Abstract trait contract; no concrete keyring exists in this commit. The "MUST NOT decrypt a data key when a PDK is already present" behavior is exercised today by mock-driven contract tests in tests/test_keyring_contract.rs. When a concrete keyring (Raw AES, AWS KMS, etc.) is added, this exception will be replaced with `type=implementation` on the concrete method and `type=test` on the contract test that proves it.
//# If the encryption materials do contain a plaintext data key, OnDecrypt MUST NOT decrypt a data key.
//
//= ../spec/framework/keyring-interface.md#decrypt-data-key
//= type=exception
//= reason=Abstract trait contract; no concrete keyring exists in this commit. The "MUST decrypt a data key when decryption materials lack one" behavior is exercised today by mock-driven contract tests in tests/test_keyring_contract.rs. When a concrete keyring (Raw AES, AWS KMS, etc.) is added, this exception will be replaced with `type=implementation` on the concrete method and `type=test` on the contract test that proves it.
//# If the [decryption materials](structures.md#decryption-materials) do not include a plaintext data key,
//# OnDecrypt MUST decrypt a data key.
//
//= ../spec/framework/keyring-interface.md#decrypt-data-key
//= type=exception
//= reason=Abstract trait contract; no concrete keyring exists in this commit. The "MUST modify the Plaintext-data-key field on decrypt" behavior is exercised today by mock-driven contract tests in tests/test_keyring_contract.rs. When a concrete keyring (Raw AES, AWS KMS, etc.) is added, this exception will be replaced with `type=implementation` on the concrete method and `type=test` on the contract test that proves it.
//# The decrypt data key MUST modify the following fields in the [decryption materials](structures.md#decryption-materials):
//
//= ../spec/framework/keyring-interface.md#decrypt-data-key
//= type=exception
//= reason=Abstract trait contract; no concrete keyring exists in this commit. The "SHOULD set one resulting plaintext data key on success" behavior is exercised today by mock-driven contract tests in tests/test_keyring_contract.rs. When a concrete keyring (Raw AES, AWS KMS, etc.) is added, this exception will be replaced with `type=implementation` on the concrete method and `type=test` on the contract test that proves it.
//# If the keyring is able to successfully get at least one plaintext data key from any [encrypted data key](structures.md#encrypted-data-key)
//# and the [decryption materials](structures.md#decryption-materials) still do not include a plaintext data key,
//# it SHOULD set one resulting plaintext data key on the [decryption materials](structures.md#decryption-materials).
//
//= ../spec/framework/keyring-interface.md#decrypt-data-key
//= type=exception
//= reason=Abstract trait contract; no concrete keyring exists in this commit. The "MUST NOT update materials and MUST return failure when no PDK is recoverable" behavior is exercised today by mock-driven contract tests in tests/test_keyring_contract.rs. When a concrete keyring (Raw AES, AWS KMS, etc.) is added, this exception will be replaced with `type=implementation` on the concrete method and `type=test` on the contract test that proves it.
//# If the keyring is unable to get any plaintext data key using the input [encrypted data keys](structures.md#encrypted-data-key),
//# the keyring MUST NOT not update the [decryption materials](structures.md#decryption-materials) and MUST return failure.
//
//= ../spec/framework/keyring-interface.md#security-considerations
//= type=exception
//= reason=Concrete-keyring crypto property. Raw AES will use AES-GCM and AWS KMS supplies its own authenticated encryption when implemented; the abstract trait scaffolding does not produce ciphertexts.
//# Keyring implementations SHOULD provide integrity guarantees for the [encrypted data keys](structures.md#encrypted-data-key)
//# they return on [OnEncrypt](#onencrypt) such that tampered versions of those encrypted data keys,
//# if input into [OnDecrypt](#ondecrypt), are overwhelmingly likely to cause a decryption failure
//# (i.e.
//
//= ../spec/framework/keyring-interface.md#security-considerations
//= type=exception
//= reason=Concrete-keyring crypto property. AAD-binding of the encryption context will be enforced by Raw AES (via GCM AAD) and by AWS KMS (via EncryptionContext request field) when those keyrings are implemented.
//# Such integrity guarantees SHOULD include the integrity of the [encryption context](structures.md#encryption-context)
//# such that, if the encryption context used as input to OnEncrypt to produce an encrypted data key is
//# different than the encryption context input to OnDecrypt to decrypt that encrypted data key,
//# the decryption is overwhelmingly likely to fail.
//
//= ../spec/framework/keyring-interface.md#security-considerations
//= type=exception
//= reason=User-facing recommendation about keyring choice; not implementable from a keyring trait. Documented in the trait's module docs above.
//# Users SHOULD use a keyring that protects wrapping keys and performs cryptographic operations within a secure boundary.
//
//= ../spec/framework/keyring-interface.md#security-considerations
//= type=exception
//= reason=Raw keyrings are out of scope for this commit (trait scaffolding only). Will be reflected when raw_aes_keyring.rs and raw_rsa_keyring.rs are added.
//# The [raw AES keyring](raw-aes-keyring.md) and [raw RSA keyring](raw-rsa-keyring.md) MAY be used,
//# however users should refer to their specification for notes on their respective security considerations.
#[async_trait]
pub trait Keyring: Send + Sync {
    /// Modify the supplied [`EncryptionMaterials`] by generating and/or
    /// encrypting a data key. See the
    /// [OnEncrypt](../../../spec/framework/keyring-interface.md#onencrypt)
    /// section of the keyring interface specification.
    //= ../spec/framework/keyring-interface.md#onencrypt
    //= type=implication
    //# This interface MUST take [encryption materials](structures.md#encryption-materials) as input.
    async fn on_encrypt(
        &self,
        materials: EncryptionMaterials,
    ) -> Result<EncryptionMaterials, MaterialsError>;

    /// Modify the supplied [`DecryptionMaterials`] by deriving the plaintext
    /// data key from one of the supplied encrypted data keys. See the
    /// [OnDecrypt](../../../spec/framework/keyring-interface.md#ondecrypt)
    /// section of the keyring interface specification.
    //= ../spec/framework/keyring-interface.md#ondecrypt
    //= type=implication
    //# This interface MUST take [decryption materials](structures.md#decryption-materials) and
    //# a list of [encrypted data keys](structures.md#encrypted-data-key) as input.
    async fn on_decrypt(
        &self,
        materials: DecryptionMaterials,
        encrypted_data_keys: &[EncryptedDataKey],
    ) -> Result<DecryptionMaterials, MaterialsError>;
}

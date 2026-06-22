// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The `Keystore` trait — the abstract contract every keystore MUST implement.
//!
//! # Why `async_trait` and not native AFIT
//!
//! Same dyn-compatibility rationale recorded in [`crate::keyring`] and
//! [`crate::cmm`]. The MPL needs `Box<dyn Keystore>` and `&dyn Keystore`
//! for plug-in keystore backends (DynamoDB-backed in this crate today,
//! potentially other backends later). `async_trait` boxes the future to
//! make `dyn Keystore` work on stable Rust.
//!
//! # Concrete-keystore-deferred clauses (`type=exception`)
//!
//! This commit (Phase 1 of the branch-key-store master plan) introduces
//! the abstract `Keystore` trait scaffolding plus the configuration types
//! and error type only — no concrete keystore is implemented yet. Behaviors
//! on every operation method (CreateKey, VersionKey, GetActiveBranchKey,
//! GetBranchKeyVersion, GetBeaconKey, CreateKeyStore, GetKeyStoreInfo)
//! plus the encryption-context construction, record format, and
//! AWS-KMS-backed authentication / decryption are all annotated as
//! `type=exception` here, with `reason=` lines naming the future master
//! plan phase that will fulfill each requirement. The mock-driven contract
//! harness in `tests/test_keystore_contract.rs` exercises the trait shape
//! today; per-phase work will replace the exceptions with
//! `type=implementation` on concrete methods and `type=test` on contract
//! tests that prove them.

pub mod branch_key_store;
pub mod config;
pub mod encryption_context;
pub mod error;
pub mod kms_config;
pub(crate) mod kms_ops;
pub mod record;

use async_trait::async_trait;

pub use branch_key_store::BranchKeyStore;
pub use config::{KeyStoreConfig, KeyStoreInfo, KmsConfiguration};
pub use error::{KeystoreError, KeystoreErrorKind};

use crate::structures::{BeaconKeyMaterials, BranchKeyMaterials, EncryptionContext};

// ─── In-scope implication: operations ───────────────────────────────────────

//= ../spec/framework/branch-key-store.md#operations
//= type=implication
//# The Keystore MUST support the following operations:

// ─── Group G — Phase 5 client deps (7 reqs) ─────────────────────────────────

//= ../spec/framework/branch-key-store.md#dynamodb-client
//= type=exception
//= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 5 (slug keystore-clients), this exception will be replaced with type=implementation on the default-client construction helpers and type=test on the contract test that proves it.
//# If the AWS KMS Configuration is KMS Key ARN or KMS MRKey ARN,
//# and no DynamoDb Client is provided,
//# a new DynamoDb Client MUST be created
//# with the region of the supplied KMS ARN.
//
//= ../spec/framework/branch-key-store.md#dynamodb-client
//= type=exception
//= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 5 (slug keystore-clients), this exception will be replaced with type=implementation on the default-client construction helpers and type=test on the contract test that proves it.
//# If the AWS KMS Configuration is Discovery,
//# and no DynamoDb Client is provided,
//# a new DynamoDb Client MUST be created
//# with the default configuration.
//
//= ../spec/framework/branch-key-store.md#dynamodb-client
//= type=exception
//= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 5 (slug keystore-clients), this exception will be replaced with type=implementation on the default-client construction helpers and type=test on the contract test that proves it.
//# If the AWS KMS Configuration is MRDiscovery,
//# and no DynamoDb Client is provided,
//# a new DynamoDb Client MUST be created
//# with the region configured in the MRDiscovery.
//
//= ../spec/framework/branch-key-store.md#kms-client
//= type=exception
//= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 5 (slug keystore-clients), this exception will be replaced with type=implementation on the default-client construction helpers and type=test on the contract test that proves it.
//# If the AWS KMS Configuration is KMS Key ARN or KMS MRKey ARN,
//# and no KMS Client is provided,
//# a new KMS Client MUST be created
//# with the region of the supplied KMS ARN.
//
//= ../spec/framework/branch-key-store.md#kms-client
//= type=exception
//= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 5 (slug keystore-clients), this exception will be replaced with type=implementation on the default-client construction helpers and type=test on the contract test that proves it.
//# If the AWS KMS Configuration is Discovery,
//# and no KMS Client is provided,
//# a new KMS Client MUST be created
//# with the default configuration.
//
//= ../spec/framework/branch-key-store.md#kms-client
//= type=exception
//= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 5 (slug keystore-clients), this exception will be replaced with type=implementation on the default-client construction helpers and type=test on the contract test that proves it.
//# If the AWS KMS Configuration is MRDiscovery,
//# and no KMS Client is provided,
//# a new KMS Client MUST be created
//# with the region configured in the MRDiscovery.
//
//= ../spec/framework/branch-key-store.md#kms-client
//= type=exception
//= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 5 (slug keystore-clients), this exception will be replaced with type=implementation on the default-client construction helpers and type=test on the contract test that proves it.
//# On initialization the KeyStore SHOULD
//# append a user agent string to the AWS KMS SDK Client with
//# the value `aws-kms-hierarchy`.
#[async_trait]
pub trait Keystore: Send + Sync {
    // ─── GetKeyStoreInfo ────────────────────────────────────────────────

    //= ../spec/framework/branch-key-store.md#getkeystoreinfo
    //= type=implication
    //# This operation MUST return the keystore information in this keystore configuration.
    /// Returns the keystore information for this keystore.
    async fn get_key_store_info(&self) -> Result<KeyStoreInfo, KeystoreError>;

    // ─── CreateKeyStore ─────────────────────────────────────────────────

    //= ../spec/framework/branch-key-store.md#createkeystore
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 7 (slug keystore-create-ops), this exception will be replaced with type=implementation on the concrete create_key_store impl and type=test on the contract test that proves it.
    //# This operation MUST first calls the DDB::DescribeTable API with the configured `tableName`.
    //
    //= ../spec/framework/branch-key-store.md#createkeystore
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 7 (slug keystore-create-ops), this exception will be replaced with type=implementation on the concrete create_key_store impl and type=test on the contract test that proves it.
    //# If the [KeySchema](#keyschema) does not match
    //# this operation MUST yield an error.
    //
    //= ../spec/framework/branch-key-store.md#createkeystore
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 7 (slug keystore-create-ops), this exception will be replaced with type=implementation on the concrete create_key_store impl and type=test on the contract test that proves it.
    //# The table MAY have additional information,
    //# like GlobalSecondaryIndex defined.
    //
    //= ../spec/framework/branch-key-store.md#createkeystore
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 7 (slug keystore-create-ops), this exception will be replaced with type=implementation on the concrete create_key_store impl and type=test on the contract test that proves it.
    //# If the client responds with a `ResourceNotFoundException`,
    //# then this operation MUST continue and
    //# MUST call [AWS DDB CreateTable](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_CreateTable.html)
    //# with the following specifics:
    //
    //= ../spec/framework/branch-key-store.md#createkeystore
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 7 (slug keystore-create-ops), this exception will be replaced with type=implementation on the concrete create_key_store impl and type=test on the contract test that proves it.
    //# If the operation fails to create table, the operation MUST fail.
    //
    //= ../spec/framework/branch-key-store.md#createkeystore
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 7 (slug keystore-create-ops), this exception will be replaced with type=implementation on the concrete create_key_store impl and type=test on the contract test that proves it.
    //# If the operation successfully creates a table, the operation MUST return the AWS DDB Table Arn
    //# back to the caller.
    //
    //= ../spec/framework/branch-key-store.md#keyschema
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 7 (slug keystore-create-ops), this exception will be replaced with type=implementation on the concrete create_key_store impl and type=test on the contract test that proves it.
    //# The following KeySchema MUST be configured on the table:
    /// Creates the backing DynamoDB table for this keystore.
    async fn create_key_store(&self) -> Result<String, KeystoreError>;

    // ─── CreateKey ──────────────────────────────────────────────────────

    //= ../spec/framework/branch-key-store.md#logical-keystore-name
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 7 (slug keystore-create-ops), this exception will be replaced with type=implementation on the concrete create_key impl and type=test on the contract test that proves it.
    //# The logical keystore name MUST be bound to every created key.
    //
    //= ../spec/framework/branch-key-store.md#createkey
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 7 (slug keystore-create-ops), this exception will be replaced with type=implementation on the concrete create_key impl and type=test on the contract test that proves it.
    //# The CreateKey caller MUST provide:
    //
    //= ../spec/framework/branch-key-store.md#createkey
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 7 (slug keystore-create-ops), this exception will be replaced with type=implementation on the concrete create_key impl and type=test on the contract test that proves it.
    //# If an optional branch key id is provided
    //# and no encryption context is provided this operation MUST fail.
    //
    //= ../spec/framework/branch-key-store.md#createkey
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 7 (slug keystore-create-ops), this exception will be replaced with type=implementation on the concrete create_key impl and type=test on the contract test that proves it.
    //# If the Keystore's KMS Configuration is `Discovery` or `MRDiscovery`,
    //# this operation MUST fail.
    //
    //= ../spec/framework/branch-key-store.md#createkey
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 7 (slug keystore-create-ops), this exception will be replaced with type=implementation on the concrete create_key impl and type=test on the contract test that proves it.
    //# If no branch key id is provided,
    //# then this operation MUST create a [version 4 UUID](https://www.ietf.org/rfc/rfc4122.txt)
    //# to be used as the branch key id.
    //
    //= ../spec/framework/branch-key-store.md#createkey
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 7 (slug keystore-create-ops), this exception will be replaced with type=implementation on the concrete create_key impl and type=test on the contract test that proves it.
    //# This operation MUST create a [branch key](structures.md#branch-key) and a [beacon key](structures.md#beacon-key) according to
    //# the [Branch Key and Beacon Key Creation](#branch-key-and-beacon-key-creation) section.
    //
    //= ../spec/framework/branch-key-store.md#createkey
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 7 (slug keystore-create-ops), this exception will be replaced with type=implementation on the concrete create_key impl and type=test on the contract test that proves it.
    //# If creation of the keys are successful,
    //# the operation MUST call Amazon DynamoDB TransactWriteItems according to the [write key material](#writing-branch-key-and-beacon-key-to-keystore) section.
    //
    //= ../spec/framework/branch-key-store.md#createkey
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 7 (slug keystore-create-ops), this exception will be replaced with type=implementation on the concrete create_key impl and type=test on the contract test that proves it.
    //# If writing to the keystore succeeds,
    //# the operation MUST return the branch-key-id that maps to both
    //# the branch key and the beacon key.
    //
    //= ../spec/framework/branch-key-store.md#createkey
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 7 (slug keystore-create-ops), this exception will be replaced with type=implementation on the concrete create_key impl and type=test on the contract test that proves it.
    //# Otherwise, this operation MUST yield an error.
    //
    //= ../spec/framework/branch-key-store.md#writing-branch-key-and-beacon-key-to-keystore
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 7 (slug keystore-create-ops), this exception will be replaced with type=implementation on the concrete create_key impl and type=test on the contract test that proves it.
    //# To add the branch keys and a beacon key to the keystore the
    //# operation MUST call [Amazon DynamoDB API TransactWriteItems](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html).
    //
    //= ../spec/framework/branch-key-store.md#writing-branch-key-and-beacon-key-to-keystore
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 7 (slug keystore-create-ops), this exception will be replaced with type=implementation on the concrete create_key impl and type=test on the contract test that proves it.
    //# The call to Amazon DynamoDB TransactWriteItems MUST use the configured Amazon DynamoDB Client to make the call.
    //
    //= ../spec/framework/branch-key-store.md#writing-branch-key-and-beacon-key-to-keystore
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 7 (slug keystore-create-ops), this exception will be replaced with type=implementation on the concrete create_key impl and type=test on the contract test that proves it.
    //# The operation MUST call Amazon DynamoDB TransactWriteItems with a request constructed as follows:
    //
    //= ../spec/framework/branch-key-store.md#writing-branch-key-and-beacon-key-to-keystore
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 7 (slug keystore-create-ops), this exception will be replaced with type=implementation on the concrete create_key impl and type=test on the contract test that proves it.
    //# - Every key-value pair of the custom [encryption context](./structures.md#encryption-context-3) that is associated with the branch key
    //# MUST be added with an Attribute Name of `aws-crypto-ec:` + the Key and Attribute Value (S) of the value.
    //
    //= ../spec/framework/branch-key-store.md#writing-branch-key-and-beacon-key-to-keystore
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 7 (slug keystore-create-ops), this exception will be replaced with type=implementation on the concrete create_key impl and type=test on the contract test that proves it.
    //# If DDB TransactWriteItems is successful, this operation MUST return a successful response containing no additional data.
    //
    //= ../spec/framework/branch-key-store.md#writing-branch-key-and-beacon-key-to-keystore
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 7 (slug keystore-create-ops), this exception will be replaced with type=implementation on the concrete create_key impl and type=test on the contract test that proves it.
    //# Otherwise, this operation MUST yield an error.
    //
    //= ../spec/framework/branch-key-store.md#branch-key-and-beacon-key-creation
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 6 (slug keystore-key-creation), this exception will be replaced with type=implementation on the wrapped-branch-key creation helper and type=test on the contract test that proves it.
    //# To create a branch key, this operation MUST take the following:
    //
    //= ../spec/framework/branch-key-store.md#branch-key-and-beacon-key-creation
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 6 (slug keystore-key-creation), this exception will be replaced with type=implementation on the wrapped-branch-key creation helper and type=test on the contract test that proves it.
    //# This guid MUST be [version 4 UUID](https://www.ietf.org/rfc/rfc4122.txt)
    //
    //= ../spec/framework/branch-key-store.md#branch-key-and-beacon-key-creation
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 6 (slug keystore-key-creation), this exception will be replaced with type=implementation on the wrapped-branch-key creation helper and type=test on the contract test that proves it.
    //# This timestamp MUST be in ISO 8601 format in UTC, to microsecond precision (e.g.
    //
    //= ../spec/framework/branch-key-store.md#branch-key-and-beacon-key-creation
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 6 (slug keystore-key-creation), this exception will be replaced with type=implementation on the wrapped-branch-key creation helper and type=test on the contract test that proves it.
    //# The wrapped Branch Keys, DECRYPT_ONLY and ACTIVE, MUST be created according to [Wrapped Branch Key Creation](#wrapped-branch-key-creation).
    //
    //= ../spec/framework/branch-key-store.md#branch-key-and-beacon-key-creation
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 6 (slug keystore-key-creation), this exception will be replaced with type=implementation on the wrapped-branch-key creation helper and type=test on the contract test that proves it.
    //# The operation MUST call [AWS KMS API GenerateDataKeyWithoutPlaintext](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKeyWithoutPlaintext.html).
    //
    //= ../spec/framework/branch-key-store.md#branch-key-and-beacon-key-creation
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 6 (slug keystore-key-creation), this exception will be replaced with type=implementation on the wrapped-branch-key creation helper and type=test on the contract test that proves it.
    //# The call to AWS KMS GenerateDataKeyWithoutPlaintext MUST use the configured AWS KMS client to make the call.
    //
    //= ../spec/framework/branch-key-store.md#branch-key-and-beacon-key-creation
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 6 (slug keystore-key-creation), this exception will be replaced with type=implementation on the wrapped-branch-key creation helper and type=test on the contract test that proves it.
    //# The operation MUST call AWS KMS GenerateDataKeyWithoutPlaintext with a request constructed as follows:
    //
    //= ../spec/framework/branch-key-store.md#branch-key-and-beacon-key-creation
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 6 (slug keystore-key-creation), this exception will be replaced with type=implementation on the wrapped-branch-key creation helper and type=test on the contract test that proves it.
    //# - `KeyId` MUST be the configured `AWS KMS Key ARN` in the [AWS KMS Configuration](#aws-kms-configuration) for this keystore.
    //
    //= ../spec/framework/branch-key-store.md#branch-key-and-beacon-key-creation
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 6 (slug keystore-key-creation), this exception will be replaced with type=implementation on the wrapped-branch-key creation helper and type=test on the contract test that proves it.
    //# - `NumberOfBytes` MUST be 32.
    //
    //= ../spec/framework/branch-key-store.md#branch-key-and-beacon-key-creation
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 6 (slug keystore-key-creation), this exception will be replaced with type=implementation on the wrapped-branch-key creation helper and type=test on the contract test that proves it.
    //# - `EncryptionContext` MUST be the [encryption context for beacon keys](#beacon-key-encryption-context).
    //
    //= ../spec/framework/branch-key-store.md#branch-key-and-beacon-key-creation
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 6 (slug keystore-key-creation), this exception will be replaced with type=implementation on the wrapped-branch-key creation helper and type=test on the contract test that proves it.
    //# - `GrantTokens` MUST be this keystore's [grant tokens](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#grant_token).
    //
    //= ../spec/framework/branch-key-store.md#branch-key-and-beacon-key-creation
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 6 (slug keystore-key-creation), this exception will be replaced with type=implementation on the wrapped-branch-key creation helper and type=test on the contract test that proves it.
    //# If the call to AWS KMS GenerateDataKeyWithoutPlaintext succeeds,
    //# the operation MUST use the `CiphertextBlob` as the wrapped Beacon Key.
    //
    //= ../spec/framework/branch-key-store.md#wrapped-branch-key-creation
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 6 (slug keystore-key-creation), this exception will be replaced with type=implementation on the wrapped-branch-key creation helper and type=test on the contract test that proves it.
    //# The operation MUST call [AWS KMS API GenerateDataKeyWithoutPlaintext](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKeyWithoutPlaintext.html).
    //
    //= ../spec/framework/branch-key-store.md#wrapped-branch-key-creation
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 6 (slug keystore-key-creation), this exception will be replaced with type=implementation on the wrapped-branch-key creation helper and type=test on the contract test that proves it.
    //# The call to AWS KMS GenerateDataKeyWithoutPlaintext MUST use the configured AWS KMS client to make the call.
    //
    //= ../spec/framework/branch-key-store.md#wrapped-branch-key-creation
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 6 (slug keystore-key-creation), this exception will be replaced with type=implementation on the wrapped-branch-key creation helper and type=test on the contract test that proves it.
    //# The operation MUST call AWS KMS GenerateDataKeyWithoutPlaintext with a request constructed as follows:
    //
    //= ../spec/framework/branch-key-store.md#wrapped-branch-key-creation
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 6 (slug keystore-key-creation), this exception will be replaced with type=implementation on the wrapped-branch-key creation helper and type=test on the contract test that proves it.
    //# - `KeyId` MUST be the configured `AWS KMS Key ARN` in the [AWS KMS Configuration](#aws-kms-configuration) for this keystore.
    //
    //= ../spec/framework/branch-key-store.md#wrapped-branch-key-creation
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 6 (slug keystore-key-creation), this exception will be replaced with type=implementation on the wrapped-branch-key creation helper and type=test on the contract test that proves it.
    //# - `NumberOfBytes` MUST be 32.
    //
    //= ../spec/framework/branch-key-store.md#wrapped-branch-key-creation
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 6 (slug keystore-key-creation), this exception will be replaced with type=implementation on the wrapped-branch-key creation helper and type=test on the contract test that proves it.
    //# - `EncryptionContext` MUST be the [DECRYPT_ONLY encryption context for branch keys](#decrypt_only-encryption-context).
    //
    //= ../spec/framework/branch-key-store.md#wrapped-branch-key-creation
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 6 (slug keystore-key-creation), this exception will be replaced with type=implementation on the wrapped-branch-key creation helper and type=test on the contract test that proves it.
    //# - GenerateDataKeyWithoutPlaintext `GrantTokens` MUST be this keystore's [grant tokens](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#grant_token).
    //
    //= ../spec/framework/branch-key-store.md#wrapped-branch-key-creation
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 6 (slug keystore-key-creation), this exception will be replaced with type=implementation on the wrapped-branch-key creation helper and type=test on the contract test that proves it.
    //# If the call to AWS KMS GenerateDataKeyWithoutPlaintext succeeds,
    //# the operation MUST use the GenerateDataKeyWithoutPlaintext result `CiphertextBlob`
    //# as the wrapped DECRYPT_ONLY Branch Key.
    //
    //= ../spec/framework/branch-key-store.md#wrapped-branch-key-creation
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 6 (slug keystore-key-creation), this exception will be replaced with type=implementation on the wrapped-branch-key creation helper and type=test on the contract test that proves it.
    //# The operation MUST call [AWS KMS API ReEncrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_ReEncrypt.html)
    //# with a request constructed as follows:
    //
    //= ../spec/framework/branch-key-store.md#wrapped-branch-key-creation
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 6 (slug keystore-key-creation), this exception will be replaced with type=implementation on the wrapped-branch-key creation helper and type=test on the contract test that proves it.
    //# - `SourceEncryptionContext` MUST be the [DECRYPT_ONLY encryption context for branch keys](#decrypt_only-encryption-context).
    //
    //= ../spec/framework/branch-key-store.md#wrapped-branch-key-creation
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 6 (slug keystore-key-creation), this exception will be replaced with type=implementation on the wrapped-branch-key creation helper and type=test on the contract test that proves it.
    //# - `SourceKeyId` MUST be the configured `AWS KMS Key ARN` in the [AWS KMS Configuration](#aws-kms-configuration) for this keystore.
    //
    //= ../spec/framework/branch-key-store.md#wrapped-branch-key-creation
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 6 (slug keystore-key-creation), this exception will be replaced with type=implementation on the wrapped-branch-key creation helper and type=test on the contract test that proves it.
    //# - `CiphertextBlob` MUST be the wrapped DECRYPT_ONLY Branch Key.
    //
    //= ../spec/framework/branch-key-store.md#wrapped-branch-key-creation
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 6 (slug keystore-key-creation), this exception will be replaced with type=implementation on the wrapped-branch-key creation helper and type=test on the contract test that proves it.
    //# - ReEncrypt `GrantTokens` MUST be this keystore's [grant tokens](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#grant_token).
    //
    //= ../spec/framework/branch-key-store.md#wrapped-branch-key-creation
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 6 (slug keystore-key-creation), this exception will be replaced with type=implementation on the wrapped-branch-key creation helper and type=test on the contract test that proves it.
    //# - `DestinationKeyId` MUST be the configured `AWS KMS Key ARN` in the [AWS KMS Configuration](#aws-kms-configuration) for this keystore.
    //
    //= ../spec/framework/branch-key-store.md#wrapped-branch-key-creation
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 6 (slug keystore-key-creation), this exception will be replaced with type=implementation on the wrapped-branch-key creation helper and type=test on the contract test that proves it.
    //# - `DestinationEncryptionContext` MUST be the [ACTIVE encryption context for branch keys](#active-encryption-context).
    //
    //= ../spec/framework/branch-key-store.md#wrapped-branch-key-creation
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 6 (slug keystore-key-creation), this exception will be replaced with type=implementation on the wrapped-branch-key creation helper and type=test on the contract test that proves it.
    //# If the call to AWS KMS ReEncrypt succeeds,
    //# the operation MUST use the ReEncrypt result `CiphertextBlob`
    //# as the wrapped ACTIVE Branch Key.
    /// Creates a new branch key + beacon key pair in this keystore.
    async fn create_key(
        &self,
        branch_key_id: Option<String>,
        encryption_context: Option<EncryptionContext>,
    ) -> Result<String, KeystoreError>;

    // ─── VersionKey ─────────────────────────────────────────────────────

    //= ../spec/framework/branch-key-store.md#versionkey
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 9 (slug keystore-version-key), this exception will be replaced with type=implementation on the concrete version_key impl and type=test on the contract test that proves it.
    //# - MUST supply a `branch-key-id`
    //
    //= ../spec/framework/branch-key-store.md#versionkey
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 9 (slug keystore-version-key), this exception will be replaced with type=implementation on the concrete version_key impl and type=test on the contract test that proves it.
    //# If the Keystore's KMS Configuration is `Discovery` or `MRDiscovery`,
    //# this operation MUST immediately fail.
    //
    //= ../spec/framework/branch-key-store.md#versionkey
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 9 (slug keystore-version-key), this exception will be replaced with type=implementation on the concrete version_key impl and type=test on the contract test that proves it.
    //# VersionKey MUST first get the active version for the branch key from the keystore
    //# by calling AWS DDB `GetItem`
    //# using the `branch-key-id` as the Partition Key and `"branch:ACTIVE"` value as the Sort Key.
    //
    //= ../spec/framework/branch-key-store.md#versionkey
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 9 (slug keystore-version-key), this exception will be replaced with type=implementation on the concrete version_key impl and type=test on the contract test that proves it.
    //# The `kms-arn` field of DDB response item MUST be [compatible with](#aws-key-arn-compatibility)
    //# the configured `KMS ARN` in the [AWS KMS Configuration](#aws-kms-configuration) for this keystore.
    //
    //= ../spec/framework/branch-key-store.md#versionkey
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 9 (slug keystore-version-key), this exception will be replaced with type=implementation on the concrete version_key impl and type=test on the contract test that proves it.
    //# The `kms-arn` stored in the DDB table MUST NOT change as a result of this operation,
    //# even if the KeyStore is configured with a `KMS MRKey ARN` that does not exactly match the stored ARN.
    //
    //= ../spec/framework/branch-key-store.md#versionkey
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 9 (slug keystore-version-key), this exception will be replaced with type=implementation on the concrete version_key impl and type=test on the contract test that proves it.
    //# The values on the AWS DDB response item
    //# MUST be authenticated according to [authenticating a keystore item](#authenticating-a-keystore-item).
    //
    //= ../spec/framework/branch-key-store.md#versionkey
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 9 (slug keystore-version-key), this exception will be replaced with type=implementation on the concrete version_key impl and type=test on the contract test that proves it.
    //# If the item fails to authenticate this operation MUST fail.
    //
    //= ../spec/framework/branch-key-store.md#versionkey
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 9 (slug keystore-version-key), this exception will be replaced with type=implementation on the concrete version_key impl and type=test on the contract test that proves it.
    //# The wrapped Branch Keys, DECRYPT_ONLY and ACTIVE, MUST be created according to [Wrapped Branch Key Creation](#wrapped-branch-key-creation).
    //
    //= ../spec/framework/branch-key-store.md#versionkey
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 9 (slug keystore-version-key), this exception will be replaced with type=implementation on the concrete version_key impl and type=test on the contract test that proves it.
    //# To add the new branch key to the keystore,
    //# the operation MUST call [Amazon DynamoDB API TransactWriteItems](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html).
    //
    //= ../spec/framework/branch-key-store.md#versionkey
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 9 (slug keystore-version-key), this exception will be replaced with type=implementation on the concrete version_key impl and type=test on the contract test that proves it.
    //# The call to Amazon DynamoDB TransactWriteItems MUST use the configured Amazon DynamoDB Client to make the call.
    //
    //= ../spec/framework/branch-key-store.md#versionkey
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 9 (slug keystore-version-key), this exception will be replaced with type=implementation on the concrete version_key impl and type=test on the contract test that proves it.
    //# The operation MUST call Amazon DynamoDB TransactWriteItems with a request constructed as follows:
    //
    //= ../spec/framework/branch-key-store.md#versionkey
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 9 (slug keystore-version-key), this exception will be replaced with type=implementation on the concrete version_key impl and type=test on the contract test that proves it.
    //# - Every key-value pair of the custom [encryption context](./structures.md#encryption-context-3) that is associated with the branch key
    //# MUST be added with an Attribute Name of `aws-crypto-ec:` + the Key and Attribute Value (S) of the value.
    //
    //= ../spec/framework/branch-key-store.md#versionkey
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 9 (slug keystore-version-key), this exception will be replaced with type=implementation on the concrete version_key impl and type=test on the contract test that proves it.
    //# If DDB TransactWriteItems is successful, this operation MUST return a successful response containing no additional data.
    //
    //= ../spec/framework/branch-key-store.md#versionkey
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 9 (slug keystore-version-key), this exception will be replaced with type=implementation on the concrete version_key impl and type=test on the contract test that proves it.
    //# Otherwise, this operation MUST yield an error.
    /// Rotates the ACTIVE branch key to a new version.
    async fn version_key(&self, branch_key_id: String) -> Result<(), KeystoreError>;

    // ─── GetActiveBranchKey ─────────────────────────────────────────────

    //= ../spec/framework/branch-key-store.md#discovery
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 8 (slug keystore-read-ops), this exception will be replaced with type=implementation on the concrete get_active_branch_key impl and type=test on the contract test that proves it.
    //# The Keystore MAY use the KMS Key ARNs already
    //# persisted to the backing DynamoDB table,
    //# provided they are in records created
    //# with an identical Logical Keystore Name.
    //
    //= ../spec/framework/branch-key-store.md#mrdiscovery
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 8 (slug keystore-read-ops), this exception will be replaced with type=implementation on the concrete get_active_branch_key impl and type=test on the contract test that proves it.
    //# The Keystore MAY use the KMS Key ARNs already
    //# persisted to the backing DynamoDB table,
    //# provided they are in records created
    //# with an identical Logical Keystore Name.
    //
    //= ../spec/framework/branch-key-store.md#getactivebranchkey
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 8 (slug keystore-read-ops), this exception will be replaced with type=implementation on the concrete get_active_branch_key impl and type=test on the contract test that proves it.
    //# - MUST supply a `branch-key-id`
    //
    //= ../spec/framework/branch-key-store.md#getactivebranchkey
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 8 (slug keystore-read-ops), this exception will be replaced with type=implementation on the concrete get_active_branch_key impl and type=test on the contract test that proves it.
    //# To get the active version for the branch key id from the keystore
    //# this operation MUST call AWS DDB `GetItem`
    //# using the `branch-key-id` as the Partition Key and `"branch:ACTIVE"` value as the Sort Key.
    //
    //= ../spec/framework/branch-key-store.md#getactivebranchkey
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 8 (slug keystore-read-ops), this exception will be replaced with type=implementation on the concrete get_active_branch_key impl and type=test on the contract test that proves it.
    //# The AWS DDB response MUST contain the fields defined in the [branch keystore record format](#record-format).
    //
    //= ../spec/framework/branch-key-store.md#getactivebranchkey
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 8 (slug keystore-read-ops), this exception will be replaced with type=implementation on the concrete get_active_branch_key impl and type=test on the contract test that proves it.
    //# If the record does not contain the defined fields, this operation MUST fail.
    //
    //= ../spec/framework/branch-key-store.md#getactivebranchkey
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 8 (slug keystore-read-ops), this exception will be replaced with type=implementation on the concrete get_active_branch_key impl and type=test on the contract test that proves it.
    //# The operation MUST decrypt the branch key according to the [AWS KMS Branch Key Decryption](#aws-kms-branch-key-decryption) section.
    //
    //= ../spec/framework/branch-key-store.md#getactivebranchkey
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 8 (slug keystore-read-ops), this exception will be replaced with type=implementation on the concrete get_active_branch_key impl and type=test on the contract test that proves it.
    //# If the branch key fails to decrypt, GetActiveBranchKey MUST fail.
    //
    //= ../spec/framework/branch-key-store.md#getactivebranchkey
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 8 (slug keystore-read-ops), this exception will be replaced with type=implementation on the concrete get_active_branch_key impl and type=test on the contract test that proves it.
    //# This GetActiveBranchKey MUST construct [branch key materials](./structures.md#branch-key-materials)
    //# according to [Branch Key Materials From Authenticated Encryption Context](#branch-key-materials-from-authenticated-encryption-context).
    //
    //= ../spec/framework/branch-key-store.md#getactivebranchkey
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 8 (slug keystore-read-ops), this exception will be replaced with type=implementation on the concrete get_active_branch_key impl and type=test on the contract test that proves it.
    //# This operation MUST return the constructed [branch key materials](./structures.md#branch-key-materials).
    /// Returns the ACTIVE branch key materials for the given branch-key-id.
    async fn get_active_branch_key(
        &self,
        branch_key_id: String,
    ) -> Result<BranchKeyMaterials, KeystoreError>;

    // ─── GetBranchKeyVersion ────────────────────────────────────────────

    //= ../spec/framework/branch-key-store.md#getbranchkeyversion
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 8 (slug keystore-read-ops), this exception will be replaced with type=implementation on the concrete get_branch_key_version impl and type=test on the contract test that proves it.
    //# - MUST supply a `branch-key-id`
    //
    //= ../spec/framework/branch-key-store.md#getbranchkeyversion
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 8 (slug keystore-read-ops), this exception will be replaced with type=implementation on the concrete get_branch_key_version impl and type=test on the contract test that proves it.
    //# - MUST supply a `branchKeyVersion`
    //
    //= ../spec/framework/branch-key-store.md#getbranchkeyversion
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 8 (slug keystore-read-ops), this exception will be replaced with type=implementation on the concrete get_branch_key_version impl and type=test on the contract test that proves it.
    //# To get a branch key from the keystore this operation MUST call AWS DDB `GetItem`
    //# using the `branch-key-id` as the Partition Key and "branch:version:" + `branchKeyVersion` value as the Sort Key.
    //
    //= ../spec/framework/branch-key-store.md#getbranchkeyversion
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 8 (slug keystore-read-ops), this exception will be replaced with type=implementation on the concrete get_branch_key_version impl and type=test on the contract test that proves it.
    //# The AWS DDB response MUST contain the fields defined in the [branch keystore record format](#record-format).
    //
    //= ../spec/framework/branch-key-store.md#getbranchkeyversion
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 8 (slug keystore-read-ops), this exception will be replaced with type=implementation on the concrete get_branch_key_version impl and type=test on the contract test that proves it.
    //# If the record does not contain the defined fields, this operation MUST fail.
    //
    //= ../spec/framework/branch-key-store.md#getbranchkeyversion
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 8 (slug keystore-read-ops), this exception will be replaced with type=implementation on the concrete get_branch_key_version impl and type=test on the contract test that proves it.
    //# The operation MUST decrypt the branch key according to the [AWS KMS Branch Key Decryption](#aws-kms-branch-key-decryption) section.
    //
    //= ../spec/framework/branch-key-store.md#getbranchkeyversion
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 8 (slug keystore-read-ops), this exception will be replaced with type=implementation on the concrete get_branch_key_version impl and type=test on the contract test that proves it.
    //# If the branch key fails to decrypt, this operation MUST fail.
    //
    //= ../spec/framework/branch-key-store.md#getbranchkeyversion
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 8 (slug keystore-read-ops), this exception will be replaced with type=implementation on the concrete get_branch_key_version impl and type=test on the contract test that proves it.
    //# This GetBranchKeyVersion MUST construct [branch key materials](./structures.md#branch-key-materials)
    //# according to [Branch Key Materials From Authenticated Encryption Context](#branch-key-materials-from-authenticated-encryption-context).
    //
    //= ../spec/framework/branch-key-store.md#getbranchkeyversion
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 8 (slug keystore-read-ops), this exception will be replaced with type=implementation on the concrete get_branch_key_version impl and type=test on the contract test that proves it.
    //# This operation MUST return the constructed [branch key materials](./structures.md#branch-key-materials).
    /// Returns branch key materials for a specific version.
    async fn get_branch_key_version(
        &self,
        branch_key_id: String,
        branch_key_version: String,
    ) -> Result<BranchKeyMaterials, KeystoreError>;

    // ─── GetBeaconKey ───────────────────────────────────────────────────

    //= ../spec/framework/branch-key-store.md#getbeaconkey
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 8 (slug keystore-read-ops), this exception will be replaced with type=implementation on the concrete get_beacon_key impl and type=test on the contract test that proves it.
    //# - MUST supply a `branch-key-id`
    //
    //= ../spec/framework/branch-key-store.md#getbeaconkey
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 8 (slug keystore-read-ops), this exception will be replaced with type=implementation on the concrete get_beacon_key impl and type=test on the contract test that proves it.
    //# To get a branch key from the keystore this operation MUST call AWS DDB `GetItem`
    //# using the `branch-key-id` as the Partition Key and "beacon:ACTIVE" value as the Sort Key.
    //
    //= ../spec/framework/branch-key-store.md#getbeaconkey
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 8 (slug keystore-read-ops), this exception will be replaced with type=implementation on the concrete get_beacon_key impl and type=test on the contract test that proves it.
    //# The AWS DDB response MUST contain the fields defined in the [branch keystore record format](#record-format).
    //
    //= ../spec/framework/branch-key-store.md#getbeaconkey
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 8 (slug keystore-read-ops), this exception will be replaced with type=implementation on the concrete get_beacon_key impl and type=test on the contract test that proves it.
    //# If the record does not contain the defined fields, this operation MUST fail.
    //
    //= ../spec/framework/branch-key-store.md#getbeaconkey
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 8 (slug keystore-read-ops), this exception will be replaced with type=implementation on the concrete get_beacon_key impl and type=test on the contract test that proves it.
    //# The operation MUST decrypt the beacon key according to the [AWS KMS Branch Key Decryption](#aws-kms-branch-key-decryption) section.
    //
    //= ../spec/framework/branch-key-store.md#getbeaconkey
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 8 (slug keystore-read-ops), this exception will be replaced with type=implementation on the concrete get_beacon_key impl and type=test on the contract test that proves it.
    //# If the beacon key fails to decrypt, this operation MUST fail.
    //
    //= ../spec/framework/branch-key-store.md#getbeaconkey
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 8 (slug keystore-read-ops), this exception will be replaced with type=implementation on the concrete get_beacon_key impl and type=test on the contract test that proves it.
    //# This GetBeaconKey MUST construct [beacon key materials](./structures.md#beacon-key-materials) from the decrypted branch key material
    //# and the `branchKeyId` from the returned `branch-key-id` field.
    //
    //= ../spec/framework/branch-key-store.md#getbeaconkey
    //= type=exception
    //= reason=Abstract trait contract; no concrete keystore in this commit. Per master plan Phase 8 (slug keystore-read-ops), this exception will be replaced with type=implementation on the concrete get_beacon_key impl and type=test on the contract test that proves it.
    //# This operation MUST return the constructed [beacon key materials](./structures.md#beacon-key-materials).
    /// Returns the active beacon key materials for the given branch-key-id.
    async fn get_beacon_key(
        &self,
        branch_key_id: String,
    ) -> Result<BeaconKeyMaterials, KeystoreError>;
}

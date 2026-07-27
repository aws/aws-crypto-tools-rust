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

pub mod config;
pub mod error;
pub mod kms_config;

use async_trait::async_trait;

pub use config::{KeyStoreConfig, KeyStoreInfo, KmsConfiguration};
pub use error::{KeystoreError, KeystoreErrorKind};

use crate::structures::{BeaconKeyMaterials, BranchKeyMaterials, EncryptionContext};

#[async_trait]
pub trait Keystore: Send + Sync {
    // ─── GetKeyStoreInfo ────────────────────────────────────────────────

    /// Returns the keystore information for this keystore.
    async fn get_key_store_info(&self) -> Result<KeyStoreInfo, KeystoreError>;

    // ─── CreateKeyStore ─────────────────────────────────────────────────

    /// Creates the backing DynamoDB table for this keystore.
    async fn create_key_store(&self) -> Result<String, KeystoreError>;

    // ─── CreateKey ──────────────────────────────────────────────────────

    /// Creates a new branch key + beacon key pair in this keystore.
    async fn create_key(
        &self,
        branch_key_id: Option<String>,
        encryption_context: Option<EncryptionContext>,
    ) -> Result<String, KeystoreError>;

    // ─── VersionKey ─────────────────────────────────────────────────────

    /// Rotates the ACTIVE branch key to a new version.
    async fn version_key(&self, branch_key_id: String) -> Result<(), KeystoreError>;

    // ─── GetActiveBranchKey ─────────────────────────────────────────────

    /// Returns the ACTIVE branch key materials for the given branch-key-id.
    async fn get_active_branch_key(
        &self,
        branch_key_id: String,
    ) -> Result<BranchKeyMaterials, KeystoreError>;

    // ─── GetBranchKeyVersion ────────────────────────────────────────────

    /// Returns branch key materials for a specific version.
    async fn get_branch_key_version(
        &self,
        branch_key_id: String,
        branch_key_version: String,
    ) -> Result<BranchKeyMaterials, KeystoreError>;

    // ─── GetBeaconKey ───────────────────────────────────────────────────

    /// Returns the active beacon key materials for the given branch-key-id.
    async fn get_beacon_key(
        &self,
        branch_key_id: String,
    ) -> Result<BeaconKeyMaterials, KeystoreError>;
}

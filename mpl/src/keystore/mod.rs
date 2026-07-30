// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The `Keystore` trait — the abstract contract every keystore MUST implement.
//!
//! # Why `async_trait` and not native AFIT
//!
//! The same dyn-compatibility rationale recorded in [`crate::keyring`] applies
//! here: AFIT traits are not stable-dyn-compatible, the MPL needs `dyn Keystore`
//! and `Box<dyn Keystore>` for plug-in keystore backends (DynamoDB-backed
//! branch key store today, potentially other backends later), and `async_trait`
//! boxes the future to make `dyn Keystore` work today. See `src/keyring/mod.rs`
//! for the full discussion.
//!
//! # Concrete-keystore-deferred clauses (`type=exception`)
//!
//! This commit introduces the abstract `Keystore` trait scaffolding plus the
//! configuration and error types only — no concrete keystore (DynamoDB-backed
//! branch key store, …) is implemented yet. Behavioral MUSTs on
//! `create_key_store`, `create_key`, `version_key`, `get_active_branch_key`,
//! `get_branch_key_version`, `get_beacon_key`, and `get_key_store_info`
//! (encryption-context construction, record format, AWS-KMS-backed
//! authentication / decryption) are therefore annotated `type=exception`
//! here. When each concrete keystore is added in a future commit, the
//! matching exception below will be replaced with `type=implementation` on
//! the concrete method, and `type=test` will be placed on the contract test
//! that proves it.

pub mod attributes;
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

// ─── Group G — Phase 5 client deps (7 reqs) ─────────────────────────────────

//
//
//
//
//
//
#[async_trait]
pub trait Keystore: Send + Sync {
    // ─── GetKeyStoreInfo ────────────────────────────────────────────────

    /// Returns the keystore information for this keystore.
    async fn get_key_store_info(&self) -> Result<KeyStoreInfo, KeystoreError>;

    // ─── CreateKeyStore ─────────────────────────────────────────────────

    //
    //
    //
    //
    //
    //
    /// Creates the backing DynamoDB table for this keystore.
    async fn create_key_store(&self) -> Result<String, KeystoreError>;

    // ─── CreateKey ──────────────────────────────────────────────────────

    //
    //
    //
    //
    //
    //
    //
    //
    //
    //
    //
    //
    //
    //
    //
    //
    //
    //
    //
    //
    //
    //
    //
    //
    //
    //
    //
    //
    //
    //
    //
    //
    //
    //
    //
    //
    //
    //
    //
    //
    //
    //
    /// Creates a new branch key + beacon key pair in this keystore.
    async fn create_key(
        &self,
        branch_key_id: Option<String>,
        encryption_context: Option<EncryptionContext>,
    ) -> Result<String, KeystoreError>;

    // ─── VersionKey ─────────────────────────────────────────────────────

    //
    //
    //
    //
    //
    //
    //
    //
    //
    //
    //
    //
    //
    /// Rotates the ACTIVE branch key to a new version.
    async fn version_key(&self, branch_key_id: String) -> Result<(), KeystoreError>;

    // ─── GetActiveBranchKey ─────────────────────────────────────────────

    //
    //
    //
    //
    //
    //
    //
    //
    //
    /// Returns the ACTIVE branch key materials for the given branch-key-id.
    async fn get_active_branch_key(
        &self,
        branch_key_id: String,
    ) -> Result<BranchKeyMaterials, KeystoreError>;

    // ─── GetBranchKeyVersion ────────────────────────────────────────────

    //
    //
    //
    //
    //
    //
    //
    //
    /// Returns branch key materials for a specific version.
    async fn get_branch_key_version(
        &self,
        branch_key_id: String,
        branch_key_version: String,
    ) -> Result<BranchKeyMaterials, KeystoreError>;

    // ─── GetBeaconKey ───────────────────────────────────────────────────

    //
    //
    //
    //
    //
    //
    //
    /// Returns the active beacon key materials for the given branch-key-id.
    async fn get_beacon_key(
        &self,
        branch_key_id: String,
    ) -> Result<BeaconKeyMaterials, KeystoreError>;
}

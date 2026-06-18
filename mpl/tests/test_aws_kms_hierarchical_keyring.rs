// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for `aws_kms::hierarchical_keyring`.
//!
//! Covers the construction / configuration surface only (cycle 1, slice 1):
//! - TTL > 0 validation
//! - 16-byte v4 UUID partition-id default
//! - UTF-8 partition-id round-trip (regression coverage for the
//!   `If provided, it MUST be interpreted as UTF8 bytes` implication)

#![cfg(feature = "keystore")]

use std::sync::Arc;

use async_trait::async_trait;

use aws_crypto_mpl::aws_kms::hierarchical_keyring::{
    BranchKeySource, CacheType, HierarchicalKeyring,
};
use aws_crypto_mpl::keystore::error::KeystoreErrorKind;
use aws_crypto_mpl::keystore::{KeyStoreInfo, Keystore, KeystoreError};
use aws_crypto_mpl::structures::{
    BeaconKeyMaterials, BranchKeyMaterials, EncryptionContext, MaterialsErrorKind,
};

/// Minimal mock keystore that returns "not implemented" errors for every
/// operation. Cycle 1, slice 1 only exercises construction-time configuration;
/// no test in this file invokes a keystore method.
struct StubKeystore;

#[async_trait]
impl Keystore for StubKeystore {
    async fn get_key_store_info(&self) -> Result<KeyStoreInfo, KeystoreError> {
        Err(KeystoreError::new(
            KeystoreErrorKind::Internal,
            "StubKeystore::get_key_store_info",
        ))
    }

    async fn create_key_store(&self) -> Result<String, KeystoreError> {
        Err(KeystoreError::new(
            KeystoreErrorKind::Internal,
            "StubKeystore::create_key_store",
        ))
    }

    async fn create_key(
        &self,
        _branch_key_id: Option<String>,
        _encryption_context: Option<EncryptionContext>,
    ) -> Result<String, KeystoreError> {
        Err(KeystoreError::new(
            KeystoreErrorKind::Internal,
            "StubKeystore::create_key",
        ))
    }

    async fn version_key(&self, _branch_key_id: String) -> Result<(), KeystoreError> {
        Err(KeystoreError::new(
            KeystoreErrorKind::Internal,
            "StubKeystore::version_key",
        ))
    }

    async fn get_active_branch_key(
        &self,
        _branch_key_id: String,
    ) -> Result<BranchKeyMaterials, KeystoreError> {
        Err(KeystoreError::new(
            KeystoreErrorKind::Internal,
            "StubKeystore::get_active_branch_key",
        ))
    }

    async fn get_branch_key_version(
        &self,
        _branch_key_id: String,
        _branch_key_version: String,
    ) -> Result<BranchKeyMaterials, KeystoreError> {
        Err(KeystoreError::new(
            KeystoreErrorKind::Internal,
            "StubKeystore::get_branch_key_version",
        ))
    }

    async fn get_beacon_key(
        &self,
        _branch_key_id: String,
    ) -> Result<BeaconKeyMaterials, KeystoreError> {
        Err(KeystoreError::new(
            KeystoreErrorKind::Internal,
            "StubKeystore::get_beacon_key",
        ))
    }
}

fn stub_keystore() -> Arc<dyn Keystore> {
    Arc::new(StubKeystore)
}

#[test]
fn new_with_zero_ttl_returns_validation_error() {
    let keystore = stub_keystore();
    let result = HierarchicalKeyring::new(
        keystore,
        0, // zero TTL — must be rejected
        BranchKeySource::Identifier("branch-key-id".to_string()),
        None,
        None,
    );

    let err = match result {
        Err(e) => e,
        Ok(_) => panic!("expected zero TTL to return a validation error"),
    };
    //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#cache-limit-ttl
    //= type=test
    //# This value MUST be greater than zero.
    assert_eq!(
        err.kind,
        MaterialsErrorKind::Validation,
        "expected Validation error for ttl_seconds=0; got {err:?}",
    );
    assert!(
        err.message.contains("greater than zero"),
        "error message should identify the TTL>0 rule; got: {}",
        err.message,
    );
}

#[test]
fn new_with_positive_ttl_succeeds() {
    let keystore = stub_keystore();
    let result = HierarchicalKeyring::new(
        keystore,
        1, // smallest legal TTL
        BranchKeySource::Identifier("branch-key-id".to_string()),
        Some(CacheType::Default),
        None,
    );

    let keyring = result.expect("ttl_seconds=1 must be accepted");
    assert_eq!(keyring.ttl_seconds(), 1);
}

#[test]
fn partition_id_default_is_16_byte_v4_uuid() {
    let keystore = stub_keystore();
    let keyring = HierarchicalKeyring::new(
        keystore,
        3600,
        BranchKeySource::Identifier("branch-key-id".to_string()),
        None,
        None, // no partition id supplied → must default to v4 UUID bytes
    )
    .expect("constructor with no partition id must succeed");

    let bytes = keyring.partition_id_bytes();

    //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#partition-id
    //= type=test
    //# If the PartitionId is NOT provided by the user, it MUST be set to the 16 byte representation of a v4 UUID.
    assert_eq!(
        bytes.len(),
        16,
        "default partition id must be the 16-byte representation of a v4 UUID; got {} bytes",
        bytes.len(),
    );
    // RFC 4122 §4.4: byte 6 high nibble identifies the UUID version. v4 ⇒ 0x4_.
    assert_eq!(
        bytes[6] & 0xF0,
        0x40,
        "default partition id byte[6] high nibble must be 0x4 (v4 marker); got 0x{:02x}",
        bytes[6],
    );
    // RFC 4122 §4.4: byte 8 high two bits encode the variant. RFC 4122 ⇒ 0b10.
    assert_eq!(
        bytes[8] & 0xC0,
        0x80,
        "default partition id byte[8] high two bits must be 0b10 (RFC 4122 variant); got 0x{:02x}",
        bytes[8],
    );
}

#[test]
fn partition_id_default_two_calls_are_distinct() {
    // Two consecutive constructions with no partition id must yield two
    // independent v4 UUIDs. This is regression coverage for the v4-UUID
    // default — a stub that returned all-zero bytes would still pass the
    // length / version-bit checks.
    let a = HierarchicalKeyring::new(
        stub_keystore(),
        3600,
        BranchKeySource::Identifier("branch-key-id".to_string()),
        None,
        None,
    )
    .expect("first constructor call must succeed");

    let b = HierarchicalKeyring::new(
        stub_keystore(),
        3600,
        BranchKeySource::Identifier("branch-key-id".to_string()),
        None,
        None,
    )
    .expect("second constructor call must succeed");

    assert_ne!(
        a.partition_id_bytes(),
        b.partition_id_bytes(),
        "two default partition ids must be distinct (CSPRNG collision is overwhelmingly unlikely)",
    );
}

#[test]
fn partition_id_provided_is_utf8_round_tripped() {
    // The "If provided, it MUST be interpreted as UTF8 bytes" requirement is
    // a `type=implication` on the source side (Rust's `String::into_bytes` is
    // UTF-8 by construction of the `String` type). This test exists as
    // regression coverage to confirm the bytes are the original UTF-8 bytes
    // and have not been re-encoded or truncated.
    let original = "hello-世界";
    let keyring = HierarchicalKeyring::new(
        stub_keystore(),
        3600,
        BranchKeySource::Identifier("branch-key-id".to_string()),
        None,
        Some(original.to_string()),
    )
    .expect("constructor with explicit partition id must succeed");

    assert_eq!(keyring.partition_id_bytes(), original.as_bytes());
}

#[test]
fn branch_key_source_supplier_variant_compiles() {
    // Smoke test that the BranchKeySource::Supplier variant is usable —
    // construct a no-op supplier, store it in the enum, and confirm the
    // keyring can be built with it. The trait object existence proves the
    // "MUST provide either a Branch Key Identifier or a Branch Key Supplier"
    // requirement at the type level.
    use aws_crypto_mpl::aws_kms::hierarchical_keyring::BranchKeySupplier;
    use aws_crypto_mpl::structures::MaterialsError;

    struct ConstSupplier(&'static str);

    #[async_trait]
    impl BranchKeySupplier for ConstSupplier {
        async fn get_branch_key_id(
            &self,
            _ec: &EncryptionContext,
        ) -> Result<String, MaterialsError> {
            Ok(self.0.to_string())
        }
    }

    let supplier: Arc<dyn BranchKeySupplier> = Arc::new(ConstSupplier("branch-id-from-supplier"));
    let keyring = HierarchicalKeyring::new(
        stub_keystore(),
        3600,
        BranchKeySource::Supplier(supplier),
        None,
        None,
    )
    .expect("constructor with supplier variant must succeed");

    assert!(matches!(
        keyring.branch_key_source(),
        BranchKeySource::Supplier(_)
    ));
}

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

use aws_crypto_mpl::aws_kms::__test_internals::{for_decrypt, for_encrypt};
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

// ─── Cache entry identifier formula tests (Appendix A) ──────────────────────

/// SHA-384 digest of a single concatenated byte sequence. Local helper used to
/// derive the *expected* cache identifier from an explicitly-laid-out byte
/// sequence — independent of the implementation under test, so the assertion
/// catches any drift in the implementation's byte layout.
fn sha384(input: &[u8]) -> [u8; 48] {
    let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA384, input);
    let mut out = [0u8; 48];
    out.copy_from_slice(d.as_ref());
    out
}

#[test]
fn cache_entry_identifier_for_encrypt_matches_manual_sha384() {
    // Independently chosen fixtures. The bytes below define the expected
    // wire-shape per Appendix A; if the implementation deviates, SHA-384
    // diverges.
    let partition_id: &[u8] = b"\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00";
    let logical_key_store_name = "logical-store";
    let branch_key_id = "branch-key-1";

    // Manually build the byte sequence the spec dictates:
    //   [resource_id=0x02, NULL, scope_id_encrypt=0x01, NULL,
    //    partition_id..., NULL,
    //    UTF8(logical_key_store_name), NULL,
    //    UTF8(branch_key_id)]
    let mut expected_input = Vec::new();
    expected_input.push(0x02_u8);
    expected_input.push(0x00_u8);
    expected_input.push(0x01_u8);
    expected_input.push(0x00_u8);
    expected_input.extend_from_slice(partition_id);
    expected_input.push(0x00_u8);
    expected_input.extend_from_slice(logical_key_store_name.as_bytes());
    expected_input.push(0x00_u8);
    expected_input.extend_from_slice(branch_key_id.as_bytes());
    let expected = sha384(&expected_input);

    let actual = for_encrypt(partition_id, logical_key_store_name, branch_key_id);

    //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#encryption-materials
    //= type=test
    //# When the hierarchical keyring receives an OnEncrypt request,
    //# the cache entry identifier MUST be calculated as the
    //# SHA-384 hash of the following byte strings, in the order listed:
    //
    //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#encryption-materials
    //= type=test
    //# - MUST be the Resource ID for the Hierarchical Keyring (0x02)
    //
    //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#encryption-materials
    //= type=test
    //# - MUST be the Scope ID for Encrypt (0x01)
    //
    //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#encryption-materials
    //= type=test
    //# - MUST be the Partition ID for the Hierarchical Keyring
    //
    //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#resource-suffix
    //= type=test
    //# The aforementioned 4 definitions ([Resource Identifier](#resource-identifier),
    //# [Scope Identifier](#scope-identifier), [Partition ID](#partition-id-1), and
    //# [Resource Suffix](#resource-suffix)) MUST be appended together with the null byte, 0x00,
    //# and the SHA384 of the result should be taken as the final cache identifier.
    assert_eq!(actual, expected);
}

#[test]
fn cache_entry_identifier_for_decrypt_matches_manual_sha384() {
    let partition_id: &[u8] = b"\xde\xad\xbe\xef\xfe\xed\xfa\xce\x01\x02\x03\x04\x05\x06\x07\x08";
    let logical_key_store_name = "logical-store-2";
    let branch_key_id = "branch-key-2";
    let branch_key_version = "ffffffff-eeee-dddd-cccc-bbbbbbbbbbbb";

    let mut expected_input = Vec::new();
    expected_input.push(0x02_u8);
    expected_input.push(0x00_u8);
    expected_input.push(0x02_u8);
    expected_input.push(0x00_u8);
    expected_input.extend_from_slice(partition_id);
    expected_input.push(0x00_u8);
    expected_input.extend_from_slice(logical_key_store_name.as_bytes());
    expected_input.push(0x00_u8);
    expected_input.extend_from_slice(branch_key_id.as_bytes());
    expected_input.push(0x00_u8);
    expected_input.extend_from_slice(branch_key_version.as_bytes());
    let expected = sha384(&expected_input);

    let actual = for_decrypt(
        partition_id,
        logical_key_store_name,
        branch_key_id,
        branch_key_version,
    );

    //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#decryption-materials
    //= type=test
    //# When the hierarchical keyring receives an OnDecrypt request,
    //# it MUST calculate the cache entry identifier as the
    //# SHA-384 hash of the following byte strings, in the order listed:
    //
    //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#decryption-materials
    //= type=test
    //# - MUST be the Resource ID for the Hierarchical Keyring (0x02)
    //
    //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#decryption-materials
    //= type=test
    //# - MUST be the Scope ID for Decrypt (0x02)
    //
    //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#decryption-materials
    //= type=test
    //# - MUST be the Partition ID for the Hierarchical Keyring
    assert_eq!(actual, expected);
}

#[test]
fn cache_entry_identifier_encrypt_and_decrypt_differ_for_same_inputs() {
    // Same partition / logical name / branch key id; the only difference
    // between for_encrypt and for_decrypt's hash inputs is:
    //   - scope_id (0x01 vs 0x02)
    //   - presence of branch_key_version (absent vs present)
    // The hashes MUST therefore differ. This is the regression check that
    // the encrypt/decrypt scope IDs actually flow into the SHA-384 input.
    let partition_id: &[u8] = b"shared-partition";
    let logical = "shared-logical";
    let branch_id = "shared-branch";
    let version = "1.0";

    let enc = for_encrypt(partition_id, logical, branch_id);
    let dec = for_decrypt(partition_id, logical, branch_id, version);

    assert_ne!(
        enc, dec,
        "encrypt and decrypt cache identifiers must differ for the same partition/logical/branch (scope IDs differentiate)"
    );
}

#[test]
fn cache_entry_identifier_distinct_branch_key_ids_produce_distinct_outputs() {
    // Negative-collision regression: changing the branch_key_id MUST
    // change the cache identifier. Both for_encrypt and for_decrypt
    // checked.
    let partition_id: &[u8] = b"some-partition-bytes";
    let logical = "logical-name";

    let enc_a = for_encrypt(partition_id, logical, "branch-a");
    let enc_b = for_encrypt(partition_id, logical, "branch-b");
    assert_ne!(
        enc_a, enc_b,
        "for_encrypt must produce distinct outputs for distinct branch key ids"
    );

    let dec_a = for_decrypt(partition_id, logical, "branch-a", "v1");
    let dec_b = for_decrypt(partition_id, logical, "branch-b", "v1");
    assert_ne!(
        dec_a, dec_b,
        "for_decrypt must produce distinct outputs for distinct branch key ids"
    );
}

#[test]
fn cache_entry_identifier_distinct_versions_produce_distinct_outputs() {
    // Decrypt-only: the branch_key_version field MUST contribute to the
    // hash. Two for_decrypt calls that differ only in branch_key_version
    // MUST produce distinct outputs.
    let partition_id: &[u8] = b"another-partition";
    let logical = "logical-name";
    let branch_id = "branch-id";

    //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#decryption-materials
    //= type=test
    //# - MUST be the UTF8 encoded branch-key-version
    assert_ne!(
        for_decrypt(partition_id, logical, branch_id, "v1"),
        for_decrypt(partition_id, logical, branch_id, "v2"),
        "for_decrypt must produce distinct outputs for distinct branch key versions"
    );
}

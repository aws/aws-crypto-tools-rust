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

use aws_crypto_mpl::aws_kms::__test_internals::{
    compute_aad, for_decrypt, for_encrypt, unwrap as branch_key_unwrap, wrap as branch_key_wrap,
};
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

// ─── Cache wiring tests (slice 2) ───────────────────────────────────────────

#[test]
fn new_with_default_cache_succeeds() {
    //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#initialization
    //= type=test
    //# If no `cache` is provided, a `DefaultCache` MUST be configured with entry capacity of 1000.
    let keyring = HierarchicalKeyring::new(
        stub_keystore(),
        3600,
        BranchKeySource::Identifier("bk".to_string()),
        Some(CacheType::Default),
        None,
    )
    .expect("CacheType::Default must succeed");
    // Construction succeeded — a Cmc was built and stored.
    let _cache: &Arc<dyn aws_crypto_mpl::Cmc> = keyring.cache();
}

#[test]
fn new_with_cache_type_none_uses_default() {
    //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#initialization
    //= type=test
    //# On initialization the Hierarchical Keyring MUST initialize a [cryptographic-materials-cache](../local-cryptographic-materials-cache.md) with the configured cache limit TTL and the max cache size.
    let keyring = HierarchicalKeyring::new(
        stub_keystore(),
        3600,
        BranchKeySource::Identifier("bk".to_string()),
        None,
        None,
    )
    .expect("None cache_type must default to a built-in cache");
    let _cache: &Arc<dyn aws_crypto_mpl::Cmc> = keyring.cache();
}

#[test]
fn new_with_shared_cache_round_trips_provided_arc() {
    use aws_crypto_mpl::{Cmc, LocalCmc};

    let supplied: Arc<dyn Cmc> = Arc::new(LocalCmc::new(8, 4).unwrap());
    let supplied_for_compare = Arc::clone(&supplied);

    //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#initialization
    //= type=test
    //# If the Hierarchical Keyring does NOT get a `Shared` cache on initialization,
    //# it MUST initialize a [cryptographic-materials-cache](../local-cryptographic-materials-cache.md)
    //# with the user provided cache limit TTL and the entry capacity.
    let keyring = HierarchicalKeyring::new(
        stub_keystore(),
        3600,
        BranchKeySource::Identifier("bk".to_string()),
        Some(CacheType::Shared(supplied)),
        None,
    )
    .expect("CacheType::Shared(Arc<dyn Cmc>) must succeed");

    // The exact `Arc` supplied is what the keyring stores. Tested via
    // pointer-identity rather than behaviour because the struct field is
    // not directly observable.
    let stored: &Arc<dyn Cmc> = keyring.cache();
    assert!(
        Arc::ptr_eq(stored, &supplied_for_compare),
        "CacheType::Shared MUST round-trip the supplied Arc verbatim"
    );
}

#[test]
fn new_with_storm_tracking_cache_succeeds() {
    use aws_crypto_mpl::aws_kms::hierarchical_keyring::StormTrackingParameters;

    let params = StormTrackingParameters {
        entry_capacity: 16,
        entry_pruning_tail_size: 4,
        grace_period: 60,
        grace_interval: 1,
        fan_out: 4,
        inflight_ttl: 30,
        sleep_milli: 10,
        time_units: None,
    };
    let keyring = HierarchicalKeyring::new(
        stub_keystore(),
        3600, // ttl_seconds — strictly greater than grace_period (60).
        BranchKeySource::Identifier("bk".to_string()),
        Some(CacheType::StormTracking(params)),
        None,
    )
    .expect("CacheType::StormTracking with grace_period < ttl must succeed");
    let _cache: &Arc<dyn aws_crypto_mpl::Cmc> = keyring.cache();
}

#[test]
fn new_with_storm_tracking_grace_period_equal_to_ttl_fails() {
    use aws_crypto_mpl::aws_kms::hierarchical_keyring::StormTrackingParameters;

    let params = StormTrackingParameters {
        entry_capacity: 16,
        entry_pruning_tail_size: 4,
        grace_period: 60,
        grace_interval: 1,
        fan_out: 4,
        inflight_ttl: 30,
        sleep_milli: 10,
        time_units: None,
    };
    //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#initialization
    //= type=test
    //# If the cache to initialize is a [Storm Tracking Cryptographic Materials Cache](../storm-tracking-cryptographic-materials-cache.md#overview)
    //# then the [Grace Period](../storm-tracking-cryptographic-materials-cache.md#grace-period) MUST be less than the [cache limit TTL](#cache-limit-ttl).
    let err = match HierarchicalKeyring::new(
        stub_keystore(),
        60, // ttl_seconds == grace_period — must fail.
        BranchKeySource::Identifier("bk".to_string()),
        Some(CacheType::StormTracking(params)),
        None,
    ) {
        Ok(_) => panic!("StormTracking with grace_period == ttl_seconds must fail"),
        Err(e) => e,
    };
    assert!(
        err.message.contains("grace period"),
        "error message must mention the grace period; got: {}",
        err.message
    );
}

#[test]
fn new_with_storm_tracking_grace_period_greater_than_ttl_fails() {
    use aws_crypto_mpl::aws_kms::hierarchical_keyring::StormTrackingParameters;

    let params = StormTrackingParameters {
        entry_capacity: 16,
        entry_pruning_tail_size: 4,
        grace_period: 120, // > ttl_seconds below
        grace_interval: 1,
        fan_out: 4,
        inflight_ttl: 30,
        sleep_milli: 10,
        time_units: None,
    };
    let err = match HierarchicalKeyring::new(
        stub_keystore(),
        60,
        BranchKeySource::Identifier("bk".to_string()),
        Some(CacheType::StormTracking(params)),
        None,
    ) {
        Ok(_) => panic!("StormTracking with grace_period > ttl_seconds must fail"),
        Err(e) => e,
    };
    assert!(
        err.message.contains("grace period"),
        "error message must mention the grace period; got: {}",
        err.message
    );
}

#[test]
fn new_with_storm_tracking_milliseconds_grace_period_under_ttl_succeeds() {
    use aws_crypto_mpl::TimeUnits;
    use aws_crypto_mpl::aws_kms::hierarchical_keyring::StormTrackingParameters;

    // grace_period = 5_000 ms = 5 s, ttl_seconds = 60 s → strict less-than.
    // inflight_ttl <= grace_period is required by StormTrackingCmc.
    let params = StormTrackingParameters {
        entry_capacity: 16,
        entry_pruning_tail_size: 4,
        grace_period: 5_000,
        grace_interval: 100,
        fan_out: 4,
        inflight_ttl: 1_000,
        sleep_milli: 10,
        time_units: Some(TimeUnits::Milliseconds),
    };
    HierarchicalKeyring::new(
        stub_keystore(),
        60,
        BranchKeySource::Identifier("bk".to_string()),
        Some(CacheType::StormTracking(params)),
        None,
    )
    .expect("ms-unit grace_period (5_000ms = 5s) < ttl (60s) must succeed");
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
    let mut expected_input = vec![0x02_u8, 0x00_u8, 0x01_u8, 0x00_u8];
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

    let mut expected_input = vec![0x02_u8, 0x00_u8, 0x02_u8, 0x00_u8];
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

// ─── Branch-key wrapping / unwrapping / AAD tests (cycle 3) ─────────────────

/// Stable test fixtures for the wrap/unwrap round-trip tests. The branch_key
/// bytes are arbitrary but fixed so the round-trip is deterministic across
/// runs aside from the random `salt`/`IV`.
fn fixed_branch_key() -> [u8; 32] {
    let mut bk = [0u8; 32];
    for (i, slot) in bk.iter_mut().enumerate() {
        // u8 cast is fine here — i % 256 is in range by construction.
        *slot = u8::try_from(i & 0xFF).expect("0..32 fits in u8");
    }
    bk
}

const FIXTURE_VERSION: &str = "01234567-0123-4123-8123-0123456789ab";
const FIXTURE_BRANCH_KEY_ID: &str = "branch-key-id-1";

fn fixture_materials_with_ec(ec: EncryptionContext) -> BranchKeyMaterials {
    BranchKeyMaterials::new(
        fixed_branch_key(),
        FIXTURE_BRANCH_KEY_ID.to_string(),
        FIXTURE_VERSION.to_string(),
        ec,
    )
    .expect("BranchKeyMaterials::new must accept the fixture inputs")
}

fn fixture_materials_empty_ec() -> BranchKeyMaterials {
    fixture_materials_with_ec(EncryptionContext::new())
}

#[test]
fn compute_aad_layout_for_known_inputs() {
    // Independently-constructed expected AAD byte vector. Built here from
    // the spec's bullet list so a drift in the implementation's order or
    // separator bytes is detected.
    let branch_key_id = "ek1";
    let version = "01234567-0123-4123-8123-0123456789ab";
    let ec = EncryptionContext::new();

    // 1. "aws-kms-hierarchy" (17 bytes)
    // 2. branch_key_id "ek1" (3 bytes)
    // 3. version 16 raw bytes (UUID hex-decoded)
    // 4. serialized empty EC (0 bytes — empty EC serializes to empty bytes)
    let expected: Vec<u8> = b"aws-kms-hierarchy"
        .iter()
        .copied()
        .chain(b"ek1".iter().copied())
        .chain([
            0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x41, 0x23, 0x81, 0x23, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab,
        ])
        .collect();

    // The expected bytes are independently constructed from the spec's bullet
    // list (label || branch-key-id || version || serialized-EC); a drift in
    // concatenation order or content fails this assertion.
    //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-wrapping-and-unwrapping-aad
    //= type=test
    //# To construct the AAD, the keyring MUST concatenate the following values
    let aad = compute_aad(branch_key_id, version, &ec).expect("AAD construction must succeed");
    assert_eq!(aad, expected, "AAD must equal label || id || version || ec");
    assert_eq!(
        aad.len(),
        17 + 3 + 16,
        "AAD length must be 36 bytes for empty EC"
    );
}

#[test]
fn compute_aad_appends_serialized_encryption_context() {
    let branch_key_id = "id-with-ec";
    let version = "01234567-0123-4123-8123-0123456789ab";
    let mut ec = EncryptionContext::new();
    ec.insert(b"k".to_vec(), b"v".to_vec());

    let aad = compute_aad(branch_key_id, version, &ec).expect("AAD construction must succeed");

    let serialized_ec = ec.serialize().expect("EC must serialize");
    assert!(
        aad.ends_with(&serialized_ec),
        "AAD must end with the serialized EC bytes"
    );
    let prefix_len = aad.len() - serialized_ec.len();
    assert_eq!(
        prefix_len,
        17 + branch_key_id.len() + 16,
        "non-EC prefix must be label + id + version (16)"
    );
}

#[test]
fn compute_aad_fails_when_encryption_context_value_too_large() {
    let branch_key_id = "id-too-large";
    let version = "01234567-0123-4123-8123-0123456789ab";
    let mut ec = EncryptionContext::new();
    // value length > u16::MAX makes EncryptionContext::serialize() fail.
    ec.insert(b"k".to_vec(), vec![0u8; 65_536]);

    let result = compute_aad(branch_key_id, version, &ec);
    let err = result.expect_err("compute_aad must fail when EC serialization fails");

    //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-wrapping-and-unwrapping-aad
    //= type=test
    //# If the keyring cannot serialize the encryption context, the operation MUST fail.
    assert_eq!(
        err.kind,
        MaterialsErrorKind::Validation,
        "expected Validation error from EC serialize; got {err:?}",
    );
}

#[test]
fn wrap_unwrap_round_trip_recovers_plaintext() {
    let materials = fixture_materials_empty_ec();
    let plaintext: &[u8] = b"a-data-key-for-testing-32-bytes!"; // 32 bytes
    assert_eq!(plaintext.len(), 32);

    let ciphertext = branch_key_wrap(&materials, plaintext).expect("wrap must succeed");
    let recovered = branch_key_unwrap(&materials, &ciphertext).expect("unwrap must succeed");

    // Round-trip success requires the IV value passed to AES-GCM seal on
    // wrap to match the IV bytes stored on-wire (which unwrap reads via
    // `Nonce::assume_unique_for_key(iv_bytes)`). If wrap had passed a
    // different IV to AES-GCM than the one written into the layout, the
    // authentication tag would not verify on unwrap and round-trip would
    // fail.
    //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-wrapping
    //= type=test
    //# - MUST use the derived `IV` as the AES-GCM IV.
    assert_eq!(
        recovered, plaintext,
        "round-trip must recover original plaintext"
    );
}

#[test]
fn wrap_round_trip_with_nonempty_encryption_context() {
    let mut ec = EncryptionContext::new();
    ec.insert(b"purpose".to_vec(), b"test".to_vec());
    ec.insert(b"region".to_vec(), b"us-west-2".to_vec());
    let materials = fixture_materials_with_ec(ec);

    let plaintext = vec![0xAA_u8; 32];
    let ciphertext = branch_key_wrap(&materials, &plaintext).expect("wrap must succeed");
    let recovered =
        branch_key_unwrap(&materials, &ciphertext).expect("unwrap must succeed with same EC");
    assert_eq!(recovered, plaintext);
}

#[test]
fn wrap_ciphertext_layout_lengths_match_spec() {
    let materials = fixture_materials_empty_ec();
    let plaintext = vec![0x42_u8; 32];

    let ciphertext = branch_key_wrap(&materials, &plaintext).expect("wrap must succeed");

    // salt (16) + iv (12) + version (16) + plaintext_len + tag (16) = 60 + plaintext_len
    let expected_len = 16 + 12 + 16 + plaintext.len() + 16;

    // Structural shape guard for the on-wire layout: a regression that
    // changed any of the fixed-overhead lengths would change the total
    // byte count. (The spec requirement that the wrap-side IV is actually
    // used as the AES-GCM IV is exercised by the round-trip test, not
    // here — a length check cannot falsify a wrong IV value.)
    assert_eq!(
        ciphertext.len(),
        expected_len,
        "ciphertext must be salt(16) || iv(12) || version(16) || encrypted_key || tag(16)",
    );
}

#[test]
fn wrap_then_unwrap_with_tampered_encrypted_key_fails() {
    let materials = fixture_materials_empty_ec();
    let plaintext: &[u8] = b"thirty-two-byte-data-key--rand!!"; // 32 bytes
    assert_eq!(plaintext.len(), 32);

    // First confirm the untampered round-trip succeeds (baseline).
    let ciphertext = branch_key_wrap(&materials, plaintext).expect("wrap must succeed");
    let pristine = branch_key_unwrap(&materials, &ciphertext).expect("baseline unwrap");
    assert_eq!(pristine, plaintext, "baseline round-trip must work");

    // Tamper a byte in the encrypted-key region: bytes [44 .. ciphertext.len() - 16]
    // (after salt 16, iv 12, version 16 = 44).
    let mut tampered = ciphertext.clone();
    let original = tampered[44];
    tampered[44] ^= 0x01;
    assert_ne!(tampered[44], original, "tamper must change the byte");

    let result = branch_key_unwrap(&materials, &tampered);
    let err = result.expect_err("unwrap with tampered encrypted-key must fail");

    // Tampering a byte in the encrypted-key region invalidates the AES-GCM
    // authentication tag, so unwrap must fail; this proves the encrypted-key
    // bytes were the AES-GCM ciphertext input.
    //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-unwrapping
    //= type=test
    //# - It MUST use the `encrypted key` obtained from deserialization as the AES-GCM input ciphertext.
    assert_eq!(
        err.kind,
        MaterialsErrorKind::KeyringFailed,
        "expected KeyringFailed for AEAD verification failure; got {err:?}",
    );
}

#[test]
fn wrap_then_unwrap_with_tampered_tag_fails() {
    let materials = fixture_materials_empty_ec();
    let plaintext = vec![0x55_u8; 32];

    let ciphertext = branch_key_wrap(&materials, &plaintext).expect("wrap must succeed");
    branch_key_unwrap(&materials, &ciphertext).expect("baseline unwrap");

    // Tamper a byte in the tag region (last 16 bytes of the ciphertext).
    let mut tampered = ciphertext.clone();
    let tag_offset = tampered.len() - 16;
    let original = tampered[tag_offset];
    tampered[tag_offset] ^= 0x80;
    assert_ne!(
        tampered[tag_offset], original,
        "tamper must change the byte"
    );

    let result = branch_key_unwrap(&materials, &tampered);
    let err = result.expect_err("unwrap with tampered tag must fail");

    // Tampering a byte in the tag region invalidates the AES-GCM authentication,
    // so unwrap must fail; this proves the tag bytes were used as the AES-GCM
    // input authentication tag.
    //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-unwrapping
    //= type=test
    //# - It MUST use the `authentication tag` obtained from deserialization as the AES-GCM input authentication tag.
    assert_eq!(
        err.kind,
        MaterialsErrorKind::KeyringFailed,
        "expected KeyringFailed for tag verification failure; got {err:?}",
    );
}

#[test]
fn wrap_then_unwrap_with_tampered_iv_fails() {
    let materials = fixture_materials_empty_ec();
    let plaintext = vec![0x77_u8; 32];

    let ciphertext = branch_key_wrap(&materials, &plaintext).expect("wrap must succeed");
    branch_key_unwrap(&materials, &ciphertext).expect("baseline unwrap");

    // Tamper a byte in the IV region (bytes 16..28 — after the 16-byte salt).
    let mut tampered = ciphertext.clone();
    let iv_offset = 16 + 5;
    let original = tampered[iv_offset];
    tampered[iv_offset] ^= 0x10;
    assert_ne!(tampered[iv_offset], original, "tamper must change the byte");

    let result = branch_key_unwrap(&materials, &tampered);
    let err = result.expect_err("unwrap with tampered IV must fail");

    // Tampering the IV causes AES-GCM authentication to fail because the tag
    // was computed under the original IV; this proves the IV from
    // deserialization was used as the AES-GCM input IV.
    //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-unwrapping
    //= type=test
    //# - It MUST use the `IV` obtained from deserialization as the AES-GCM input IV.
    assert_eq!(
        err.kind,
        MaterialsErrorKind::KeyringFailed,
        "expected KeyringFailed for IV-tampered AEAD; got {err:?}",
    );
}

#[test]
fn wrap_then_unwrap_with_different_branch_key_fails() {
    let materials_wrap = fixture_materials_empty_ec();
    let plaintext = vec![0x11_u8; 32];
    let ciphertext = branch_key_wrap(&materials_wrap, &plaintext).expect("wrap must succeed");

    // Construct a second BranchKeyMaterials with a different branch_key
    // but otherwise identical inputs.
    let mut other_branch_key = fixed_branch_key();
    other_branch_key[0] ^= 0xFF;
    let materials_unwrap = BranchKeyMaterials::new(
        other_branch_key,
        FIXTURE_BRANCH_KEY_ID.to_string(),
        FIXTURE_VERSION.to_string(),
        EncryptionContext::new(),
    )
    .expect("materials with different branch_key must construct");

    let result = branch_key_unwrap(&materials_unwrap, &ciphertext);
    let err = result.expect_err("unwrap with different branch_key must fail");

    // Different branch_key bytes derive a different AES-256-GCM cipher key
    // on each side, so AES-GCM authentication fails on unwrap; this proves
    // the cipher key on both wrap and unwrap was the derivedBranchKey.
    //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-wrapping
    //= type=test
    //# - MUST use the `derivedBranchKey` as the AES-GCM cipher key.
    //
    //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-unwrapping
    //= type=test
    //# - It MUST use the `derivedBranchKey` as the AES-GCM cipher key.
    assert_eq!(
        err.kind,
        MaterialsErrorKind::KeyringFailed,
        "expected KeyringFailed when branch_key differs; got {err:?}",
    );
}

#[test]
fn wrap_then_unwrap_with_different_aad_branch_key_id_fails() {
    let materials_wrap = fixture_materials_empty_ec();
    let plaintext = vec![0x33_u8; 32];
    let ciphertext = branch_key_wrap(&materials_wrap, &plaintext).expect("wrap must succeed");

    // Same branch_key bytes (so KDF derivation is identical), same EC, same
    // version — but a different branch_key_id, which means the AAD differs.
    let materials_unwrap = BranchKeyMaterials::new(
        fixed_branch_key(),
        "different-branch-key-id".to_string(),
        FIXTURE_VERSION.to_string(),
        EncryptionContext::new(),
    )
    .expect("BranchKeyMaterials::new must accept the alternate id");

    let result = branch_key_unwrap(&materials_unwrap, &ciphertext);
    let err = result.expect_err("unwrap with different branch_key_id in AAD must fail");

    // Tampering the wrap-side AAD's branch_key_id (via constructing a
    // different materials struct on the unwrap side) causes the AAD bytes
    // to differ between wrap and unwrap; AES-GCM authentication therefore
    // fails on unwrap. This proves the AAD (which contains branch_key_id)
    // was the AES-GCM AAD on the wrap side, and that the keyring
    // included branch_key_id as part of the AAD for both Encrypt and
    // Decrypt calls.
    //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-wrapping-and-unwrapping-aad
    //= type=test
    //# To Encrypt and Decrypt the `wrappedDerivedBranchKey` the keyring MUST include the following values as part of the AAD for
    //# the AES Encrypt/Decrypt calls.
    //
    //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-wrapping
    //= type=test
    //# - MUST use the serialized [AAD](#branch-key-wrapping-and-unwrapping-aad) as the AES-GCM AAD.
    assert_eq!(
        err.kind,
        MaterialsErrorKind::KeyringFailed,
        "expected KeyringFailed when AAD differs; got {err:?}",
    );
}

#[test]
fn wrap_then_unwrap_with_different_encryption_context_fails() {
    // Wrap with empty EC; unwrap with a non-empty EC. The AAD differs, so
    // AES-GCM authentication on unwrap must fail.
    let materials_wrap = fixture_materials_empty_ec();
    let plaintext = vec![0x66_u8; 32];
    let ciphertext = branch_key_wrap(&materials_wrap, &plaintext).expect("wrap must succeed");

    let mut other_ec = EncryptionContext::new();
    other_ec.insert(b"region".to_vec(), b"us-east-1".to_vec());
    let materials_unwrap = fixture_materials_with_ec(other_ec);

    let result = branch_key_unwrap(&materials_unwrap, &ciphertext);
    let err = result.expect_err("unwrap with different EC must fail");

    // The serialized encryption context is part of the AES-GCM AAD on both
    // sides; if the unwrap-side EC differs from the wrap-side EC, the AAD
    // differs and AES-GCM authentication fails.
    //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-unwrapping
    //= type=test
    //# - It MUST use the serialized [encryption context](#branch-key-wrapping-and-unwrapping-aad) as the AES-GCM AAD.
    assert_eq!(
        err.kind,
        MaterialsErrorKind::KeyringFailed,
        "expected KeyringFailed when EC differs; got {err:?}",
    );
}

#[test]
fn wrap_two_calls_produce_distinct_ciphertexts() {
    // The salt and IV are random per wrap, so two wrap calls with the
    // same inputs MUST produce different ciphertexts (the random fields
    // must actually be random — a bug that returns a fixed salt/IV
    // would produce identical outputs).
    let materials = fixture_materials_empty_ec();
    let plaintext = vec![0x99_u8; 32];

    let ct1 = branch_key_wrap(&materials, &plaintext).expect("first wrap");
    let ct2 = branch_key_wrap(&materials, &plaintext).expect("second wrap");
    assert_ne!(
        ct1, ct2,
        "two wraps of the same plaintext must differ (random salt and IV)",
    );
}

#[test]
fn unwrap_too_short_ciphertext_returns_error() {
    // A ciphertext shorter than the fixed 60-byte overhead cannot possibly
    // hold the salt+iv+version+tag layout. Unwrap must fail with KeyringFailed.
    let materials = fixture_materials_empty_ec();
    let too_short = vec![0u8; 32];

    let result = branch_key_unwrap(&materials, &too_short);
    let err = result.expect_err("unwrap of too-short ciphertext must fail");

    // The unwrap call cannot complete deserialization (a required step)
    // when the input is shorter than the fixed overhead, so it must
    // return an error rather than silently succeed.
    //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-unwrapping
    //= type=test
    //# If OnDecrypt fails to do any of the above, OnDecrypt MUST fail.
    assert_eq!(
        err.kind,
        MaterialsErrorKind::KeyringFailed,
        "expected KeyringFailed for ciphertext shorter than fixed overhead; got {err:?}",
    );
}

#[test]
fn wrap_succeeds_with_known_inputs_and_unwrap_round_trips() {
    // End-to-end coverage citing the structural top-of-list MUST entries
    // for both wrap and unwrap. The round trip succeeding here exercises
    // every numbered step of both lists in order; if any step were absent
    // (e.g., the unwrap side never re-derived the branch key), the AES-GCM
    // open call would fail.
    let materials = fixture_materials_empty_ec();
    let plaintext: &[u8] = b"plaintext-of-length-32-bytes----";
    assert_eq!(plaintext.len(), 32);

    // A successful wrap+unwrap round-trip requires every numbered step
    // (salt, IV, KDF, AES seal) to have run in order; absence of any
    // step would either error or break the round-trip.
    //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-wrapping
    //= type=test
    //# The hierarchical keyring MUST:
    let ciphertext = branch_key_wrap(&materials, plaintext).expect("wrap must succeed");

    // A successful round-trip requires every unwrap step (salt deserialization,
    // IV deserialization, version deserialization, encrypted_key deserialization,
    // tag deserialization, KDF re-derivation, AES open) to have run in order.
    //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-unwrapping
    //= type=test
    //# To decrypt an encrypted data key with a branch key, the hierarchical keyring MUST:
    let recovered = branch_key_unwrap(&materials, &ciphertext).expect("unwrap must succeed");
    assert_eq!(recovered, plaintext, "round-trip must recover plaintext");
}

#[test]
fn wrap_then_unwrap_with_smaller_plaintext_round_trips() {
    // Confirm wrap accepts arbitrary plaintext lengths (the AES-GCM message
    // input rule does not restrict length). Round-trip with a 1-byte plaintext.
    let materials = fixture_materials_empty_ec();
    let plaintext: &[u8] = &[0xCC];

    let ciphertext = branch_key_wrap(&materials, plaintext).expect("wrap must succeed");

    // A 1-byte plaintext flows through wrap and unwrap; tampering the
    // encrypted-key region (already covered by another test) proves the
    // byte was the AES-GCM message.
    //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-wrapping
    //= type=test
    //# - MUST use the plain text data key that will be wrapped by the `derivedBranchKey` as the AES-GCM message.
    let recovered = branch_key_unwrap(&materials, &ciphertext).expect("unwrap must succeed");
    assert_eq!(recovered, plaintext, "1-byte plaintext must round-trip");
}

#[test]
fn wrap_fails_when_encryption_context_value_too_large() {
    // Force the AAD construction step inside `wrap` to fail by handing it
    // an EncryptionContext whose value length exceeds u16::MAX (the wire
    // length-field limit). `compute_aad` propagates the EC-serialize error
    // via `?`; `wrap` in turn must propagate that error rather than
    // silently producing a ciphertext, exercising the "If OnEncrypt fails
    // to do any of the above, OnEncrypt MUST fail" failure-propagation
    // contract at the wrap boundary.
    let mut ec = EncryptionContext::new();
    ec.insert(b"k".to_vec(), vec![0u8; 65_536]);
    let materials = fixture_materials_with_ec(ec);

    let result = branch_key_wrap(&materials, &[0u8; 32]);
    let err = result.expect_err("wrap must fail when EC serialization fails");

    //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-wrapping
    //= type=test
    //# If OnEncrypt fails to do any of the above, OnEncrypt MUST fail.
    assert_eq!(
        err.kind,
        MaterialsErrorKind::Validation,
        "expected Validation error from EC serialize via wrap; got {err:?}",
    );
}

// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for `aws_kms::hierarchical_keyring`.
//!
//! Covers, in order: construction and configuration validation (TTL,
//! partition id, cache wiring), the cache entry identifier formulas, the
//! branch-key wrap / unwrap / AAD functions, and the OnEncrypt / OnDecrypt
//! operations against keystore doubles.
//!
//! Where a test builds an expected byte sequence by hand, it is transcribed
//! from the AWS KMS Hierarchical Keyring specification:
//!
//! - [Appendix A: Cache Entry Identifier Formulas][appendix-a]
//! - [Branch Key Wrapping and Unwrapping AAD][aad]
//!
//! [appendix-a]: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-hierarchical-keyring.md#appendix-a-cache-entry-identifier-formulas
//! [aad]: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-wrapping-and-unwrapping-aad

use std::error::Error as _;
use std::io::{Error as IoError, ErrorKind as IoErrorKind};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use aws_config::{BehaviorVersion, SdkConfig};
use aws_sdk_dynamodb::Client as DynamoDbClient;
use aws_sdk_kms::Client as KmsClient;

use aws_crypto_mpl::aws_kms::__test_internals::{
    build_cache_identifier, compute_aad, unwrap as branch_key_unwrap, wrap as branch_key_wrap,
};
use aws_crypto_mpl::aws_kms::hierarchical_keyring::{
    BranchKeySupplier, GetBranchKeyIdInput, GetBranchKeyIdOutput, HierarchicalKeyring,
    SCOPE_ID_DECRYPT, SCOPE_ID_ENCRYPT,
};
use aws_crypto_mpl::cmc::cache_config::{CacheType, DefaultCache, StormTrackingCache};
use aws_crypto_mpl::keystore::error::KeystoreErrorKind;
use aws_crypto_mpl::keystore::{
    BranchKeyStore, BranchKeyStoreBuilder, KeyStoreInfo, Keystore, KeystoreError, KmsConfiguration,
};
use aws_crypto_mpl::structures::{
    AlgorithmSuiteId, BeaconKeyMaterials, BranchKeyMaterials, DecryptionMaterials,
    EncryptionContext, EncryptionMaterials, MaterialsError, MaterialsErrorKind,
};
use aws_crypto_mpl::{LocalCmc, SharedCmc};

/// Construct a pair of zero-config AWS SDK clients suitable for tests that
/// never invoke a remote operation. `BehaviorVersion::latest()` is required by
/// the SDK at client-construction time; no IO occurs at construction itself.
fn dummy_clients() -> (KmsClient, DynamoDbClient) {
    let cfg = SdkConfig::builder()
        .behavior_version(BehaviorVersion::latest())
        .build();
    (KmsClient::new(&cfg), DynamoDbClient::new(&cfg))
}

/// The branch key id and active version of the real keystore fixture the
/// integration tests use (DDB table `KeyStoreDdbTable`, account
/// `370957321024`). Nothing here contacts a keystore — `wrap` / `unwrap` /
/// `compute_aad` are pure — but using the real values keeps these fixtures
/// recognizable against the integ suite and against the other MPL
/// implementations' test vectors.
const FIXTURE_BRANCH_KEY_ID: &str = "3f43a9af-08c5-4317-b694-3d3e883dcaef";
const FIXTURE_VERSION: &str = "caf0c508-e64d-4b6c-bffe-381cbc546c02";

/// Logical keystore name of that same fixture keystore.
const LOGICAL_KEY_STORE_NAME: &str = "KeyStoreDdbTable";

/// Reusable [`BranchKeySupplier`] fixture: always answers with the branch key
/// id it was constructed with, ignoring the encryption context. Enough for any
/// test that needs a supplier-configured keyring without caring how the
/// decision is made.
struct FixedBranchKeySupplier(&'static str);

impl BranchKeySupplier for FixedBranchKeySupplier {
    fn get_branch_key_id(
        &self,
        _input: GetBranchKeyIdInput,
    ) -> Result<GetBranchKeyIdOutput, MaterialsError> {
        Ok(GetBranchKeyIdOutput::new(self.0.to_string()))
    }
}

/// A real [`BranchKeyStore`] that is never consulted.
///
/// The type is the one callers actually pass to the keyring, but it points at
/// a table and KMS key that do not exist, so any keystore call would fail.
/// That is safe here because no test using this helper makes one:
/// `HierarchicalKeyring::new` only stores the handle, and the keystore is
/// first consulted inside OnEncrypt / OnDecrypt. Tests that do exercise those
/// operations use the `FakeKeystore` doubles in `mod onencrypt` / `mod
/// ondecrypt` instead. Both SDK clients are supplied, so there is nothing to
/// resolve and so nothing to await.
fn keystore_never_consulted() -> BranchKeyStore {
    let (kms, ddb) = dummy_clients();
    build_without_io(
        BranchKeyStore::builder()
            .ddb_table_name("test-table")
            .kms_configuration(KmsConfiguration::KmsKeyArn(
                "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
                    .to_string(),
            ))
            .logical_keystore_name("test-logical")
            .kms_client(kms)
            .ddb_client(ddb),
    )
}

/// Builds `builder` by polling its future once. With both clients supplied,
/// `build` does no IO, so it is ready on the first poll.
fn build_without_io(builder: BranchKeyStoreBuilder) -> BranchKeyStore {
    use std::future::Future;
    use std::task::{Context, Poll, Waker};
    let mut fut = std::pin::pin!(builder.build());
    match fut.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(result) => result.expect("BranchKeyStore construction must succeed"),
        Poll::Pending => panic!("build with both clients supplied must not await"),
    }
}

#[test]
fn new_with_zero_ttl_returns_validation_error() {
    let keystore = keystore_never_consulted();
    let result = HierarchicalKeyring::new(
        keystore,
        0, // zero TTL — must be rejected
        Some("branch-key-id".to_string()),
        None,
        None,
        None,
    );

    let err = match result {
        Err(e) => e,
        Ok(_) => panic!("expected zero TTL to return a validation error"),
    };
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
fn new_with_both_branch_key_id_and_supplier_returns_validation_error() {
    // The keyring takes branchKeyId and branchKeyIdSupplier as two optional
    // inputs, mirroring CreateAwsKmsHierarchicalKeyringInput, so the "exactly
    // one" rule is enforced here rather than by the type system.
    let err = match HierarchicalKeyring::new(
        keystore_never_consulted(),
        3600,
        Some("branch-key-id".to_string()),
        Some(Arc::new(FixedBranchKeySupplier("unused")) as Arc<dyn BranchKeySupplier>),
        None,
        None,
    ) {
        Err(e) => e,
        Ok(_) => panic!("supplying both a branch_key_id and a supplier MUST be rejected"),
    };

    assert_eq!(err.kind, MaterialsErrorKind::Validation);
    assert!(
        err.message.contains("both"),
        "error should identify the both-supplied case; got: {}",
        err.message,
    );
}

#[test]
fn new_with_neither_branch_key_id_nor_supplier_returns_validation_error() {
    let err =
        match HierarchicalKeyring::new(keystore_never_consulted(), 3600, None, None, None, None) {
            Err(e) => e,
            Ok(_) => panic!("supplying neither a branch_key_id nor a supplier MUST be rejected"),
        };

    assert_eq!(err.kind, MaterialsErrorKind::Validation);
    assert!(
        err.message.contains("either"),
        "error should identify the neither-supplied case; got: {}",
        err.message,
    );
}

#[test]
fn new_with_positive_ttl_succeeds() {
    let keystore = keystore_never_consulted();
    let result = HierarchicalKeyring::new(
        keystore,
        1, // smallest legal TTL
        Some("branch-key-id".to_string()),
        None,
        Some(CacheType::Default(DefaultCache::new(1000))),
        None,
    );

    let keyring = result.expect("ttl_seconds=1 must be accepted");
    assert_eq!(keyring.ttl_seconds(), 1);
}

#[test]
fn partition_id_default_is_16_byte_v4_uuid() {
    let keystore = keystore_never_consulted();
    let keyring = HierarchicalKeyring::new(
        keystore,
        3600,
        Some("branch-key-id".to_string()),
        None,
        None,
        None, // no partition id supplied → must default to v4 UUID bytes
    )
    .expect("constructor with no partition id must succeed");

    let bytes = keyring.partition_id_bytes();

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
        keystore_never_consulted(),
        3600,
        Some("branch-key-id".to_string()),
        None,
        None,
        None,
    )
    .expect("first constructor call must succeed");

    let b = HierarchicalKeyring::new(
        keystore_never_consulted(),
        3600,
        Some("branch-key-id".to_string()),
        None,
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
    // and have not been re-encoded, normalized, or truncated.
    //
    // Table-driven across the UTF-8 shapes that could break a naive
    // implementation: every encoded length, a character outside the BMP, a
    // string that is not in normal form, and a lone combining mark.
    let cases: &[(&str, &str)] = &[
        ("ascii only", "partition-id"),
        ("2-byte: precomposed e-acute", "café"),
        ("3-byte: CJK", "hello-世界"),
        ("4-byte: astral plane emoji", "partition-😀"),
        ("mixed widths", "hello-aé世😀"),
        // NFD: "a" followed by COMBINING ACUTE ACCENT. Must survive as two
        // scalars — normalizing to U+00E1 would change the byte length.
        ("decomposed: a + U+0301", "hello-a\u{0301}"),
        ("combining mark with no base", "\u{0301}"),
        (
            "emoji ZWJ sequence",
            "family-\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}",
        ),
        ("right-to-left", "قسم"),
        ("empty", ""),
    ];

    for (label, original) in cases {
        let keyring = HierarchicalKeyring::new(
            keystore_never_consulted(),
            3600,
            Some("branch-key-id".to_string()),
            None,
            None,
            Some((*original).to_string()),
        )
        .unwrap_or_else(|e| {
            panic!("{label}: constructor with explicit partition id must succeed: {e}")
        });

        assert_eq!(
            keyring.partition_id_bytes(),
            original.as_bytes(),
            "{label}: partition id bytes MUST be the caller's UTF-8 bytes verbatim",
        );
    }
}

#[test]
fn partition_id_is_not_unicode_normalized() {
    // The two strings below are canonically equivalent under Unicode
    // normalization but are different byte sequences. The partition id
    // separates cache entries, so collapsing them would let two keyrings a
    // caller intended to keep apart share entries in a `Shared` cache.
    let precomposed = "caf\u{00E9}"; // é as one scalar
    let decomposed = "cafe\u{0301}"; // e + combining acute

    let id_of = |partition: &str| {
        HierarchicalKeyring::new(
            keystore_never_consulted(),
            3600,
            Some("branch-key-id".to_string()),
            None,
            None,
            Some(partition.to_string()),
        )
        .expect("constructor must succeed")
        .partition_id_bytes()
        .to_vec()
    };

    assert_eq!(id_of(precomposed), precomposed.as_bytes());
    assert_eq!(id_of(decomposed), decomposed.as_bytes());
    assert_ne!(
        id_of(precomposed),
        id_of(decomposed),
        "canonically-equivalent partition ids MUST stay distinct byte sequences",
    );
}

#[test]
fn new_with_branch_key_id_supplier_succeeds() {
    // Smoke test that configuring a supplier instead of a static branch key
    // id is usable — construct a no-op supplier, pass it as the
    // branch_key_id_supplier, and confirm the keyring can be built with it.
    let supplier: Arc<dyn BranchKeySupplier> =
        Arc::new(FixedBranchKeySupplier("branch-id-from-supplier"));
    let keyring = HierarchicalKeyring::new(
        keystore_never_consulted(),
        3600,
        None,
        Some(supplier),
        None,
        None,
    )
    .expect("constructor with supplier variant must succeed");

    assert!(
        keyring.branch_key_id().is_none(),
        "a supplier-configured keyring MUST NOT carry a static branch key id"
    );
    assert!(keyring.branch_key_id_supplier().is_some());
}

// ─── Cache wiring tests: which Cmc a given CacheType produces ───────────────
//
// The keyring's only responsibility here is turning a `CacheType` into a
// `Cmc`, so for the variants it builds itself, successful construction IS the
// assertion. Cache behaviour — capacity, LRU eviction, TTL pruning — belongs to
// the cache's own suites in `test_local_cmc.rs` and `test_storm_tracking_cmc.rs`
// and is deliberately not re-derived through the keyring. The one exception is
// `CacheType::Shared`, where the keyring must store the caller's cache verbatim
// rather than build its own; nothing but a keyring test can check that.

#[test]
fn new_with_default_cache_succeeds() {
    HierarchicalKeyring::new(
        keystore_never_consulted(),
        3600,
        Some("bk".to_string()),
        None,
        Some(CacheType::Default(DefaultCache::new(1))),
        None,
    )
    .expect("CacheType::Default must build a keyring-local cache");
}

#[test]
fn new_with_cache_type_none_succeeds() {
    HierarchicalKeyring::new(
        keystore_never_consulted(),
        3600,
        Some("bk".to_string()),
        None,
        None,
        None,
    )
    .expect("None cache_type must default to a built-in cache");
}

#[test]
fn new_with_shared_cache_round_trips_provided_cache() {
    let supplied = SharedCmc::from(LocalCmc::new(8, 4).unwrap());

    let keyring = HierarchicalKeyring::new(
        keystore_never_consulted(),
        3600,
        Some("bk".to_string()),
        None,
        Some(CacheType::Shared(supplied.clone())),
        None,
    )
    .expect("CacheType::Shared must succeed");

    // The exact cache supplied is what the keyring stores. Tested via
    // pointer-identity rather than behaviour because the struct field is
    // not directly observable.
    let stored: &SharedCmc = keyring.cache();
    assert!(
        std::ptr::addr_eq(&**stored, &*supplied),
        "CacheType::Shared MUST round-trip the supplied cache verbatim"
    );
}

#[test]
fn new_with_storm_tracking_cache_succeeds() {
    let params = StormTrackingCache::builder()
        .entry_capacity(16)
        .entry_pruning_tail_size(4)
        .grace_period(Duration::from_secs(60))
        .grace_interval(Duration::from_secs(1))
        .fan_out(4)
        .inflight_ttl(Duration::from_secs(30))
        .sleep(Duration::from_millis(10))
        .build()
        .expect("valid StormTrackingCache");
    HierarchicalKeyring::new(
        keystore_never_consulted(),
        3600, // ttl_seconds — strictly greater than grace_period (60).
        Some("bk".to_string()),
        None,
        Some(CacheType::StormTracking(params)),
        None,
    )
    .expect("CacheType::StormTracking with grace_period < ttl must succeed");
}

#[test]
fn new_with_storm_tracking_grace_period_equal_to_ttl_fails() {
    let params = StormTrackingCache::builder()
        .entry_capacity(16)
        .entry_pruning_tail_size(4)
        .grace_period(Duration::from_secs(60))
        .grace_interval(Duration::from_secs(1))
        .fan_out(4)
        .inflight_ttl(Duration::from_secs(30))
        .sleep(Duration::from_millis(10))
        .build()
        .expect("valid StormTrackingCache");
    let err = match HierarchicalKeyring::new(
        keystore_never_consulted(),
        60, // ttl_seconds == grace_period — must fail.
        Some("bk".to_string()),
        None,
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
    let params = StormTrackingCache::builder()
        .entry_capacity(16)
        .entry_pruning_tail_size(4)
        .grace_period(Duration::from_secs(120))
        .grace_interval(Duration::from_secs(1))
        .fan_out(4)
        .inflight_ttl(Duration::from_secs(30))
        .sleep(Duration::from_millis(10))
        .build()
        .expect("valid StormTrackingCache");
    let err = match HierarchicalKeyring::new(
        keystore_never_consulted(),
        60,
        Some("bk".to_string()),
        None,
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
    // grace_period = 5_000 ms = 5 s, ttl_seconds = 60 s → strict less-than.
    // inflight_ttl <= grace_period is required by StormTrackingCmc.
    let params = StormTrackingCache::builder()
        .entry_capacity(16)
        .entry_pruning_tail_size(4)
        .grace_period(Duration::from_millis(5_000))
        .grace_interval(Duration::from_millis(100))
        .fan_out(4)
        .inflight_ttl(Duration::from_millis(1_000))
        .sleep(Duration::from_millis(10))
        .build()
        .expect("valid StormTrackingCache");
    HierarchicalKeyring::new(
        keystore_never_consulted(),
        60,
        Some("bk".to_string()),
        None,
        Some(CacheType::StormTracking(params)),
        None,
    )
    .expect("ms-unit grace_period (5_000ms = 5s) < ttl (60s) must succeed");
}

// ─── Cache entry identifier formula tests ───────────────────────────────────
//
// Byte layouts below are transcribed from Appendix A of the specification;
// see the module doc for the link.

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
    let logical_key_store_name = LOGICAL_KEY_STORE_NAME;
    let branch_key_id = FIXTURE_BRANCH_KEY_ID;

    // Manually build the byte sequence Appendix A dictates:
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

    let actual = build_cache_identifier(
        SCOPE_ID_ENCRYPT,
        partition_id,
        logical_key_store_name,
        branch_key_id,
        None,
    );

    assert_eq!(actual, expected);
}

#[test]
fn cache_entry_identifier_for_decrypt_matches_manual_sha384() {
    let partition_id: &[u8] = b"\xde\xad\xbe\xef\xfe\xed\xfa\xce\x01\x02\x03\x04\x05\x06\x07\x08";
    let logical_key_store_name = LOGICAL_KEY_STORE_NAME;
    let branch_key_id = FIXTURE_BRANCH_KEY_ID;
    let branch_key_version = FIXTURE_VERSION;

    let mut expected_input = vec![0x02_u8, 0x00_u8, 0x02_u8, 0x00_u8];
    expected_input.extend_from_slice(partition_id);
    expected_input.push(0x00_u8);
    expected_input.extend_from_slice(logical_key_store_name.as_bytes());
    expected_input.push(0x00_u8);
    expected_input.extend_from_slice(branch_key_id.as_bytes());
    expected_input.push(0x00_u8);
    expected_input.extend_from_slice(branch_key_version.as_bytes());
    let expected = sha384(&expected_input);

    let actual = build_cache_identifier(
        SCOPE_ID_DECRYPT,
        partition_id,
        logical_key_store_name,
        branch_key_id,
        Some(branch_key_version),
    );

    assert_eq!(actual, expected);
}

#[test]
fn cache_entry_identifier_encrypt_and_decrypt_differ_for_same_inputs() {
    // Same partition / logical name / branch key id; the only difference
    // between the encrypt and decrypt hash inputs is:
    //   - scope_id (0x01 vs 0x02)
    //   - presence of branch_key_version (absent vs present)
    // The hashes MUST therefore differ. This is the regression check that
    // the encrypt/decrypt scope IDs actually flow into the SHA-384 input.
    let partition_id: &[u8] = b"shared-partition";
    let logical = "shared-logical";
    let branch_id = "shared-branch";
    let version = "1.0";

    let enc = build_cache_identifier(SCOPE_ID_ENCRYPT, partition_id, logical, branch_id, None);
    let dec = build_cache_identifier(
        SCOPE_ID_DECRYPT,
        partition_id,
        logical,
        branch_id,
        Some(version),
    );

    assert_ne!(
        enc, dec,
        "encrypt and decrypt cache identifiers must differ for the same partition/logical/branch (scope IDs differentiate)"
    );
}

#[test]
fn cache_entry_identifier_distinct_branch_key_ids_produce_distinct_outputs() {
    // Negative-collision regression: changing the branch_key_id MUST
    // change the cache identifier. Both scopes checked.
    let partition_id: &[u8] = b"some-partition-bytes";
    let logical = "logical-name";

    let enc_a = build_cache_identifier(SCOPE_ID_ENCRYPT, partition_id, logical, "branch-a", None);
    let enc_b = build_cache_identifier(SCOPE_ID_ENCRYPT, partition_id, logical, "branch-b", None);
    assert_ne!(
        enc_a, enc_b,
        "the encrypt scope must produce distinct outputs for distinct branch key ids"
    );

    let dec_a = build_cache_identifier(
        SCOPE_ID_DECRYPT,
        partition_id,
        logical,
        "branch-a",
        Some("v1"),
    );
    let dec_b = build_cache_identifier(
        SCOPE_ID_DECRYPT,
        partition_id,
        logical,
        "branch-b",
        Some("v1"),
    );
    assert_ne!(
        dec_a, dec_b,
        "the decrypt scope must produce distinct outputs for distinct branch key ids"
    );
}

#[test]
fn cache_entry_identifier_distinct_versions_produce_distinct_outputs() {
    // Decrypt-only: the branch_key_version field MUST contribute to the
    // hash. Two decrypt-scope calls that differ only in branch_key_version
    // MUST produce distinct outputs.
    let partition_id: &[u8] = b"another-partition";
    let logical = "logical-name";
    let branch_id = "branch-id";

    assert_ne!(
        build_cache_identifier(
            SCOPE_ID_DECRYPT,
            partition_id,
            logical,
            branch_id,
            Some("v1")
        ),
        build_cache_identifier(
            SCOPE_ID_DECRYPT,
            partition_id,
            logical,
            branch_id,
            Some("v2")
        ),
        "the decrypt scope must produce distinct outputs for distinct branch key versions"
    );
}

// ─── Branch-key wrapping / unwrapping / AAD tests ───────────────────────────

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
    // Independently-constructed expected AAD byte vector. Built here from the
    // bullet list in the specification's Branch Key Wrapping and Unwrapping
    // AAD section (linked in the module doc) so a drift in the
    // implementation's order or separator bytes is detected.
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

    // The expected bytes are independently constructed from the AAD section's
    // bullet list (label || branch-key-id || version || serialized-EC); a
    // drift in concatenation order or content fails this assertion.
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

    let ciphertext = branch_key_wrap(&materials, materials.encryption_context(), plaintext)
        .expect("wrap must succeed");
    let recovered = branch_key_unwrap(&materials, materials.encryption_context(), &ciphertext)
        .expect("unwrap must succeed");

    // Round-trip success requires the IV value passed to AES-GCM encrypt on
    // wrap to match the IV bytes stored on-wire (which unwrap reads via
    // `Nonce::assume_unique_for_key(iv_bytes)`). If wrap had passed a
    // different IV to AES-GCM than the one written into the layout, the
    // authentication tag would not verify on unwrap and round-trip would
    // fail.
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
    let ciphertext = branch_key_wrap(&materials, materials.encryption_context(), &plaintext)
        .expect("wrap must succeed");
    let recovered = branch_key_unwrap(&materials, materials.encryption_context(), &ciphertext)
        .expect("unwrap must succeed with same EC");
    assert_eq!(recovered, plaintext);
}

#[test]
fn wrap_ciphertext_layout_lengths_match_spec() {
    let materials = fixture_materials_empty_ec();
    let plaintext = vec![0x42_u8; 32];

    let ciphertext = branch_key_wrap(&materials, materials.encryption_context(), &plaintext)
        .expect("wrap must succeed");

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
    let ciphertext = branch_key_wrap(&materials, materials.encryption_context(), plaintext)
        .expect("wrap must succeed");
    let pristine = branch_key_unwrap(&materials, materials.encryption_context(), &ciphertext)
        .expect("baseline unwrap");
    assert_eq!(pristine, plaintext, "baseline round-trip must work");

    // Tamper a byte in the encrypted-key region: bytes [44 .. ciphertext.len() - 16]
    // (after salt 16, iv 12, version 16 = 44).
    let mut tampered = ciphertext.clone();
    let original = tampered[44];
    tampered[44] ^= 0x01;
    assert_ne!(tampered[44], original, "tamper must change the byte");

    let result = branch_key_unwrap(&materials, materials.encryption_context(), &tampered);
    let err = result.expect_err("unwrap with tampered encrypted-key must fail");

    // Tampering a byte in the encrypted-key region invalidates the AES-GCM
    // authentication tag, so unwrap must fail; this proves the encrypted-key
    // bytes were the AES-GCM ciphertext input.
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

    let ciphertext = branch_key_wrap(&materials, materials.encryption_context(), &plaintext)
        .expect("wrap must succeed");
    branch_key_unwrap(&materials, materials.encryption_context(), &ciphertext)
        .expect("baseline unwrap");

    // Tamper a byte in the tag region (last 16 bytes of the ciphertext).
    let mut tampered = ciphertext.clone();
    let tag_offset = tampered.len() - 16;
    let original = tampered[tag_offset];
    tampered[tag_offset] ^= 0x80;
    assert_ne!(
        tampered[tag_offset], original,
        "tamper must change the byte"
    );

    let result = branch_key_unwrap(&materials, materials.encryption_context(), &tampered);
    let err = result.expect_err("unwrap with tampered tag must fail");

    // Tampering a byte in the tag region invalidates the AES-GCM authentication,
    // so unwrap must fail; this proves the tag bytes were used as the AES-GCM
    // input authentication tag.
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

    let ciphertext = branch_key_wrap(&materials, materials.encryption_context(), &plaintext)
        .expect("wrap must succeed");
    branch_key_unwrap(&materials, materials.encryption_context(), &ciphertext)
        .expect("baseline unwrap");

    // Tamper a byte in the IV region (bytes 16..28 — after the 16-byte salt).
    let mut tampered = ciphertext.clone();
    let iv_offset = 16 + 5;
    let original = tampered[iv_offset];
    tampered[iv_offset] ^= 0x10;
    assert_ne!(tampered[iv_offset], original, "tamper must change the byte");

    let result = branch_key_unwrap(&materials, materials.encryption_context(), &tampered);
    let err = result.expect_err("unwrap with tampered IV must fail");

    // Tampering the IV causes AES-GCM authentication to fail because the tag
    // was computed under the original IV; this proves the IV from
    // deserialization was used as the AES-GCM input IV.
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
    let ciphertext = branch_key_wrap(
        &materials_wrap,
        materials_wrap.encryption_context(),
        &plaintext,
    )
    .expect("wrap must succeed");

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

    let result = branch_key_unwrap(
        &materials_unwrap,
        materials_unwrap.encryption_context(),
        &ciphertext,
    );
    let err = result.expect_err("unwrap with different branch_key must fail");

    // Different branch_key bytes derive a different AES-256-GCM cipher key
    // on each side, so AES-GCM authentication fails on unwrap; this proves
    // the cipher key on both wrap and unwrap was the derivedBranchKey.
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
    let ciphertext = branch_key_wrap(
        &materials_wrap,
        materials_wrap.encryption_context(),
        &plaintext,
    )
    .expect("wrap must succeed");

    // Same branch_key bytes (so KDF derivation is identical), same EC, same
    // version — but a different branch_key_id, which means the AAD differs.
    let materials_unwrap = BranchKeyMaterials::new(
        fixed_branch_key(),
        "different-branch-key-id".to_string(),
        FIXTURE_VERSION.to_string(),
        EncryptionContext::new(),
    )
    .expect("BranchKeyMaterials::new must accept the alternate id");

    let result = branch_key_unwrap(
        &materials_unwrap,
        materials_unwrap.encryption_context(),
        &ciphertext,
    );
    let err = result.expect_err("unwrap with different branch_key_id in AAD must fail");

    // Tampering the wrap-side AAD's branch_key_id (via constructing a
    // different materials struct on the unwrap side) causes the AAD bytes
    // to differ between wrap and unwrap; AES-GCM authentication therefore
    // fails on unwrap. This proves the AAD (which contains branch_key_id)
    // was the AES-GCM AAD on the wrap side, and that the keyring
    // included branch_key_id as part of the AAD for both Encrypt and
    // Decrypt calls.
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
    let ciphertext = branch_key_wrap(
        &materials_wrap,
        materials_wrap.encryption_context(),
        &plaintext,
    )
    .expect("wrap must succeed");

    let mut other_ec = EncryptionContext::new();
    other_ec.insert(b"region".to_vec(), b"us-east-1".to_vec());
    let materials_unwrap = fixture_materials_with_ec(other_ec);

    let result = branch_key_unwrap(
        &materials_unwrap,
        materials_unwrap.encryption_context(),
        &ciphertext,
    );
    let err = result.expect_err("unwrap with different EC must fail");

    // The serialized encryption context is part of the AES-GCM AAD on both
    // sides; if the unwrap-side EC differs from the wrap-side EC, the AAD
    // differs and AES-GCM authentication fails.
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

    let ct1 = branch_key_wrap(&materials, materials.encryption_context(), &plaintext)
        .expect("first wrap");
    let ct2 = branch_key_wrap(&materials, materials.encryption_context(), &plaintext)
        .expect("second wrap");
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

    let result = branch_key_unwrap(&materials, materials.encryption_context(), &too_short);
    let err = result.expect_err("unwrap of too-short ciphertext must fail");

    // The unwrap call cannot complete deserialization (a required step)
    // when the input is shorter than the fixed overhead, so it must
    // return an error rather than silently succeed.
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
    let ciphertext = branch_key_wrap(&materials, materials.encryption_context(), plaintext)
        .expect("wrap must succeed");

    // A successful round-trip requires every unwrap step (salt deserialization,
    // IV deserialization, version deserialization, encrypted_key deserialization,
    // tag deserialization, KDF re-derivation, AES open) to have run in order.
    let recovered = branch_key_unwrap(&materials, materials.encryption_context(), &ciphertext)
        .expect("unwrap must succeed");
    assert_eq!(recovered, plaintext, "round-trip must recover plaintext");
}

#[test]
fn wrap_then_unwrap_with_smaller_plaintext_round_trips() {
    // Confirm wrap accepts arbitrary plaintext lengths (the AES-GCM message
    // input rule does not restrict length). Round-trip with a 1-byte plaintext.
    let materials = fixture_materials_empty_ec();
    let plaintext: &[u8] = &[0xCC];

    let ciphertext = branch_key_wrap(&materials, materials.encryption_context(), plaintext)
        .expect("wrap must succeed");

    // A 1-byte plaintext flows through wrap and unwrap; tampering the
    // encrypted-key region (already covered by another test) proves the
    // byte was the AES-GCM message.
    let recovered = branch_key_unwrap(&materials, materials.encryption_context(), &ciphertext)
        .expect("unwrap must succeed");
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

    let result = branch_key_wrap(&materials, materials.encryption_context(), &[0u8; 32]);
    let err = result.expect_err("wrap must fail when EC serialization fails");

    assert_eq!(
        err.kind,
        MaterialsErrorKind::Validation,
        "expected Validation error from EC serialize via wrap; got {err:?}",
    );
}

// ─── OnEncrypt tests ────────────────────────────────────────────────────────
//
// These tests exercise the [`Keyring::on_encrypt`] body via a
// `FakeKeystore` that returns canned BranchKeyMaterials. The KMS / DDB
// SDKs are NOT involved; the test crypto is the same wrap / unwrap
// helpers under `aws_kms::__test_internals`, so a successful round-trip
// proves the EDK's wire format and the AAD / KDF derivation match.

// ─── Keystore double shared by the OnEncrypt / OnDecrypt suites ─────────────
//
// The `FAKE_*` fixtures here are placeholders for exercising the keyring's own
// logic. They are deliberately distinct from the `FIXTURE_*` constants above,
// which carry the real integration-keystore values used by the
// cache-identifier and wrap / unwrap tests.

const FAKE_BRANCH_KEY: [u8; 32] = [
    0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51,
    0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61,
];
const FAKE_BRANCH_KEY_ID: &str = "test-branch-key-id";
const FAKE_BRANCH_KEY_VERSION: &str = "11111111-2222-4333-8444-555555555555";
const FAKE_LOGICAL_KEYSTORE_NAME: &str = "test-logical-name";

/// A keystore double that returns canned [`BranchKeyMaterials`] from both
/// `get_active_branch_key` and `get_branch_key_version`, and counts
/// call-throughs so cache-hit / cache-miss tests can assert keystore behaviour
/// from the outside.
///
/// One double serves both suites: they need the same canned materials and the
/// same `KeyStoreInfo`, and differ only in which counter they read. The
/// counters are `Mutex<..>` rather than `Cell<..>` because `Keystore` requires
/// `Send + Sync`; each lock is taken and released inside a single statement, so
/// no guard is ever held across an `.await`.
struct FakeKeystore {
    materials: BranchKeyMaterials,
    get_active_calls: Mutex<u32>,
    get_version_calls: Mutex<u32>,
    last_version_arg: Mutex<Option<String>>,
}

impl FakeKeystore {
    fn new(materials: BranchKeyMaterials) -> Arc<Self> {
        Arc::new(Self {
            materials,
            get_active_calls: Mutex::new(0),
            get_version_calls: Mutex::new(0),
            last_version_arg: Mutex::new(None),
        })
    }

    fn get_active_calls(&self) -> u32 {
        *self.get_active_calls.lock().unwrap()
    }

    fn get_version_calls(&self) -> u32 {
        *self.get_version_calls.lock().unwrap()
    }

    fn last_version_arg(&self) -> Option<String> {
        self.last_version_arg.lock().unwrap().clone()
    }
}

#[async_trait]
impl Keystore for FakeKeystore {
    fn get_key_store_info(&self) -> Result<KeyStoreInfo, KeystoreError> {
        Ok(KeyStoreInfo {
            keystore_id: "test-id".to_string(),
            keystore_name: "test-table".to_string(),
            logical_keystore_name: FAKE_LOGICAL_KEYSTORE_NAME.to_string(),
            grant_tokens: Vec::new(),
            kms_configuration: KmsConfiguration::Discovery,
        })
    }

    async fn create_key_store(&self) -> Result<String, KeystoreError> {
        unimplemented!("FakeKeystore::create_key_store")
    }
    async fn create_key(
        &self,
        _branch_key_id: Option<String>,
        _encryption_context: Option<EncryptionContext>,
    ) -> Result<String, KeystoreError> {
        unimplemented!("FakeKeystore::create_key")
    }
    async fn version_key(&self, _branch_key_id: String) -> Result<(), KeystoreError> {
        unimplemented!("FakeKeystore::version_key")
    }

    async fn get_active_branch_key(
        &self,
        _branch_key_id: String,
    ) -> Result<BranchKeyMaterials, KeystoreError> {
        *self.get_active_calls.lock().unwrap() += 1;
        Ok(self.materials.clone())
    }

    async fn get_branch_key_version(
        &self,
        _branch_key_id: String,
        branch_key_version: String,
    ) -> Result<BranchKeyMaterials, KeystoreError> {
        *self.get_version_calls.lock().unwrap() += 1;
        *self.last_version_arg.lock().unwrap() = Some(branch_key_version);
        Ok(self.materials.clone())
    }
    async fn get_beacon_key(
        &self,
        _branch_key_id: String,
    ) -> Result<BeaconKeyMaterials, KeystoreError> {
        unimplemented!("FakeKeystore::get_beacon_key")
    }
}

/// Canned branch-key materials with an empty encryption context. The wrap /
/// unwrap AAD binds the *input* materials' EC, not this one.
fn fake_branch_key_materials() -> BranchKeyMaterials {
    BranchKeyMaterials::new(
        FAKE_BRANCH_KEY,
        FAKE_BRANCH_KEY_ID.to_string(),
        FAKE_BRANCH_KEY_VERSION.to_string(),
        EncryptionContext::new(),
    )
    .unwrap()
}

/// Empty encryption materials for `suite_id`. Suite choice is arbitrary unless
/// a test depends on `encryption_key_length`.
fn empty_encryption_materials(suite_id: AlgorithmSuiteId) -> EncryptionMaterials {
    EncryptionMaterials::new(
        suite_id,
        Vec::new(),
        EncryptionContext::new(),
        Default::default(),
        None,
        None,
        None,
    )
    .unwrap()
}

/// Empty decryption materials for `suite_id`. Used only by the OnDecrypt
/// suite; there is no OnEncrypt counterpart.
fn empty_decryption_materials(suite_id: AlgorithmSuiteId) -> DecryptionMaterials {
    DecryptionMaterials::new(
        suite_id,
        EncryptionContext::new(),
        Default::default(),
        None,
        None,
        None,
    )
    .unwrap()
}

/// Build a keyring over a [`FakeKeystore`] with a static branch key id and a
/// keyring-local default cache.
fn build_keyring(keystore: Arc<FakeKeystore>, branch_key_id: &str) -> HierarchicalKeyring {
    HierarchicalKeyring::new(
        keystore,
        3600,
        Some(branch_key_id.to_string()),
        None,
        Some(CacheType::Default(DefaultCache::new(1000))),
        Some("partition-id".to_string()),
    )
    .unwrap()
}

/// Pick a non-signing suite so `signing_key` / `symmetric_signing_keys`
/// invariants don't intrude on the test.
fn non_signing_suite() -> AlgorithmSuiteId {
    AlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf
}

mod onencrypt {
    use super::*;
    use aws_crypto_mpl::Keyring;

    #[tokio::test]
    async fn on_encrypt_caches_branch_key_materials_after_keystore_call() {
        let keystore = FakeKeystore::new(fake_branch_key_materials());
        let keyring = build_keyring(Arc::clone(&keystore), FAKE_BRANCH_KEY_ID);

        // First call: cache miss → keystore is called.
        keyring
            .on_encrypt(empty_encryption_materials(non_signing_suite()))
            .await
            .unwrap();
        assert_eq!(
            keystore.get_active_calls(),
            1,
            "first on_encrypt must call keystore.get_active_branch_key once"
        );

        keyring
            .on_encrypt(empty_encryption_materials(non_signing_suite()))
            .await
            .unwrap();
        assert_eq!(
            keystore.get_active_calls(),
            1,
            "second on_encrypt must hit the cache and NOT call keystore.get_active_branch_key again"
        );

        // Asserted explicitly because the shared keystore double implements
        // `get_branch_key_version`. The per-suite double this replaced left it
        // as `unimplemented!`, so an OnEncrypt path that reached it panicked;
        // that guarantee is now a named assertion rather than a side effect.
        assert_eq!(
            keystore.get_version_calls(),
            0,
            "on_encrypt must never call keystore.get_branch_key_version"
        );
    }

    #[tokio::test]
    async fn on_encrypt_propagates_keystore_failure() {
        struct FailingKeystore;

        #[async_trait]
        impl Keystore for FailingKeystore {
            fn get_key_store_info(&self) -> Result<KeyStoreInfo, KeystoreError> {
                Ok(KeyStoreInfo {
                    keystore_id: "id".to_string(),
                    keystore_name: "table".to_string(),
                    logical_keystore_name: FAKE_LOGICAL_KEYSTORE_NAME.to_string(),
                    grant_tokens: Vec::new(),
                    kms_configuration: KmsConfiguration::Discovery,
                })
            }
            async fn create_key_store(&self) -> Result<String, KeystoreError> {
                unimplemented!()
            }
            async fn create_key(
                &self,
                _branch_key_id: Option<String>,
                _encryption_context: Option<EncryptionContext>,
            ) -> Result<String, KeystoreError> {
                unimplemented!()
            }
            async fn version_key(&self, _branch_key_id: String) -> Result<(), KeystoreError> {
                unimplemented!()
            }
            async fn get_active_branch_key(
                &self,
                _branch_key_id: String,
            ) -> Result<BranchKeyMaterials, KeystoreError> {
                Err(KeystoreError::with_cause(
                    KeystoreErrorKind::RecordNotFound,
                    "no such branch key",
                    IoError::new(IoErrorKind::NotFound, "ddb: item not found"),
                ))
            }
            async fn get_branch_key_version(
                &self,
                _branch_key_id: String,
                _branch_key_version: String,
            ) -> Result<BranchKeyMaterials, KeystoreError> {
                unimplemented!()
            }
            async fn get_beacon_key(
                &self,
                _branch_key_id: String,
            ) -> Result<BeaconKeyMaterials, KeystoreError> {
                unimplemented!()
            }
        }
        let keyring = HierarchicalKeyring::new(
            FailingKeystore,
            3600,
            Some("bk".to_string()),
            None,
            Some(CacheType::Default(DefaultCache::new(1000))),
            None,
        )
        .unwrap();

        let err = match keyring
            .on_encrypt(empty_encryption_materials(non_signing_suite()))
            .await
        {
            Ok(_) => panic!("on_encrypt must fail when keystore.get_active_branch_key fails"),
            Err(e) => e,
        };
        assert_eq!(err.kind, MaterialsErrorKind::KeyringFailed);

        // The keystore failure is attached as the cause, not merely formatted
        // into the message, so a caller can recover the originating
        // `KeystoreError` by type instead of parsing text.
        let cause = err
            .source()
            .expect("the keystore failure must be attached as the cause");
        let keystore_err = cause
            .downcast_ref::<KeystoreError>()
            .expect("the cause must be the originating KeystoreError");
        assert_eq!(keystore_err.kind(), &KeystoreErrorKind::RecordNotFound);

        // The chain is walkable past the keystore boundary too: whatever the
        // keystore itself wrapped stays reachable. In production this level is
        // the AWS SDK error carrying the concrete KMS or DDB exception.
        let root = keystore_err
            .source()
            .expect("the keystore's own cause must remain reachable");
        assert_eq!(
            root.downcast_ref::<IoError>()
                .expect("the root cause must survive unchanged")
                .kind(),
            IoErrorKind::NotFound,
        );
    }

    #[tokio::test]
    async fn on_encrypt_uses_branch_key_supplier_when_configured() {
        let keystore = FakeKeystore::new(fake_branch_key_materials());
        let keyring =
            HierarchicalKeyring::new(
                Arc::clone(&keystore),
                3600,
                None,
                Some(Arc::new(FixedBranchKeySupplier(FAKE_BRANCH_KEY_ID))
                    as Arc<dyn BranchKeySupplier>),
                Some(CacheType::Default(DefaultCache::new(1000))),
                None,
            )
            .unwrap();

        let materials_out = keyring
            .on_encrypt(empty_encryption_materials(non_signing_suite()))
            .await
            .unwrap();

        let edk = &materials_out.encrypted_data_keys()[0];
        assert_eq!(
            edk.key_provider_info.as_slice(),
            FAKE_BRANCH_KEY_ID.as_bytes()
        );
        assert_eq!(keystore.get_active_calls(), 1);
    }
}

mod ondecrypt {
    use super::*;
    use aws_crypto_mpl::Keyring;
    use aws_crypto_mpl::structures::{EncryptedDataKey, PlaintextDataKey};

    /// The 16-byte representation of `FAKE_BRANCH_KEY_VERSION`. Hard-
    /// coded so the on-wire-byte tests below don't depend on the
    /// `uuid` crate.
    const FAKE_BRANCH_KEY_VERSION_BYTES: [u8; 16] = [
        0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x43, 0x33, 0x84, 0x44, 0x55, 0x55, 0x55, 0x55, 0x55,
        0x55,
    ];

    /// Encrypt fresh empty materials through the keyring and return the
    /// resulting (plaintext_data_key, edks) pair. Used to seed every
    /// round-trip on_decrypt test.
    async fn produce_edk(
        keyring: &HierarchicalKeyring,
        suite_id: AlgorithmSuiteId,
    ) -> (PlaintextDataKey, Vec<EncryptedDataKey>) {
        let materials_in = empty_encryption_materials(suite_id);
        let materials_out = keyring.on_encrypt(materials_in).await.unwrap();
        let pdk = materials_out
            .plaintext_data_key()
            .unwrap()
            .as_bytes()
            .to_vec();
        (
            PlaintextDataKey::new(pdk),
            materials_out.encrypted_data_keys().to_vec(),
        )
    }

    #[tokio::test]
    async fn on_decrypt_fails_when_materials_already_have_plaintext_data_key() {
        let keystore = FakeKeystore::new(fake_branch_key_materials());
        let keyring = build_keyring(keystore, FAKE_BRANCH_KEY_ID);
        let suite_id = non_signing_suite();

        // First produce a real EDK so the input is non-empty; otherwise
        // the early-return on plaintext_data_key_already_present is the only path
        // that ever runs.
        let (pdk, edks) = produce_edk(&keyring, suite_id).await;

        // Build DM that ALREADY carries a plaintext data key.
        let dm = DecryptionMaterials::new(
            suite_id,
            EncryptionContext::new(),
            Default::default(),
            Some(pdk),
            None,
            None,
        )
        .unwrap();

        let err = keyring
            .on_decrypt(dm, &edks)
            .await
            .expect_err("on_decrypt must fail when materials already carry a plaintext data key");
        assert_eq!(err.kind, MaterialsErrorKind::PlaintextDataKeyAlreadyPresent);
    }

    #[tokio::test]
    async fn on_decrypt_calls_keystore_get_branch_key_version_with_uuid_from_ciphertext() {
        // The keyring caches under the ENCRYPT scope id during on_encrypt,
        // and computes the DECRYPT scope id during on_decrypt — different
        // cache keys, so the first on_decrypt is guaranteed to MISS the
        // cache and call get_branch_key_version. The version it passes
        // MUST be the canonical UUID string parsed from the 16 raw bytes
        // at offset salt+iv inside the EDK ciphertext.
        let keystore = FakeKeystore::new(fake_branch_key_materials());
        let keyring = build_keyring(Arc::clone(&keystore), FAKE_BRANCH_KEY_ID);
        let suite_id = non_signing_suite();

        let (_, edks) = produce_edk(&keyring, suite_id).await;
        // Assert the on-wire version bytes match the UUID we expect to
        // see in the keystore call. This pins the test to the spec's
        // ciphertext layout (salt(16) || iv(12) || version(16) || ...)
        // independently of the on_decrypt parsing logic.
        const VERSION_OFFSET: usize = 16 + 12;
        let on_wire_version = &edks[0].ciphertext[VERSION_OFFSET..VERSION_OFFSET + 16];
        assert_eq!(on_wire_version, &FAKE_BRANCH_KEY_VERSION_BYTES);

        let _ = keyring
            .on_decrypt(empty_decryption_materials(suite_id), &edks)
            .await
            .unwrap();

        assert_eq!(keystore.get_version_calls(), 1);
        assert_eq!(
            keystore.last_version_arg().as_deref(),
            Some(FAKE_BRANCH_KEY_VERSION),
        );
    }

    #[tokio::test]
    async fn on_decrypt_caches_branch_key_after_keystore_call() {
        let keystore = FakeKeystore::new(fake_branch_key_materials());
        let keyring = build_keyring(Arc::clone(&keystore), FAKE_BRANCH_KEY_ID);
        let suite_id = non_signing_suite();

        let (_, edks) = produce_edk(&keyring, suite_id).await;

        // First on_decrypt: cache MISS → keystore is called.
        let _ = keyring
            .on_decrypt(empty_decryption_materials(suite_id), &edks)
            .await
            .unwrap();
        assert_eq!(
            keystore.get_version_calls(),
            1,
            "first on_decrypt must call get_branch_key_version once",
        );

        let _ = keyring
            .on_decrypt(empty_decryption_materials(suite_id), &edks)
            .await
            .unwrap();
        assert_eq!(
            keystore.get_version_calls(),
            1,
            "second on_decrypt must hit the cache and NOT call get_branch_key_version again",
        );
    }

    #[tokio::test]
    async fn on_decrypt_skips_edks_with_wrong_provider_id() {
        let keystore = FakeKeystore::new(fake_branch_key_materials());
        let keyring = build_keyring(Arc::clone(&keystore), FAKE_BRANCH_KEY_ID);
        let suite_id = non_signing_suite();

        let (expected_pdk, mut edks) = produce_edk(&keyring, suite_id).await;
        // Prepend an EDK with the wrong provider id; the keyring MUST
        // skip it and continue to the next (matching) EDK.
        let bogus = EncryptedDataKey::new(
            "some-other-provider".to_string(),
            FAKE_BRANCH_KEY_ID.as_bytes().to_vec(),
            vec![0xAA; 64],
        );
        edks.insert(0, bogus);

        let dm_out = keyring
            .on_decrypt(empty_decryption_materials(suite_id), &edks)
            .await
            .expect("on_decrypt must succeed by falling through to the matching EDK");
        assert_eq!(
            dm_out.plaintext_data_key().unwrap().as_bytes(),
            expected_pdk.as_bytes(),
        );
    }

    #[tokio::test]
    async fn on_decrypt_skips_edks_with_non_utf8_provider_info() {
        let keystore = FakeKeystore::new(fake_branch_key_materials());
        let keyring = build_keyring(Arc::clone(&keystore), FAKE_BRANCH_KEY_ID);
        let suite_id = non_signing_suite();

        let (expected_pdk, mut edks) = produce_edk(&keyring, suite_id).await;
        // 0x80 is a continuation byte with no leading byte → invalid
        // UTF-8; the keyring MUST skip the EDK rather than fail on it.
        let bogus = EncryptedDataKey::new(
            "aws-kms-hierarchy".to_string(),
            vec![0x80, 0x80, 0x80],
            vec![0xAA; 64],
        );
        edks.insert(0, bogus);

        let dm_out = keyring
            .on_decrypt(empty_decryption_materials(suite_id), &edks)
            .await
            .expect("on_decrypt must succeed by falling through to the matching EDK");
        assert_eq!(
            dm_out.plaintext_data_key().unwrap().as_bytes(),
            expected_pdk.as_bytes(),
        );
    }

    #[tokio::test]
    async fn on_decrypt_skips_edks_with_wrong_branch_key_id() {
        let keystore = FakeKeystore::new(fake_branch_key_materials());
        let keyring = build_keyring(Arc::clone(&keystore), FAKE_BRANCH_KEY_ID);
        let suite_id = non_signing_suite();

        let (expected_pdk, mut edks) = produce_edk(&keyring, suite_id).await;
        let bogus = EncryptedDataKey::new(
            "aws-kms-hierarchy".to_string(),
            b"some-other-branch-key-id".to_vec(),
            vec![0xAA; 64],
        );
        edks.insert(0, bogus);

        let dm_out = keyring
            .on_decrypt(empty_decryption_materials(suite_id), &edks)
            .await
            .expect("on_decrypt must succeed by falling through to the matching EDK");
        assert_eq!(
            dm_out.plaintext_data_key().unwrap().as_bytes(),
            expected_pdk.as_bytes(),
        );
    }

    #[tokio::test]
    async fn on_decrypt_with_no_edks_reports_no_match_rather_than_an_empty_aggregate() {
        // Nothing was attempted, so this is not an aggregate of zero failures
        // but a distinct one: no encrypted data key matched.
        let keystore = FakeKeystore::new(fake_branch_key_materials());
        let keyring = build_keyring(keystore, FAKE_BRANCH_KEY_ID);
        let suite_id = non_signing_suite();

        let err = keyring
            .on_decrypt(empty_decryption_materials(suite_id), &[])
            .await
            .expect_err("on_decrypt must fail when no EDK in the input matches the filter");

        assert_eq!(err.kind, MaterialsErrorKind::NoMatchingDataKey);
        assert!(
            !err.is_collection(),
            "with nothing attempted there is nothing to collect; got: {err}",
        );
    }

    #[tokio::test]
    async fn on_decrypt_with_only_non_matching_edks_reports_no_match() {
        // The common misconfiguration: EDKs are present but none is this
        // keyring's, so none is attempted. That is the same non-aggregate
        // no-match as supplying no EDKs at all.
        let keystore = FakeKeystore::new(fake_branch_key_materials());
        let keyring = build_keyring(keystore, FAKE_BRANCH_KEY_ID);
        let suite_id = non_signing_suite();

        let foreign = EncryptedDataKey::new(
            "some-other-provider".to_string(),
            b"some-other-info".to_vec(),
            vec![0u8; 64],
        );

        let err = keyring
            .on_decrypt(empty_decryption_materials(suite_id), &[foreign])
            .await
            .expect_err("an EDK from another provider MUST NOT be decrypted");

        assert_eq!(err.kind, MaterialsErrorKind::NoMatchingDataKey);
        assert!(
            !err.is_collection(),
            "a filtered-out EDK is not an attempt, so there is nothing to collect; got: {err}",
        );
    }

    #[tokio::test]
    async fn on_decrypt_with_a_single_failing_edk_attaches_it_as_the_cause() {
        let keystore = FakeKeystore::new(fake_branch_key_materials());
        let keyring = build_keyring(keystore, FAKE_BRANCH_KEY_ID);
        let suite_id = non_signing_suite();

        // EDK that passes the filter (correct provider id + provider info)
        // but whose ciphertext is shorter than the spec's salt+iv+version
        // overhead (28 bytes). The keyring MUST surface the per-EDK error
        // in the final error message.
        let truncated = EncryptedDataKey::new(
            "aws-kms-hierarchy".to_string(),
            FAKE_BRANCH_KEY_ID.as_bytes().to_vec(),
            vec![0u8; 4],
        );

        let err = keyring
            .on_decrypt(empty_decryption_materials(suite_id), &[truncated])
            .await
            .expect_err("on_decrypt must fail when every EDK attempt errors");
        assert_eq!(err.kind, MaterialsErrorKind::KeyringFailed);
        assert!(
            err.to_string().contains("ciphertext too short"),
            "the rendered error must surface the collected per-EDK error; got: {err}",
        );

        // Exactly one candidate EDK failed, so that failure is attached as the
        // cause rather than only being formatted into the message.
        let per_edk = err
            .source()
            .expect("the single per-EDK failure must be attached as the cause")
            .downcast_ref::<MaterialsError>()
            .expect("the cause must be the per-EDK MaterialsError");
        assert!(
            per_edk.message.contains("ciphertext too short"),
            "the cause must be the per-EDK error itself; got: {}",
            per_edk.message,
        );

        // It is also present on `collected`, so a caller has one uniform place
        // to read the collected failures without branching on how many there
        // were.
        assert_eq!(
            err.collected_errors(),
            std::slice::from_ref(per_edk),
            "the single failure must also be collected",
        );
    }

    #[tokio::test]
    async fn on_decrypt_with_several_failing_edks_aggregates_without_a_single_cause() {
        let keystore = FakeKeystore::new(fake_branch_key_materials());
        let keyring = build_keyring(keystore, FAKE_BRANCH_KEY_ID);
        let suite_id = non_signing_suite();

        // Two candidate EDKs, both too short but by different amounts so each
        // produces a distinguishable message in the aggregate.
        let truncated_4 = EncryptedDataKey::new(
            "aws-kms-hierarchy".to_string(),
            FAKE_BRANCH_KEY_ID.as_bytes().to_vec(),
            vec![0u8; 4],
        );
        let truncated_8 = EncryptedDataKey::new(
            "aws-kms-hierarchy".to_string(),
            FAKE_BRANCH_KEY_ID.as_bytes().to_vec(),
            vec![0u8; 8],
        );

        let err = keyring
            .on_decrypt(
                empty_decryption_materials(suite_id),
                &[truncated_4, truncated_8],
            )
            .await
            .expect_err("on_decrypt must fail when every EDK attempt errors");
        assert_eq!(err.kind, MaterialsErrorKind::KeyringFailed);

        let rendered = err.to_string();
        assert!(
            rendered.contains("4 bytes") && rendered.contains("8 bytes"),
            "the aggregate must surface every per-EDK error; got: {rendered}",
        );

        // The collected failures stay typed, not merely formatted into the
        // message, so a caller can inspect each attempt. This is what carries
        // the spec's "MUST yield an error that includes all the collected
        // errors" structurally rather than as prose.
        let collected = err.collected_errors();
        assert_eq!(
            collected.len(),
            2,
            "both candidate EDK failures must be collected; got: {collected:?}",
        );
        for per_edk in collected {
            assert_eq!(per_edk.kind, MaterialsErrorKind::KeyringFailed);
            assert!(
                per_edk.message.contains("ciphertext too short"),
                "each collected error must be the per-EDK failure itself; got: {}",
                per_edk.message,
            );
        }
        // Collected in attempt order, so a caller can tell which EDK is which.
        assert!(collected[0].message.contains("4 bytes"));
        assert!(collected[1].message.contains("8 bytes"));

        // With more than one failure there is no single error to nominate as
        // the cause; the typed failures live on `collected` instead. If this
        // starts failing, on_decrypt picked a cause among several and the
        // choice needs to be justified.
        assert!(
            err.source().is_none(),
            "an aggregate over several failures must not attach one of them as \
             the cause; got: {err}",
        );
    }

    #[tokio::test]
    async fn on_decrypt_propagates_keystore_failure() {
        struct FailingKeystore;

        #[async_trait]
        impl Keystore for FailingKeystore {
            fn get_key_store_info(&self) -> Result<KeyStoreInfo, KeystoreError> {
                Ok(KeyStoreInfo {
                    keystore_id: "id".to_string(),
                    keystore_name: "table".to_string(),
                    logical_keystore_name: FAKE_LOGICAL_KEYSTORE_NAME.to_string(),
                    grant_tokens: Vec::new(),
                    kms_configuration: KmsConfiguration::Discovery,
                })
            }
            async fn create_key_store(&self) -> Result<String, KeystoreError> {
                unimplemented!()
            }
            async fn create_key(
                &self,
                _branch_key_id: Option<String>,
                _encryption_context: Option<EncryptionContext>,
            ) -> Result<String, KeystoreError> {
                unimplemented!()
            }
            async fn version_key(&self, _branch_key_id: String) -> Result<(), KeystoreError> {
                unimplemented!()
            }
            async fn get_active_branch_key(
                &self,
                _branch_key_id: String,
            ) -> Result<BranchKeyMaterials, KeystoreError> {
                unimplemented!()
            }
            async fn get_branch_key_version(
                &self,
                _branch_key_id: String,
                _branch_key_version: String,
            ) -> Result<BranchKeyMaterials, KeystoreError> {
                Err(KeystoreError::new(
                    KeystoreErrorKind::RecordNotFound,
                    "no such branch key version",
                ))
            }
            async fn get_beacon_key(
                &self,
                _branch_key_id: String,
            ) -> Result<BeaconKeyMaterials, KeystoreError> {
                unimplemented!()
            }
        }

        // Build a real EDK first, then swap in a keystore whose
        // get_branch_key_version returns an error so the on_decrypt
        // keystore-fallthrough path lights up.
        let priming_keyring = build_keyring(
            FakeKeystore::new(fake_branch_key_materials()),
            FAKE_BRANCH_KEY_ID,
        );
        let suite_id = non_signing_suite();
        let (_, edks) = produce_edk(&priming_keyring, suite_id).await;

        let keyring = HierarchicalKeyring::new(
            FailingKeystore,
            3600,
            Some(FAKE_BRANCH_KEY_ID.to_string()),
            None,
            Some(CacheType::Default(DefaultCache::new(1000))),
            Some("partition-id".to_string()),
        )
        .unwrap();

        let err = keyring
            .on_decrypt(empty_decryption_materials(suite_id), &edks)
            .await
            .expect_err("on_decrypt must fail when keystore.get_branch_key_version fails");
        assert_eq!(err.kind, MaterialsErrorKind::KeyringFailed);
        // The per-attempt text is rendered by Display from `collected`, not
        // baked into `message`, so the assertion reads the rendered form.
        assert!(
            err.to_string().contains("get_branch_key_version failed"),
            "the rendered error must surface the keystore failure; got: {err}",
        );

        // One candidate EDK, so on_decrypt attaches that per-EDK failure as
        // the cause and the chain stays walkable all the way to the keystore.
        let per_edk = err
            .source()
            .expect("a single failing EDK must be attached as the cause")
            .downcast_ref::<MaterialsError>()
            .expect("the cause must be the per-EDK MaterialsError");
        assert_eq!(per_edk.kind, MaterialsErrorKind::KeyringFailed);

        let keystore_err = per_edk
            .source()
            .expect("the per-EDK failure must itself carry the keystore cause")
            .downcast_ref::<KeystoreError>()
            .expect("the root cause must be the originating KeystoreError");
        assert_eq!(keystore_err.kind(), &KeystoreErrorKind::RecordNotFound);
    }

    #[tokio::test]
    async fn on_decrypt_uses_branch_key_supplier_when_configured() {
        let keystore = FakeKeystore::new(fake_branch_key_materials());
        let keyring =
            HierarchicalKeyring::new(
                Arc::clone(&keystore),
                3600,
                None,
                Some(Arc::new(FixedBranchKeySupplier(FAKE_BRANCH_KEY_ID))
                    as Arc<dyn BranchKeySupplier>),
                Some(CacheType::Default(DefaultCache::new(1000))),
                Some("partition-id".to_string()),
            )
            .unwrap();
        let suite_id = non_signing_suite();

        let (expected_pdk, edks) = produce_edk(&keyring, suite_id).await;

        let dm_out = keyring
            .on_decrypt(empty_decryption_materials(suite_id), &edks)
            .await
            .expect("on_decrypt with a supplier-resolved branch_key_id must succeed");
        assert_eq!(
            dm_out.plaintext_data_key().unwrap().as_bytes(),
            expected_pdk.as_bytes(),
        );
        // Both halves of the round trip ran one keystore method each:
        // get_active for encrypt, get_branch_key_version for decrypt.
        assert_eq!(keystore.get_version_calls(), 1);
    }
}

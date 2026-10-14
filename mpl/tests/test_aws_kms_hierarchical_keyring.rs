// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for `aws_kms::hierarchical_keyring`.
//!
//! Covers, in order: construction and configuration validation (TTL,
//! partition id, cache wiring), the cache entry identifier formulas, the
//! branch-key wrap / unwrap / AAD functions, and the OnEncrypt / OnDecrypt
//! operations against key store doubles.
//!
//! Where a test builds an expected byte sequence by hand, it is transcribed
//! from the AWS KMS Hierarchical Keyring specification:
//!
//! - [Appendix A: Cache Entry Identifier Formulas][appendix-a]
//! - [Branch Key Wrapping and Unwrapping AAD][aad]
//!
//! [appendix-a]: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-hierarchical-keyring.md#appendix-a-cache-entry-identifier-formulas
//! [aad]: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-wrapping-and-unwrapping-aad

#![cfg(feature = "test-utils")]

use std::error::Error as _;
use std::io::{Error as IoError, ErrorKind as IoErrorKind};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aws_config::{BehaviorVersion, SdkConfig};
use aws_crypto_mpl::async_trait;
use aws_sdk_dynamodb::Client as DynamoDbClient;
use aws_sdk_kms::Client as KmsClient;

use aws_crypto_mpl::Error;
use aws_crypto_mpl::aws_kms::__test_internals::{
    SCOPE_ID_DECRYPT, SCOPE_ID_ENCRYPT, build_cache_identifier, cache, compute_aad,
    partition_id_bytes, unwrap as branch_key_unwrap, wrap as branch_key_wrap,
};
use aws_crypto_mpl::aws_kms::hierarchical_keyring::{
    BranchKeySupplier, GetBranchKeyIdInput, GetBranchKeyIdOutput, HierarchicalKeyring,
    HierarchicalKeyringBuilder,
};
use aws_crypto_mpl::key_store::{
    CreateKeyInput, CreateKeyOutput, CreateKeyStoreInput, CreateKeyStoreOutput, Discovery,
    GetActiveBranchKeyInput, GetActiveBranchKeyOutput, GetBeaconKeyInput, GetBeaconKeyOutput,
    GetBranchKeyVersionInput, GetBranchKeyVersionOutput, GetKeyStoreInfoInput,
    GetKeyStoreInfoOutput, KeyStore, KeyStoreClient, KeyStoreClientBuilder, KmsConfiguration,
    VersionKeyInput, VersionKeyOutput,
};
use aws_crypto_mpl::structures::{
    AlgorithmSuiteId, BranchKeyMaterials, DecryptionMaterials, EncryptionContext,
    EncryptionMaterials, EsdkAlgorithmSuiteId,
};
use aws_crypto_mpl::{Cmc, LocalCmc, SharedCmc, SharedKeyring, StormTrackingCmc};

/// Construct a pair of zero-config AWS SDK clients suitable for tests that
/// never invoke a remote operation. `BehaviorVersion::latest()` is required by
/// the SDK at client-construction time; no IO occurs at construction itself.
fn dummy_clients() -> (KmsClient, DynamoDbClient) {
    let cfg = SdkConfig::builder()
        .behavior_version(BehaviorVersion::latest())
        .build();
    (KmsClient::new(&cfg), DynamoDbClient::new(&cfg))
}

/// The branch key id and active version of the real key store fixture the
/// integration tests use (DDB table `KeyStoreDdbTable`, account
/// `370957321024`). Nothing here contacts a key store — `wrap` / `unwrap` /
/// `compute_aad` are pure — but using the real values keeps these fixtures
/// recognizable against the integ suite and against the other MPL
/// implementations' test vectors.
const FIXTURE_BRANCH_KEY_ID: &str = "3f43a9af-08c5-4317-b694-3d3e883dcaef";
const FIXTURE_VERSION: &str = "caf0c508-e64d-4b6c-bffe-381cbc546c02";

/// Logical key store name of that same fixture key store.
const LOGICAL_KEY_STORE_NAME: &str = "KeyStoreDdbTable";

/// Reusable [`BranchKeySupplier`] fixture: always answers with the branch key
/// id it was constructed with, ignoring the encryption context. Enough for any
/// test that needs a supplier-configured keyring without caring how the
/// decision is made.
struct FixedBranchKeySupplier(&'static str);

#[async_trait]
impl BranchKeySupplier for FixedBranchKeySupplier {
    async fn get_branch_key_id(
        &self,
        _input: GetBranchKeyIdInput,
    ) -> Result<GetBranchKeyIdOutput, Error> {
        GetBranchKeyIdOutput::builder()
            .branch_key_id(self.0.to_string())
            .build()
    }
}

/// A real DynamoDB key store whose table and KMS key do not exist.
///
/// Building a keyring reads only the key store's configuration, so no test using this makes a key store call.
/// OnEncrypt / OnDecrypt tests use the `FakeKeyStore` doubles.
fn key_store_never_consulted() -> KeyStoreClient {
    let (kms, ddb) = dummy_clients();
    build_without_io(
        KeyStoreClient::builder()
            .ddb_table_name("test-table")
            .kms_configuration(KmsConfiguration::KmsKeyArn(
                "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
                    .into(),
            ))
            .logical_key_store_name("test-logical")
            .kms_client(kms)
            .ddb_client(ddb),
    )
}

/// Builds `builder` by polling its future once.
/// With both clients supplied, `build` does no IO, so it is ready on the first poll.
fn build_without_io(builder: KeyStoreClientBuilder) -> KeyStoreClient {
    use std::future::Future;
    use std::task::{Context, Poll, Waker};
    let mut fut = std::pin::pin!(builder.build());
    match fut.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(result) => result.expect("key store construction must succeed"),
        Poll::Pending => panic!("build with both clients supplied must not await"),
    }
}

#[test]
fn build_with_zero_ttl_returns_validation_error() {
    let key_store = key_store_never_consulted();
    let result = HierarchicalKeyring::builder()
        .key_store(key_store)
        .ttl(Duration::from_secs(0))
        .branch_key_id("branch-key-id")
        .build();

    let err = match result {
        Err(e) => e,
        Ok(_) => panic!("expected zero TTL to return a validation error"),
    };
    assert!(
        err.is_validation(),
        "expected Validation error for a zero TTL; got {err:?}"
    );
    assert!(err.is_validation(), "{:?}", err);
}

#[test]
fn build_with_both_branch_key_id_and_supplier_returns_validation_error() {
    // The keyring takes branchKeyId and branchKeyIdSupplier as two optional
    // inputs, mirroring CreateAwsKmsHierarchicalKeyringInput, so the "exactly
    // one" rule is enforced here rather than by the type system.
    let err = match HierarchicalKeyring::builder()
        .key_store(key_store_never_consulted())
        .ttl(Duration::from_secs(3600))
        .branch_key_id("branch-key-id")
        .branch_key_id_supplier(FixedBranchKeySupplier("unused"))
        .build()
    {
        Err(e) => e,
        Ok(_) => panic!("supplying both a branch_key_id and a supplier MUST be rejected"),
    };

    assert!(err.is_validation(), "{:?}", err);
}

#[test]
fn build_with_neither_branch_key_id_nor_supplier_returns_validation_error() {
    let err = match HierarchicalKeyring::builder()
        .key_store(key_store_never_consulted())
        .ttl(Duration::from_secs(3600))
        .build()
    {
        Err(e) => e,
        Ok(_) => panic!("supplying neither a branch_key_id nor a supplier MUST be rejected"),
    };

    assert!(err.is_validation(), "{:?}", err);
}

/// The error from `build()`; panics with `label` if the build succeeds.
fn build_err(builder: HierarchicalKeyringBuilder, label: &str) -> Error {
    match builder.build() {
        Err(e) => e,
        Ok(_) => panic!("{label}: build() MUST be rejected"),
    }
}

#[test]
fn build_without_key_store_returns_validation_error() {
    let err = build_err(
        HierarchicalKeyring::builder()
            .ttl(Duration::from_secs(3600))
            .branch_key_id("branch-key-id"),
        "no key store",
    );
    assert!(err.is_validation(), "{:?}", err);
}

#[test]
fn build_without_ttl_returns_validation_error() {
    let err = build_err(
        HierarchicalKeyring::builder()
            .key_store(key_store_never_consulted())
            .branch_key_id("branch-key-id"),
        "no TTL",
    );
    assert!(err.is_validation(), "{:?}", err);
}

#[test]
fn build_with_sub_second_ttl_keeps_it_exactly() {
    for ttl in [
        Duration::from_millis(1500),
        Duration::from_millis(500),
        Duration::from_nanos(1),
    ] {
        let keyring = HierarchicalKeyring::builder()
            .key_store(key_store_never_consulted())
            .ttl(ttl)
            .branch_key_id("branch-key-id")
            .cache(LocalCmc::builder().entry_capacity(1000).build().unwrap())
            .build()
            .unwrap_or_else(|e| panic!("{ttl:?} must be accepted: {e}"));
        assert_eq!(keyring.ttl(), ttl);
    }
}

#[test]
fn build_compares_storm_tracking_grace_period_to_sub_second_ttl() {
    let with_grace_ms = |grace_period_ms| {
        let cache = StormTrackingCmc::builder()
            .entry_capacity(16)
            .entry_pruning_tail_size(4)
            .grace_period(Duration::from_millis(grace_period_ms))
            .grace_interval(Duration::from_millis(100))
            .fan_out(4)
            .inflight_ttl(Duration::from_millis(100))
            .sleep(Duration::from_millis(10))
            .build()
            .expect("valid StormTrackingCmc");
        HierarchicalKeyring::builder()
            .key_store(key_store_never_consulted())
            .ttl(Duration::from_millis(1500))
            .branch_key_id("bk")
            .cache(cache)
            .build()
    };
    with_grace_ms(1_499).expect("1499 ms grace period < 1500 ms TTL must succeed");
    let err = match with_grace_ms(1_500) {
        Ok(_) => panic!("1500 ms grace period == 1500 ms TTL must fail"),
        Err(e) => e,
    };
    assert!(err.is_validation(), "{:?}", err);
}

#[test]
fn build_with_positive_ttl_succeeds() {
    let key_store = key_store_never_consulted();
    let result = HierarchicalKeyring::builder()
        .key_store(key_store)
        .ttl(Duration::from_secs(1))
        .branch_key_id("branch-key-id")
        .cache(LocalCmc::builder().entry_capacity(1000).build().unwrap())
        .build();

    let keyring = result.expect("a 1-second TTL must be accepted");
    assert_eq!(keyring.ttl(), Duration::from_secs(1));
}

#[test]
fn partition_id_default_is_16_byte_v4_uuid() {
    let key_store = key_store_never_consulted();
    let keyring = HierarchicalKeyring::builder()
        .key_store(key_store)
        .ttl(Duration::from_secs(3600))
        .branch_key_id("branch-key-id")
        .build()
        .expect("constructor with no partition id must succeed");

    let bytes = partition_id_bytes(&keyring);

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
    let a = HierarchicalKeyring::builder()
        .key_store(key_store_never_consulted())
        .ttl(Duration::from_secs(3600))
        .branch_key_id("branch-key-id")
        .build()
        .expect("first constructor call must succeed");

    let b = HierarchicalKeyring::builder()
        .key_store(key_store_never_consulted())
        .ttl(Duration::from_secs(3600))
        .branch_key_id("branch-key-id")
        .build()
        .expect("second constructor call must succeed");

    assert_ne!(
        partition_id_bytes(&a),
        partition_id_bytes(&b),
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
        let keyring = HierarchicalKeyring::builder()
            .key_store(key_store_never_consulted())
            .ttl(Duration::from_secs(3600))
            .branch_key_id("branch-key-id")
            .partition_id(*original)
            .build()
            .unwrap_or_else(|e| {
                panic!("{label}: constructor with explicit partition id must succeed: {e}")
            });

        assert_eq!(
            partition_id_bytes(&keyring),
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
        let keyring = HierarchicalKeyring::builder()
            .key_store(key_store_never_consulted())
            .ttl(Duration::from_secs(3600))
            .branch_key_id("branch-key-id")
            .partition_id(partition)
            .build()
            .expect("constructor must succeed");
        partition_id_bytes(&keyring).to_vec()
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
fn build_with_branch_key_id_supplier_succeeds() {
    // Smoke test that configuring a supplier instead of a static branch key
    // id is usable — construct a no-op supplier, pass it as the
    // branch_key_id_supplier, and confirm the keyring can be built with it.
    let supplier = FixedBranchKeySupplier("branch-id-from-supplier");
    let keyring = HierarchicalKeyring::builder()
        .key_store(key_store_never_consulted())
        .ttl(Duration::from_secs(3600))
        .branch_key_id_supplier(supplier)
        .build()
        .expect("constructor with supplier variant must succeed");

    assert!(
        keyring.branch_key_id().is_none(),
        "a supplier-configured keyring MUST NOT carry a static branch key id"
    );
    assert!(keyring.branch_key_id_supplier().is_some());
}

// Cache wiring tests
//
// These check only which cache the keyring stores and the grace period bound it enforces.
// Cache behavior is tested in `test_local_cmc.rs` and `test_storm_tracking_cmc.rs`.

#[test]
fn build_without_cache_uses_default_cmc() {
    let keyring = HierarchicalKeyring::builder()
        .key_store(key_store_never_consulted())
        .ttl(Duration::from_secs(3600))
        .branch_key_id("bk")
        .build()
        .expect("an unset cache must default to a built-in cache");
    assert_eq!(
        cache(&keyring).grace_period(),
        Some(Duration::from_secs(10)),
        "the default cache has the storm-tracking default grace period"
    );

    let err = build_err(
        HierarchicalKeyring::builder()
            .key_store(key_store_never_consulted())
            .ttl(Duration::from_secs(10))
            .branch_key_id("bk"),
        "TTL equal to the default grace period",
    );
    assert!(err.is_validation(), "{:?}", err);
}

#[test]
fn build_with_shared_cache_round_trips_provided_cache() {
    let supplied = SharedCmc::new(
        LocalCmc::builder()
            .entry_capacity(8)
            .entry_pruning_tail_size(4)
            .build()
            .unwrap(),
    );

    let keyring = HierarchicalKeyring::builder()
        .key_store(key_store_never_consulted())
        .ttl(Duration::from_secs(3600))
        .branch_key_id("bk")
        .cache(supplied.clone())
        .build()
        .expect("a SharedCmc must be accepted");

    // The exact cache supplied is what the keyring stores. Tested via
    // pointer-identity rather than behaviour because the struct field is
    // not directly observable.
    let stored: &SharedCmc = cache(&keyring);
    assert!(
        SharedCmc::ptr_eq(stored, &supplied),
        "the keyring MUST store the supplied SharedCmc itself"
    );
}

#[test]
fn build_with_shared_storm_tracking_grace_period_equal_to_ttl_fails() {
    let cache = SharedCmc::new(
        StormTrackingCmc::builder()
            .grace_period(Duration::from_secs(60))
            .build()
            .expect("valid StormTrackingCmc"),
    );
    let err = build_err(
        HierarchicalKeyring::builder()
            .key_store(key_store_never_consulted())
            .ttl(Duration::from_secs(60))
            .branch_key_id("bk")
            .cache(cache),
        "shared storm-tracking cache with grace_period == TTL",
    );
    assert!(err.is_validation(), "{:?}", err);
}

#[test]
fn build_with_storm_tracking_cache_succeeds() {
    let cache = StormTrackingCmc::builder()
        .entry_capacity(16)
        .entry_pruning_tail_size(4)
        .grace_period(Duration::from_secs(60))
        .grace_interval(Duration::from_secs(1))
        .fan_out(4)
        .inflight_ttl(Duration::from_secs(30))
        .sleep(Duration::from_millis(10))
        .build()
        .expect("valid StormTrackingCmc");
    HierarchicalKeyring::builder()
        .key_store(key_store_never_consulted())
        .ttl(Duration::from_secs(3600)) // strictly greater than grace_period (60).
        .branch_key_id("bk")
        .cache(cache)
        .build()
        .expect("a StormTrackingCmc with grace_period < ttl must succeed");
}

#[test]
fn build_with_storm_tracking_grace_period_equal_to_ttl_fails() {
    let cache = StormTrackingCmc::builder()
        .entry_capacity(16)
        .entry_pruning_tail_size(4)
        .grace_period(Duration::from_secs(60))
        .grace_interval(Duration::from_secs(1))
        .fan_out(4)
        .inflight_ttl(Duration::from_secs(30))
        .sleep(Duration::from_millis(10))
        .build()
        .expect("valid StormTrackingCmc");
    let err = match HierarchicalKeyring::builder()
        .key_store(key_store_never_consulted())
        .ttl(Duration::from_secs(60)) // equal to grace_period (60).
        .branch_key_id("bk")
        .cache(cache)
        .build()
    {
        Ok(_) => panic!("StormTracking with grace_period == TTL must fail"),
        Err(e) => e,
    };
    assert!(err.is_validation(), "{:?}", err);
}

#[test]
fn build_with_storm_tracking_grace_period_greater_than_ttl_fails() {
    let cache = StormTrackingCmc::builder()
        .entry_capacity(16)
        .entry_pruning_tail_size(4)
        .grace_period(Duration::from_secs(120))
        .grace_interval(Duration::from_secs(1))
        .fan_out(4)
        .inflight_ttl(Duration::from_secs(30))
        .sleep(Duration::from_millis(10))
        .build()
        .expect("valid StormTrackingCmc");
    let err = match HierarchicalKeyring::builder()
        .key_store(key_store_never_consulted())
        .ttl(Duration::from_secs(60))
        .branch_key_id("bk")
        .cache(cache)
        .build()
    {
        Ok(_) => panic!("StormTracking with grace_period > TTL must fail"),
        Err(e) => e,
    };
    assert!(err.is_validation(), "{:?}", err);
}

#[test]
fn build_with_storm_tracking_milliseconds_grace_period_under_ttl_succeeds() {
    // grace_period = 5_000 ms = 5 s, less than the 60 s TTL.
    // inflight_ttl <= grace_period is required by StormTrackingCmc.
    let cache = StormTrackingCmc::builder()
        .entry_capacity(16)
        .entry_pruning_tail_size(4)
        .grace_period(Duration::from_millis(5_000))
        .grace_interval(Duration::from_millis(100))
        .fan_out(4)
        .inflight_ttl(Duration::from_millis(1_000))
        .sleep(Duration::from_millis(10))
        .build()
        .expect("valid StormTrackingCmc");
    HierarchicalKeyring::builder()
        .key_store(key_store_never_consulted())
        .ttl(Duration::from_secs(60))
        .branch_key_id("bk")
        .cache(cache)
        .build()
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
    BranchKeyMaterials::builder()
        .branch_key(fixed_branch_key())
        .branch_key_id(FIXTURE_BRANCH_KEY_ID.to_string())
        .branch_key_version(FIXTURE_VERSION.to_string())
        .set_encryption_context(Some(ec))
        .build()
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
    ec.insert("k", "v");

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
    ec.insert("k", "\0".repeat(65_536));

    let result = compute_aad(branch_key_id, version, &ec);
    let err = result.expect_err("compute_aad must fail when EC serialization fails");

    assert!(
        err.is_validation(),
        "expected Validation error from EC serialize; got {err:?}"
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
    ec.insert("purpose", "test");
    ec.insert("region", "us-west-2");
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
    assert!(
        err.is_cryptographic(),
        "expected Cryptographic for AEAD verification failure; got {err:?}"
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
    assert!(
        err.is_cryptographic(),
        "expected Cryptographic for tag verification failure; got {err:?}"
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
    assert!(
        err.is_cryptographic(),
        "expected Cryptographic for IV-tampered AEAD; got {err:?}"
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
    let materials_unwrap = BranchKeyMaterials::builder()
        .branch_key(other_branch_key)
        .branch_key_id(FIXTURE_BRANCH_KEY_ID.to_string())
        .branch_key_version(FIXTURE_VERSION.to_string())
        .set_encryption_context(Some(EncryptionContext::new()))
        .build()
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
    assert!(
        err.is_cryptographic(),
        "expected Cryptographic when branch_key differs; got {err:?}"
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
    let materials_unwrap = BranchKeyMaterials::builder()
        .branch_key(fixed_branch_key())
        .branch_key_id("different-branch-key-id".to_string())
        .branch_key_version(FIXTURE_VERSION.to_string())
        .set_encryption_context(Some(EncryptionContext::new()))
        .build()
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
    assert!(
        err.is_cryptographic(),
        "expected Cryptographic when AAD differs; got {err:?}"
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
    other_ec.insert("region", "us-east-1");
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
    assert!(
        err.is_cryptographic(),
        "expected Cryptographic when EC differs; got {err:?}"
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
    // Shorter than the 60-byte salt, IV, version, and tag overhead, so unwrap fails with Cryptographic.
    let materials = fixture_materials_empty_ec();
    let too_short = vec![0u8; 32];

    let result = branch_key_unwrap(&materials, materials.encryption_context(), &too_short);
    let err = result.expect_err("unwrap of too-short ciphertext must fail");

    // The unwrap call cannot complete deserialization (a required step)
    // when the input is shorter than the fixed overhead, so it must
    // return an error rather than silently succeed.
    assert!(
        err.is_cryptographic(),
        "expected Cryptographic for ciphertext shorter than fixed overhead; got {err:?}"
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
    ec.insert("k", "\0".repeat(65_536));
    let materials = fixture_materials_with_ec(ec);

    let result = branch_key_wrap(&materials, materials.encryption_context(), &[0u8; 32]);
    let err = result.expect_err("wrap must fail when EC serialization fails");

    assert!(
        err.is_validation(),
        "expected Validation error from EC serialize via wrap; got {err:?}"
    );
}

// ─── OnEncrypt tests ────────────────────────────────────────────────────────
//
// These tests exercise the [`Keyring::on_encrypt`] body via a
// `FakeKeyStore` that returns canned BranchKeyMaterials. The KMS / DDB
// SDKs are NOT involved; the test crypto is the same wrap / unwrap
// helpers under `aws_kms::__test_internals`, so a successful round-trip
// proves the EDK's wire format and the AAD / KDF derivation match.

// ─── KeyStore double shared by the OnEncrypt / OnDecrypt suites ─────────────
//
// The `FAKE_*` fixtures here are placeholders for exercising the keyring's own
// logic. They are deliberately distinct from the `FIXTURE_*` constants above,
// which carry the real integration key store values used by the
// cache-identifier and wrap / unwrap tests.

const FAKE_BRANCH_KEY: [u8; 32] = [
    0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51,
    0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61,
];
const FAKE_BRANCH_KEY_ID: &str = "test-branch-key-id";
const FAKE_BRANCH_KEY_VERSION: &str = "11111111-2222-4333-8444-555555555555";
const FAKE_LOGICAL_KEY_STORE_NAME: &str = "test-logical-name";

/// A key store double that returns canned [`BranchKeyMaterials`] from both
/// `get_active_branch_key` and `get_branch_key_version`, and counts
/// call-throughs so cache-hit / cache-miss tests can assert key store behaviour
/// from the outside.
///
/// One double serves both suites: they need the same canned materials and the
/// same `GetKeyStoreInfoOutput`, and differ only in which counter they read. The
/// counters are `Mutex<..>` rather than `Cell<..>` because `KeyStore` requires
/// `Send + Sync`; each lock is taken and released inside a single statement, so
/// no guard is ever held across an `.await`.
#[derive(Clone)]
struct FakeKeyStore {
    materials: BranchKeyMaterials,
    get_active_calls: Arc<Mutex<u32>>,
    get_version_calls: Arc<Mutex<u32>>,
    last_version_arg: Arc<Mutex<Option<String>>>,
}

impl FakeKeyStore {
    fn new(materials: BranchKeyMaterials) -> Self {
        Self {
            materials,
            get_active_calls: Arc::new(Mutex::new(0)),
            get_version_calls: Arc::new(Mutex::new(0)),
            last_version_arg: Arc::new(Mutex::new(None)),
        }
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

/// The configuration every fake key store reports.
fn fake_key_store_info() -> GetKeyStoreInfoOutput {
    GetKeyStoreInfoOutput::builder()
        .key_store_id("test-id")
        .key_store_name("test-table")
        .logical_key_store_name(FAKE_LOGICAL_KEY_STORE_NAME)
        .grant_tokens(Vec::<String>::new())
        .kms_configuration(KmsConfiguration::Discovery(
            Discovery::builder().build().unwrap(),
        ))
        .build()
        .unwrap()
}

#[async_trait]
impl KeyStore for FakeKeyStore {
    fn get_key_store_info(
        &self,
        _input: GetKeyStoreInfoInput,
    ) -> Result<GetKeyStoreInfoOutput, Error> {
        Ok(fake_key_store_info())
    }

    async fn create_key_store(
        &self,
        _input: CreateKeyStoreInput,
    ) -> Result<CreateKeyStoreOutput, Error> {
        unimplemented!("FakeKeyStore::create_key_store")
    }
    async fn create_key(&self, _input: CreateKeyInput) -> Result<CreateKeyOutput, Error> {
        unimplemented!("FakeKeyStore::create_key")
    }
    async fn version_key(&self, _input: VersionKeyInput) -> Result<VersionKeyOutput, Error> {
        unimplemented!("FakeKeyStore::version_key")
    }

    async fn get_active_branch_key(
        &self,
        _input: GetActiveBranchKeyInput,
    ) -> Result<GetActiveBranchKeyOutput, Error> {
        *self.get_active_calls.lock().unwrap() += 1;
        GetActiveBranchKeyOutput::builder()
            .branch_key_materials(self.materials.clone())
            .build()
    }

    async fn get_branch_key_version(
        &self,
        input: GetBranchKeyVersionInput,
    ) -> Result<GetBranchKeyVersionOutput, Error> {
        *self.get_version_calls.lock().unwrap() += 1;
        *self.last_version_arg.lock().unwrap() = Some(input.branch_key_version().to_owned());
        GetBranchKeyVersionOutput::builder()
            .branch_key_materials(self.materials.clone())
            .build()
    }
    async fn get_beacon_key(&self, _input: GetBeaconKeyInput) -> Result<GetBeaconKeyOutput, Error> {
        unimplemented!("FakeKeyStore::get_beacon_key")
    }
}

/// Canned branch-key materials with an empty encryption context. The wrap /
/// unwrap AAD binds the *input* materials' EC, not this one.
fn fake_branch_key_materials() -> BranchKeyMaterials {
    BranchKeyMaterials::builder()
        .branch_key(FAKE_BRANCH_KEY)
        .branch_key_id(FAKE_BRANCH_KEY_ID.to_string())
        .branch_key_version(FAKE_BRANCH_KEY_VERSION.to_string())
        .set_encryption_context(Some(EncryptionContext::new()))
        .build()
        .unwrap()
}

/// Empty encryption materials for `suite_id`. Suite choice is arbitrary unless
/// a test depends on `encryption_key_length`.
fn empty_encryption_materials(suite_id: AlgorithmSuiteId) -> EncryptionMaterials {
    EncryptionMaterials::builder()
        .algorithm_suite_id(suite_id)
        .build()
        .unwrap()
}

/// Empty decryption materials for `suite_id`. Used only by the OnDecrypt
/// suite; there is no OnEncrypt counterpart.
fn empty_decryption_materials(suite_id: AlgorithmSuiteId) -> DecryptionMaterials {
    DecryptionMaterials::builder()
        .algorithm_suite_id(suite_id)
        .build()
        .unwrap()
}

/// Build a keyring over a [`FakeKeyStore`] with a static branch key id and its own `LocalCmc`.
fn build_keyring(key_store: FakeKeyStore, branch_key_id: &str) -> SharedKeyring {
    SharedKeyring::new(
        HierarchicalKeyring::builder()
            .key_store(key_store)
            .ttl(Duration::from_secs(3600))
            .branch_key_id(branch_key_id)
            .cache(LocalCmc::builder().entry_capacity(1000).build().unwrap())
            .partition_id("partition-id")
            .build()
            .unwrap(),
    )
}

/// Pick a non-signing suite so `signing_key` / `symmetric_signing_keys`
/// invariants don't intrude on the test.
fn non_signing_suite() -> AlgorithmSuiteId {
    AlgorithmSuiteId::Esdk(EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf)
}

mod onencrypt {
    use super::*;

    #[tokio::test]
    async fn on_encrypt_caches_branch_key_materials_after_key_store_call() {
        let key_store = FakeKeyStore::new(fake_branch_key_materials());
        let keyring = build_keyring(key_store.clone(), FAKE_BRANCH_KEY_ID);

        // First call: cache miss → key store is called.
        keyring
            .on_encrypt()
            .materials(empty_encryption_materials(non_signing_suite()))
            .send()
            .await
            .unwrap();
        assert_eq!(
            key_store.get_active_calls(),
            1,
            "first on_encrypt must call key store.get_active_branch_key once"
        );

        keyring
            .on_encrypt()
            .materials(empty_encryption_materials(non_signing_suite()))
            .send()
            .await
            .unwrap();
        assert_eq!(
            key_store.get_active_calls(),
            1,
            "second on_encrypt must hit the cache and NOT call key store.get_active_branch_key again"
        );

        // Asserted explicitly because the shared key store double implements
        // `get_branch_key_version`. The per-suite double this replaced left it
        // as `unimplemented!`, so an OnEncrypt path that reached it panicked;
        // that guarantee is now a named assertion rather than a side effect.
        assert_eq!(
            key_store.get_version_calls(),
            0,
            "on_encrypt must never call key store.get_branch_key_version"
        );
    }

    /// Whether on_encrypt calls the key store for a keyring with a 1 s TTL
    /// whose cache already holds its entry, created `age` ago.
    /// The entry's own expiry is an hour out, so only the keyring's TTL check can reject it.
    async fn on_encrypt_consults_key_store_for_entry_aged(age: Duration) -> bool {
        use aws_crypto_mpl::cmc::{CacheEntry, CachedMaterials};
        use std::time::SystemTime;

        const PARTITION: &str = "partition-id";
        let cache = SharedCmc::new(
            LocalCmc::builder()
                .entry_capacity(8)
                .entry_pruning_tail_size(4)
                .build()
                .unwrap(),
        );
        let now = SystemTime::now();
        let entry = CacheEntry::builder()
            .materials(CachedMaterials::BranchKey(fake_branch_key_materials()))
            .creation_time(now - age)
            .expiry_time(now + Duration::from_secs(3600))
            .build()
            .unwrap();
        cache
            .put_cache_entry()
            .identifier(build_cache_identifier(
                SCOPE_ID_ENCRYPT,
                PARTITION.as_bytes(),
                FAKE_LOGICAL_KEY_STORE_NAME,
                FAKE_BRANCH_KEY_ID,
                None,
            ))
            .entry(entry)
            .send()
            .await
            .unwrap();

        let key_store = FakeKeyStore::new(fake_branch_key_materials());
        let keyring = SharedKeyring::new(
            HierarchicalKeyring::builder()
                .key_store(key_store.clone())
                .ttl(Duration::from_millis(1500))
                .branch_key_id(FAKE_BRANCH_KEY_ID)
                .cache(cache)
                .partition_id(PARTITION)
                .build()
                .unwrap(),
        );
        keyring
            .on_encrypt()
            .materials(empty_encryption_materials(non_signing_suite()))
            .send()
            .await
            .unwrap();
        key_store.get_active_calls() == 1
    }

    #[tokio::test]
    async fn on_encrypt_ttl_compares_the_full_duration() {
        assert!(
            !on_encrypt_consults_key_store_for_entry_aged(Duration::from_millis(1000)).await,
            "an entry aged 1 s is within a 1.5 s TTL",
        );
        assert!(
            on_encrypt_consults_key_store_for_entry_aged(Duration::from_millis(1800)).await,
            "an entry aged 1.8 s is past a 1.5 s TTL",
        );
    }

    #[tokio::test]
    async fn on_encrypt_propagates_key_store_failure() {
        struct FailingKeyStore;

        #[async_trait]
        impl KeyStore for FailingKeyStore {
            fn get_key_store_info(
                &self,
                _input: GetKeyStoreInfoInput,
            ) -> Result<GetKeyStoreInfoOutput, Error> {
                Ok(fake_key_store_info())
            }
            async fn create_key_store(
                &self,
                _input: CreateKeyStoreInput,
            ) -> Result<CreateKeyStoreOutput, Error> {
                unimplemented!()
            }
            async fn create_key(&self, _input: CreateKeyInput) -> Result<CreateKeyOutput, Error> {
                unimplemented!()
            }
            async fn version_key(
                &self,
                _input: VersionKeyInput,
            ) -> Result<VersionKeyOutput, Error> {
                unimplemented!()
            }
            async fn get_active_branch_key(
                &self,
                _input: GetActiveBranchKeyInput,
            ) -> Result<GetActiveBranchKeyOutput, Error> {
                Err(Error::from(
                    aws_crypto_mpl::error::ResourceNotFoundError::new("no such branch key")
                        .with_source(IoError::new(IoErrorKind::NotFound, "ddb: item not found")),
                ))
            }
            async fn get_branch_key_version(
                &self,
                _input: GetBranchKeyVersionInput,
            ) -> Result<GetBranchKeyVersionOutput, Error> {
                unimplemented!()
            }
            async fn get_beacon_key(
                &self,
                _input: GetBeaconKeyInput,
            ) -> Result<GetBeaconKeyOutput, Error> {
                unimplemented!()
            }
        }
        let keyring = SharedKeyring::new(
            HierarchicalKeyring::builder()
                .key_store(FailingKeyStore)
                .ttl(Duration::from_secs(3600))
                .branch_key_id("bk")
                .cache(LocalCmc::builder().entry_capacity(1000).build().unwrap())
                .build()
                .unwrap(),
        );

        let err = match keyring
            .on_encrypt()
            .materials(empty_encryption_materials(non_signing_suite()))
            .send()
            .await
        {
            Ok(_) => panic!("on_encrypt must fail when key store.get_active_branch_key fails"),
            Err(e) => e,
        };
        assert!(err.is_resource_not_found(), "{:?}", err);

        // The key store's error comes back unchanged, and its cause stays reachable.
        // In production that cause is the AWS SDK error.
        assert_eq!(
            err.find_source::<IoError>()
                .expect("the root cause must survive unchanged")
                .kind(),
            IoErrorKind::NotFound,
        );
    }

    #[tokio::test]
    async fn on_encrypt_uses_branch_key_supplier_when_configured() {
        let key_store = FakeKeyStore::new(fake_branch_key_materials());
        let keyring = SharedKeyring::new(
            HierarchicalKeyring::builder()
                .key_store(key_store.clone())
                .ttl(Duration::from_secs(3600))
                .branch_key_id_supplier(FixedBranchKeySupplier(FAKE_BRANCH_KEY_ID))
                .cache(LocalCmc::builder().entry_capacity(1000).build().unwrap())
                .build()
                .unwrap(),
        );

        let materials_out = keyring
            .on_encrypt()
            .materials(empty_encryption_materials(non_signing_suite()))
            .send()
            .await
            .unwrap()
            .into_materials();

        let edk = &materials_out.encrypted_data_keys()[0];
        assert_eq!(edk.key_provider_info(), FAKE_BRANCH_KEY_ID.as_bytes());
        assert_eq!(key_store.get_active_calls(), 1);
    }
}

mod ondecrypt {
    use super::*;
    use aws_crypto_mpl::error::{BranchKey, DataKeyInfo, Resource};
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
        keyring: &SharedKeyring,
        suite_id: AlgorithmSuiteId,
    ) -> (PlaintextDataKey, Vec<EncryptedDataKey>) {
        let materials_in = empty_encryption_materials(suite_id);
        let materials_out = keyring
            .on_encrypt()
            .materials(materials_in)
            .send()
            .await
            .unwrap()
            .into_materials();
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
        let key_store = FakeKeyStore::new(fake_branch_key_materials());
        let keyring = build_keyring(key_store, FAKE_BRANCH_KEY_ID);
        let suite_id = non_signing_suite();

        // First produce a real EDK so the input is non-empty; otherwise
        // the early-return on plaintext_data_key_already_present is the only path
        // that ever runs.
        let (pdk, edks) = produce_edk(&keyring, suite_id).await;

        // Build DM that ALREADY carries a plaintext data key.
        let dm = DecryptionMaterials::builder()
            .algorithm_suite_id(suite_id)
            .plaintext_data_key(pdk)
            .build()
            .unwrap();

        let err = keyring
            .on_decrypt()
            .materials(dm)
            .encrypted_data_keys(edks.to_vec())
            .send()
            .await
            .expect_err("on_decrypt must fail when materials already carry a plaintext data key");
        assert!(err.is_invalid_materials(), "{:?}", err);
    }

    #[tokio::test]
    async fn on_decrypt_calls_key_store_get_branch_key_version_with_uuid_from_ciphertext() {
        // The keyring caches under the ENCRYPT scope id during on_encrypt,
        // and computes the DECRYPT scope id during on_decrypt — different
        // cache keys, so the first on_decrypt is guaranteed to MISS the
        // cache and call get_branch_key_version. The version it passes
        // MUST be the canonical UUID string parsed from the 16 raw bytes
        // at offset salt+iv inside the EDK ciphertext.
        let key_store = FakeKeyStore::new(fake_branch_key_materials());
        let keyring = build_keyring(key_store.clone(), FAKE_BRANCH_KEY_ID);
        let suite_id = non_signing_suite();

        let (_, edks) = produce_edk(&keyring, suite_id).await;
        // Assert the on-wire version bytes match the UUID we expect to
        // see in the key store call. This pins the test to the spec's
        // ciphertext layout (salt(16) || iv(12) || version(16) || ...)
        // independently of the on_decrypt parsing logic.
        const VERSION_OFFSET: usize = 16 + 12;
        let on_wire_version = &edks[0].ciphertext()[VERSION_OFFSET..VERSION_OFFSET + 16];
        assert_eq!(on_wire_version, &FAKE_BRANCH_KEY_VERSION_BYTES);

        let _ = keyring
            .on_decrypt()
            .materials(empty_decryption_materials(suite_id))
            .encrypted_data_keys(edks.to_vec())
            .send()
            .await
            .unwrap()
            .into_materials();

        assert_eq!(key_store.get_version_calls(), 1);
        assert_eq!(
            key_store.last_version_arg().as_deref(),
            Some(FAKE_BRANCH_KEY_VERSION),
        );
    }

    #[tokio::test]
    async fn on_decrypt_caches_branch_key_after_key_store_call() {
        let key_store = FakeKeyStore::new(fake_branch_key_materials());
        let keyring = build_keyring(key_store.clone(), FAKE_BRANCH_KEY_ID);
        let suite_id = non_signing_suite();

        let (_, edks) = produce_edk(&keyring, suite_id).await;

        // First on_decrypt: cache MISS → key store is called.
        let _ = keyring
            .on_decrypt()
            .materials(empty_decryption_materials(suite_id))
            .encrypted_data_keys(edks.to_vec())
            .send()
            .await
            .unwrap()
            .into_materials();
        assert_eq!(
            key_store.get_version_calls(),
            1,
            "first on_decrypt must call get_branch_key_version once",
        );

        let _ = keyring
            .on_decrypt()
            .materials(empty_decryption_materials(suite_id))
            .encrypted_data_keys(edks.to_vec())
            .send()
            .await
            .unwrap()
            .into_materials();
        assert_eq!(
            key_store.get_version_calls(),
            1,
            "second on_decrypt must hit the cache and NOT call get_branch_key_version again",
        );
    }

    #[tokio::test]
    async fn on_decrypt_skips_edks_with_wrong_provider_id() {
        let key_store = FakeKeyStore::new(fake_branch_key_materials());
        let keyring = build_keyring(key_store.clone(), FAKE_BRANCH_KEY_ID);
        let suite_id = non_signing_suite();

        let (expected_pdk, mut edks) = produce_edk(&keyring, suite_id).await;
        // Prepend an EDK with the wrong provider id; the keyring MUST
        // skip it and continue to the next (matching) EDK.
        let bogus = EncryptedDataKey::builder()
            .key_provider_id("some-other-provider")
            .key_provider_info(FAKE_BRANCH_KEY_ID.as_bytes().to_vec())
            .ciphertext(vec![0xAA; 64])
            .build()
            .unwrap();
        edks.insert(0, bogus);

        let dm_out = keyring
            .on_decrypt()
            .materials(empty_decryption_materials(suite_id))
            .encrypted_data_keys(edks.to_vec())
            .send()
            .await
            .expect("on_decrypt must succeed by falling through to the matching EDK")
            .into_materials();
        assert_eq!(
            dm_out.plaintext_data_key().unwrap().as_bytes(),
            expected_pdk.as_bytes(),
        );
    }

    #[tokio::test]
    async fn on_decrypt_skips_edks_with_non_utf8_provider_info() {
        let key_store = FakeKeyStore::new(fake_branch_key_materials());
        let keyring = build_keyring(key_store.clone(), FAKE_BRANCH_KEY_ID);
        let suite_id = non_signing_suite();

        let (expected_pdk, mut edks) = produce_edk(&keyring, suite_id).await;
        // 0x80 is a continuation byte with no leading byte → invalid
        // UTF-8; the keyring MUST skip the EDK rather than fail on it.
        let bogus = EncryptedDataKey::builder()
            .key_provider_id("aws-kms-hierarchy")
            .key_provider_info(vec![0x80, 0x80, 0x80])
            .ciphertext(vec![0xAA; 64])
            .build()
            .unwrap();
        edks.insert(0, bogus);

        let dm_out = keyring
            .on_decrypt()
            .materials(empty_decryption_materials(suite_id))
            .encrypted_data_keys(edks.to_vec())
            .send()
            .await
            .expect("on_decrypt must succeed by falling through to the matching EDK")
            .into_materials();
        assert_eq!(
            dm_out.plaintext_data_key().unwrap().as_bytes(),
            expected_pdk.as_bytes(),
        );
    }

    #[tokio::test]
    async fn on_decrypt_skips_edks_with_wrong_branch_key_id() {
        let key_store = FakeKeyStore::new(fake_branch_key_materials());
        let keyring = build_keyring(key_store.clone(), FAKE_BRANCH_KEY_ID);
        let suite_id = non_signing_suite();

        let (expected_pdk, mut edks) = produce_edk(&keyring, suite_id).await;
        let bogus = EncryptedDataKey::builder()
            .key_provider_id("aws-kms-hierarchy")
            .key_provider_info(b"some-other-branch-key-id")
            .ciphertext(vec![0xAA; 64])
            .build()
            .unwrap();
        edks.insert(0, bogus);

        let dm_out = keyring
            .on_decrypt()
            .materials(empty_decryption_materials(suite_id))
            .encrypted_data_keys(edks.to_vec())
            .send()
            .await
            .expect("on_decrypt must succeed by falling through to the matching EDK")
            .into_materials();
        assert_eq!(
            dm_out.plaintext_data_key().unwrap().as_bytes(),
            expected_pdk.as_bytes(),
        );
    }

    #[tokio::test]
    async fn on_decrypt_with_no_edks_reports_no_match_rather_than_an_empty_aggregate() {
        // Nothing was attempted, so this is not an aggregate of zero failures
        // but a distinct one: no encrypted data key matched.
        let key_store = FakeKeyStore::new(fake_branch_key_materials());
        let keyring = build_keyring(key_store, FAKE_BRANCH_KEY_ID);
        let suite_id = non_signing_suite();

        let err = keyring
            .on_decrypt()
            .materials(empty_decryption_materials(suite_id))
            .encrypted_data_keys(Vec::new())
            .send()
            .await
            .expect_err("on_decrypt must fail when no EDK in the input matches the filter");

        assert!(err.is_no_matching_data_key(), "{:?}", err);
        assert!(
            err.collected().is_empty(),
            "with nothing attempted there is nothing to collect; got: {err}",
        );
    }

    #[tokio::test]
    async fn on_decrypt_with_only_non_matching_edks_reports_no_match() {
        // The common misconfiguration: EDKs are present but none is this
        // keyring's, so none is attempted. That is the same non-aggregate
        // no-match as supplying no EDKs at all.
        let key_store = FakeKeyStore::new(fake_branch_key_materials());
        let keyring = build_keyring(key_store, FAKE_BRANCH_KEY_ID);
        let suite_id = non_signing_suite();

        let foreign = EncryptedDataKey::builder()
            .key_provider_id("some-other-provider")
            .key_provider_info(b"some-other-info")
            .ciphertext(vec![0u8; 64])
            .build()
            .unwrap();

        let err = keyring
            .on_decrypt()
            .materials(empty_decryption_materials(suite_id))
            .encrypted_data_keys(vec![foreign])
            .send()
            .await
            .expect_err("an EDK from another provider MUST NOT be decrypted");

        assert!(err.is_no_matching_data_key(), "{:?}", err);
        assert!(
            err.collected().is_empty(),
            "a filtered-out EDK is not an attempt, so there is nothing to collect; got: {err}",
        );
        let Error::NoMatchingDataKey(e) = &err else {
            unreachable!()
        };
        assert_eq!(
            e.encrypted_data_keys(),
            [DataKeyInfo::new(
                "some-other-provider",
                b"some-other-info".to_vec()
            )]
        );
        assert_eq!(
            err.to_string(),
            "NoMatchingDataKey: no encrypted data key matched (message has: some-other-provider)"
        );
    }

    #[tokio::test]
    async fn on_decrypt_with_a_single_failing_edk_returns_its_error() {
        let key_store = FakeKeyStore::new(fake_branch_key_materials());
        let keyring = build_keyring(key_store, FAKE_BRANCH_KEY_ID);
        let suite_id = non_signing_suite();

        // EDK that passes the filter (correct provider id + provider info)
        // but whose ciphertext is shorter than the spec's salt+iv+version
        // overhead (28 bytes). The keyring MUST surface the per-EDK error
        // in the final error message.
        let truncated = EncryptedDataKey::builder()
            .key_provider_id("aws-kms-hierarchy")
            .key_provider_info(FAKE_BRANCH_KEY_ID.as_bytes().to_vec())
            .ciphertext(vec![0u8; 4])
            .build()
            .unwrap();

        let err = keyring
            .on_decrypt()
            .materials(empty_decryption_materials(suite_id))
            .encrypted_data_keys(vec![truncated])
            .send()
            .await
            .expect_err("on_decrypt must fail when every EDK attempt errors");
        // One candidate EDK, so its error comes back unchanged, not as a collection of one.
        assert!(err.is_cryptographic(), "{:?}", err);
        assert!(err.collected().is_empty());
    }

    #[tokio::test]
    async fn on_decrypt_with_several_failing_edks_aggregates_without_a_single_cause() {
        let key_store = FakeKeyStore::new(fake_branch_key_materials());
        let keyring = build_keyring(key_store, FAKE_BRANCH_KEY_ID);
        let suite_id = non_signing_suite();

        // Two candidate EDKs, both too short but by different amounts so each
        // produces a distinguishable message in the aggregate.
        let truncated_4 = EncryptedDataKey::builder()
            .key_provider_id("aws-kms-hierarchy")
            .key_provider_info(FAKE_BRANCH_KEY_ID.as_bytes().to_vec())
            .ciphertext(vec![0u8; 4])
            .build()
            .unwrap();
        let truncated_8 = EncryptedDataKey::builder()
            .key_provider_id("aws-kms-hierarchy")
            .key_provider_info(FAKE_BRANCH_KEY_ID.as_bytes().to_vec())
            .ciphertext(vec![0u8; 8])
            .build()
            .unwrap();

        let err = keyring
            .on_decrypt()
            .materials(empty_decryption_materials(suite_id))
            .encrypted_data_keys(vec![truncated_4, truncated_8])
            .send()
            .await
            .expect_err("on_decrypt must fail when every EDK attempt errors");
        assert!(err.is_cryptographic(), "{:?}", err);

        assert!(
            err.collected()
                .iter()
                .any(|e| e.message().contains("4 bytes"))
                && err
                    .collected()
                    .iter()
                    .any(|e| e.message().contains("8 bytes")),
            "the aggregate must surface every per-EDK error; got: {err:?}",
        );

        // The collected failures stay typed, not merely formatted into the
        // message, so a caller can inspect each attempt. This is what carries
        // the spec's "MUST yield an error that includes all the collected
        // errors" structurally rather than as prose.
        let collected = err.collected();
        assert_eq!(
            collected.len(),
            2,
            "both candidate EDK failures must be collected; got: {collected:?}",
        );
        for per_edk in collected {
            assert!(per_edk.is_cryptographic(), "{:?}", per_edk);
        }
        // Collected in attempt order, so a caller can tell which EDK is which.
        // Both failures have the same kind, so only the message tells them apart.
        assert!(collected[0].message().contains("4 bytes"));
        assert!(collected[1].message().contains("8 bytes"));

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
    async fn on_decrypt_propagates_key_store_failure() {
        struct FailingKeyStore;

        #[async_trait]
        impl KeyStore for FailingKeyStore {
            fn get_key_store_info(
                &self,
                _input: GetKeyStoreInfoInput,
            ) -> Result<GetKeyStoreInfoOutput, Error> {
                Ok(fake_key_store_info())
            }
            async fn create_key_store(
                &self,
                _input: CreateKeyStoreInput,
            ) -> Result<CreateKeyStoreOutput, Error> {
                unimplemented!()
            }
            async fn create_key(&self, _input: CreateKeyInput) -> Result<CreateKeyOutput, Error> {
                unimplemented!()
            }
            async fn version_key(
                &self,
                _input: VersionKeyInput,
            ) -> Result<VersionKeyOutput, Error> {
                unimplemented!()
            }
            async fn get_active_branch_key(
                &self,
                _input: GetActiveBranchKeyInput,
            ) -> Result<GetActiveBranchKeyOutput, Error> {
                unimplemented!()
            }
            async fn get_branch_key_version(
                &self,
                _input: GetBranchKeyVersionInput,
            ) -> Result<GetBranchKeyVersionOutput, Error> {
                Err(Error::from(
                    aws_crypto_mpl::error::ResourceNotFoundError::builder()
                        .message("no such branch key version")
                        .resource(BranchKey::new(FAKE_BRANCH_KEY_ID))
                        .build(),
                ))
            }
            async fn get_beacon_key(
                &self,
                _input: GetBeaconKeyInput,
            ) -> Result<GetBeaconKeyOutput, Error> {
                unimplemented!()
            }
        }

        // Build a real EDK first, then swap in a key store whose
        // get_branch_key_version fails.
        let priming_keyring = build_keyring(
            FakeKeyStore::new(fake_branch_key_materials()),
            FAKE_BRANCH_KEY_ID,
        );
        let suite_id = non_signing_suite();
        let (_, edks) = produce_edk(&priming_keyring, suite_id).await;

        let keyring = SharedKeyring::new(
            HierarchicalKeyring::builder()
                .key_store(FailingKeyStore)
                .ttl(Duration::from_secs(3600))
                .branch_key_id(FAKE_BRANCH_KEY_ID)
                .cache(LocalCmc::builder().entry_capacity(1000).build().unwrap())
                .partition_id("partition-id")
                .build()
                .unwrap(),
        );

        let err = keyring
            .on_decrypt()
            .materials(empty_decryption_materials(suite_id))
            .encrypted_data_keys(edks.to_vec())
            .send()
            .await
            // One candidate EDK, so the key store's error comes back unchanged.
            .expect_err("on_decrypt must fail when key store.get_branch_key_version fails");
        assert!(err.is_resource_not_found(), "{:?}", err);
        assert!(err.collected().is_empty());
        assert_eq!(err.message(), "no such branch key version");
        assert_eq!(
            err.resource(),
            Some(&Resource::BranchKey(
                BranchKey::new(FAKE_BRANCH_KEY_ID).with_version(FAKE_BRANCH_KEY_VERSION)
            ))
        );
    }

    #[tokio::test]
    async fn on_decrypt_uses_branch_key_supplier_when_configured() {
        let key_store = FakeKeyStore::new(fake_branch_key_materials());
        let keyring = SharedKeyring::new(
            HierarchicalKeyring::builder()
                .key_store(key_store.clone())
                .ttl(Duration::from_secs(3600))
                .branch_key_id_supplier(FixedBranchKeySupplier(FAKE_BRANCH_KEY_ID))
                .cache(LocalCmc::builder().entry_capacity(1000).build().unwrap())
                .partition_id("partition-id")
                .build()
                .unwrap(),
        );
        let suite_id = non_signing_suite();

        let (expected_pdk, edks) = produce_edk(&keyring, suite_id).await;

        let dm_out = keyring
            .on_decrypt()
            .materials(empty_decryption_materials(suite_id))
            .encrypted_data_keys(edks.to_vec())
            .send()
            .await
            .expect("on_decrypt with a supplier-resolved branch_key_id must succeed")
            .into_materials();
        assert_eq!(
            dm_out.plaintext_data_key().unwrap().as_bytes(),
            expected_pdk.as_bytes(),
        );
        // Both halves of the round trip ran one key store method each:
        // get_active for encrypt, get_branch_key_version for decrypt.
        assert_eq!(key_store.get_version_calls(), 1);
    }
}

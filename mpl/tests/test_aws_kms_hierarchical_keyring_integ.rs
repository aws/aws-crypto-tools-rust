// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Real-AWS integration tests for [`HierarchicalKeyring::on_encrypt`].
//!
//! These run as part of `cargo test`, against the same assumed role CI uses
//! for the key store integration tests (`configure-aws-credentials` in
//! `.github/workflows/library_rust_tests.yml`). They need read access to the
//! key store fixtures: DDB table `KeyStoreDdbTable` and the KMS key
//! `9d989aa2-2f9c-438c-a745-cc57d3ad0126`, both in account `370957321024`,
//! region `us-west-2`. Without credentials for that account they fail rather
//! than skip, the same way `test_key_store_branch_key_store_integ` does.
//!
//! Ported from the Dafny suite at
//! <https://github.com/aws/aws-cryptographic-material-providers-library/blob/main/AwsCryptographicMaterialProviders/dafny/AwsCryptographicMaterialProviders/test/Keyrings/AwsKms/AwsKmsHierarchicalKeyring/TestAwsKmsHierarchicalKeyring.dfy>
//! (commit `09e485a3...`).
//!
//! This file ports the on-encrypt tests, the encrypt → on_decrypt full round
//! trip, and the shared-cache suites (`TestHierarchyClientESDKSuite` and
//! `TestSharedCache*`). The Discovery and MRDiscovery sections at the end
//! reach further than the Dafny keyring suite does: Dafny covers those KMS
//! configurations against the KeyStore directly, never through a keyring. See
//! the comments on those two sections.
//!
//! Per-operation caching is NOT asserted here. A real DynamoDB key store exposes
//! no call counter, and proving a cache hit by comparing wall-clock latency
//! between a cold and a warm call is a timing heuristic, not an assertion — it
//! passes or flakes with runner load. Caching is asserted instead in
//! `test_aws_kms_hierarchical_keyring.rs`, where the key store doubles count
//! calls (`on_encrypt_caches_branch_key_materials_after_key_store_call`,
//! `on_decrypt_caches_branch_key_after_key_store_call`). The shared-cache tests
//! below do observe the cache, but through behaviour: a second keyring succeeds
//! only when the first has populated an entry it is allowed to reuse.
//!
//! Two Dafny suites are intentionally NOT ported here:
//! - `TestHierarchyClientDBESuite` — DBE algorithm suites are out of scope
//!   for this Rust implementation (annotated `type=exception` on every DBE /
//!   S3EC variant in `structures/algorithm_suite.rs`).
//! - `TestBranchKeyIdSupplier` and `TestInvalidDataKeyError` — both need two
//!   distinct, usable branch keys. Under a pinned `KmsKeyArn` key store the team
//!   fixtures do not provide that: only `BRANCH_KEY_ID` matches `KEY_ARN`, and
//!   `DISCOVERY_BRANCH_KEY_ID` is deliberately configured with a mismatched
//!   kms-arn. A Discovery key store serves both (see the Discovery section
//!   below), so these are now portable and left as a follow-up rather than a
//!   limitation. Meanwhile the supplier and wrong-EC failure paths are covered
//!   by unit tests in `test_aws_kms_hierarchical_keyring.rs` (the
//!   `*_uses_branch_key_supplier_when_configured`,
//!   `*_skips_edks_with_wrong_branch_key_id`, and `*_collects_per_edk_errors_*`
//!   tests), which use key store doubles to count calls — something a real
//!   DynamoDB key store cannot expose.
//!
//! Sections of the AWS KMS Hierarchical Keyring specification these tests cite:
//!
//! - [OnEncrypt][onencrypt]
//! - [Appendix A: Cache Entry Identifier Formulas][appendix-a]
//! - [Shared Cache Considerations][shared-cache]
//!
//! [onencrypt]: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
//! [appendix-a]: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-hierarchical-keyring.md#appendix-a-cache-entry-identifier-formulas
//! [shared-cache]: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-hierarchical-keyring.md#shared-cache-considerations

#![cfg(feature = "test-utils")]

use std::time::Duration;

use aws_config::{BehaviorVersion, Region};
use aws_sdk_dynamodb::Client as DynamoDbClient;
use aws_sdk_kms::Client as KmsClient;
use aws_sdk_kms::error::SdkError;
use aws_sdk_kms::operation::decrypt::DecryptError;

use aws_crypto_mpl::Error;
use aws_crypto_mpl::aws_kms::__test_internals::unwrap as branch_key_unwrap;
use aws_crypto_mpl::aws_kms::hierarchical_keyring::HierarchicalKeyring;
use aws_crypto_mpl::key_store::{Discovery, KeyStoreClient, MrDiscovery};
use aws_crypto_mpl::structures::{
    AlgorithmSuiteId, BranchKeyMaterials, DecryptionMaterials, EncryptionContext,
    EncryptionMaterials, EsdkAlgorithmSuiteId,
};
use aws_crypto_mpl::{IntoShared, KmsConfiguration, LocalCmc, SharedCmc, SharedKeyring};

// ─── Fixtures (mirror Dafny Fixtures.dfy) ──────────────────────────────────

const BRANCH_KEY_STORE_NAME: &str = "KeyStoreDdbTable";
const LOGICAL_KEY_STORE_NAME: &str = "KeyStoreDdbTable";
const BRANCH_KEY_ID: &str = "3f43a9af-08c5-4317-b694-3d3e883dcaef";
const BRANCH_KEY_ACTIVE_VERSION: &str = "caf0c508-e64d-4b6c-bffe-381cbc546c02";
const KEY_ARN: &str = "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126";

async fn build_clients() -> (KmsClient, DynamoDbClient) {
    let cfg = aws_config::defaults(BehaviorVersion::latest())
        .region(Region::new("us-west-2"))
        .load()
        .await;
    (KmsClient::new(&cfg), DynamoDbClient::new(&cfg))
}

async fn build_key_store() -> KeyStoreClient {
    let (kms, ddb) = build_clients().await;
    KeyStoreClient::builder()
        .ddb_table_name(BRANCH_KEY_STORE_NAME)
        .kms_configuration(KmsConfiguration::KmsKeyArn(KEY_ARN.into()))
        .logical_key_store_name(LOGICAL_KEY_STORE_NAME)
        .ddb_client(ddb)
        .kms_client(kms)
        .build()
        .await
        .unwrap()
}

/// TTL for the fixture keyrings.
/// Long enough that no test races an expiry.
const FIXTURE_TTL: Duration = Duration::from_secs(3600);

/// Build a keyring over `key_store` for `branch_key_id`, with its own `LocalCmc`.
/// Every test varies only these three things, so they share one fixture.
async fn keyring_for(
    key_store: impl Into<KeyStoreClient>,
    branch_key_id: &str,
    partition: &str,
) -> SharedKeyring {
    keyring_with_cache(
        key_store,
        branch_key_id,
        partition,
        LocalCmc::builder().entry_capacity(1000).build().unwrap(),
    )
    .await
}

/// Same, with an explicit cache. Used by the shared-cache tests, which hand
/// two keyrings the same `SharedCmc`.
async fn keyring_with_cache(
    key_store: impl Into<KeyStoreClient>,
    branch_key_id: &str,
    partition: &str,
    cache: impl IntoShared<SharedCmc>,
) -> SharedKeyring {
    SharedKeyring::new(
        HierarchicalKeyring::builder()
            .key_store(key_store)
            .ttl(FIXTURE_TTL)
            .branch_key_id(branch_key_id)
            .cache(cache)
            .partition_id(partition)
            .build()
            .await
            .expect("fixture keyring configuration must be valid"),
    )
}

/// Pick a non-signing suite so signing-key invariants don't intrude.
fn non_signing_suite() -> AlgorithmSuiteId {
    AlgorithmSuiteId::Esdk(EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf)
}

/// Build empty encryption materials with a small encryption context, in
/// the spirit of the Dafny `GetTestMaterials`:
/// <https://github.com/aws/aws-cryptographic-material-providers-library/blob/main/AwsCryptographicMaterialProviders/dafny/AwsCryptographicMaterialProviders/test/Keyrings/AwsKms/AwsKmsHierarchicalKeyring/TestAwsKmsHierarchicalKeyring.dfy#L64>
fn fresh_materials() -> EncryptionMaterials {
    let mut ec = EncryptionContext::new();
    ec.insert("region", "us-west-2");
    EncryptionMaterials::builder()
        .algorithm_suite_id(non_signing_suite())
        .encryption_context(ec)
        .build()
        .unwrap()
}

#[tokio::test]
async fn integ_on_encrypt_round_trips_through_real_key_store_and_kms() {
    let key_store = build_key_store().await;
    let keyring = keyring_for(key_store, BRANCH_KEY_ID, "partition-id-integ").await;

    let materials_in = fresh_materials();
    let ec = materials_in.encryption_context().clone();
    let materials_out = keyring
        .on_encrypt()
        .materials(materials_in)
        .send()
        .await
        .expect("on_encrypt against real key store must succeed")
        .into_materials();

    // Exactly one EDK with the spec's provider id and provider info.
    let edks = materials_out.encrypted_data_keys();
    assert_eq!(edks.len(), 1);
    assert_eq!(edks[0].key_provider_id(), "aws-kms-hierarchy");
    assert_eq!(edks[0].key_provider_info(), BRANCH_KEY_ID.as_bytes());

    // Plaintext DK was generated (suite is 32 bytes).
    let pdk = materials_out.plaintext_data_key().unwrap();
    assert_eq!(pdk.len(), 32);

    // Round-trip the EDK ciphertext via branch_key_unwrap by re-fetching
    // the same active branch-key materials from the real key store. This
    // proves the on-wire EDK ciphertext is decryptable end-to-end with
    // the real KMS-backed branch key, not just the stub fake.
    let real_key_store = build_key_store().await;
    let bkm: BranchKeyMaterials = real_key_store
        .get_active_branch_key()
        .branch_key_id(BRANCH_KEY_ID.to_string())
        .send()
        .await
        .unwrap()
        .into_branch_key_materials();
    assert_eq!(bkm.branch_key_version(), BRANCH_KEY_ACTIVE_VERSION);

    let recovered = branch_key_unwrap(&bkm, &ec, edks[0].ciphertext())
        .expect("EDK ciphertext MUST round-trip through real branch key materials");
    assert_eq!(recovered, pdk.as_bytes());
}

#[tokio::test]
async fn integ_on_decrypt_round_trips_through_real_key_store_and_kms() {
    // Full encrypt → decrypt round trip against the real key store. Proves
    // the EDK ciphertext produced by on_encrypt is decryptable by
    // on_decrypt going through:
    //   1. Branch-key id resolution
    //   2. Logical key store name lookup (DDB GetItem path on get_key_store_info)
    //   3. Cache lookup (decrypt scope id) — MISS, since on_encrypt cached
    //      under the encrypt scope id, which is a different key
    //   4. the key store's get_branch_key_version call
    //      (DDB GetItem + KMS Decrypt for the version-specific record)
    //   5. branch_key_unwrap with the input DM's encryption context
    let key_store = build_key_store().await;
    let keyring = keyring_for(key_store, BRANCH_KEY_ID, "partition-id-integ-decrypt").await;

    let materials_in = fresh_materials();
    let ec = materials_in.encryption_context().clone();
    let materials_out = keyring
        .on_encrypt()
        .materials(materials_in)
        .send()
        .await
        .unwrap()
        .into_materials();
    let pdk_bytes = materials_out
        .plaintext_data_key()
        .unwrap()
        .as_bytes()
        .to_vec();
    let edks = materials_out.encrypted_data_keys().to_vec();

    // Build empty decryption materials with the same EC the encrypt side
    // used; the AAD bound into the EDK ciphertext is computed over this EC.
    let dm_in = DecryptionMaterials::builder()
        .algorithm_suite_id(non_signing_suite())
        .encryption_context(ec)
        .build()
        .unwrap();
    let dm_out = keyring
        .on_decrypt()
        .materials(dm_in)
        .encrypted_data_keys(edks.to_vec())
        .send()
        .await
        .expect("on_decrypt against real key store must succeed for an EDK we just produced")
        .into_materials();

    assert_eq!(
        dm_out.plaintext_data_key().unwrap().as_bytes(),
        pdk_bytes,
        "on_decrypt must recover the same plaintext data key on_encrypt set",
    );
}

// ─── Helpers for shared-cache tests ────────────────────────────────────────

/// Build a KMS client pinned to the supplied region. Mirrors Dafny's
/// `KMSClientForRegion`:
/// <https://github.com/aws/aws-cryptographic-material-providers-library/blob/main/AwsCryptographicMaterialProviders/dafny/AwsCryptographyKeyStore/test/Fixtures.dfy>
async fn kms_client_for_region(region: &'static str) -> KmsClient {
    let cfg = aws_config::defaults(BehaviorVersion::latest())
        .region(Region::new(region))
        .load()
        .await;
    KmsClient::new(&cfg)
}

/// Build a DynamoDB client pinned to `us-west-2` (where the test table
/// lives, regardless of which KMS region the key store is using).
async fn ddb_client_us_west_2() -> DynamoDbClient {
    let cfg = aws_config::defaults(BehaviorVersion::latest())
        .region(Region::new("us-west-2"))
        .load()
        .await;
    DynamoDbClient::new(&cfg)
}

/// Build a DynamoDB key store with the supplied KMS client and logical
/// key store name. The DDB client is pinned to `us-west-2`.
async fn build_key_store_with_kms_and_logical_name(
    kms: KmsClient,
    logical_key_store_name: &str,
) -> KeyStoreClient {
    KeyStoreClient::builder()
        .ddb_table_name(BRANCH_KEY_STORE_NAME)
        .kms_configuration(KmsConfiguration::KmsKeyArn(KEY_ARN.into()))
        .logical_key_store_name(logical_key_store_name)
        .ddb_client(ddb_client_us_west_2().await)
        .kms_client(kms)
        .build()
        .await
        .unwrap()
}

/// Assert that `hk2`'s encrypt failed, and failed at the KMS call rather than
/// earlier.
///
/// What this checks is narrower than why these tests expect a failure. Every
/// `hk2` here is built by `build_key_store_with_kms_and_logical_name`, which pins
/// `KmsConfiguration::KmsKeyArn(KEY_ARN.into())` -- a us-west-2 ARN -- while handing the
/// key store a KMS client for another region, so the intended failure is the KMS
/// `Decrypt` rejecting a key from a different region.
///
/// Asserts the source chain holds the `SdkError<DecryptError>`, which proves the call reached KMS.
/// That means the DDB record was read, so `hk2` went to the key store instead of
/// being served from the shared cache, and a cache miss is what is under test.
/// A bare `is_err()` would also be satisfied by a missing record or an
/// unreachable table.
///
/// The service-error variant is deliberately not pinned here. These are
/// shared-cache tests where the KMS-side rejection depends on the fixture's
/// cross-region setup, and unlike
/// `integ_discovery_key_store_cannot_reach_an_out_of_region_mrk` there is no
/// Dafny assertion naming the expected exception for this path. Where Dafny
/// does name one, that test pins it.
fn assert_failed_at_kms(result: Result<EncryptionMaterials, Error>, context: &str) {
    let err = match result {
        Err(e) => e,
        Ok(_) => panic!("{context}: expected on_encrypt to fail"),
    };

    assert!(
        err.find_source::<SdkError<DecryptError>>().is_some(),
        "{context}: the KMS SDK error must be in the source chain, got: {err:#}",
    );
}

/// Run an `on_encrypt` → `on_decrypt` round trip and assert the recovered
/// PDK matches. Mirrors Dafny's `TestRoundtrip`.
async fn run_round_trip(
    keyring: &SharedKeyring,
    materials_in: EncryptionMaterials,
    expected_branch_key_id: &str,
) {
    let suite_id = materials_in.algorithm_suite_id();
    let ec = materials_in.encryption_context().clone();

    let materials_out = keyring
        .on_encrypt()
        .materials(materials_in)
        .send()
        .await
        .expect("on_encrypt against real key store must succeed")
        .into_materials();

    // Verify the EDK was created with the expected branch key id.
    let edks = materials_out.encrypted_data_keys().to_vec();
    assert_eq!(edks.len(), 1);
    assert_eq!(edks[0].key_provider_id(), "aws-kms-hierarchy");
    assert_eq!(
        edks[0].key_provider_info(),
        expected_branch_key_id.as_bytes(),
        "EDK provider_info MUST equal the configured branch_key_id",
    );
    let pdk_bytes = materials_out
        .plaintext_data_key()
        .unwrap()
        .as_bytes()
        .to_vec();

    let dm_in = DecryptionMaterials::builder()
        .algorithm_suite_id(suite_id)
        .encryption_context(ec)
        .build()
        .unwrap();
    let dm_out = keyring
        .on_decrypt()
        .materials(dm_in)
        .encrypted_data_keys(edks.to_vec())
        .send()
        .await
        .expect("on_decrypt against real key store must succeed for an EDK we just produced")
        .into_materials();

    assert_eq!(
        dm_out.plaintext_data_key().unwrap().as_bytes(),
        pdk_bytes,
        "round trip MUST recover the same plaintext data key on_encrypt set",
    );
}

// ─── TestHierarchyClientESDKSuite — pre-existing PDK variant ───────────────

#[tokio::test]
async fn integ_on_encrypt_with_pre_existing_pdk_round_trips() {
    // Second half of Dafny `TestHierarchyClientESDKSuite`: encrypt with
    // a caller-supplied (zeroed) PDK. on_encrypt MUST preserve the PDK
    // (per the specification's OnEncrypt section, linked in the module doc:
    // "If the input materials' plaintext data key is
    // not empty ... MUST use the existing plaintext data key") and the
    // produced EDK MUST round-trip back to the same PDK on decrypt.
    let key_store = build_key_store().await;
    let keyring = keyring_for(key_store, BRANCH_KEY_ID, "partition-id-integ-existing-pdk").await;

    let suite = non_signing_suite();
    let key_len = suite.specification().encryption_key_length();
    let zeroed = vec![0u8; key_len];

    let mut ec = EncryptionContext::new();
    ec.insert("region", "us-west-2");
    let materials_in = EncryptionMaterials::builder()
        .algorithm_suite_id(suite)
        .encryption_context(ec)
        .plaintext_data_key(aws_crypto_mpl::structures::PlaintextDataKey::new(
            zeroed.clone(),
        ))
        .build()
        .unwrap();

    run_round_trip(&keyring, materials_in, BRANCH_KEY_ID).await;
}

// ─── TestSharedCache* suites ───────────────────────────────────────────────
//
// These four tests mirror the Dafny `TestSharedCache*` suites. They each
// build two `HierarchicalKeyring`s (HK1, HK2) that share a single
// `LocalCmc` through clones of one `SharedCmc`.
// HK1's key store uses a us-west-2 KMS client; HK2's key store uses a us-east-2 KMS client.
// KEY_ARN is in us-west-2, so any KMS Decrypt issued by HK2's key store fails.
//
// The four tests differ only in (partition_id, logical_key_store_name)
// configuration and observe whether HK1's cache entry is reachable from
// HK2 — i.e., they verify the cache identifier formula at
// Appendix A of the specification (linked in the module doc) binds those
// exact fields.

/// Build a non-signing-suite encryption materials with a small EC. Mirrors
/// the Dafny `GetTestMaterials(TEST_ESDK_ALG_SUITE_ID)` call.
fn shared_cache_materials() -> EncryptionMaterials {
    fresh_materials()
}

/// A `SharedCmc` over a fresh `LocalCmc`, for HK1 and HK2 to share.
fn shared_cache() -> SharedCmc {
    SharedCmc::new(
        LocalCmc::builder()
            .entry_capacity(100)
            .entry_pruning_tail_size(50)
            .build()
            .unwrap(),
    )
}

#[tokio::test]
async fn integ_shared_cache_with_same_partition_id_and_same_logical_key_store_name() {
    // HK1 and HK2 share Partition ID, Logical Key Store Name, and Branch
    // Key ID — so per the specification's Shared Cache Considerations section
    // (linked in the module doc) they MUST share cache
    // entries. After HK1's round trip populates the cache, HK2's encrypt
    // (which would otherwise fail because its KMS client is us-east-2 and
    // the key is us-west-2) succeeds entirely from the cached entry.
    let key_store_west = build_key_store_with_kms_and_logical_name(
        kms_client_for_region("us-west-2").await,
        LOGICAL_KEY_STORE_NAME,
    )
    .await;
    let key_store_east = build_key_store_with_kms_and_logical_name(
        kms_client_for_region("us-east-2").await,
        LOGICAL_KEY_STORE_NAME,
    )
    .await;

    let cache = shared_cache();

    let hk1 = keyring_with_cache(key_store_west, BRANCH_KEY_ID, "partitionId", cache.clone()).await;
    let hk2 = keyring_with_cache(key_store_east, BRANCH_KEY_ID, "partitionId", cache).await;

    // HK2 encrypt fails first: the shared cache is cold, so it must reach KMS.
    assert_failed_at_kms(
        hk2.on_encrypt()
            .materials(shared_cache_materials())
            .send()
            .await
            .map(|o| o.into_materials()),
        "HK2 on_encrypt before the cache is populated",
    );

    // HK1 round-trip succeeds (and populates the shared cache).
    run_round_trip(&hk1, shared_cache_materials(), BRANCH_KEY_ID).await;

    run_round_trip(&hk2, shared_cache_materials(), BRANCH_KEY_ID).await;
}

#[tokio::test]
async fn integ_shared_cache_with_different_unspecified_partition_id_and_same_logical_key_store_name()
 {
    // HK1 and HK2 leave partition_id = None, so each keyring generates a
    // fresh v4 UUID. The cache identifier binds the partition id, so the
    // entries do NOT collide and HK2's second encrypt MUST still fail.
    let key_store_west = build_key_store_with_kms_and_logical_name(
        kms_client_for_region("us-west-2").await,
        LOGICAL_KEY_STORE_NAME,
    )
    .await;
    let key_store_east = build_key_store_with_kms_and_logical_name(
        kms_client_for_region("us-east-2").await,
        LOGICAL_KEY_STORE_NAME,
    )
    .await;

    let cache = shared_cache();

    // Not built through `keyring_for` / `keyring_with_cache`: those supply a
    // partition id, and the point of this test is the `None` case, where each
    // keyring generates its own distinct v4 UUID partition id.
    let hk1 = SharedKeyring::new(
        HierarchicalKeyring::builder()
            .key_store(key_store_west)
            .ttl(FIXTURE_TTL)
            .branch_key_id(BRANCH_KEY_ID)
            .cache(cache.clone())
            .build()
            .await
            .unwrap(),
    );
    let hk2 = SharedKeyring::new(
        HierarchicalKeyring::builder()
            .key_store(key_store_east)
            .ttl(FIXTURE_TTL)
            .branch_key_id(BRANCH_KEY_ID)
            .cache(cache)
            .build()
            .await
            .unwrap(),
    );

    assert_failed_at_kms(
        hk2.on_encrypt()
            .materials(shared_cache_materials())
            .send()
            .await
            .map(|o| o.into_materials()),
        "HK2 on_encrypt MUST fail before the cache is populated",
    );

    run_round_trip(&hk1, shared_cache_materials(), BRANCH_KEY_ID).await;

    assert_failed_at_kms(
        hk2.on_encrypt()
            .materials(shared_cache_materials())
            .send()
            .await
            .map(|o| o.into_materials()),
        "HK2 on_encrypt MUST still fail — distinct random partition ids prevent cache reuse",
    );
}

#[tokio::test]
async fn integ_shared_cache_with_different_specified_partition_id_and_same_logical_key_store_name()
{
    // HK1 and HK2 set explicit, distinct partition ids. Cache miss
    // expected: HK2's encrypt MUST still fail.
    let key_store_west = build_key_store_with_kms_and_logical_name(
        kms_client_for_region("us-west-2").await,
        LOGICAL_KEY_STORE_NAME,
    )
    .await;
    let key_store_east = build_key_store_with_kms_and_logical_name(
        kms_client_for_region("us-east-2").await,
        LOGICAL_KEY_STORE_NAME,
    )
    .await;

    let cache = shared_cache();

    let hk1 = keyring_with_cache(
        key_store_west,
        BRANCH_KEY_ID,
        "partitionIdHK1",
        cache.clone(),
    )
    .await;
    let hk2 = keyring_with_cache(key_store_east, BRANCH_KEY_ID, "partitionIdHK2", cache).await;

    assert_failed_at_kms(
        hk2.on_encrypt()
            .materials(shared_cache_materials())
            .send()
            .await
            .map(|o| o.into_materials()),
        "HK2 on_encrypt MUST fail before the cache is populated",
    );

    run_round_trip(&hk1, shared_cache_materials(), BRANCH_KEY_ID).await;

    assert_failed_at_kms(
        hk2.on_encrypt()
            .materials(shared_cache_materials())
            .send()
            .await
            .map(|o| o.into_materials()),
        "HK2 on_encrypt MUST still fail — distinct partition ids prevent cache reuse",
    );
}

#[tokio::test]
async fn integ_shared_cache_with_same_partition_id_and_different_logical_key_store_name() {
    // HK1 and HK2 share Partition ID but differ in Logical Key Store Name.
    // Cache identifier binds the logical key store name, so HK2's encrypt
    // MUST still fail after HK1's round trip populates the cache.
    let key_store_west = build_key_store_with_kms_and_logical_name(
        kms_client_for_region("us-west-2").await,
        LOGICAL_KEY_STORE_NAME,
    )
    .await;
    let key_store_east = build_key_store_with_kms_and_logical_name(
        kms_client_for_region("us-east-2").await,
        &format!("{LOGICAL_KEY_STORE_NAME}New"),
    )
    .await;

    let cache = shared_cache();

    let hk1 = keyring_with_cache(key_store_west, BRANCH_KEY_ID, "partitionId", cache.clone()).await;
    let hk2 = keyring_with_cache(key_store_east, BRANCH_KEY_ID, "partitionId", cache).await;

    assert_failed_at_kms(
        hk2.on_encrypt()
            .materials(shared_cache_materials())
            .send()
            .await
            .map(|o| o.into_materials()),
        "HK2 on_encrypt MUST fail before the cache is populated",
    );

    run_round_trip(&hk1, shared_cache_materials(), BRANCH_KEY_ID).await;

    assert_failed_at_kms(
        hk2.on_encrypt()
            .materials(shared_cache_materials())
            .send()
            .await
            .map(|o| o.into_materials()),
        "HK2 on_encrypt MUST still fail — different logical key store names prevent cache reuse",
    );
}

// ─── Discovery key store ────────────────────────────────────────────────────
//
// `KmsConfiguration::Discovery` takes the KMS key ARN from each DDB record
// instead of pinning one at construction, so a single key store can serve
// branch keys protected by different KMS keys.
//
// The Dafny suite has no equivalent of these: its Discovery coverage
// (AwsCryptographyKeyStore/test/TestDiscoveryGetKeys.dfy) calls
// GetActiveBranchKey / GetBranchKeyVersion / GetBeaconKey on the KeyStore
// directly and never drives a Hierarchical Keyring, and
// TestAwsKmsHierarchicalKeyring.dfy never configures Discovery. These tests
// close that gap by exercising the keyring's OnEncrypt and OnDecrypt paths,
// both of which resolve the record's ARN through the key store.

/// A branch key whose record's `kms-arn` is NOT `KEY_ARN`, so only a Discovery
/// key store can serve it. This is Dafny's `postalHornBranchKeyId` fixture in
/// AwsCryptographyKeyStore/test/Fixtures.dfy.
const DISCOVERY_BRANCH_KEY_ID: &str = "682dfba7-4c35-491d-8d6a-5a9c56194061";
const DISCOVERY_BRANCH_KEY_ACTIVE_VERSION: &str = "6b7a8ef4-8c1c-4f63-b196-a6ef7e496e50";

/// Build a key store in Discovery mode: no configured KMS key ARN, so each
/// record's own `kms-arn` is used for the KMS Decrypt.
async fn build_discovery_key_store() -> KeyStoreClient {
    let (kms, ddb) = build_clients().await;
    KeyStoreClient::builder()
        .ddb_table_name(BRANCH_KEY_STORE_NAME)
        .kms_configuration(KmsConfiguration::Discovery(
            Discovery::builder().build().unwrap(),
        ))
        .logical_key_store_name(LOGICAL_KEY_STORE_NAME)
        .ddb_client(ddb)
        .kms_client(kms)
        .build()
        .await
        .unwrap()
}

#[tokio::test]
async fn integ_discovery_key_store_wraps_under_the_records_own_kms_key() {
    // The Discovery branch key's record names a different KMS key than
    // KEY_ARN. Discovery must pick that ARN up from the record, so
    // on_encrypt succeeds and the EDK is unwrappable with the same
    // record's materials.
    let keyring = keyring_for(
        build_discovery_key_store().await,
        DISCOVERY_BRANCH_KEY_ID,
        "partition-id-integ-discovery",
    )
    .await;

    let materials_in = fresh_materials();
    let ec = materials_in.encryption_context().clone();
    let materials_out = keyring
        .on_encrypt()
        .materials(materials_in)
        .send()
        .await
        .expect("Discovery key store must wrap under the branch-key record's own kms-arn")
        .into_materials();

    let edks = materials_out.encrypted_data_keys();
    assert_eq!(edks.len(), 1);
    assert_eq!(
        edks[0].key_provider_info(),
        DISCOVERY_BRANCH_KEY_ID.as_bytes(),
        "EDK provider info must carry the Discovery branch key id",
    );

    let pdk = materials_out.plaintext_data_key().unwrap();
    let bkm: BranchKeyMaterials = build_discovery_key_store()
        .await
        .get_active_branch_key()
        .branch_key_id(DISCOVERY_BRANCH_KEY_ID.to_string())
        .send()
        .await
        .unwrap()
        .into_branch_key_materials();
    assert_eq!(
        bkm.branch_key_version(),
        DISCOVERY_BRANCH_KEY_ACTIVE_VERSION
    );

    let recovered = branch_key_unwrap(&bkm, &ec, edks[0].ciphertext())
        .expect("EDK from a Discovery key store MUST round-trip through the same materials");
    assert_eq!(recovered, pdk.as_bytes());
}

#[tokio::test]
async fn integ_pinned_key_store_rejects_a_branch_key_under_another_kms_key() {
    // The contrast that makes the test above meaningful: the same branch key
    // through a key store pinned to KEY_ARN MUST fail, because the record's
    // kms-arn disagrees with the configured one. Without this, the Discovery
    // test would pass even if Discovery were silently ignoring the record.
    let keyring = keyring_for(
        build_key_store().await,
        DISCOVERY_BRANCH_KEY_ID,
        "partition-id-integ-discovery-negative",
    )
    .await;

    let err = keyring
        .on_encrypt()
        .materials(fresh_materials())
        .send()
        .await
        .expect_err("a key store pinned to KEY_ARN MUST reject the Discovery-only branch key");
    // Only the kms-arn-compat check in resolve_key_store_arn returns Validation;
    // a missing record or an unreachable table returns a remote kind.
    assert!(err.is_validation(), "got: {err}");
}

#[tokio::test]
async fn integ_discovery_key_store_serves_two_branch_keys_under_different_kms_keys() {
    // Mirrors the property Dafny's TestGetActiveKeyForTwoKmsArnsSuccess
    // asserts at the key store level, but through two keyrings sharing one
    // Discovery key store: BRANCH_KEY_ID is protected by KEY_ARN and
    // DISCOVERY_BRANCH_KEY_ID by a different key, and one key store serves
    // both. No pinned configuration can do this.
    let key_store = build_discovery_key_store().await;

    for (branch_key_id, partition) in [
        (BRANCH_KEY_ID, "partition-id-integ-discovery-two-a"),
        (
            DISCOVERY_BRANCH_KEY_ID,
            "partition-id-integ-discovery-two-b",
        ),
    ] {
        let keyring = keyring_for(key_store.clone(), branch_key_id, partition).await;
        let materials_out = keyring
            .on_encrypt()
            .materials(fresh_materials())
            .send()
            .await
            .unwrap_or_else(|e| {
                panic!("Discovery key store must serve branch key {branch_key_id}: {e}")
            })
            .into_materials();
        assert_eq!(
            materials_out.encrypted_data_keys()[0].key_provider_info(),
            branch_key_id.as_bytes(),
        );
    }
}

#[tokio::test]
async fn integ_discovery_key_store_on_decrypt_round_trips() {
    // OnDecrypt resolves the record ARN through get_branch_key_version,
    // a different key store call than OnEncrypt's get_active_branch_key, so
    // Discovery has to hold on that path too.
    let keyring = keyring_for(
        build_discovery_key_store().await,
        DISCOVERY_BRANCH_KEY_ID,
        "partition-id-integ-discovery-decrypt",
    )
    .await;
    run_round_trip(&keyring, fresh_materials(), DISCOVERY_BRANCH_KEY_ID).await;
}

// ─── MrDiscovery key store — mirrors Dafny TestGetKeysForMrk ────────────────
//
// `MyEastBranch2`'s record names a us-east-1 MRK. `MrDiscovery`
// rewrites the record's ARN into that region before calling KMS, so a
// us-west-2 client reaches the MRK replica; plain `Discovery` passes the
// us-east-1 ARN through unchanged and the us-west-2 endpoint rejects it.
//
// Dafny asserts this pair at the key store level in
// AwsCryptographyKeyStore/test/TestDiscoveryGetKeys.dfy `TestGetKeysForMrk`,
// over GetBeaconKey and GetActiveBranchKey. Beacon keys are not part of the
// keyring's path, so the keyring analog of GetActiveBranchKey is OnEncrypt,
// and a round trip additionally covers GetBranchKeyVersion.

/// A branch key whose record's `kms-arn` is a us-east-1 MRK. Mirrors Dafny's
/// `EastBranchKey`. The MRK lives in account `658956600833`, replicated to
/// us-east-1 and us-west-2.
const EAST_BRANCH_KEY: &str = "MyEastBranch2";

/// Build a key store in MRDiscovery mode: the record's `kms-arn` is used, but
/// rewritten into `region` first.
async fn build_mr_discovery_key_store(region: &str) -> KeyStoreClient {
    let (kms, ddb) = build_clients().await;
    KeyStoreClient::builder()
        .ddb_table_name(BRANCH_KEY_STORE_NAME)
        .kms_configuration(KmsConfiguration::MrDiscovery(
            MrDiscovery::builder().region(region).build().unwrap(),
        ))
        .logical_key_store_name(LOGICAL_KEY_STORE_NAME)
        .ddb_client(ddb)
        .kms_client(kms)
        .build()
        .await
        .unwrap()
}

#[tokio::test]
async fn integ_mr_discovery_key_store_reaches_an_mrk_replica_in_the_configured_region() {
    // build_clients() pins KMS to us-west-2, and MrDiscovery rewrites the
    // record's us-east-1 ARN to us-west-2, so the decrypt lands on the
    // replica that client can reach.
    let keyring = keyring_for(
        build_mr_discovery_key_store("us-west-2").await,
        EAST_BRANCH_KEY,
        "partition-id-integ-mrdiscovery",
    )
    .await;

    let materials_out = keyring.on_encrypt().materials(fresh_materials()).send().await.expect(
        "MrDiscovery MUST rewrite the record's us-east-1 ARN into us-west-2 and reach the replica",
    ).into_materials();

    let edks = materials_out.encrypted_data_keys();
    assert_eq!(edks.len(), 1);
    assert_eq!(edks[0].key_provider_info(), EAST_BRANCH_KEY.as_bytes(),);
    assert_eq!(materials_out.plaintext_data_key().unwrap().len(), 32);
}

#[tokio::test]
async fn integ_discovery_key_store_cannot_reach_an_out_of_region_mrk() {
    // The contrast half of Dafny's TestGetKeysForMrk: plain Discovery does no
    // region rewrite, so the us-east-1 ARN from the record goes to the
    // us-west-2 client and KMS rejects it.
    let keyring = keyring_for(
        build_discovery_key_store().await,
        EAST_BRANCH_KEY,
        "partition-id-integ-mrdiscovery-negative",
    )
    .await;

    let err = keyring
        .on_encrypt()
        .materials(fresh_materials())
        .send()
        .await
        .expect_err("plain Discovery MUST NOT reach a us-east-1 MRK from a us-west-2 client");
    assert!(err.is_service(), "{:?}", err);

    // Dafny asserts the specific KMS `IncorrectKeyException` here
    // (AwsCryptographyKeyStore/test/TestDiscoveryGetKeys.dfy):
    //
    //     match branchKeyResultSr.error {
    //       case ComAmazonawsKms(nestedError) =>
    //         expect nestedError.IncorrectKeyException?;
    //
    // The keyring returns the key store's error, whose source is the SDK error.
    let sdk_err = err
        .find_source::<SdkError<DecryptError>>()
        .expect("the nested cause must be the originating Decrypt SdkError");
    let service_err = sdk_err
        .as_service_error()
        .expect("KMS rejecting an out-of-region key is a modeled service error");
    assert!(
        service_err.is_incorrect_key_exception(),
        "plain Discovery reaching an out-of-region MRK MUST surface \
         IncorrectKeyException; got: {service_err:?}",
    );
}

#[tokio::test]
async fn integ_mr_discovery_key_store_on_decrypt_round_trips() {
    // GetBranchKeyVersion resolves the record ARN separately from
    // GetActiveBranchKey, so the region rewrite has to hold there too.
    let keyring = keyring_for(
        build_mr_discovery_key_store("us-west-2").await,
        EAST_BRANCH_KEY,
        "partition-id-integ-mrdiscovery-decrypt",
    )
    .await;
    run_round_trip(&keyring, fresh_materials(), EAST_BRANCH_KEY).await;
}

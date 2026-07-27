// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Real-AWS integration tests for [`HierarchicalKeyring::on_encrypt`].
//!
//! All tests are `#[ignore]` and skipped by `cargo test`. To run, AWS
//! credentials with read access to the keystore fixtures are needed
//! (DDB `KeyStoreDdbTable` in account `370957321024`, KMS keys in
//! accounts `370957321024` and `658956600833`).
//!
//! ```text
//! cargo test \
//!     --test test_aws_kms_hierarchical_keyring_integ -- --ignored
//! ```
//!
//! Ported from the Dafny suite at
//! aws-cryptographic-material-providers-library /
//! AwsCryptographicMaterialProviders / dafny / AwsCryptographicMaterialProviders /
//! test / Keyrings / AwsKms / AwsKmsHierarchicalKeyring /
//! `TestAwsKmsHierarchicalKeyring.dfy` (commit `09e485a3...`).
//!
//! Slice 3 ports the on-encrypt half of the Dafny round-trip tests; slice 4
//! ports the encrypt → on_decrypt full round trip. Slice 5 ports the
//! remaining suites (`TestHierarchyClientESDKSuite` second half +
//! `TestSharedCache*`).
//!
//! Two Dafny suites are intentionally NOT ported here:
//! - `TestHierarchyClientDBESuite` — DBE algorithm suites are out of scope
//!   for this Rust implementation (annotated `type=exception` on every DBE /
//!   S3EC variant in `structures/algorithm_suite.rs`).
//! - `TestBranchKeyIdSupplier` and `TestInvalidDataKeyError` — both require
//!   two distinct branch keys configured under the SAME KEY_ARN. The team
//!   keystore currently only has one such key (`BRANCH_KEY_ID`); the second
//!   key (`POSTAL_HORN_BRANCH_KEY_ID`) is intentionally configured with a
//!   mismatched kms-arn for ARN-disagreement tests. The supplier and
//!   wrong-EC failure paths are fully covered by unit tests in
//!   `test_aws_kms_hierarchical_keyring.rs::ondecrypt::*` (the
//!   `*_uses_branch_key_supplier_when_configured`,
//!   `*_skips_edks_with_wrong_branch_key_id`, and `*_collects_per_edk_errors_*`
//!   tests).

use std::sync::Arc;

use aws_config::{BehaviorVersion, Region};
use aws_sdk_dynamodb::Client as DynamoDbClient;
use aws_sdk_kms::Client as KmsClient;

use aws_crypto_mpl::aws_kms::__test_internals::unwrap as branch_key_unwrap;
use aws_crypto_mpl::aws_kms::hierarchical_keyring::{
    BranchKeySource, CacheType, DefaultCache, HierarchicalKeyring,
};
use aws_crypto_mpl::keystore::{BranchKeyStore, Keystore};
use aws_crypto_mpl::structures::{
    AlgorithmSuiteId, BranchKeyMaterials, DecryptionMaterials, EncryptionContext,
    EncryptionMaterials,
};
use aws_crypto_mpl::{KeyStoreConfig, Keyring, KmsConfiguration};

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

async fn build_keystore() -> Arc<dyn Keystore> {
    let (kms, ddb) = build_clients().await;
    Arc::new(
        BranchKeyStore::new(
            KeyStoreConfig {
                table_name: BRANCH_KEY_STORE_NAME.to_string(),
                kms_configuration: KmsConfiguration::KmsKeyArn(KEY_ARN.to_string()),
                logical_keystore_name: LOGICAL_KEY_STORE_NAME.to_string(),
                keystore_id: None,
                aws_kms_grant_tokens: None,
            },
            kms,
            ddb,
        )
        .unwrap(),
    )
}

/// Pick a non-signing suite so signing-key invariants don't intrude.
fn non_signing_suite() -> AlgorithmSuiteId {
    AlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf
}

/// Build empty encryption materials with a small encryption context, in
/// the spirit of the Dafny `GetTestMaterials`.
fn fresh_materials() -> EncryptionMaterials {
    let mut ec = EncryptionContext::new();
    ec.insert(b"region".to_vec(), b"us-west-2".to_vec());
    EncryptionMaterials::new(
        non_signing_suite(),
        Vec::new(),
        ec,
        Default::default(),
        None,
        None,
        None,
    )
    .unwrap()
}

#[tokio::test]
#[ignore]
async fn integ_on_encrypt_round_trips_through_real_keystore_and_kms() {
    let keystore = build_keystore().await;
    let keyring = HierarchicalKeyring::new(
        keystore,
        3600,
        BranchKeySource::Identifier(BRANCH_KEY_ID.to_string()),
        Some(CacheType::Default(DefaultCache::default())),
        Some("partition-id-integ".to_string()),
    )
    .unwrap();

    let materials_in = fresh_materials();
    let ec = materials_in.encryption_context().clone();
    let materials_out = keyring
        .on_encrypt(materials_in)
        .await
        .expect("on_encrypt against real keystore must succeed");

    // Exactly one EDK with the spec's provider id and provider info.
    let edks = materials_out.encrypted_data_keys();
    assert_eq!(edks.len(), 1);
    assert_eq!(edks[0].key_provider_id, "aws-kms-hierarchy");
    assert_eq!(
        edks[0].key_provider_info.as_slice(),
        BRANCH_KEY_ID.as_bytes()
    );

    // Plaintext DK was generated (suite is 32 bytes).
    let pdk = materials_out.plaintext_data_key().unwrap();
    assert_eq!(pdk.len(), 32);

    // Round-trip the EDK ciphertext via branch_key_unwrap by re-fetching
    // the same active branch-key materials from the real keystore. This
    // proves the on-wire EDK ciphertext is decryptable end-to-end with
    // the real KMS-backed branch key, not just the stub fake.
    let real_keystore = build_keystore().await;
    let bkm: BranchKeyMaterials = real_keystore
        .get_active_branch_key(BRANCH_KEY_ID.to_string())
        .await
        .unwrap();
    assert_eq!(bkm.branch_key_version(), BRANCH_KEY_ACTIVE_VERSION);

    let recovered = branch_key_unwrap(&bkm, &ec, &edks[0].ciphertext)
        .expect("EDK ciphertext MUST round-trip through real branch key materials");
    assert_eq!(recovered, pdk.as_bytes());
}

#[tokio::test]
#[ignore]
async fn integ_on_encrypt_caches_branch_key_across_two_calls() {
    // Two on_encrypt calls with the same branch_key_id should hit the
    // keystore exactly once. We can't observe keystore call counts from
    // outside the BranchKeyStore (no fake / spy), but we can observe
    // wall-clock latency: the second call should be substantially
    // faster because no DDB GetItem + KMS Decrypt round-trip happens.
    use std::time::Instant;

    let keystore = build_keystore().await;
    let keyring = HierarchicalKeyring::new(
        keystore,
        3600,
        BranchKeySource::Identifier(BRANCH_KEY_ID.to_string()),
        Some(CacheType::Default(DefaultCache::default())),
        Some("partition-id-integ-cache".to_string()),
    )
    .unwrap();

    let t0 = Instant::now();
    let _ = keyring.on_encrypt(fresh_materials()).await.unwrap();
    let cold = t0.elapsed();

    let t1 = Instant::now();
    let _ = keyring.on_encrypt(fresh_materials()).await.unwrap();
    let warm = t1.elapsed();

    assert!(
        warm * 5 < cold,
        "second on_encrypt should be at least 5x faster than the first \
         (cold={:?}, warm={:?}); cache may not be in use",
        cold,
        warm
    );
}

#[tokio::test]
#[ignore]
async fn integ_on_decrypt_round_trips_through_real_keystore_and_kms() {
    // Full encrypt → decrypt round trip against the real keystore. Proves
    // the EDK ciphertext produced by on_encrypt is decryptable by
    // on_decrypt going through:
    //   1. Branch-key id resolution
    //   2. Logical keystore name lookup (DDB GetItem path on get_key_store_info)
    //   3. Cache lookup (decrypt scope id) — MISS, since on_encrypt cached
    //      under the encrypt scope id, which is a different key
    //   4. keystore.get_branch_key_version(branch_key_id, version) call
    //      (DDB GetItem + KMS Decrypt for the version-specific record)
    //   5. branch_key_unwrap with the input DM's encryption context
    let keystore = build_keystore().await;
    let keyring = HierarchicalKeyring::new(
        keystore,
        3600,
        BranchKeySource::Identifier(BRANCH_KEY_ID.to_string()),
        Some(CacheType::Default(DefaultCache::default())),
        Some("partition-id-integ-decrypt".to_string()),
    )
    .unwrap();

    let materials_in = fresh_materials();
    let ec = materials_in.encryption_context().clone();
    let materials_out = keyring.on_encrypt(materials_in).await.unwrap();
    let pdk_bytes = materials_out
        .plaintext_data_key()
        .unwrap()
        .as_bytes()
        .to_vec();
    let edks = materials_out.encrypted_data_keys().to_vec();

    // Build empty decryption materials with the same EC the encrypt side
    // used; the AAD bound into the EDK ciphertext is computed over this EC.
    let dm_in = DecryptionMaterials::new(
        non_signing_suite(),
        ec,
        Default::default(),
        None,
        None,
        None,
    )
    .unwrap();
    let dm_out = keyring
        .on_decrypt(dm_in, &edks)
        .await
        .expect("on_decrypt against real keystore must succeed for an EDK we just produced");

    assert_eq!(
        dm_out.plaintext_data_key().unwrap().as_bytes(),
        pdk_bytes,
        "on_decrypt must recover the same plaintext data key on_encrypt set",
    );
}

#[tokio::test]
#[ignore]
async fn integ_on_decrypt_caches_branch_key_version_across_two_calls() {
    // First on_decrypt MUST hit the keystore (cache miss). Second
    // on_decrypt MUST be served entirely from the cache. We can't observe
    // keystore call counts directly through the BranchKeyStore API, but
    // we can observe the latency difference: a cached on_decrypt skips
    // the DDB GetItem + KMS Decrypt round-trip and is dramatically faster.
    use std::time::Instant;

    let keystore = build_keystore().await;
    let keyring = HierarchicalKeyring::new(
        keystore,
        3600,
        BranchKeySource::Identifier(BRANCH_KEY_ID.to_string()),
        Some(CacheType::Default(DefaultCache::default())),
        Some("partition-id-integ-decrypt-cache".to_string()),
    )
    .unwrap();

    let materials_in = fresh_materials();
    let ec = materials_in.encryption_context().clone();
    let materials_out = keyring.on_encrypt(materials_in).await.unwrap();
    let edks = materials_out.encrypted_data_keys().to_vec();

    let make_dm = || {
        DecryptionMaterials::new(
            non_signing_suite(),
            ec.clone(),
            Default::default(),
            None,
            None,
            None,
        )
        .unwrap()
    };

    let t0 = Instant::now();
    let _ = keyring.on_decrypt(make_dm(), &edks).await.unwrap();
    let cold = t0.elapsed();

    let t1 = Instant::now();
    let _ = keyring.on_decrypt(make_dm(), &edks).await.unwrap();
    let warm = t1.elapsed();

    assert!(
        warm * 5 < cold,
        "second on_decrypt should be at least 5x faster than the first \
         (cold={:?}, warm={:?}); cache may not be in use",
        cold,
        warm
    );
}

// ─── Helpers for shared-cache tests ────────────────────────────────────────

/// Build a KMS client pinned to the supplied region. Mirrors Dafny's
/// `KMS.KMSClientForRegion`.
async fn kms_client_for_region(region: &'static str) -> KmsClient {
    let cfg = aws_config::defaults(BehaviorVersion::latest())
        .region(Region::new(region))
        .load()
        .await;
    KmsClient::new(&cfg)
}

/// Build a DynamoDB client pinned to `us-west-2` (where the test table
/// lives, regardless of which KMS region the keystore is using).
async fn ddb_client_us_west_2() -> DynamoDbClient {
    let cfg = aws_config::defaults(BehaviorVersion::latest())
        .region(Region::new("us-west-2"))
        .load()
        .await;
    DynamoDbClient::new(&cfg)
}

/// Build a `BranchKeyStore` with the supplied KMS client and logical
/// keystore name. The DDB client is pinned to `us-west-2`.
async fn build_keystore_with_kms_and_logical_name(
    kms: KmsClient,
    logical_keystore_name: &str,
) -> Arc<dyn Keystore> {
    Arc::new(
        BranchKeyStore::new(
            KeyStoreConfig {
                table_name: BRANCH_KEY_STORE_NAME.to_string(),
                kms_configuration: KmsConfiguration::KmsKeyArn(KEY_ARN.to_string()),
                logical_keystore_name: logical_keystore_name.to_string(),
                keystore_id: None,
                aws_kms_grant_tokens: None,
            },
            kms,
            ddb_client_us_west_2().await,
        )
        .unwrap(),
    )
}

/// Run an `on_encrypt` → `on_decrypt` round trip and assert the recovered
/// PDK matches. Mirrors Dafny's `TestRoundtrip`.
async fn run_round_trip(
    keyring: &HierarchicalKeyring,
    materials_in: EncryptionMaterials,
    expected_branch_key_id: &str,
) {
    let suite_id = materials_in.algorithm_suite_id();
    let ec = materials_in.encryption_context().clone();

    let materials_out = keyring
        .on_encrypt(materials_in)
        .await
        .expect("on_encrypt against real keystore must succeed");

    // Verify the EDK was created with the expected branch key id.
    let edks = materials_out.encrypted_data_keys().to_vec();
    assert_eq!(edks.len(), 1);
    assert_eq!(edks[0].key_provider_id, "aws-kms-hierarchy");
    assert_eq!(
        edks[0].key_provider_info.as_slice(),
        expected_branch_key_id.as_bytes(),
        "EDK provider_info MUST equal the configured branch_key_id",
    );
    let pdk_bytes = materials_out
        .plaintext_data_key()
        .unwrap()
        .as_bytes()
        .to_vec();

    let dm_in =
        DecryptionMaterials::new(suite_id, ec, Default::default(), None, None, None).unwrap();
    let dm_out = keyring
        .on_decrypt(dm_in, &edks)
        .await
        .expect("on_decrypt against real keystore must succeed for an EDK we just produced");

    assert_eq!(
        dm_out.plaintext_data_key().unwrap().as_bytes(),
        pdk_bytes,
        "round trip MUST recover the same plaintext data key on_encrypt set",
    );
}

// ─── TestHierarchyClientESDKSuite — pre-existing PDK variant ───────────────

#[tokio::test]
#[ignore]
async fn integ_on_encrypt_with_pre_existing_pdk_round_trips() {
    // Second half of Dafny `TestHierarchyClientESDKSuite`: encrypt with
    // a caller-supplied (zeroed) PDK. on_encrypt MUST preserve the PDK
    // (per `#onencrypt` "If the input materials' plaintext data key is
    // not empty ... MUST use the existing plaintext data key") and the
    // produced EDK MUST round-trip back to the same PDK on decrypt.
    let keystore = build_keystore().await;
    let keyring = HierarchicalKeyring::new(
        keystore,
        3600,
        BranchKeySource::Identifier(BRANCH_KEY_ID.to_string()),
        Some(CacheType::Default(DefaultCache::default())),
        Some("partition-id-integ-existing-pdk".to_string()),
    )
    .unwrap();

    let suite = non_signing_suite();
    let key_len = suite.specification().encryption_key_length();
    let zeroed = vec![0u8; key_len];

    let mut ec = EncryptionContext::new();
    ec.insert(b"region".to_vec(), b"us-west-2".to_vec());
    let materials_in = EncryptionMaterials::new(
        suite,
        Vec::new(),
        ec,
        Default::default(),
        Some(aws_crypto_mpl::structures::PlaintextDataKey::new(
            zeroed.clone(),
        )),
        None,
        None,
    )
    .unwrap();

    run_round_trip(&keyring, materials_in, BRANCH_KEY_ID).await;
}

// ─── TestSharedCache* suites ───────────────────────────────────────────────
//
// These four tests mirror the Dafny `TestSharedCache*` suites. They each
// build two `HierarchicalKeyring`s (HK1, HK2) that share a single
// `LocalCmc` via `CacheType::Shared`. HK1's keystore uses a us-west-2 KMS
// client; HK2's keystore uses a us-east-2 KMS client. KEY_ARN is in
// us-west-2, so any KMS Decrypt issued by HK2's keystore fails.
//
// The four tests differ only in (partition_id, logical_keystore_name)
// configuration and observe whether HK1's cache entry is reachable from
// HK2 — i.e., they verify the cache identifier formula at
// `#appendix-a-cache-entry-identifier-formulas` binds those exact fields.

/// Build a non-signing-suite encryption materials with a small EC. Mirrors
/// the Dafny `GetTestMaterials(TEST_ESDK_ALG_SUITE_ID)` call.
fn shared_cache_materials() -> EncryptionMaterials {
    fresh_materials()
}

/// Build a fresh `LocalCmc` wrapped in `Arc<dyn Cmc>`, suitable for
/// constructing a `CacheType::Shared` for each of HK1 and HK2.
fn shared_cache_arc() -> Arc<dyn aws_crypto_mpl::Cmc> {
    use aws_crypto_mpl::{Cmc, LocalCmc};
    let local: Arc<dyn Cmc> = Arc::new(LocalCmc::new(100, 50).unwrap());
    local
}

#[tokio::test]
#[ignore]
async fn integ_shared_cache_with_same_partition_id_and_same_logical_keystore_name() {
    // HK1 and HK2 share Partition ID, Logical Key Store Name, and Branch
    // Key ID — so per `#shared-cache-considerations` they MUST share cache
    // entries. After HK1's round trip populates the cache, HK2's encrypt
    // (which would otherwise fail because its KMS client is us-east-2 and
    // the key is us-west-2) succeeds entirely from the cached entry.
    let keystore_west = build_keystore_with_kms_and_logical_name(
        kms_client_for_region("us-west-2").await,
        LOGICAL_KEY_STORE_NAME,
    )
    .await;
    let keystore_east = build_keystore_with_kms_and_logical_name(
        kms_client_for_region("us-east-2").await,
        LOGICAL_KEY_STORE_NAME,
    )
    .await;

    let cache_arc = shared_cache_arc();

    let hk1 = HierarchicalKeyring::new(
        keystore_west,
        3600,
        BranchKeySource::Identifier(BRANCH_KEY_ID.to_string()),
        Some(CacheType::Shared(Arc::clone(&cache_arc))),
        Some("partitionId".to_string()),
    )
    .unwrap();
    let hk2 = HierarchicalKeyring::new(
        keystore_east,
        3600,
        BranchKeySource::Identifier(BRANCH_KEY_ID.to_string()),
        Some(CacheType::Shared(cache_arc)),
        Some("partitionId".to_string()),
    )
    .unwrap();

    // HK2 encrypt fails first (cache empty, KMS region mismatch).
    let err = hk2.on_encrypt(shared_cache_materials()).await;
    assert!(
        err.is_err(),
        "HK2 on_encrypt MUST fail before the cache is populated (KMS region mismatch)",
    );

    // HK1 round-trip succeeds (and populates the shared cache).
    run_round_trip(&hk1, shared_cache_materials(), BRANCH_KEY_ID).await;

    //
    //
    //
    run_round_trip(&hk2, shared_cache_materials(), BRANCH_KEY_ID).await;
}

#[tokio::test]
#[ignore]
async fn integ_shared_cache_with_different_unspecified_partition_id_and_same_logical_keystore_name()
{
    // HK1 and HK2 leave partition_id = None, so each keyring generates a
    // fresh v4 UUID. The cache identifier binds the partition id, so the
    // entries do NOT collide and HK2's second encrypt MUST still fail.
    let keystore_west = build_keystore_with_kms_and_logical_name(
        kms_client_for_region("us-west-2").await,
        LOGICAL_KEY_STORE_NAME,
    )
    .await;
    let keystore_east = build_keystore_with_kms_and_logical_name(
        kms_client_for_region("us-east-2").await,
        LOGICAL_KEY_STORE_NAME,
    )
    .await;

    let cache_arc = shared_cache_arc();

    let hk1 = HierarchicalKeyring::new(
        keystore_west,
        3600,
        BranchKeySource::Identifier(BRANCH_KEY_ID.to_string()),
        Some(CacheType::Shared(Arc::clone(&cache_arc))),
        None,
    )
    .unwrap();
    let hk2 = HierarchicalKeyring::new(
        keystore_east,
        3600,
        BranchKeySource::Identifier(BRANCH_KEY_ID.to_string()),
        Some(CacheType::Shared(cache_arc)),
        None,
    )
    .unwrap();

    assert!(
        hk2.on_encrypt(shared_cache_materials()).await.is_err(),
        "HK2 on_encrypt MUST fail before the cache is populated",
    );

    run_round_trip(&hk1, shared_cache_materials(), BRANCH_KEY_ID).await;

    assert!(
        hk2.on_encrypt(shared_cache_materials()).await.is_err(),
        "HK2 on_encrypt MUST still fail — distinct random partition ids prevent cache reuse",
    );
}

#[tokio::test]
#[ignore]
async fn integ_shared_cache_with_different_specified_partition_id_and_same_logical_keystore_name() {
    // HK1 and HK2 set explicit, distinct partition ids. Cache miss
    // expected: HK2's encrypt MUST still fail.
    let keystore_west = build_keystore_with_kms_and_logical_name(
        kms_client_for_region("us-west-2").await,
        LOGICAL_KEY_STORE_NAME,
    )
    .await;
    let keystore_east = build_keystore_with_kms_and_logical_name(
        kms_client_for_region("us-east-2").await,
        LOGICAL_KEY_STORE_NAME,
    )
    .await;

    let cache_arc = shared_cache_arc();

    let hk1 = HierarchicalKeyring::new(
        keystore_west,
        3600,
        BranchKeySource::Identifier(BRANCH_KEY_ID.to_string()),
        Some(CacheType::Shared(Arc::clone(&cache_arc))),
        Some("partitionIdHK1".to_string()),
    )
    .unwrap();
    let hk2 = HierarchicalKeyring::new(
        keystore_east,
        3600,
        BranchKeySource::Identifier(BRANCH_KEY_ID.to_string()),
        Some(CacheType::Shared(cache_arc)),
        Some("partitionIdHK2".to_string()),
    )
    .unwrap();

    assert!(
        hk2.on_encrypt(shared_cache_materials()).await.is_err(),
        "HK2 on_encrypt MUST fail before the cache is populated",
    );

    run_round_trip(&hk1, shared_cache_materials(), BRANCH_KEY_ID).await;

    assert!(
        hk2.on_encrypt(shared_cache_materials()).await.is_err(),
        "HK2 on_encrypt MUST still fail — distinct partition ids prevent cache reuse",
    );
}

#[tokio::test]
#[ignore]
async fn integ_shared_cache_with_same_partition_id_and_different_logical_keystore_name() {
    // HK1 and HK2 share Partition ID but differ in Logical Key Store Name.
    // Cache identifier binds the logical keystore name, so HK2's encrypt
    // MUST still fail after HK1's round trip populates the cache.
    let keystore_west = build_keystore_with_kms_and_logical_name(
        kms_client_for_region("us-west-2").await,
        LOGICAL_KEY_STORE_NAME,
    )
    .await;
    let keystore_east = build_keystore_with_kms_and_logical_name(
        kms_client_for_region("us-east-2").await,
        &format!("{LOGICAL_KEY_STORE_NAME}New"),
    )
    .await;

    let cache_arc = shared_cache_arc();

    let hk1 = HierarchicalKeyring::new(
        keystore_west,
        3600,
        BranchKeySource::Identifier(BRANCH_KEY_ID.to_string()),
        Some(CacheType::Shared(Arc::clone(&cache_arc))),
        Some("partitionId".to_string()),
    )
    .unwrap();
    let hk2 = HierarchicalKeyring::new(
        keystore_east,
        3600,
        BranchKeySource::Identifier(BRANCH_KEY_ID.to_string()),
        Some(CacheType::Shared(cache_arc)),
        Some("partitionId".to_string()),
    )
    .unwrap();

    assert!(
        hk2.on_encrypt(shared_cache_materials()).await.is_err(),
        "HK2 on_encrypt MUST fail before the cache is populated",
    );

    run_round_trip(&hk1, shared_cache_materials(), BRANCH_KEY_ID).await;

    assert!(
        hk2.on_encrypt(shared_cache_materials()).await.is_err(),
        "HK2 on_encrypt MUST still fail — different logical keystore names prevent cache reuse",
    );
}

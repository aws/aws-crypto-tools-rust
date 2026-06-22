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
//! cargo test --features keystore \
//!     --test test_aws_kms_hierarchical_keyring_integ -- --ignored
//! ```
//!
//! Ported from the Dafny suite at
//! aws-cryptographic-material-providers-library /
//! AwsCryptographicMaterialProviders / dafny / AwsCryptographicMaterialProviders /
//! test / Keyrings / AwsKms / AwsKmsHierarchicalKeyring /
//! `TestAwsKmsHierarchicalKeyring.dfy` (commit `09e485a3...`).
//!
//! Slice 3 ports the on-encrypt half of the Dafny round-trip tests; the
//! decrypt half lands in slice 4 once `on_decrypt` is implemented.

#![cfg(feature = "keystore")]

use std::sync::Arc;

use aws_config::{BehaviorVersion, Region};
use aws_sdk_dynamodb::Client as DynamoDbClient;
use aws_sdk_kms::Client as KmsClient;

use aws_crypto_mpl::aws_kms::__test_internals::unwrap as branch_key_unwrap;
use aws_crypto_mpl::aws_kms::hierarchical_keyring::{
    BranchKeySource, CacheType, HierarchicalKeyring,
};
use aws_crypto_mpl::keystore::{BranchKeyStore, Keystore};
use aws_crypto_mpl::structures::{
    AlgorithmSuiteId, BranchKeyMaterials, EncryptionContext, EncryptionMaterials,
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
        Some(CacheType::Default),
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
        Some(CacheType::Default),
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

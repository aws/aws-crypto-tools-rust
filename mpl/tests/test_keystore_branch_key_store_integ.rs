// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Real-AWS integration tests for the [`BranchKeyStore`] read path.
//!
//! All tests in this file are marked `#[ignore]` and therefore skipped
//! by `cargo test`. To run them you need:
//!
//! 1. AWS credentials with read access to the test resources (DDB
//!    `KeyStoreDdbTable` in account `370957321024`, KMS keys in
//!    accounts `370957321024` and `658956600833`).
//! 2. A region default of `us-west-2` (where the DDB table lives). The
//!    multi-region MRK tests build per-region KMS clients explicitly.
//!
//! Run with:
//!
//! ```text
//! cargo test \
//!     --test test_keystore_branch_key_store_integ -- --ignored
//! ```
//!
//! The fixtures, branch-key ids, KMS ARNs and assertions are ported
//! from the Dafny test suite at
//! `aws-cryptographic-material-providers-library` /
//! `AwsCryptographicMaterialProviders/dafny/AwsCryptographyKeyStore/test/`
//! (commit `09e485a3...`), specifically `Fixtures.dfy` and
//! `TestGetKeys.dfy`. Slice 1b ports the read-path tests only;
//! `TestGetBeaconKey`, `TestGetActiveKeyWithNoClients`, and the
//! `VersionKey`/`CreateKey` suites land in later slices.

use aws_config::{BehaviorVersion, Region};
use aws_sdk_dynamodb::Client as DynamoDbClient;
use aws_sdk_kms::Client as KmsClient;

use aws_crypto_mpl::{
    BranchKeyStore, KeyStoreConfig, Keystore, KmsConfiguration, keystore::KeystoreErrorKind,
};

// ─── Fixtures (mirror Fixtures.dfy) ─────────────────────────────────────────

const BRANCH_KEY_STORE_NAME: &str = "KeyStoreDdbTable";
const LOGICAL_KEY_STORE_NAME: &str = "KeyStoreDdbTable";

const BRANCH_KEY_ID: &str = "3f43a9af-08c5-4317-b694-3d3e883dcaef";
const BRANCH_KEY_ACTIVE_VERSION: &str = "caf0c508-e64d-4b6c-bffe-381cbc546c02";

const KEY_ARN: &str = "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126";

const MRK_ARN_EAST: &str =
    "arn:aws:kms:us-east-1:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7";
const MRK_ARN_WEST: &str =
    "arn:aws:kms:us-west-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7";
// MRK key MUST NOT exist in ap-south-2 — used to assert KMS-side failure.
const MRK_ARN_AP: &str =
    "arn:aws:kms:ap-south-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7";

const EAST_BRANCH_KEY: &str = "MyEastBranch2";
const WEST_BRANCH_KEY: &str = "MyWestBranch2";

/// A branch-key id whose `kms-arn` field intentionally does NOT match
/// `KEY_ARN` — used to exercise the ARN-disagreement path.
const POSTAL_HORN_BRANCH_KEY_ID: &str = "682dfba7-4c35-491d-8d6a-5a9c56194061";

const INCORRECT_LOGICAL_NAME: &str = "MySuperAwesomeTableName";

// ─── Client construction ────────────────────────────────────────────────────

/// Build a DynamoDB client pinned to `us-west-2` (where the test table
/// lives). The user's environment supplies credentials.
async fn ddb_client_us_west_2() -> DynamoDbClient {
    let cfg = aws_config::defaults(BehaviorVersion::latest())
        .region(Region::new("us-west-2"))
        .load()
        .await;
    DynamoDbClient::new(&cfg)
}

/// Build a KMS client pinned to the supplied region.
async fn kms_client_for_region(region: &'static str) -> KmsClient {
    let cfg = aws_config::defaults(BehaviorVersion::latest())
        .region(Region::new(region))
        .load()
        .await;
    KmsClient::new(&cfg)
}

/// Common config builder. Slice-1b tests vary `kms_configuration` and
/// `logical_keystore_name`; everything else is constant.
fn keystore_config(
    kms_configuration: KmsConfiguration,
    logical_keystore_name: &str,
) -> KeyStoreConfig {
    KeyStoreConfig {
        ddb_table_name: BRANCH_KEY_STORE_NAME.to_string(),
        kms_configuration,
        logical_keystore_name: logical_keystore_name.to_string(),
        id: None,
        grant_tokens: None,
    }
}

// ─── TestGetActiveKey ───────────────────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn integ_get_active_branch_key_returns_expected_materials() {
    let kms = kms_client_for_region("us-west-2").await;
    let ddb = ddb_client_us_west_2().await;
    let store = BranchKeyStore::new(
        keystore_config(
            KmsConfiguration::KmsKeyArn(KEY_ARN.to_string()),
            LOGICAL_KEY_STORE_NAME,
        ),
        kms,
        ddb,
    )
    .unwrap();

    let materials = store
        .get_active_branch_key(BRANCH_KEY_ID.to_string())
        .await
        .expect("active branch key fetch must succeed");

    assert_eq!(materials.branch_key_id(), BRANCH_KEY_ID);
    assert_eq!(materials.branch_key_version(), BRANCH_KEY_ACTIVE_VERSION);
    assert_eq!(materials.branch_key().len(), 32);
}

// ─── TestGetBranchKeyVersion ────────────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn integ_get_branch_key_version_returns_expected_materials() {
    let kms = kms_client_for_region("us-west-2").await;
    let ddb = ddb_client_us_west_2().await;
    let store = BranchKeyStore::new(
        keystore_config(
            KmsConfiguration::KmsKeyArn(KEY_ARN.to_string()),
            LOGICAL_KEY_STORE_NAME,
        ),
        kms,
        ddb,
    )
    .unwrap();

    let materials = store
        .get_branch_key_version(
            BRANCH_KEY_ID.to_string(),
            BRANCH_KEY_ACTIVE_VERSION.to_string(),
        )
        .await
        .expect("branch key version fetch must succeed");

    assert_eq!(materials.branch_key_id(), BRANCH_KEY_ID);
    assert_eq!(materials.branch_key_version(), BRANCH_KEY_ACTIVE_VERSION);
    assert_eq!(materials.branch_key().len(), 32);
}

// ─── TestGetActiveMrkKey: same-region happy paths ───────────────────────────

#[tokio::test]
#[ignore]
async fn integ_get_active_mrk_key_west_kmskeyarn_west_branch() {
    let store = BranchKeyStore::new(
        keystore_config(
            KmsConfiguration::KmsKeyArn(MRK_ARN_WEST.to_string()),
            LOGICAL_KEY_STORE_NAME,
        ),
        kms_client_for_region("us-west-2").await,
        ddb_client_us_west_2().await,
    )
    .unwrap();
    let materials = store
        .get_active_branch_key(WEST_BRANCH_KEY.to_string())
        .await
        .expect("west KmsKeyArn + WestBranchKey must succeed");
    assert_eq!(materials.branch_key_id(), WEST_BRANCH_KEY);
    assert_eq!(materials.branch_key().len(), 32);
}

#[tokio::test]
#[ignore]
async fn integ_get_active_mrk_key_east_kmskeyarn_east_branch() {
    let store = BranchKeyStore::new(
        keystore_config(
            KmsConfiguration::KmsKeyArn(MRK_ARN_EAST.to_string()),
            LOGICAL_KEY_STORE_NAME,
        ),
        kms_client_for_region("us-east-1").await,
        ddb_client_us_west_2().await,
    )
    .unwrap();
    let materials = store
        .get_active_branch_key(EAST_BRANCH_KEY.to_string())
        .await
        .expect("east KmsKeyArn + EastBranchKey must succeed");
    assert_eq!(materials.branch_key_id(), EAST_BRANCH_KEY);
    assert_eq!(materials.branch_key().len(), 32);
}

#[tokio::test]
#[ignore]
async fn integ_get_active_mrk_key_west_mrk_west_branch() {
    let store = BranchKeyStore::new(
        keystore_config(
            KmsConfiguration::KmsMrKeyArn(MRK_ARN_WEST.to_string()),
            LOGICAL_KEY_STORE_NAME,
        ),
        kms_client_for_region("us-west-2").await,
        ddb_client_us_west_2().await,
    )
    .unwrap();
    let materials = store
        .get_active_branch_key(WEST_BRANCH_KEY.to_string())
        .await
        .expect("west KmsMrKeyArn + WestBranchKey must succeed");
    assert_eq!(materials.branch_key_id(), WEST_BRANCH_KEY);
    assert_eq!(materials.branch_key().len(), 32);
}

#[tokio::test]
#[ignore]
async fn integ_get_active_mrk_key_east_mrk_east_branch() {
    let store = BranchKeyStore::new(
        keystore_config(
            KmsConfiguration::KmsMrKeyArn(MRK_ARN_EAST.to_string()),
            LOGICAL_KEY_STORE_NAME,
        ),
        kms_client_for_region("us-east-1").await,
        ddb_client_us_west_2().await,
    )
    .unwrap();
    let materials = store
        .get_active_branch_key(EAST_BRANCH_KEY.to_string())
        .await
        .expect("east KmsMrKeyArn + EastBranchKey must succeed");
    assert_eq!(materials.branch_key_id(), EAST_BRANCH_KEY);
    assert_eq!(materials.branch_key().len(), 32);
}

// ─── TestGetActiveMrkKey: MRK cross-region success ──────────────────────────

#[tokio::test]
#[ignore]
async fn integ_get_active_mrk_key_west_mrk_fetches_east_branch() {
    let store = BranchKeyStore::new(
        keystore_config(
            KmsConfiguration::KmsMrKeyArn(MRK_ARN_WEST.to_string()),
            LOGICAL_KEY_STORE_NAME,
        ),
        kms_client_for_region("us-west-2").await,
        ddb_client_us_west_2().await,
    )
    .unwrap();
    let materials = store
        .get_active_branch_key(EAST_BRANCH_KEY.to_string())
        .await
        .expect("KmsMrKeyArn(west) + EastBranchKey must succeed via MRK match");
    assert_eq!(materials.branch_key_id(), EAST_BRANCH_KEY);
    assert_eq!(materials.branch_key().len(), 32);
}

#[tokio::test]
#[ignore]
async fn integ_get_active_mrk_key_east_mrk_fetches_west_branch() {
    let store = BranchKeyStore::new(
        keystore_config(
            KmsConfiguration::KmsMrKeyArn(MRK_ARN_EAST.to_string()),
            LOGICAL_KEY_STORE_NAME,
        ),
        kms_client_for_region("us-east-1").await,
        ddb_client_us_west_2().await,
    )
    .unwrap();
    let materials = store
        .get_active_branch_key(WEST_BRANCH_KEY.to_string())
        .await
        .expect("KmsMrKeyArn(east) + WestBranchKey must succeed via MRK match");
    assert_eq!(materials.branch_key_id(), WEST_BRANCH_KEY);
    assert_eq!(materials.branch_key().len(), 32);
}

// ─── TestGetActiveMrkKey: KmsKeyArn cross-region disagreement ──────────────

#[tokio::test]
#[ignore]
async fn integ_get_active_kmskeyarn_west_fetches_east_branch_fails() {
    let store = BranchKeyStore::new(
        keystore_config(
            KmsConfiguration::KmsKeyArn(MRK_ARN_WEST.to_string()),
            LOGICAL_KEY_STORE_NAME,
        ),
        kms_client_for_region("us-west-2").await,
        ddb_client_us_west_2().await,
    )
    .unwrap();
    let err = match store
        .get_active_branch_key(EAST_BRANCH_KEY.to_string())
        .await
    {
        Ok(_) => panic!("KmsKeyArn(west) + EastBranchKey must fail (single-region match strict)"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), &KeystoreErrorKind::Authentication);
}

#[tokio::test]
#[ignore]
async fn integ_get_active_kmskeyarn_east_fetches_west_branch_fails() {
    let store = BranchKeyStore::new(
        keystore_config(
            KmsConfiguration::KmsKeyArn(MRK_ARN_EAST.to_string()),
            LOGICAL_KEY_STORE_NAME,
        ),
        kms_client_for_region("us-east-1").await,
        ddb_client_us_west_2().await,
    )
    .unwrap();
    let err = match store
        .get_active_branch_key(WEST_BRANCH_KEY.to_string())
        .await
    {
        Ok(_) => panic!("KmsKeyArn(east) + WestBranchKey must fail (single-region match strict)"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), &KeystoreErrorKind::Authentication);
}

// ─── TestGetActiveMrkKey: AP MRK config (key absent in region) ──────────────

#[tokio::test]
#[ignore]
async fn integ_get_active_mrk_key_ap_config_fails_at_kms() {
    let store = BranchKeyStore::new(
        keystore_config(
            KmsConfiguration::KmsMrKeyArn(MRK_ARN_AP.to_string()),
            LOGICAL_KEY_STORE_NAME,
        ),
        kms_client_for_region("ap-south-2").await,
        ddb_client_us_west_2().await,
    )
    .unwrap();
    let err = match store
        .get_active_branch_key(WEST_BRANCH_KEY.to_string())
        .await
    {
        Ok(_) => panic!("KmsMrKeyArn(ap-south-2) MUST fail — key does not exist in AP"),
        Err(e) => e,
    };
    // Dafny test asserts the error is a KMS opaque error; we map any
    // KMS SDK error to KeystoreErrorKind::Kms.
    assert_eq!(err.kind(), &KeystoreErrorKind::Kms);
}

// ─── TestGetActiveKeyWithIncorrectKmsKeyArn ────────────────────────────────

#[tokio::test]
#[ignore]
async fn integ_get_active_key_with_arn_disagreement_fails() {
    // KEY_ARN is configured but POSTAL_HORN_BRANCH_KEY_ID's record was
    // created with a different KMS ARN — the kms-arn-compat check in
    // resolve_keystore_arn rejects with Authentication errkind.
    let store = BranchKeyStore::new(
        keystore_config(
            KmsConfiguration::KmsKeyArn(KEY_ARN.to_string()),
            LOGICAL_KEY_STORE_NAME,
        ),
        kms_client_for_region("us-west-2").await,
        ddb_client_us_west_2().await,
    )
    .unwrap();
    let err = match store
        .get_active_branch_key(POSTAL_HORN_BRANCH_KEY_ID.to_string())
        .await
    {
        Ok(_) => panic!("Configured KEY_ARN + postalHornBranchKeyId MUST fail (ARN mismatch)"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), &KeystoreErrorKind::Authentication);
}

// ─── TestGetActiveKeyWrongLogicalKeyStoreName ──────────────────────────────

#[tokio::test]
#[ignore]
async fn integ_get_active_key_wrong_logical_name_fails_at_kms() {
    // A wrong logical name binds a different `tablename` value into the
    // EC, so KMS Decrypt fails to authenticate and returns
    // InvalidCiphertextException — mapped to KeystoreErrorKind::Kms.
    let store = BranchKeyStore::new(
        keystore_config(
            KmsConfiguration::KmsKeyArn(KEY_ARN.to_string()),
            INCORRECT_LOGICAL_NAME,
        ),
        kms_client_for_region("us-west-2").await,
        ddb_client_us_west_2().await,
    )
    .unwrap();
    let err = match store.get_active_branch_key(BRANCH_KEY_ID.to_string()).await {
        Ok(_) => panic!("Wrong logical name MUST fail at KMS"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), &KeystoreErrorKind::Kms);
}

// ─── TestGetActiveKeyDoesNotExistFails ─────────────────────────────────────

#[tokio::test]
#[ignore]
async fn integ_get_active_key_does_not_exist() {
    let store = BranchKeyStore::new(
        keystore_config(
            KmsConfiguration::KmsKeyArn(KEY_ARN.to_string()),
            LOGICAL_KEY_STORE_NAME,
        ),
        kms_client_for_region("us-west-2").await,
        ddb_client_us_west_2().await,
    )
    .unwrap();
    let err = match store.get_active_branch_key("Robbie".to_string()).await {
        Ok(_) => panic!("nonexistent branch key MUST fail with RecordNotFound"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), &KeystoreErrorKind::RecordNotFound);
}

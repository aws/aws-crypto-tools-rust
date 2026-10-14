// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Real-AWS integration tests for the DynamoDB key store read path.
//!
//! These tests call real AWS and run in CI via the OIDC-assumed role.
//! They require read access to the test resources (DDB `KeyStoreDdbTable`
//! in account `370957321024`, KMS keys in accounts `370957321024` and
//! `658956600833`). The DDB table lives in `us-west-2`; the multi-region
//! MRK tests build per-region KMS clients explicitly.
//!
//! The fixtures, branch-key ids, KMS ARNs and assertions are ported
//! from the Dafny test suite at
//! `aws-cryptographic-material-providers-library` /
//! `AwsCryptographicMaterialProviders/dafny/AwsCryptographyKeyStore/test/`
//! (`Fixtures.dfy` and `TestGetKeys.dfy`).

use std::error::Error as _;

use aws_config::{BehaviorVersion, Region};
use aws_sdk_dynamodb::Client as DynamoDbClient;
use aws_sdk_dynamodb::operation::get_item::GetItemError;
use aws_sdk_dynamodb::types::AttributeValue;
use aws_sdk_kms::Client as KmsClient;
use aws_sdk_kms::error::SdkError;
use aws_sdk_kms::operation::decrypt::DecryptError;

use aws_crypto_mpl::error_chain::aws_service_error_code;
use aws_crypto_mpl::{KeyStoreClient, KeyStoreConfig, KmsConfiguration};

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
/// `KEY_ARN` — used to exercise the ARN-disagreement path. This is Dafny's
/// `postalHornBranchKeyId` fixture in
/// AwsCryptographyKeyStore/test/Fixtures.dfy.
const DISCOVERY_BRANCH_KEY_ID: &str = "682dfba7-4c35-491d-8d6a-5a9c56194061";

const INCORRECT_LOGICAL_NAME: &str = "MySuperAwesomeTableName";

// ─── Client construction ────────────────────────────────────────────────────

/// Build a DynamoDB client pinned to `us-west-2` (where the test table
/// lives). Credentials come from the CI OIDC role / the caller's env.
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

/// Build a DynamoDB key store for the given KMS configuration, logical
/// key store name, and explicit region-pinned clients. The clients are
/// supplied via the config so no default client is constructed.
async fn build_store(
    kms_configuration: KmsConfiguration,
    logical_key_store_name: &str,
    kms_client: KmsClient,
    ddb_client: DynamoDbClient,
) -> KeyStoreClient {
    KeyStoreClient::from_conf(
        KeyStoreConfig::builder()
            .ddb_table_name(BRANCH_KEY_STORE_NAME)
            .kms_configuration(kms_configuration)
            .logical_key_store_name(logical_key_store_name)
            .ddb_client(ddb_client)
            .kms_client(kms_client)
            .build()
            .unwrap(),
    )
    .await
    .expect("construction with valid config must succeed")
}

// ─── TestGetActiveKey ───────────────────────────────────────────────────────

#[tokio::test]
async fn integ_get_active_branch_key_returns_expected_materials() {
    let store = build_store(
        KmsConfiguration::KmsKeyArn(KEY_ARN.into()),
        LOGICAL_KEY_STORE_NAME,
        kms_client_for_region("us-west-2").await,
        ddb_client_us_west_2().await,
    )
    .await;

    let materials = store
        .get_active_branch_key()
        .branch_key_id(BRANCH_KEY_ID.to_string())
        .send()
        .await
        .expect("active branch key fetch must succeed")
        .into_branch_key_materials();

    assert_eq!(materials.branch_key_id(), BRANCH_KEY_ID);
    assert_eq!(materials.branch_key_version(), BRANCH_KEY_ACTIVE_VERSION);
    assert_eq!(materials.branch_key().len(), 32);
}

// ─── TestGetBranchKeyVersion ────────────────────────────────────────────────

#[tokio::test]
async fn integ_get_branch_key_version_returns_expected_materials() {
    let store = build_store(
        KmsConfiguration::KmsKeyArn(KEY_ARN.into()),
        LOGICAL_KEY_STORE_NAME,
        kms_client_for_region("us-west-2").await,
        ddb_client_us_west_2().await,
    )
    .await;

    let materials = store
        .get_branch_key_version()
        .branch_key_id(BRANCH_KEY_ID.to_string())
        .branch_key_version(BRANCH_KEY_ACTIVE_VERSION.to_string())
        .send()
        .await
        .expect("branch key version fetch must succeed")
        .into_branch_key_materials();

    assert_eq!(materials.branch_key_id(), BRANCH_KEY_ID);
    assert_eq!(materials.branch_key_version(), BRANCH_KEY_ACTIVE_VERSION);
    assert_eq!(materials.branch_key().len(), 32);
}

// ─── TestGetActiveMrkKey: same-region happy paths ───────────────────────────

#[tokio::test]
async fn integ_get_active_mrk_key_west_kmskeyarn_west_branch() {
    let store = build_store(
        KmsConfiguration::KmsKeyArn(MRK_ARN_WEST.into()),
        LOGICAL_KEY_STORE_NAME,
        kms_client_for_region("us-west-2").await,
        ddb_client_us_west_2().await,
    )
    .await;
    let materials = store
        .get_active_branch_key()
        .branch_key_id(WEST_BRANCH_KEY.to_string())
        .send()
        .await
        .expect("west KmsKeyArn + WestBranchKey must succeed")
        .into_branch_key_materials();
    assert_eq!(materials.branch_key_id(), WEST_BRANCH_KEY);
    assert_eq!(materials.branch_key().len(), 32);
}

#[tokio::test]
async fn integ_get_active_mrk_key_east_kmskeyarn_east_branch() {
    let store = build_store(
        KmsConfiguration::KmsKeyArn(MRK_ARN_EAST.into()),
        LOGICAL_KEY_STORE_NAME,
        kms_client_for_region("us-east-1").await,
        ddb_client_us_west_2().await,
    )
    .await;
    let materials = store
        .get_active_branch_key()
        .branch_key_id(EAST_BRANCH_KEY.to_string())
        .send()
        .await
        .expect("east KmsKeyArn + EastBranchKey must succeed")
        .into_branch_key_materials();
    assert_eq!(materials.branch_key_id(), EAST_BRANCH_KEY);
    assert_eq!(materials.branch_key().len(), 32);
}

#[tokio::test]
async fn integ_get_active_mrk_key_west_mrk_west_branch() {
    let store = build_store(
        KmsConfiguration::KmsMrKeyArn(MRK_ARN_WEST.into()),
        LOGICAL_KEY_STORE_NAME,
        kms_client_for_region("us-west-2").await,
        ddb_client_us_west_2().await,
    )
    .await;
    let materials = store
        .get_active_branch_key()
        .branch_key_id(WEST_BRANCH_KEY.to_string())
        .send()
        .await
        .expect("west KmsMrKeyArn + WestBranchKey must succeed")
        .into_branch_key_materials();
    assert_eq!(materials.branch_key_id(), WEST_BRANCH_KEY);
    assert_eq!(materials.branch_key().len(), 32);
}

#[tokio::test]
async fn integ_get_active_mrk_key_east_mrk_east_branch() {
    let store = build_store(
        KmsConfiguration::KmsMrKeyArn(MRK_ARN_EAST.into()),
        LOGICAL_KEY_STORE_NAME,
        kms_client_for_region("us-east-1").await,
        ddb_client_us_west_2().await,
    )
    .await;
    let materials = store
        .get_active_branch_key()
        .branch_key_id(EAST_BRANCH_KEY.to_string())
        .send()
        .await
        .expect("east KmsMrKeyArn + EastBranchKey must succeed")
        .into_branch_key_materials();
    assert_eq!(materials.branch_key_id(), EAST_BRANCH_KEY);
    assert_eq!(materials.branch_key().len(), 32);
}

// ─── TestGetActiveMrkKey: MRK cross-region success ──────────────────────────

#[tokio::test]
async fn integ_get_active_mrk_key_west_mrk_fetches_east_branch() {
    let store = build_store(
        KmsConfiguration::KmsMrKeyArn(MRK_ARN_WEST.into()),
        LOGICAL_KEY_STORE_NAME,
        kms_client_for_region("us-west-2").await,
        ddb_client_us_west_2().await,
    )
    .await;
    let materials = store
        .get_active_branch_key()
        .branch_key_id(EAST_BRANCH_KEY.to_string())
        .send()
        .await
        .expect("KmsMrKeyArn(west) + EastBranchKey must succeed via MRK match")
        .into_branch_key_materials();
    assert_eq!(materials.branch_key_id(), EAST_BRANCH_KEY);
    assert_eq!(materials.branch_key().len(), 32);
}

#[tokio::test]
async fn integ_get_active_mrk_key_east_mrk_fetches_west_branch() {
    let store = build_store(
        KmsConfiguration::KmsMrKeyArn(MRK_ARN_EAST.into()),
        LOGICAL_KEY_STORE_NAME,
        kms_client_for_region("us-east-1").await,
        ddb_client_us_west_2().await,
    )
    .await;
    let materials = store
        .get_active_branch_key()
        .branch_key_id(WEST_BRANCH_KEY.to_string())
        .send()
        .await
        .expect("KmsMrKeyArn(east) + WestBranchKey must succeed via MRK match")
        .into_branch_key_materials();
    assert_eq!(materials.branch_key_id(), WEST_BRANCH_KEY);
    assert_eq!(materials.branch_key().len(), 32);
}

// ─── TestGetActiveMrkKey: KmsKeyArn cross-region disagreement ──────────────

#[tokio::test]
async fn integ_get_active_kmskeyarn_west_fetches_east_branch_fails() {
    let store = build_store(
        KmsConfiguration::KmsKeyArn(MRK_ARN_WEST.into()),
        LOGICAL_KEY_STORE_NAME,
        kms_client_for_region("us-west-2").await,
        ddb_client_us_west_2().await,
    )
    .await;
    let err = match store
        .get_active_branch_key()
        .branch_key_id(EAST_BRANCH_KEY.to_string())
        .send()
        .await
    {
        Ok(_) => panic!("KmsKeyArn(west) + EastBranchKey must fail (single-region match strict)"),
        Err(e) => e,
    };
    assert!(err.is_validation(), "{:?}", err);
}

#[tokio::test]
async fn integ_get_active_kmskeyarn_east_fetches_west_branch_fails() {
    let store = build_store(
        KmsConfiguration::KmsKeyArn(MRK_ARN_EAST.into()),
        LOGICAL_KEY_STORE_NAME,
        kms_client_for_region("us-east-1").await,
        ddb_client_us_west_2().await,
    )
    .await;
    let err = match store
        .get_active_branch_key()
        .branch_key_id(WEST_BRANCH_KEY.to_string())
        .send()
        .await
    {
        Ok(_) => panic!("KmsKeyArn(east) + WestBranchKey must fail (single-region match strict)"),
        Err(e) => e,
    };
    assert!(err.is_validation(), "{:?}", err);
}

// ─── TestGetActiveMrkKey: AP MRK config (key absent in region) ──────────────

#[tokio::test]
async fn integ_get_active_mrk_key_ap_config_fails_at_kms() {
    let store = build_store(
        KmsConfiguration::KmsMrKeyArn(MRK_ARN_AP.into()),
        LOGICAL_KEY_STORE_NAME,
        kms_client_for_region("ap-south-2").await,
        ddb_client_us_west_2().await,
    )
    .await;
    let err = match store
        .get_active_branch_key()
        .branch_key_id(WEST_BRANCH_KEY.to_string())
        .send()
        .await
    {
        Ok(_) => panic!("KmsMrKeyArn(ap-south-2) MUST fail — key does not exist in AP"),
        Err(e) => e,
    };
    // Dafny asserts the error is a KMS opaque error. The SDK error is nested
    // as the cause here, so the assertion goes one level deeper than the kind.
    // The service-error variant is deliberately not pinned: whether an absent
    // key in a possibly-unenabled region comes back as a modeled exception or
    // as a dispatch failure is an account-configuration detail, so only the
    // nesting itself is asserted.
    assert!(
        err.source()
            .and_then(|c| c.downcast_ref::<SdkError<DecryptError>>())
            .is_some(),
        "the KMS SDK error must be nested as the cause; got: {err}",
    );
}

// ─── TestGetActiveKeyWithIncorrectKmsKeyArn ────────────────────────────────

#[tokio::test]
async fn integ_get_active_key_with_arn_disagreement_fails() {
    // KEY_ARN is configured but DISCOVERY_BRANCH_KEY_ID's record was
    // created with a different KMS ARN — the kms-arn-compat check in
    // resolve_key_store_arn rejects with Authentication errkind.
    let store = build_store(
        KmsConfiguration::KmsKeyArn(KEY_ARN.into()),
        LOGICAL_KEY_STORE_NAME,
        kms_client_for_region("us-west-2").await,
        ddb_client_us_west_2().await,
    )
    .await;
    let err = match store
        .get_active_branch_key()
        .branch_key_id(DISCOVERY_BRANCH_KEY_ID.to_string())
        .send()
        .await
    {
        Ok(_) => panic!("Configured KEY_ARN + DISCOVERY_BRANCH_KEY_ID MUST fail (ARN mismatch)"),
        Err(e) => e,
    };
    assert!(err.is_validation(), "{:?}", err);
}

// ─── TestGetActiveKeyWrongLogicalKeyStoreName ──────────────────────────────

#[tokio::test]
async fn integ_get_active_key_wrong_logical_name_fails_at_kms() {
    // A wrong logical name binds a different `tablename` value into the
    // EC, so KMS Decrypt fails to authenticate and returns
    // InvalidCiphertextException, which is a `Service` error.
    let store = build_store(
        KmsConfiguration::KmsKeyArn(KEY_ARN.into()),
        INCORRECT_LOGICAL_NAME,
        kms_client_for_region("us-west-2").await,
        ddb_client_us_west_2().await,
    )
    .await;
    let err = match store
        .get_active_branch_key()
        .branch_key_id(BRANCH_KEY_ID.to_string())
        .send()
        .await
    {
        Ok(_) => panic!("Wrong logical name MUST fail at KMS"),
        Err(e) => e,
    };
    assert!(err.is_service(), "{:?}", err);

    // The originating SDK error is nested as the cause, so the specific KMS
    // exception is recoverable by type. This ports the assertion Dafny makes
    // in AwsCryptographyKeyStore/test/TestGetKeys.dfy:
    //
    //     match activeResult.error {
    //       case ComAmazonawsKms(nestedError) =>
    //         expect nestedError.InvalidCiphertextException?;
    //
    // Asserting only the error kind would equally admit throttling, access
    // denied, or a disabled key.
    let sdk_err = err
        .source()
        .expect("the KMS SDK error must be attached as the cause")
        .downcast_ref::<SdkError<DecryptError>>()
        .expect("the cause must be the originating Decrypt SdkError");
    let service_err = sdk_err
        .as_service_error()
        .expect("a wrong-EC Decrypt is a modeled service error, not a dispatch failure");
    assert!(
        service_err.is_invalid_ciphertext_exception(),
        "a mismatched encryption context MUST surface InvalidCiphertextException; got: {service_err:?}",
    );

    // The same exception is reachable without knowing which KMS operation
    // failed, via the error code the SDK prescribes for forward-compatible
    // matching. This is the `Some(code)` half of `aws_service_error_code`;
    // the `None` half (a dispatch failure carries no service metadata) is
    // covered in `tests/test_key_store_branch_key_store.rs`.
    assert_eq!(
        aws_service_error_code(&err),
        Some("InvalidCiphertextException"),
        "the service error code must be reachable from the top of the chain",
    );
}

// ─── DynamoDB error nesting ─────────────────────────────────────────────────

#[tokio::test]
async fn integ_get_active_key_against_a_missing_table_nests_the_ddb_sdk_error() {
    // The DynamoDB half of the same guarantee: a failed GetItem must surface
    // the originating SDK error as the cause, not merely a Dynamodb-kind error
    // with the SDK error formatted into the message. No Dafny counterpart —
    // the Dafny suite does not exercise an unreachable table.
    //
    // The modeled service-error variant is deliberately not pinned, because it
    // depends on the caller's IAM policy rather than on this code. CI's role is
    // scoped to the fixture table, so an unknown table name is denied by IAM
    // before DynamoDB reports on its existence and the operation error arrives
    // as `Unhandled` carrying `AccessDeniedException`. A caller permitted on
    // the whole table namespace instead sees `ResourceNotFoundException`. Both
    // are the same nesting, which is what is under test here.
    let store = KeyStoreClient::from_conf(
        KeyStoreConfig::builder()
            .ddb_table_name("aws-crypto-tools-rust-table-that-does-not-exist")
            .kms_configuration(KmsConfiguration::KmsKeyArn(KEY_ARN.into()))
            .logical_key_store_name(LOGICAL_KEY_STORE_NAME)
            .ddb_client(ddb_client_us_west_2().await)
            .kms_client(kms_client_for_region("us-west-2").await)
            .build()
            .unwrap(),
    )
    .await
    .expect("construction does not touch DynamoDB, so it must succeed");

    let err = match store
        .get_active_branch_key()
        .branch_key_id(BRANCH_KEY_ID.to_string())
        .send()
        .await
    {
        Ok(_) => panic!("GetItem against an unreachable table MUST fail"),
        Err(e) => e,
    };
    // Which of the two depends on the caller's IAM policy, as above.
    assert!(
        (err.is_access_denied() || err.is_resource_not_found()),
        "expected an access-denied or not-found kind, got: {err:?}"
    );

    let sdk_err = err
        .source()
        .expect("the DynamoDB SDK error must be attached as the cause")
        .downcast_ref::<SdkError<GetItemError>>()
        .expect("the cause must be the originating GetItem SdkError");
    assert!(
        sdk_err.as_service_error().is_some(),
        "the nested SDK error must carry the service response, so a caller can \
         match on the DynamoDB exception; got: {sdk_err:?}",
    );
}

// ─── TestGetActiveKeyDoesNotExistFails ─────────────────────────────────────

#[tokio::test]
async fn integ_get_active_key_does_not_exist() {
    let store = build_store(
        KmsConfiguration::KmsKeyArn(KEY_ARN.into()),
        LOGICAL_KEY_STORE_NAME,
        kms_client_for_region("us-west-2").await,
        ddb_client_us_west_2().await,
    )
    .await;
    let err = match store
        .get_active_branch_key()
        .branch_key_id("Robbie".to_string())
        .send()
        .await
    {
        Ok(_) => panic!("nonexistent branch key MUST fail with ResourceNotFound"),
        Err(e) => e,
    };
    assert!(err.is_resource_not_found(), "{:?}", err);
}

// ─── Write path: CreateKeyStore / CreateKey / VersionKey round trips ─────────
//
// These tests mutate the shared key store table. Each uses a random
// branch-key-id (so it never collides with the read fixtures) and deletes
// every item it created via `cleanup_branch_key` before asserting, so a
// failed assertion still leaves the table clean. They require write
// permissions in addition to the read role: `kms:GenerateDataKeyWithoutPlaintext`
// and `kms:ReEncrypt` on the test key, and `dynamodb:PutItem` /
// `TransactWriteItems` / `Query` / `DeleteItem` on the table.

/// Delete every item stored under `branch_key_id` (all `type` sort keys),
/// so a create/version round trip leaves no residue in the shared table.
async fn cleanup_branch_key(ddb: &DynamoDbClient, table: &str, branch_key_id: &str) {
    let response = ddb
        .query()
        .table_name(table)
        .consistent_read(true)
        .key_condition_expression("#bk = :bk")
        .expression_attribute_names("#bk", "branch-key-id")
        .expression_attribute_values(":bk", AttributeValue::S(branch_key_id.to_string()))
        .send()
        .await
        .expect("cleanup Query must succeed");

    for item in response.items() {
        if let Some(AttributeValue::S(type_value)) = item.get("type") {
            ddb.delete_item()
                .table_name(table)
                .key(
                    "branch-key-id",
                    AttributeValue::S(branch_key_id.to_string()),
                )
                .key("type", AttributeValue::S(type_value.clone()))
                .send()
                .await
                .expect("cleanup DeleteItem must succeed");
        }
    }
}

#[tokio::test]
async fn integ_create_key_store_returns_existing_table_arn() {
    // The table already exists, so CreateKeyStore takes the DescribeTable
    // path, validates the KeySchema, and returns the existing table ARN.
    let store = build_store(
        KmsConfiguration::KmsKeyArn(KEY_ARN.into()),
        LOGICAL_KEY_STORE_NAME,
        kms_client_for_region("us-west-2").await,
        ddb_client_us_west_2().await,
    )
    .await;

    let arn = store
        .create_key_store()
        .send()
        .await
        .expect("CreateKeyStore against the existing table must return its ARN")
        .into_table_arn();
    assert!(
        arn.contains(&format!(":table/{BRANCH_KEY_STORE_NAME}")),
        "expected a DynamoDB table ARN, got: {arn}"
    );
}

#[tokio::test]
async fn integ_create_key_round_trips() {
    let store = build_store(
        KmsConfiguration::KmsKeyArn(KEY_ARN.into()),
        LOGICAL_KEY_STORE_NAME,
        kms_client_for_region("us-west-2").await,
        ddb_client_us_west_2().await,
    )
    .await;
    let cleanup_ddb = ddb_client_us_west_2().await;

    // Create a brand-new branch key (random id) with no custom EC.
    let branch_key_id = store
        .create_key()
        .send()
        .await
        .expect("create_key must succeed")
        .into_branch_key_id();

    // Read back the ACTIVE, the specific version, and the beacon key.
    let active = store
        .get_active_branch_key()
        .branch_key_id(branch_key_id.clone())
        .send()
        .await
        .map(|o| o.into_branch_key_materials());
    let version = active
        .as_ref()
        .ok()
        .map(|m| m.branch_key_version().to_string());
    let by_version = match &version {
        Some(v) => Some(
            store
                .get_branch_key_version()
                .branch_key_id(branch_key_id.clone())
                .branch_key_version(v.clone())
                .send()
                .await
                .map(|o| o.into_branch_key_materials()),
        ),
        None => None,
    };
    let beacon = store
        .get_beacon_key()
        .branch_key_id(branch_key_id.clone())
        .send()
        .await
        .map(|o| o.into_beacon_key_materials());

    cleanup_branch_key(&cleanup_ddb, BRANCH_KEY_STORE_NAME, &branch_key_id).await;

    let active = active.expect("get_active_branch_key must succeed after create_key");
    assert_eq!(active.branch_key_id(), branch_key_id);
    assert_eq!(active.branch_key().len(), 32);

    let by_version = by_version
        .expect("a version must have been read")
        .expect("get_branch_key_version must succeed for the created version");
    assert_eq!(by_version.branch_key_id(), branch_key_id);
    assert_eq!(by_version.branch_key().len(), 32);
    assert_eq!(
        by_version.branch_key_version(),
        active.branch_key_version(),
        "the created version MUST be the ACTIVE version"
    );

    let beacon = beacon.expect("get_beacon_key must succeed after create_key");
    assert_eq!(beacon.beacon_key_id(), branch_key_id);
    assert_eq!(beacon.beacon_key().map(<[u8]>::len), Some(32));
}

#[tokio::test]
async fn integ_version_key_round_trips() {
    let store = build_store(
        KmsConfiguration::KmsKeyArn(KEY_ARN.into()),
        LOGICAL_KEY_STORE_NAME,
        kms_client_for_region("us-west-2").await,
        ddb_client_us_west_2().await,
    )
    .await;
    let cleanup_ddb = ddb_client_us_west_2().await;

    let branch_key_id = store
        .create_key()
        .send()
        .await
        .expect("create_key must succeed")
        .into_branch_key_id();

    let first_version = store
        .get_active_branch_key()
        .branch_key_id(branch_key_id.clone())
        .send()
        .await
        .expect("get_active_branch_key must succeed after create_key")
        .into_branch_key_materials()
        .branch_key_version()
        .to_string();

    // Rotate the ACTIVE branch key to a new version.
    let version_result = store
        .version_key()
        .branch_key_id(branch_key_id.clone())
        .send()
        .await;

    // After versioning, ACTIVE points at a new version, and the original
    // version is still retrievable by version id.
    let new_active = store
        .get_active_branch_key()
        .branch_key_id(branch_key_id.clone())
        .send()
        .await
        .map(|o| o.into_branch_key_materials());
    let old_by_version = store
        .get_branch_key_version()
        .branch_key_id(branch_key_id.clone())
        .branch_key_version(first_version.clone())
        .send()
        .await
        .map(|o| o.into_branch_key_materials());

    cleanup_branch_key(&cleanup_ddb, BRANCH_KEY_STORE_NAME, &branch_key_id).await;

    version_result.expect("version_key must succeed");

    let new_active = new_active.expect("get_active_branch_key must succeed after version_key");
    assert_eq!(new_active.branch_key_id(), branch_key_id);
    assert_eq!(new_active.branch_key().len(), 32);
    assert_ne!(
        new_active.branch_key_version(),
        first_version,
        "version_key MUST rotate ACTIVE to a new version"
    );

    let old = old_by_version.expect("the original version must remain retrievable");
    assert_eq!(old.branch_key_version(), first_version);
    assert_eq!(old.branch_key().len(), 32);
}

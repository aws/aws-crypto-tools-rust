// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for the DynamoDB key store — construction surface,
//! `GetKeyStoreInfo`, and read-path dispatch.
//!
//! No real AWS calls are made in this file: the fixtures supply zero-config
//! SDK clients so construction never triggers default-client creation, and
//! the read-path tests only assert that the operation dispatches into the
//! SDK. Happy-path read coverage lives in the real-AWS integration tests in
//! `tests/test_key_store_branch_key_store_integ.rs`.

use std::error::Error as _;

use aws_config::{BehaviorVersion, SdkConfig};
use aws_sdk_dynamodb::Client as DynamoDbClient;
use aws_sdk_dynamodb::error::SdkError;
use aws_sdk_dynamodb::operation::describe_table::DescribeTableError;
use aws_sdk_dynamodb::operation::get_item::GetItemError;
use aws_sdk_kms::Client as KmsClient;

use aws_crypto_mpl::__test_internals::error_chain::{aws_service_error_code, find_in_error_chain};
use aws_crypto_mpl::key_store::Client as KeyStoreClient;
use aws_crypto_mpl::key_store::client::Builder as KeyStoreClientBuilder;
use aws_crypto_mpl::key_store::types::KmsConfiguration;
use aws_crypto_mpl::key_store::types::{Discovery, MrDiscovery};

async fn key_store_id(store: &KeyStoreClient) -> String {
    store
        .get_key_store_info()
        .send()
        .await
        .expect("get_key_store_info must succeed")
        .key_store_id()
        .to_owned()
}

/// Construct a pair of zero-config AWS SDK clients suitable for tests
/// that never invoke a remote operation. `BehaviorVersion::latest()` is
/// required by the SDK at client-construction time; no IO occurs at
/// construction itself.
fn dummy_clients() -> (KmsClient, DynamoDbClient) {
    let cfg = SdkConfig::builder()
        .behavior_version(BehaviorVersion::latest())
        .build();
    (KmsClient::new(&cfg), DynamoDbClient::new(&cfg))
}

const KMS_KEY_ARN: &str =
    "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";

/// A builder with every required field, the simplest
/// `KmsConfiguration::KmsKeyArn` variant, and no optional fields.
fn required_only() -> KeyStoreClientBuilder {
    KeyStoreClient::builder()
        .ddb_table_name("test-table")
        .kms_configuration(KmsConfiguration::KmsKeyArn(KMS_KEY_ARN.into()))
        .logical_key_store_name("test-logical")
}

/// `required_only` plus a key store id and the dummy clients,
/// so construction never builds a default client.
fn fixture_config_with_id(id: &str) -> KeyStoreClientBuilder {
    let (kms, ddb) = dummy_clients();
    required_only().id(id).ddb_client(ddb).kms_client(kms)
}

/// Same as `fixture_config_with_id` but with no id, so construction
/// exercises the v4-UUID fallback.
fn fixture_config_no_id() -> KeyStoreClientBuilder {
    fixture_config_with_id("placeholder").set_id(None)
}

async fn build_err(builder: KeyStoreClientBuilder) -> aws_crypto_mpl::Error {
    match builder.build().await {
        Ok(_) => panic!("build must fail"),
        Err(e) => e,
    }
}

#[tokio::test]
async fn build_without_ddb_table_name_returns_configuration_error() {
    let (kms, ddb) = dummy_clients();
    let builder = KeyStoreClient::builder()
        .kms_configuration(KmsConfiguration::KmsKeyArn(KMS_KEY_ARN.into()))
        .logical_key_store_name("test-logical")
        .kms_client(kms)
        .ddb_client(ddb);
    let err = build_err(builder).await;
    assert!(err.is_validation(), "{:?}", err);
}

#[tokio::test]
async fn build_without_logical_key_store_name_returns_configuration_error() {
    let (kms, ddb) = dummy_clients();
    let builder = KeyStoreClient::builder()
        .ddb_table_name("test-table")
        .kms_configuration(KmsConfiguration::KmsKeyArn(KMS_KEY_ARN.into()))
        .kms_client(kms)
        .ddb_client(ddb);
    let err = build_err(builder).await;
    assert!(err.is_validation(), "{:?}", err);
}

#[tokio::test]
async fn build_without_kms_configuration_returns_configuration_error() {
    let (kms, ddb) = dummy_clients();
    let builder = KeyStoreClient::builder()
        .ddb_table_name("test-table")
        .logical_key_store_name("test-logical")
        .kms_client(kms)
        .ddb_client(ddb);
    let err = build_err(builder).await;
    assert!(err.is_validation(), "{:?}", err);
}

#[tokio::test]
async fn build_with_both_clients_is_ready_on_first_poll() {
    use std::future::Future;
    use std::task::{Context, Poll, Waker};

    let mut fut = std::pin::pin!(fixture_config_with_id("supplied-clients").build());
    let Poll::Ready(result) = fut.as_mut().poll(&mut Context::from_waker(Waker::noop())) else {
        panic!("build with both clients supplied must not await");
    };
    let store = result.expect("build must succeed");
    assert_eq!(key_store_id(&store).await, "supplied-clients");
}

#[cfg(feature = "test-utils")]
#[tokio::test]
async fn build_defaults_absent_clients_to_the_kms_arn_region() {
    use aws_crypto_mpl::key_store::__test_internals::branch_key_store::build_clients;

    let (kms, ddb) = build_clients(required_only())
        .await
        .expect("build must default both absent clients");
    assert_eq!(kms.config().region().map(|r| r.as_ref()), Some("us-west-2"));
    assert_eq!(ddb.config().region().map(|r| r.as_ref()), Some("us-west-2"));
}

#[cfg(feature = "test-utils")]
#[tokio::test]
async fn build_defaults_only_the_absent_client() {
    use aws_crypto_mpl::key_store::__test_internals::branch_key_store::build_clients;

    // The supplied DynamoDB client has no Region; the defaulted KMS client
    // gets the ARN's.
    let (_, ddb) = dummy_clients();
    let (kms, ddb) = build_clients(required_only().ddb_client(ddb))
        .await
        .unwrap();
    assert_eq!(kms.config().region().map(|r| r.as_ref()), Some("us-west-2"));
    assert!(ddb.config().region().is_none());
}

#[tokio::test]
async fn new_with_caller_supplied_key_store_id_records_it_verbatim() {
    let store = fixture_config_with_id("caller-id")
        .build()
        .await
        .expect("construction with valid config must succeed");
    assert_eq!(key_store_id(&store).await, "caller-id");
}

#[tokio::test]
async fn new_without_key_store_id_generates_v4_uuid() {
    let store = fixture_config_no_id()
        .build()
        .await
        .expect("construction with valid config must succeed");

    let id = key_store_id(&store).await;
    assert_eq!(id.len(), 36, "v4 UUID canonical form is 36 chars");
    let bytes = id.as_bytes();
    assert_eq!(bytes[8], b'-');
    assert_eq!(bytes[13], b'-');
    assert_eq!(bytes[18], b'-');
    assert_eq!(bytes[23], b'-');
    // RFC 4122 §4.4: the version nibble (position 14) MUST be '4'.
    assert_eq!(bytes[14], b'4');
    // RFC 4122 §4.4: the variant nibble (position 19) MUST be 8/9/a/b.
    assert!(
        matches!(bytes[19], b'8' | b'9' | b'a' | b'b'),
        "variant nibble must be 8/9/a/b, got {:?}",
        bytes[19] as char
    );
    // All other positions are lowercase hex digits.
    for (i, &b) in bytes.iter().enumerate() {
        if matches!(i, 8 | 13 | 18 | 23) {
            continue;
        }
        assert!(
            b.is_ascii_hexdigit() && (b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "position {i} must be a lowercase hex digit, got {:?}",
            b as char
        );
    }
}

#[tokio::test]
async fn new_without_key_store_id_two_calls_produce_distinct_uuids() {
    let store1 = fixture_config_no_id().build().await.unwrap();
    let store2 = fixture_config_no_id().build().await.unwrap();
    assert_ne!(
        key_store_id(&store1).await,
        key_store_id(&store2).await,
        "fresh v4 UUIDs MUST be distinct with overwhelming probability"
    );
}

#[tokio::test]
async fn new_with_malformed_kms_arn_returns_configuration_error() {
    let cfg = fixture_config_with_id("caller-id")
        .kms_configuration(KmsConfiguration::KmsKeyArn("not-an-arn".into()));
    let err = match cfg.build().await {
        Ok(_) => panic!("construction with malformed ARN must fail"),
        Err(e) => e,
    };
    assert!(err.is_validation(), "{:?}", err);
}

#[tokio::test]
async fn new_with_alias_kms_arn_returns_configuration_error() {
    let cfg = fixture_config_with_id("caller-id").kms_configuration(KmsConfiguration::KmsKeyArn(
        "arn:aws:kms:us-west-2:111122223333:alias/my-alias".into(),
    ));
    let err = match cfg.build().await {
        Ok(_) => panic!("construction with alias ARN must fail"),
        Err(e) => e,
    };
    assert!(err.is_validation(), "{:?}", err);
}

#[tokio::test]
async fn new_with_discovery_config_succeeds_without_arn() {
    let cfg = fixture_config_with_id("caller-id").kms_configuration(KmsConfiguration::Discovery(
        Discovery::builder().build().unwrap(),
    ));
    cfg.build()
        .await
        .expect("Discovery config requires no ARN and must succeed");
}

#[tokio::test]
async fn new_with_mr_discovery_config_succeeds() {
    let cfg = fixture_config_with_id("caller-id").kms_configuration(KmsConfiguration::MrDiscovery(
        MrDiscovery::builder().region("us-west-2").build().unwrap(),
    ));
    cfg.build()
        .await
        .expect("MrDiscovery config requires no ARN and must succeed");
}

#[tokio::test]
async fn get_key_store_info_returns_configured_values() {
    let (kms, ddb) = dummy_clients();
    let cfg = KeyStoreClient::builder()
        .ddb_table_name("my-table")
        .kms_configuration(KmsConfiguration::KmsKeyArn(KMS_KEY_ARN.into()))
        .logical_key_store_name("my-logical")
        .id("my-id")
        .set_grant_tokens(Some(["grant-1", "grant-2"].map(String::from).into()))
        .ddb_client(ddb)
        .kms_client(kms);
    let store = cfg.build().await.unwrap();

    let info = store.get_key_store_info().send().await.unwrap();
    assert_eq!(info.key_store_id(), "my-id");
    assert_eq!(info.key_store_name(), "my-table");
    assert_eq!(info.logical_key_store_name(), "my-logical");
    assert_eq!(info.grant_tokens(), vec!["grant-1", "grant-2"]);
    assert!(matches!(
        info.kms_configuration(),
        KmsConfiguration::KmsKeyArn(_)
    ));
}

#[tokio::test]
async fn get_key_store_info_returns_empty_grant_tokens_when_none() {
    let store = fixture_config_with_id("id-x").build().await.unwrap();
    let info = store.get_key_store_info().send().await.unwrap();
    assert!(info.grant_tokens().is_empty());
}

// ─── Read-path APIs ─────────────────────────────────────────────────────────
//
// Without AWS credentials the read path fails at the SDK call.
// A `Dispatch` error shows the method reached the SDK, which sends no request without credentials.
// The real-AWS integration tests cover the happy path.

#[tokio::test]
async fn get_active_branch_key_dispatches_to_dynamodb() {
    let store = fixture_config_with_id("id-x").build().await.unwrap();
    let err = match store
        .get_active_branch_key()
        .branch_key_id("bk-1".to_string())
        .send()
        .await
    {
        Ok(_) => panic!("get_active_branch_key unexpectedly succeeded with no AWS configured"),
        Err(e) => e,
    };
    assert!(err.is_dispatch(), "{:?}", err);

    // The originating SDK error is attached as the cause, not merely formatted
    // into the message, so a caller can recover it by type and inspect the
    // concrete DynamoDB failure.
    let cause = err
        .source()
        .expect("the DynamoDB SDK error must be attached as the cause");
    assert!(
        cause.downcast_ref::<SdkError<GetItemError>>().is_some(),
        "the cause must be the originating GetItem SdkError; got: {cause}",
    );
}

#[tokio::test]
async fn get_branch_key_version_dispatches_to_dynamodb() {
    let store = fixture_config_with_id("id-x").build().await.unwrap();
    let err = match store
        .get_branch_key_version()
        .branch_key_id("bk-1".to_string())
        .branch_key_version("v-1".to_string())
        .send()
        .await
    {
        Ok(_) => panic!("get_branch_key_version unexpectedly succeeded with no AWS configured"),
        Err(e) => e,
    };
    assert!(err.is_dispatch(), "{:?}", err);
    assert!(
        err.source()
            .and_then(|c| c.downcast_ref::<SdkError<GetItemError>>())
            .is_some(),
        "the versioned read path must preserve the SDK error as the cause too; got: {err}",
    );
}

#[tokio::test]
async fn create_key_store_dispatches_to_dynamodb() {
    // With no AWS configured, CreateKeyStore's initial DescribeTable call
    // fails at dispatch (not a modeled ResourceNotFoundException), so the
    // operation surfaces a Dynamodb-kind error rather than the old
    // not-implemented stub.
    let store = fixture_config_with_id("id-x").build().await.unwrap();
    let err = match store.create_key_store().send().await {
        Ok(_) => panic!("create_key_store unexpectedly succeeded with no AWS configured"),
        Err(e) => e,
    };
    assert!(err.is_dispatch(), "{:?}", err);

    // A different call site than the read path above, so its cause is asserted
    // separately: the DescribeTable error is attached rather than discarded.
    assert!(
        err.source()
            .and_then(|c| c.downcast_ref::<SdkError<DescribeTableError>>())
            .is_some(),
        "the cause must be the originating DescribeTable SdkError; got: {err}",
    );
}

#[tokio::test]
async fn create_key_with_branch_key_id_but_no_ec_fails() {
    let store = fixture_config_with_id("id-x").build().await.unwrap();
    let err = match store
        .create_key()
        .branch_key_id("bk-1".to_string())
        .send()
        .await
    {
        Ok(_) => panic!("create_key with a branch key id and no EC must fail"),
        Err(e) => e,
    };
    assert!(err.is_validation(), "{:?}", err);
}

#[tokio::test]
async fn create_key_with_discovery_config_fails() {
    let cfg = fixture_config_with_id("id-x").kms_configuration(KmsConfiguration::Discovery(
        Discovery::builder().build().unwrap(),
    ));
    let store = cfg.build().await.unwrap();
    let err = match store.create_key().send().await {
        Ok(_) => panic!("create_key under a Discovery configuration must fail"),
        Err(e) => e,
    };
    assert!(err.is_validation(), "{:?}", err);
}

#[tokio::test]
async fn create_key_dispatches_to_kms() {
    // With no AWS configured, CreateKey reaches the first KMS
    // GenerateDataKeyWithoutPlaintext call, which fails at dispatch and is
    // surfaced as a Kms-kind error.
    let store = fixture_config_with_id("id-x").build().await.unwrap();
    let err = match store.create_key().send().await {
        Ok(_) => panic!("create_key unexpectedly succeeded with no AWS configured"),
        Err(e) => e,
    };
    assert!(err.is_dispatch(), "{:?}", err);
}

#[tokio::test]
async fn version_key_without_a_branch_key_id_fails_before_dispatch() {
    let store = fixture_config_with_id("id-x").build().await.unwrap();
    let err = store.version_key().send().await.unwrap_err();
    assert!(err.is_validation(), "{:?}", err);
}

#[tokio::test]
async fn version_key_with_discovery_config_fails() {
    let cfg = fixture_config_with_id("id-x").kms_configuration(KmsConfiguration::Discovery(
        Discovery::builder().build().unwrap(),
    ));
    let store = cfg.build().await.unwrap();
    let err = match store
        .version_key()
        .branch_key_id("bk-1".to_string())
        .send()
        .await
    {
        Ok(_) => panic!("version_key under a Discovery configuration must fail"),
        Err(e) => e,
    };
    assert!(err.is_validation(), "{:?}", err);
}

#[tokio::test]
async fn version_key_dispatches_to_dynamodb() {
    // VersionKey first reads the ACTIVE record; with no AWS configured that
    // GetItem fails at dispatch and surfaces a Dynamodb-kind error.
    let store = fixture_config_with_id("id-x").build().await.unwrap();
    let err = match store
        .version_key()
        .branch_key_id("bk-1".to_string())
        .send()
        .await
    {
        Ok(_) => panic!("version_key unexpectedly succeeded with no AWS configured"),
        Err(e) => e,
    };
    assert!(err.is_dispatch(), "{:?}", err);
    assert!(
        err.source()
            .and_then(|c| c.downcast_ref::<SdkError<GetItemError>>())
            .is_some(),
        "the SDK error must be preserved as the cause here too; got: {err}",
    );
}

#[tokio::test]
async fn get_beacon_key_dispatches_to_dynamodb() {
    // GetBeaconKey reads the beacon:ACTIVE record; with no AWS configured
    // that GetItem fails at dispatch and surfaces a Dynamodb-kind error.
    let store = fixture_config_with_id("id-x").build().await.unwrap();
    let err = match store
        .get_beacon_key()
        .branch_key_id("bk-1".to_string())
        .send()
        .await
    {
        Ok(_) => panic!("get_beacon_key unexpectedly succeeded with no AWS configured"),
        Err(e) => e,
    };
    assert!(err.is_dispatch(), "{:?}", err);
    assert!(
        err.source()
            .and_then(|c| c.downcast_ref::<SdkError<GetItemError>>())
            .is_some(),
        "the SDK error must be preserved as the cause here too; got: {err}",
    );
}

#[tokio::test]
async fn the_message_does_not_render_the_sdk_errors_display() {
    // `SdkError`'s `Display` is a bare lifecycle label, so the message must
    // carry this layer and the operation; the detail is in the cause.
    let store = fixture_config_with_id("id-x").build().await.unwrap();
    let err = match store
        .get_active_branch_key()
        .branch_key_id("bk-1".to_string())
        .send()
        .await
    {
        Ok(_) => panic!("get_active_branch_key unexpectedly succeeded with no AWS configured"),
        Err(e) => e,
    };

    assert_eq!(
        err.message(),
        "DynamoDB GetItem for branch key bk-1 failed",
        "the message must name this layer and the operation, with no SDK Display appended"
    );
    assert_eq!(
        err.to_string(),
        "Dispatch: DynamoDB GetItem for branch key bk-1 failed (Amazon DynamoDB, table test-table)",
        "Display renders only this layer; a chain-walking printer renders the cause"
    );
}

#[tokio::test]
async fn find_in_error_chain_recovers_the_sdk_error_by_type() {
    let store = fixture_config_with_id("id-x").build().await.unwrap();
    let err = match store
        .get_active_branch_key()
        .branch_key_id("bk-1".to_string())
        .send()
        .await
    {
        Ok(_) => panic!("get_active_branch_key unexpectedly succeeded with no AWS configured"),
        Err(e) => e,
    };

    assert!(
        find_in_error_chain::<SdkError<GetItemError>>(&err).is_some(),
        "find_in_error_chain must recover the concrete GetItem SdkError from the chain"
    );
    assert!(
        find_in_error_chain::<SdkError<DescribeTableError>>(&err).is_none(),
        "a different operation's SdkError is a different type and must not match"
    );
}

#[tokio::test]
async fn a_dispatch_failure_has_no_service_error_code() {
    // Only `SdkError::ServiceError` carries service metadata; construction,
    // timeout, dispatch, and response-parsing failures return the SDK's
    // empty metadata. With no AWS configured this fails at dispatch, so
    // there is no code to report. A real service code is asserted in the
    // real-AWS integration suites.
    let store = fixture_config_with_id("id-x").build().await.unwrap();
    let err = match store
        .get_active_branch_key()
        .branch_key_id("bk-1".to_string())
        .send()
        .await
    {
        Ok(_) => panic!("get_active_branch_key unexpectedly succeeded with no AWS configured"),
        Err(e) => e,
    };

    let sdk = find_in_error_chain::<SdkError<GetItemError>>(&err)
        .expect("precondition: the SDK error is in the chain");
    assert!(
        sdk.as_service_error().is_none(),
        "precondition: with no AWS configured this is a dispatch failure, not a service error"
    );
    assert!(
        aws_service_error_code(&err).is_none(),
        "a dispatch failure carries no service metadata, so it has no code"
    );
}

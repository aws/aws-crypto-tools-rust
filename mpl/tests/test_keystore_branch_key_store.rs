// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for the concrete [`BranchKeyStore`] — construction surface,
//! `GetKeyStoreInfo`, and read-path dispatch.
//!
//! No real AWS calls are made in this file: the fixtures supply zero-config
//! SDK clients so construction never triggers default-client creation, and
//! the read-path tests only assert that the operation dispatches into the
//! SDK. Happy-path read coverage lives in the real-AWS integration tests in
//! `tests/test_keystore_branch_key_store_integ.rs`.

use std::error::Error as _;

use aws_config::{BehaviorVersion, SdkConfig};
use aws_sdk_dynamodb::Client as DynamoDbClient;
use aws_sdk_dynamodb::error::SdkError;
use aws_sdk_dynamodb::operation::describe_table::DescribeTableError;
use aws_sdk_dynamodb::operation::get_item::GetItemError;
use aws_sdk_kms::Client as KmsClient;

use aws_crypto_mpl::error_chain::{aws_service_error_code, find_in_error_chain};
use aws_crypto_mpl::{
    BranchKeyStore, KeyStoreConfig, Keystore, KmsConfiguration, keystore::KeystoreErrorKind,
};

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

/// A `KeyStoreConfig` with a caller-supplied keystore-id, the simplest
/// `KmsConfiguration::KmsKeyArn` variant, no grant tokens, and the dummy
/// clients supplied so construction never builds a default client.
fn fixture_config_with_id(id: &str) -> KeyStoreConfig {
    let (kms, ddb) = dummy_clients();
    KeyStoreConfig {
        ddb_table_name: "test-table".to_string(),
        kms_configuration: KmsConfiguration::KmsKeyArn(
            "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
                .to_string(),
        ),
        logical_keystore_name: "test-logical".to_string(),
        id: Some(id.to_string()),
        grant_tokens: None,
        ddb_client: Some(ddb),
        kms_client: Some(kms),
    }
}

/// Same as [`fixture_config_with_id`] but with `id: None`, so
/// `BranchKeyStore::new` exercises the v4-UUID fallback.
fn fixture_config_no_id() -> KeyStoreConfig {
    let mut cfg = fixture_config_with_id("placeholder");
    cfg.id = None;
    cfg
}

#[test]
fn with_clients_succeeds_when_both_clients_are_supplied() {
    // The sync constructor for the common case: a caller with its own SDK
    // configuration supplies both clients, so there is nothing to resolve and
    // no reason to await. Same validation and id resolution as `new`.
    let store = BranchKeyStore::with_clients(fixture_config_with_id("supplied-clients"))
        .expect("with_clients must succeed when both clients are present");
    let info = store
        .get_key_store_info()
        .expect("get_key_store_info must succeed");
    assert_eq!(info.keystore_id, "supplied-clients");
}

// Construction tags the KMS client's user agent with this crate's identifier,
// and leaves the DynamoDB client alone. The tagging helper itself is covered in
// `tests/test_aws_kms_user_agent.rs`; this only checks the keystore applies it.
#[cfg(feature = "test-utils")]
#[test]
fn with_clients_tags_the_kms_client_and_not_the_ddb_client() {
    use aws_crypto_mpl::keystore::branch_key_store::__test_internals as ks;

    let store = BranchKeyStore::with_clients(fixture_config_with_id("user-agent"))
        .expect("with_clients must succeed when both clients are present");

    let kms_names: Vec<&str> = ks::kms_client(&store)
        .config()
        .framework_metadata()
        .iter()
        .map(|metadata| metadata.name())
        .collect();
    assert_eq!(kms_names, vec!["AwsCryptographicMPL-Rust"]);
    assert!(
        ks::ddb_client(&store)
            .config()
            .framework_metadata()
            .is_empty(),
        "the DynamoDB client must carry no identifier"
    );
}

#[test]
fn with_clients_without_kms_client_returns_configuration_error() {
    let mut config = fixture_config_with_id("no-kms-client");
    config.kms_client = None;

    let err = match BranchKeyStore::with_clients(config) {
        Err(e) => e,
        Ok(_) => panic!("with_clients MUST reject a config missing the kms_client"),
    };
    assert_eq!(err.kind(), &KeystoreErrorKind::Configuration);
}

#[test]
fn with_clients_without_ddb_client_returns_configuration_error() {
    let mut config = fixture_config_with_id("no-ddb-client");
    config.ddb_client = None;

    let err = match BranchKeyStore::with_clients(config) {
        Err(e) => e,
        Ok(_) => panic!("with_clients MUST reject a config missing the ddb_client"),
    };
    assert_eq!(err.kind(), &KeystoreErrorKind::Configuration);
}

#[test]
fn with_clients_validates_the_kms_arn() {
    // Validation is not skipped on the sync path.
    let mut config = fixture_config_with_id("bad-arn");
    config.kms_configuration = KmsConfiguration::KmsKeyArn("not-an-arn".to_string());

    let err = match BranchKeyStore::with_clients(config) {
        Err(e) => e,
        Ok(_) => panic!("with_clients MUST reject a malformed KMS ARN"),
    };
    assert_eq!(err.kind(), &KeystoreErrorKind::Configuration);
}

#[tokio::test]
async fn new_with_caller_supplied_keystore_id_records_it_verbatim() {
    let store = BranchKeyStore::new(fixture_config_with_id("caller-id"))
        .await
        .expect("construction with valid config must succeed");
    assert_eq!(store.keystore_id(), "caller-id");
}

#[tokio::test]
async fn new_without_keystore_id_generates_v4_uuid() {
    let store = BranchKeyStore::new(fixture_config_no_id())
        .await
        .expect("construction with valid config must succeed");

    let id = store.keystore_id();
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
async fn new_without_keystore_id_two_calls_produce_distinct_uuids() {
    let store1 = BranchKeyStore::new(fixture_config_no_id()).await.unwrap();
    let store2 = BranchKeyStore::new(fixture_config_no_id()).await.unwrap();
    assert_ne!(
        store1.keystore_id(),
        store2.keystore_id(),
        "fresh v4 UUIDs MUST be distinct with overwhelming probability"
    );
}

#[tokio::test]
async fn new_with_malformed_kms_arn_returns_configuration_error() {
    let mut cfg = fixture_config_with_id("caller-id");
    cfg.kms_configuration = KmsConfiguration::KmsKeyArn("not-an-arn".to_string());
    let err = match BranchKeyStore::new(cfg).await {
        Ok(_) => panic!("construction with malformed ARN must fail"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), &KeystoreErrorKind::Configuration);
}

#[tokio::test]
async fn new_with_alias_kms_arn_returns_configuration_error() {
    let mut cfg = fixture_config_with_id("caller-id");
    cfg.kms_configuration = KmsConfiguration::KmsKeyArn(
        "arn:aws:kms:us-west-2:111122223333:alias/my-alias".to_string(),
    );
    let err = match BranchKeyStore::new(cfg).await {
        Ok(_) => panic!("construction with alias ARN must fail"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), &KeystoreErrorKind::Configuration);
}

#[tokio::test]
async fn new_with_discovery_config_succeeds_without_arn() {
    let mut cfg = fixture_config_with_id("caller-id");
    cfg.kms_configuration = KmsConfiguration::Discovery;
    BranchKeyStore::new(cfg)
        .await
        .expect("Discovery config requires no ARN and must succeed");
}

#[tokio::test]
async fn new_with_mr_discovery_config_succeeds() {
    let mut cfg = fixture_config_with_id("caller-id");
    cfg.kms_configuration = KmsConfiguration::MrDiscovery {
        region: "us-west-2".to_string(),
    };
    BranchKeyStore::new(cfg)
        .await
        .expect("MrDiscovery config requires no ARN and must succeed");
}

#[tokio::test]
async fn get_key_store_info_returns_configured_values() {
    let (kms, ddb) = dummy_clients();
    let cfg = KeyStoreConfig {
        ddb_table_name: "my-table".to_string(),
        kms_configuration: KmsConfiguration::KmsKeyArn(
            "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
                .to_string(),
        ),
        logical_keystore_name: "my-logical".to_string(),
        id: Some("my-id".to_string()),
        grant_tokens: Some(vec!["grant-1".to_string(), "grant-2".to_string()]),
        ddb_client: Some(ddb),
        kms_client: Some(kms),
    };
    let store = BranchKeyStore::new(cfg).await.unwrap();

    let info = store.get_key_store_info().unwrap();
    assert_eq!(info.keystore_id, "my-id");
    assert_eq!(info.keystore_name, "my-table");
    assert_eq!(info.logical_keystore_name, "my-logical");
    assert_eq!(info.grant_tokens, vec!["grant-1", "grant-2"]);
    assert!(matches!(
        info.kms_configuration,
        KmsConfiguration::KmsKeyArn(_)
    ));
}

#[tokio::test]
async fn get_key_store_info_returns_empty_grant_tokens_when_none() {
    let store = BranchKeyStore::new(fixture_config_with_id("id-x"))
        .await
        .unwrap();
    let info = store.get_key_store_info().unwrap();
    assert!(info.grant_tokens.is_empty());
}

#[tokio::test]
async fn get_key_store_info_uses_generated_uuid_when_id_was_none() {
    let store = BranchKeyStore::new(fixture_config_no_id()).await.unwrap();
    let info = store.get_key_store_info().unwrap();
    assert_eq!(info.keystore_id.len(), 36);
    assert_eq!(info.keystore_id, store.keystore_id());
}

// ─── Read-path APIs ─────────────────────────────────────────────────────────
//
// Without real AWS credentials and a real DynamoDB table, the read path
// fails at the SDK call. These tests assert the methods dispatch into the
// SDK (rather than returning an `Internal` stub) by observing a
// `Dynamodb`-kind error. Happy-path coverage lands in the real-AWS
// integration tests.

#[tokio::test]
async fn get_active_branch_key_dispatches_to_dynamodb() {
    let store = BranchKeyStore::new(fixture_config_with_id("id-x"))
        .await
        .unwrap();
    let err = match store.get_active_branch_key("bk-1".to_string()).await {
        Ok(_) => panic!("get_active_branch_key unexpectedly succeeded with no AWS configured"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), &KeystoreErrorKind::Dynamodb);

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
    let store = BranchKeyStore::new(fixture_config_with_id("id-x"))
        .await
        .unwrap();
    let err = match store
        .get_branch_key_version("bk-1".to_string(), "v-1".to_string())
        .await
    {
        Ok(_) => panic!("get_branch_key_version unexpectedly succeeded with no AWS configured"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), &KeystoreErrorKind::Dynamodb);
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
    let store = BranchKeyStore::new(fixture_config_with_id("id-x"))
        .await
        .unwrap();
    let err = match store.create_key_store().await {
        Ok(_) => panic!("create_key_store unexpectedly succeeded with no AWS configured"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), &KeystoreErrorKind::Dynamodb);

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
    let store = BranchKeyStore::new(fixture_config_with_id("id-x"))
        .await
        .unwrap();
    let err = match store.create_key(Some("bk-1".to_string()), None).await {
        Ok(_) => panic!("create_key with a branch key id and no EC must fail"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), &KeystoreErrorKind::Configuration);
}

#[tokio::test]
async fn create_key_with_discovery_config_fails() {
    let mut cfg = fixture_config_with_id("id-x");
    cfg.kms_configuration = KmsConfiguration::Discovery;
    let store = BranchKeyStore::new(cfg).await.unwrap();
    let err = match store.create_key(None, None).await {
        Ok(_) => panic!("create_key under a Discovery configuration must fail"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), &KeystoreErrorKind::Configuration);
}

#[tokio::test]
async fn create_key_dispatches_to_kms() {
    // With no AWS configured, CreateKey reaches the first KMS
    // GenerateDataKeyWithoutPlaintext call, which fails at dispatch and is
    // surfaced as a Kms-kind error.
    let store = BranchKeyStore::new(fixture_config_with_id("id-x"))
        .await
        .unwrap();
    let err = match store.create_key(None, None).await {
        Ok(_) => panic!("create_key unexpectedly succeeded with no AWS configured"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), &KeystoreErrorKind::Kms);
}

#[tokio::test]
async fn version_key_with_discovery_config_fails() {
    let mut cfg = fixture_config_with_id("id-x");
    cfg.kms_configuration = KmsConfiguration::Discovery;
    let store = BranchKeyStore::new(cfg).await.unwrap();
    let err = match store.version_key("bk-1".to_string()).await {
        Ok(_) => panic!("version_key under a Discovery configuration must fail"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), &KeystoreErrorKind::Configuration);
}

#[tokio::test]
async fn version_key_dispatches_to_dynamodb() {
    // VersionKey first reads the ACTIVE record; with no AWS configured that
    // GetItem fails at dispatch and surfaces a Dynamodb-kind error.
    let store = BranchKeyStore::new(fixture_config_with_id("id-x"))
        .await
        .unwrap();
    let err = match store.version_key("bk-1".to_string()).await {
        Ok(_) => panic!("version_key unexpectedly succeeded with no AWS configured"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), &KeystoreErrorKind::Dynamodb);
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
    let store = BranchKeyStore::new(fixture_config_with_id("id-x"))
        .await
        .unwrap();
    let err = match store.get_beacon_key("bk-1".to_string()).await {
        Ok(_) => panic!("get_beacon_key unexpectedly succeeded with no AWS configured"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), &KeystoreErrorKind::Dynamodb);
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
    let store = BranchKeyStore::new(fixture_config_with_id("id-x"))
        .await
        .unwrap();
    let err = match store.get_active_branch_key("bk-1".to_string()).await {
        Ok(_) => panic!("get_active_branch_key unexpectedly succeeded with no AWS configured"),
        Err(e) => e,
    };

    assert_eq!(
        err.message(),
        "DynamoDB GetItem failed",
        "the message must name this layer and the operation, with no SDK Display appended"
    );
    assert_eq!(
        err.to_string(),
        "KeystoreError(Dynamodb): DynamoDB GetItem failed",
        "Display renders only this layer; a chain-walking printer renders the cause"
    );
}

#[tokio::test]
async fn find_in_error_chain_recovers_the_sdk_error_by_type() {
    let store = BranchKeyStore::new(fixture_config_with_id("id-x"))
        .await
        .unwrap();
    let err = match store.get_active_branch_key("bk-1".to_string()).await {
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
    let store = BranchKeyStore::new(fixture_config_with_id("id-x"))
        .await
        .unwrap();
    let err = match store.get_active_branch_key("bk-1".to_string()).await {
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

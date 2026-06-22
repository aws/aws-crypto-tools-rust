// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for the concrete [`BranchKeyStore`] — slice 1a
//! (construction surface + `GetKeyStoreInfo`).
//!
//! No real AWS calls are made in this file. Operations that would
//! require KMS or DDB IO live in subsequent slices and have separate
//! `tests/test_keystore_branch_key_store_integ.rs` (real-AWS) coverage.

#![cfg(feature = "keystore")]

use aws_config::{BehaviorVersion, SdkConfig};
use aws_sdk_dynamodb::Client as DynamoDbClient;
use aws_sdk_kms::Client as KmsClient;

use aws_crypto_mpl::{
    BranchKeyStore, KeyStoreConfig, Keystore, KeystoreError, KmsConfiguration,
    keystore::KeystoreErrorKind,
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
/// `KmsConfiguration::KmsKeyArn` variant, and no grant tokens.
fn fixture_config_with_id(id: &str) -> KeyStoreConfig {
    KeyStoreConfig {
        table_name: "test-table".to_string(),
        kms_configuration: KmsConfiguration::KmsKeyArn(
            "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
                .to_string(),
        ),
        logical_keystore_name: "test-logical".to_string(),
        keystore_id: Some(id.to_string()),
        aws_kms_grant_tokens: None,
    }
}

/// Same as [`fixture_config_with_id`] but with `keystore_id: None`, so
/// `BranchKeyStore::new` exercises the v4-UUID fallback.
fn fixture_config_no_id() -> KeyStoreConfig {
    let mut cfg = fixture_config_with_id("placeholder");
    cfg.keystore_id = None;
    cfg
}

#[test]
fn new_with_caller_supplied_keystore_id_records_it_verbatim() {
    let (kms, ddb) = dummy_clients();
    let store = BranchKeyStore::new(fixture_config_with_id("caller-id"), kms, ddb)
        .expect("construction with valid config must succeed");
    assert_eq!(store.keystore_id(), "caller-id");
}

#[test]
fn new_without_keystore_id_generates_v4_uuid() {
    let (kms, ddb) = dummy_clients();
    let store = BranchKeyStore::new(fixture_config_no_id(), kms, ddb)
        .expect("construction with valid config must succeed");

    //= ../spec/framework/branch-key-store.md#keystore-id
    //= type=test
    //# If one is not supplied, then a [version 4 UUID](https://www.ietf.org/rfc/rfc4122.txt) MUST be used.
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

#[test]
fn new_without_keystore_id_two_calls_produce_distinct_uuids() {
    let (kms1, ddb1) = dummy_clients();
    let store1 = BranchKeyStore::new(fixture_config_no_id(), kms1, ddb1).unwrap();
    let (kms2, ddb2) = dummy_clients();
    let store2 = BranchKeyStore::new(fixture_config_no_id(), kms2, ddb2).unwrap();
    assert_ne!(
        store1.keystore_id(),
        store2.keystore_id(),
        "fresh v4 UUIDs MUST be distinct with overwhelming probability"
    );
}

#[test]
fn new_with_malformed_kms_arn_returns_configuration_error() {
    let (kms, ddb) = dummy_clients();
    let mut cfg = fixture_config_with_id("caller-id");
    cfg.kms_configuration = KmsConfiguration::KmsKeyArn("not-an-arn".to_string());
    let err = match BranchKeyStore::new(cfg, kms, ddb) {
        Ok(_) => panic!("construction with malformed ARN must fail"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), &KeystoreErrorKind::Configuration);
}

#[test]
fn new_with_alias_kms_arn_returns_configuration_error() {
    let (kms, ddb) = dummy_clients();
    let mut cfg = fixture_config_with_id("caller-id");
    cfg.kms_configuration = KmsConfiguration::KmsKeyArn(
        "arn:aws:kms:us-west-2:111122223333:alias/my-alias".to_string(),
    );
    let err = match BranchKeyStore::new(cfg, kms, ddb) {
        Ok(_) => panic!("construction with alias ARN must fail"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), &KeystoreErrorKind::Configuration);
}

#[test]
fn new_with_discovery_config_succeeds_without_arn() {
    let (kms, ddb) = dummy_clients();
    let mut cfg = fixture_config_with_id("caller-id");
    cfg.kms_configuration = KmsConfiguration::Discovery;
    BranchKeyStore::new(cfg, kms, ddb).expect("Discovery config requires no ARN and must succeed");
}

#[test]
fn new_with_mr_discovery_config_succeeds() {
    let (kms, ddb) = dummy_clients();
    let mut cfg = fixture_config_with_id("caller-id");
    cfg.kms_configuration = KmsConfiguration::MrDiscovery {
        region: "us-west-2".to_string(),
    };
    BranchKeyStore::new(cfg, kms, ddb)
        .expect("MrDiscovery config requires no ARN and must succeed");
}

#[tokio::test]
async fn get_key_store_info_returns_configured_values() {
    let (kms, ddb) = dummy_clients();
    let cfg = KeyStoreConfig {
        table_name: "my-table".to_string(),
        kms_configuration: KmsConfiguration::KmsKeyArn(
            "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
                .to_string(),
        ),
        logical_keystore_name: "my-logical".to_string(),
        keystore_id: Some("my-id".to_string()),
        aws_kms_grant_tokens: Some(vec!["grant-1".to_string(), "grant-2".to_string()]),
    };
    let store = BranchKeyStore::new(cfg, kms, ddb).unwrap();

    //= ../spec/framework/branch-key-store.md#getkeystoreinfo
    //= type=test
    //# This operation MUST return the keystore information in this keystore configuration.
    let info = store.get_key_store_info().await.unwrap();
    assert_eq!(info.keystore_id, "my-id");
    assert_eq!(info.keystore_name, "my-table");
    assert_eq!(info.logical_keystore_name, "my-logical");
    assert_eq!(info.aws_kms_grant_tokens, vec!["grant-1", "grant-2"]);
    assert!(matches!(
        info.aws_kms_configuration,
        KmsConfiguration::KmsKeyArn(_)
    ));
}

#[tokio::test]
async fn get_key_store_info_returns_empty_grant_tokens_when_none() {
    let (kms, ddb) = dummy_clients();
    let store = BranchKeyStore::new(fixture_config_with_id("id-x"), kms, ddb).unwrap();
    let info = store.get_key_store_info().await.unwrap();
    assert!(info.aws_kms_grant_tokens.is_empty());
}

#[tokio::test]
async fn get_key_store_info_uses_generated_uuid_when_id_was_none() {
    let (kms, ddb) = dummy_clients();
    let store = BranchKeyStore::new(fixture_config_no_id(), kms, ddb).unwrap();
    let info = store.get_key_store_info().await.unwrap();
    assert_eq!(info.keystore_id.len(), 36);
    assert_eq!(info.keystore_id, store.keystore_id());
}

// ─── Slice 1a stubs: deferred operations return errors ──────────────────────
//
// These tests pin the contract that operations beyond `get_key_store_info`
// return an explicit "not yet implemented in this slice" error rather
// than panicking. They will be replaced (or deleted) when the
// corresponding slice lands a real implementation.

#[tokio::test]
async fn create_key_store_is_not_implemented_in_slice_1a() {
    let (kms, ddb) = dummy_clients();
    let store = BranchKeyStore::new(fixture_config_with_id("id-x"), kms, ddb).unwrap();
    assert_not_implemented(store.create_key_store().await, "create_key_store");
}

#[tokio::test]
async fn create_key_is_not_implemented_in_slice_1a() {
    let (kms, ddb) = dummy_clients();
    let store = BranchKeyStore::new(fixture_config_with_id("id-x"), kms, ddb).unwrap();
    assert_not_implemented(store.create_key(None, None).await, "create_key");
}

#[tokio::test]
async fn version_key_is_not_implemented_in_slice_1a() {
    let (kms, ddb) = dummy_clients();
    let store = BranchKeyStore::new(fixture_config_with_id("id-x"), kms, ddb).unwrap();
    assert_not_implemented(store.version_key("bk-1".to_string()).await, "version_key");
}

#[tokio::test]
async fn get_active_branch_key_is_not_implemented_in_slice_1a() {
    let (kms, ddb) = dummy_clients();
    let store = BranchKeyStore::new(fixture_config_with_id("id-x"), kms, ddb).unwrap();
    assert_not_implemented(
        store.get_active_branch_key("bk-1".to_string()).await,
        "get_active_branch_key",
    );
}

#[tokio::test]
async fn get_branch_key_version_is_not_implemented_in_slice_1a() {
    let (kms, ddb) = dummy_clients();
    let store = BranchKeyStore::new(fixture_config_with_id("id-x"), kms, ddb).unwrap();
    assert_not_implemented(
        store
            .get_branch_key_version("bk-1".to_string(), "v-1".to_string())
            .await,
        "get_branch_key_version",
    );
}

#[tokio::test]
async fn get_beacon_key_is_not_implemented_in_slice_1a() {
    let (kms, ddb) = dummy_clients();
    let store = BranchKeyStore::new(fixture_config_with_id("id-x"), kms, ddb).unwrap();
    assert_not_implemented(
        store.get_beacon_key("bk-1".to_string()).await,
        "get_beacon_key",
    );
}

fn assert_not_implemented<T>(result: Result<T, KeystoreError>, op_name: &str) {
    let err = match result {
        Ok(_) => panic!("{op_name} unexpectedly succeeded — slice 1a should return an error"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), &KeystoreErrorKind::Internal);
    assert!(
        err.message().contains(op_name),
        "error message must mention the op name '{op_name}', got: {}",
        err.message()
    );
    assert!(
        err.message().contains("not yet implemented"),
        "error message must mention 'not yet implemented', got: {}",
        err.message()
    );
}

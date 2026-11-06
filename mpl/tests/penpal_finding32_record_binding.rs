// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Reproduction + regression for PenPal finding 32 (CWE-345): the DynamoDB key
//! store must reject a record whose own `branch-key-id`/`type` attributes do
//! not match the `(branch_key_id, sort_key)` that was requested. Without that
//! check an authentic record relocated into another key's slot decrypts and is
//! accepted, because the KMS encryption context is built from the record's own
//! attributes rather than the request.
//!
//! The Dafny reference enforces this (GetActiveBranchKeyItem / GetVersionBranchKeyItem
//! require `item["branch-key-id"] == branchKeyIdentifier`, and the version item
//! also `item["type"] == "branch:version:" + branchKeyVersion`). These tests
//! drive the real public key-store API with a mocked DynamoDB that returns a
//! mismatched record, and assert the read is refused BEFORE any KMS call.

use std::sync::{Arc, Mutex};

use aws_crypto_mpl::Error;
use aws_crypto_mpl::key_store::DynamoDbKeyStore;
use aws_crypto_mpl::key_store::types::KmsConfiguration;
use aws_sdk_dynamodb::Client as DynamoDbClient;
use aws_sdk_kms::Client as KmsClient;
use aws_smithy_runtime_api::client::http::{
    HttpConnector, HttpConnectorFuture, SharedHttpConnector, http_client_fn,
};
use aws_smithy_runtime_api::client::orchestrator::HttpRequest;
use aws_smithy_runtime_api::http::{Response, StatusCode};
use aws_smithy_types::body::SdkBody;
use aws_smithy_types::retry::RetryConfig;

const KEY_ARN: &str = "arn:aws:kms:us-west-2:111122223333:key/1234abcd";
const TABLE: &str = "KeyStoreTable";

/// A DynamoDB/KMS mock that answers every `GetItem` with a record carrying the
/// configured `record_id`/`record_type` attributes (regardless of the key that
/// was requested), and records which service operations were invoked so a test
/// can prove KMS was or was not reached.
#[derive(Clone, Debug)]
struct Mock {
    record_id: String,
    record_type: String,
    ops: Arc<Mutex<Vec<String>>>,
}

impl Mock {
    fn new(record_id: &str, record_type: &str) -> Self {
        Self {
            record_id: record_id.to_string(),
            record_type: record_type.to_string(),
            ops: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn ops(&self) -> Vec<String> {
        self.ops.lock().unwrap().clone()
    }
}

impl HttpConnector for Mock {
    fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
        let op = request
            .headers()
            .get("x-amz-target")
            .unwrap_or_default()
            .to_owned();
        self.ops.lock().unwrap().push(op.clone());
        let (body, content_type) = match op.as_str() {
            "DynamoDB_20120810.GetItem" => (
                format!(
                    r#"{{"Item":{{"branch-key-id":{{"S":"{}"}},"type":{{"S":"{}"}},"version":{{"S":"branch:version:4e6b3e4a-1c8b-4f5e-9d2a-7b3c1d2e3f40"}},"create-time":{{"S":"2026-01-01T00:00:00.000000Z"}},"hierarchy-version":{{"N":"1"}},"kms-arn":{{"S":"{KEY_ARN}"}},"enc":{{"B":"AAAA"}}}}}}"#,
                    self.record_id, self.record_type
                ),
                "application/x-amz-json-1.0",
            ),
            "TrentService.Decrypt" => (
                format!(
                    r#"{{"KeyId":"{KEY_ARN}","Plaintext":"QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI="}}"#
                ),
                "application/x-amz-json-1.1",
            ),
            _ => ("{}".to_owned(), "application/x-amz-json-1.0"),
        };
        let mut response = Response::new(StatusCode::try_from(200).unwrap(), SdkBody::from(body));
        response.headers_mut().insert("content-type", content_type);
        HttpConnectorFuture::ready(Ok(response))
    }
}

fn sdk_client_pair(mock: &Mock) -> (KmsClient, DynamoDbClient) {
    let creds =
        |access: &str| aws_sdk_kms::config::Credentials::new(access, "secret", None, None, "fake");
    let kms = {
        let mock = mock.clone();
        KmsClient::from_conf(
            aws_sdk_kms::Config::builder()
                .behavior_version(aws_sdk_kms::config::BehaviorVersion::latest())
                .region(aws_sdk_kms::config::Region::new("us-west-2"))
                .credentials_provider(creds("AKIDFAKE"))
                .retry_config(RetryConfig::disabled())
                .http_client(http_client_fn(move |_, _| {
                    SharedHttpConnector::new(mock.clone())
                }))
                .build(),
        )
    };
    let ddb = {
        let mock = mock.clone();
        DynamoDbClient::from_conf(
            aws_sdk_dynamodb::Config::builder()
                .behavior_version(aws_sdk_dynamodb::config::BehaviorVersion::latest())
                .region(aws_sdk_dynamodb::config::Region::new("us-west-2"))
                .credentials_provider(aws_sdk_dynamodb::config::Credentials::new(
                    "AKIDFAKE", "secret", None, None, "fake",
                ))
                .retry_config(RetryConfig::disabled())
                .http_client(http_client_fn(move |_, _| {
                    SharedHttpConnector::new(mock.clone())
                }))
                .build(),
        )
    };
    (kms, ddb)
}

async fn key_store(mock: &Mock) -> DynamoDbKeyStore {
    let (kms, ddb) = sdk_client_pair(mock);
    DynamoDbKeyStore::builder()
        .ddb_table_name(TABLE)
        .logical_key_store_name(TABLE)
        .kms_configuration(KmsConfiguration::kms_key_arn(KEY_ARN))
        .kms_client(kms)
        .ddb_client(ddb)
        .build()
        .await
        .unwrap()
}

/// get_active_branch_key: the table returns an ACTIVE record belonging to a
/// DIFFERENT branch key. It must be rejected, and KMS must never be called.
#[tokio::test]
async fn active_record_with_mismatched_branch_key_id_is_rejected_before_kms() {
    // Requested "tenant-x", but the slot holds "tenant-y"'s authentic record.
    let mock = Mock::new("tenant-y", "branch:ACTIVE");
    let store = key_store(&mock).await;

    let err = store
        .get_active_branch_key()
        .branch_key_id("tenant-x".to_string())
        .send()
        .await
        .expect_err("a relocated active record must be rejected");

    assert!(
        matches!(err, Error::InvalidMaterials(_)),
        "expected InvalidMaterials, got {err:?}"
    );
    assert!(
        !mock.ops().iter().any(|o| o == "TrentService.Decrypt"),
        "the mismatch must be caught before any KMS Decrypt; ops = {:?}",
        mock.ops()
    );
}

/// get_branch_key_version: the table returns a record whose `type` is not the
/// requested version. It must be rejected before KMS.
#[tokio::test]
async fn version_record_with_mismatched_type_is_rejected_before_kms() {
    // Requested version "v-requested", but the slot holds a different version.
    let mock = Mock::new("tenant-x", "branch:version:v-other");
    let store = key_store(&mock).await;

    let err = store
        .get_branch_key_version()
        .branch_key_id("tenant-x".to_string())
        .branch_key_version("v-requested".to_string())
        .send()
        .await
        .expect_err("a relocated version record must be rejected");

    assert!(
        matches!(err, Error::InvalidMaterials(_)),
        "expected InvalidMaterials, got {err:?}"
    );
    assert!(
        !mock.ops().iter().any(|o| o == "TrentService.Decrypt"),
        "the mismatch must be caught before any KMS Decrypt; ops = {:?}",
        mock.ops()
    );
}

/// Control: when the record's identity DOES match the request, `fetch_record`
/// accepts it and the read proceeds to KMS (proving the new check does not
/// reject legitimate records). The call may fail later in KMS/EC handling; all
/// this asserts is that the DynamoDB GetItem was accepted and a Decrypt was
/// attempted.
#[tokio::test]
async fn matching_active_record_proceeds_to_kms() {
    let mock = Mock::new("tenant-x", "branch:ACTIVE");
    let store = key_store(&mock).await;

    let _ = store
        .get_active_branch_key()
        .branch_key_id("tenant-x".to_string())
        .send()
        .await;

    assert!(
        mock.ops().iter().any(|o| o == "TrentService.Decrypt"),
        "a matching record must pass the binding check and reach KMS; ops = {:?}",
        mock.ops()
    );
}

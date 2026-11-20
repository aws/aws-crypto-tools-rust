// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! A key store record returned for one `(branch-key-id, type)` key must
//! carry that same `branch-key-id` and `type`. These tests use a DynamoDB
//! client that returns the wrong item, which the key store must reject.

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
const REQUESTED_ID: &str = "victim-key";
const VERSION_A: &str = "4e6b3e4a-1c8b-4f5e-9d2a-7b3c1d2e3f40";
const VERSION_B: &str = "9a9a9a9a-1c8b-4f5e-9d2a-7b3c1d2e3f40";

/// Answers every GetItem with `(id, type)` regardless of the requested key,
/// and every KMS Decrypt with 32 bytes of plaintext.
#[derive(Clone, Debug)]
struct Relocated {
    id: &'static str,
    record_type: String,
}

impl HttpConnector for Relocated {
    fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
        let op = request
            .headers()
            .get("x-amz-target")
            .unwrap_or_default()
            .to_owned();
        let (id, ty) = (self.id, &self.record_type);
        let (body, content_type) = match op.as_str() {
            "DynamoDB_20120810.GetItem" => {
                let version = if ty == "branch:ACTIVE" {
                    format!(r#","version":{{"S":"branch:version:{VERSION_A}"}}"#)
                } else {
                    String::new()
                };
                (
                    format!(
                        r#"{{"Item":{{"branch-key-id":{{"S":"{id}"}},"type":{{"S":"{ty}"}}{version},"create-time":{{"S":"2026-01-01T00:00:00.000000Z"}},"hierarchy-version":{{"N":"1"}},"kms-arn":{{"S":"{KEY_ARN}"}},"enc":{{"B":"AAAA"}}}}}}"#
                    ),
                    "application/x-amz-json-1.0",
                )
            }
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

async fn key_store(id: &'static str, record_type: &str) -> DynamoDbKeyStore {
    let connector = Relocated {
        id,
        record_type: record_type.to_owned(),
    };
    let creds = || aws_sdk_kms::config::Credentials::new("AKIDFAKE", "fake", None, None, "fake");
    let kms_conn = connector.clone();
    let kms = KmsClient::from_conf(
        aws_sdk_kms::Config::builder()
            .behavior_version(aws_sdk_kms::config::BehaviorVersion::latest())
            .region(aws_sdk_kms::config::Region::new("us-west-2"))
            .credentials_provider(creds())
            .retry_config(RetryConfig::disabled())
            .http_client(http_client_fn(move |_, _| {
                SharedHttpConnector::new(kms_conn.clone())
            }))
            .build(),
    );
    let ddb = DynamoDbClient::from_conf(
        aws_sdk_dynamodb::Config::builder()
            .behavior_version(aws_sdk_dynamodb::config::BehaviorVersion::latest())
            .region(aws_sdk_dynamodb::config::Region::new("us-west-2"))
            .credentials_provider(creds())
            .retry_config(RetryConfig::disabled())
            .http_client(http_client_fn(move |_, _| {
                SharedHttpConnector::new(connector.clone())
            }))
            .build(),
    );
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

#[tokio::test]
async fn get_active_branch_key_rejects_another_keys_record() {
    let store = key_store("attacker-key", "branch:ACTIVE").await;
    let result = store
        .get_active_branch_key()
        .branch_key_id(REQUESTED_ID)
        .send()
        .await;
    let err = result.expect_err("a record for another branch key must be rejected");
    assert!(err.is_invalid_materials(), "{err:?}");
}

#[tokio::test]
async fn get_active_branch_key_rejects_a_version_record() {
    let store = key_store(REQUESTED_ID, &format!("branch:version:{VERSION_B}")).await;
    let result = store
        .get_active_branch_key()
        .branch_key_id(REQUESTED_ID)
        .send()
        .await;
    let err = result.expect_err("a version record in the ACTIVE slot must be rejected");
    assert!(err.is_invalid_materials(), "{err:?}");
}

#[tokio::test]
async fn get_branch_key_version_rejects_another_keys_record() {
    let store = key_store("attacker-key", &format!("branch:version:{VERSION_A}")).await;
    let result = store
        .get_branch_key_version()
        .branch_key_id(REQUESTED_ID)
        .branch_key_version(VERSION_A)
        .send()
        .await;
    let err = result.expect_err("a record for another branch key must be rejected");
    assert!(err.is_invalid_materials(), "{err:?}");
}

#[tokio::test]
async fn get_branch_key_version_rejects_another_version() {
    let store = key_store(REQUESTED_ID, &format!("branch:version:{VERSION_B}")).await;
    let result = store
        .get_branch_key_version()
        .branch_key_id(REQUESTED_ID)
        .branch_key_version(VERSION_A)
        .send()
        .await;
    let err = result.expect_err("a record for another version must be rejected");
    assert!(err.is_invalid_materials(), "{err:?}");
}

#[tokio::test]
async fn get_beacon_key_rejects_another_keys_record() {
    let store = key_store("attacker-key", "beacon:ACTIVE").await;
    let result = store
        .get_beacon_key()
        .branch_key_id(REQUESTED_ID)
        .send()
        .await;
    let err = result.expect_err("a record for another branch key must be rejected");
    assert!(err.is_invalid_materials(), "{err:?}");
}

#[tokio::test]
async fn get_beacon_key_rejects_a_branch_record() {
    let store = key_store(REQUESTED_ID, "branch:ACTIVE").await;
    let result = store
        .get_beacon_key()
        .branch_key_id(REQUESTED_ID)
        .send()
        .await;
    let err = result.expect_err("a branch key record in the beacon slot must be rejected");
    assert!(err.is_invalid_materials(), "{err:?}");
}

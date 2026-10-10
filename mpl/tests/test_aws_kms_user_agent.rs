// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The user agent on the AWS requests a `BranchKeyStore` sends.

use std::sync::{Arc, Mutex};

use aws_config::FrameworkMetadata;
use aws_crypto_mpl::{BranchKeyStore, KeyStoreClient, KmsConfiguration};
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
const BRANCH_KEY_ID: &str = "my-branch-key";
const MPL_USER_AGENT: &str = concat!("lib/AwsCryptographicMPL-Rust/", env!("CARGO_PKG_VERSION"));

/// Records each request's `x-amz-target` and `x-amz-user-agent`, and answers with a well-formed success.
#[derive(Clone, Debug, Default)]
struct Capture(Arc<Mutex<Vec<(String, String)>>>);

impl Capture {
    fn requests(&self) -> Vec<(String, String)> {
        self.0.lock().unwrap().clone()
    }
}

impl HttpConnector for Capture {
    fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
        let header = |name| request.headers().get(name).unwrap_or_default().to_owned();
        let op = header("x-amz-target");
        self.0
            .lock()
            .unwrap()
            .push((op.clone(), header("x-amz-user-agent")));
        let (body, content_type) = match op.as_str() {
            "DynamoDB_20120810.GetItem" => (
                format!(
                    r#"{{"Item":{{"branch-key-id":{{"S":"{BRANCH_KEY_ID}"}},"type":{{"S":"branch:ACTIVE"}},"version":{{"S":"branch:version:4e6b3e4a-1c8b-4f5e-9d2a-7b3c1d2e3f40"}},"create-time":{{"S":"2026-01-01T00:00:00.000000Z"}},"hierarchy-version":{{"N":"1"}},"kms-arn":{{"S":"{KEY_ARN}"}},"enc":{{"B":"AAAA"}}}}}}"#
                ),
                "application/x-amz-json-1.0",
            ),
            "TrentService.Decrypt" => (
                format!(
                    r#"{{"KeyId":"{KEY_ARN}","Plaintext":"QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI="}}"#
                ),
                "application/x-amz-json-1.1",
            ),
            "TrentService.GenerateDataKeyWithoutPlaintext" | "TrentService.ReEncrypt" => (
                format!(r#"{{"KeyId":"{KEY_ARN}","CiphertextBlob":"AAAA"}}"#),
                "application/x-amz-json-1.1",
            ),
            _ => ("{}".to_owned(), "application/x-amz-json-1.0"),
        };
        let mut response = Response::new(StatusCode::try_from(200).unwrap(), SdkBody::from(body));
        response.headers_mut().insert("content-type", content_type);
        HttpConnectorFuture::ready(Ok(response))
    }
}

fn kms_client(capture: &Capture, framework: Option<FrameworkMetadata>) -> KmsClient {
    let capture = capture.clone();
    let mut config = aws_sdk_kms::Config::builder()
        .behavior_version(aws_sdk_kms::config::BehaviorVersion::latest())
        .region(aws_sdk_kms::config::Region::new("us-west-2"))
        .credentials_provider(aws_sdk_kms::config::Credentials::new(
            "AKIDFAKE",
            "fake-secret",
            None,
            None,
            "fake",
        ))
        .retry_config(RetryConfig::disabled())
        .http_client(http_client_fn(move |_, _| {
            SharedHttpConnector::new(capture.clone())
        }));
    if let Some(framework) = framework {
        config = config.framework_metadata(framework);
    }
    KmsClient::from_conf(config.build())
}

fn ddb_client(capture: &Capture) -> DynamoDbClient {
    let capture = capture.clone();
    let config = aws_sdk_dynamodb::Config::builder()
        .behavior_version(aws_sdk_dynamodb::config::BehaviorVersion::latest())
        .region(aws_sdk_dynamodb::config::Region::new("us-west-2"))
        .credentials_provider(aws_sdk_dynamodb::config::Credentials::new(
            "AKIDFAKE",
            "fake-secret",
            None,
            None,
            "fake",
        ))
        .retry_config(RetryConfig::disabled())
        .http_client(http_client_fn(move |_, _| {
            SharedHttpConnector::new(capture.clone())
        }))
        .build();
    DynamoDbClient::from_conf(config)
}

async fn key_store(capture: &Capture, framework: Option<FrameworkMetadata>) -> KeyStoreClient {
    BranchKeyStore::builder()
        .ddb_table_name(TABLE)
        .logical_key_store_name(TABLE)
        .kms_configuration(KmsConfiguration::KmsKeyArn(KEY_ARN.to_owned()))
        .kms_client(kms_client(capture, framework))
        .ddb_client(ddb_client(capture))
        .build()
        .await
        .unwrap()
}

/// Sends every KMS operation the key store uses: GenerateDataKeyWithoutPlaintext, ReEncrypt, and Decrypt.
async fn exercise(key_store: &KeyStoreClient) {
    key_store.create_key().send().await.unwrap();
    key_store
        .get_active_branch_key()
        .branch_key_id(BRANCH_KEY_ID)
        .send()
        .await
        .unwrap();
}

#[tokio::test]
async fn every_kms_request_carries_the_mpl_user_agent() {
    let capture = Capture::default();
    exercise(&key_store(&capture, None).await).await;

    let requests = capture.requests();
    let kms_ops: Vec<&str> = requests
        .iter()
        .map(|(op, _)| op.as_str())
        .filter(|op| op.starts_with("TrentService."))
        .collect();
    assert_eq!(
        kms_ops,
        [
            "TrentService.GenerateDataKeyWithoutPlaintext",
            "TrentService.ReEncrypt",
            "TrentService.GenerateDataKeyWithoutPlaintext",
            "TrentService.Decrypt",
        ]
    );
    for (op, user_agent) in &requests {
        let has_mpl = user_agent.split(' ').any(|token| token == MPL_USER_AGENT);
        assert_eq!(
            has_mpl,
            op.starts_with("TrentService."),
            "{op} user agent: {user_agent}"
        );
    }
}

#[tokio::test]
async fn kms_requests_keep_the_callers_framework_metadata() {
    let capture = Capture::default();
    let caller = FrameworkMetadata::new("caller-framework", Some("1.2.3")).unwrap();
    exercise(&key_store(&capture, Some(caller)).await).await;

    let requests = capture.requests();
    let kms: Vec<&str> = requests
        .iter()
        .filter(|(op, _)| op.starts_with("TrentService."))
        .map(|(_, user_agent)| user_agent.as_str())
        .collect();
    assert_eq!(kms.len(), 4);
    for user_agent in kms {
        let tokens: Vec<&str> = user_agent.split(' ').collect();
        let caller_at = tokens
            .iter()
            .position(|t| *t == "lib/caller-framework/1.2.3");
        let mpl_at = tokens.iter().position(|t| *t == MPL_USER_AGENT);
        assert!(
            matches!((caller_at, mpl_at), (Some(c), Some(m)) if c < m),
            "user agent: {user_agent}"
        );
        assert_eq!(
            tokens.iter().filter(|t| **t == MPL_USER_AGENT).count(),
            1,
            "user agent: {user_agent}"
        );
    }
}

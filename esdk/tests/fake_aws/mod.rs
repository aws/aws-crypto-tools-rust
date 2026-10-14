// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! A fake AWS KMS and DynamoDB, for tests of the errors customers see.
#![allow(dead_code)]

use std::sync::Arc;
use std::time::Duration;

use aws_crypto_mpl::aws_sdk_dynamodb;
use aws_crypto_mpl::aws_sdk_kms;
use aws_crypto_mpl::cmc::DefaultCmc;
use aws_crypto_mpl::{HierarchicalKeyring, KeyStoreClient, KmsConfiguration};
use aws_smithy_runtime_api::client::http::{
    HttpConnector, HttpConnectorFuture, SharedHttpConnector, http_client_fn,
};
use aws_smithy_runtime_api::client::orchestrator::HttpRequest;
use aws_smithy_runtime_api::http::{Response, StatusCode};
use aws_smithy_types::body::SdkBody;
use aws_smithy_types::retry::RetryConfig;

pub const KEY_ARN: &str = "arn:aws:kms:us-west-2:111122223333:key/1234abcd";
pub const TABLE: &str = "KeyStoreTable";
pub const BRANCH_KEY_ID: &str = "my-branch-key";
pub const VERSION: &str = "4e6b3e4a-1c8b-4f5e-9d2a-7b3c1d2e3f40";
/// The plaintext branch key the fake KMS returns: 32 bytes of 0x42.
pub const BRANCH_KEY_B64: &str = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=";

/// An answer to one AWS call.
#[derive(Debug, Clone)]
pub struct Reply {
    pub status: u16,
    pub body: String,
    pub request_id: &'static str,
}

impl Reply {
    pub fn ok(body: impl Into<String>) -> Self {
        Self {
            status: 200,
            body: body.into(),
            request_id: "ok-request",
        }
    }

    /// An AWS JSON-protocol error with `code`.
    pub fn error(status: u16, code: &str, request_id: &'static str) -> Self {
        Self {
            status,
            body: format!(r#"{{"__type":"{code}","message":"{code} from the fake"}}"#),
            request_id,
        }
    }
}

type Handler = dyn Fn(&str, &str) -> Option<Reply> + Send + Sync;

/// Answers each call with the handler's reply, or a well-formed success.
#[derive(Clone)]
pub struct FakeAws {
    handler: Arc<Handler>,
}

impl std::fmt::Debug for FakeAws {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FakeAws")
    }
}

impl FakeAws {
    /// `handler(operation, request_body)` answers a call, for example
    /// `("TrentService.Decrypt", ..)` or `("DynamoDB_20120810.GetItem", ..)`,
    /// or returns `None` for the default success.
    pub fn new(handler: impl Fn(&str, &str) -> Option<Reply> + Send + Sync + 'static) -> Self {
        Self {
            handler: Arc::new(handler),
        }
    }

    pub fn ok() -> Self {
        Self::new(|_, _| None)
    }

    fn answer(&self, op: &str, body: &str) -> Reply {
        (self.handler)(op, body).unwrap_or_else(|| default_reply(op, body))
    }

    pub fn kms_client(&self) -> aws_sdk_kms::Client {
        let fake = self.clone();
        let config = aws_sdk_kms::Config::builder()
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
                SharedHttpConnector::new(fake.clone())
            }))
            .build();
        aws_sdk_kms::Client::from_conf(config)
    }

    pub fn ddb_client(&self) -> aws_sdk_dynamodb::Client {
        let fake = self.clone();
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
                SharedHttpConnector::new(fake.clone())
            }))
            .build();
        aws_sdk_dynamodb::Client::from_conf(config)
    }

    pub async fn key_store(&self) -> KeyStoreClient {
        KeyStoreClient::builder()
            .ddb_table_name(TABLE)
            .logical_key_store_name(TABLE)
            .kms_configuration(KmsConfiguration::KmsKeyArn(KEY_ARN.into()))
            .kms_client(self.kms_client())
            .ddb_client(self.ddb_client())
            .build()
            .await
            .expect("the key store configuration is valid")
    }

    /// A hierarchical keyring for [`BRANCH_KEY_ID`] with its own empty cache.
    pub async fn keyring(&self) -> HierarchicalKeyring {
        HierarchicalKeyring::builder()
            .key_store(self.key_store().await)
            .branch_key_id(BRANCH_KEY_ID)
            .ttl(Duration::from_secs(600))
            .cache(
                DefaultCmc::builder()
                    .entry_capacity(10)
                    .build()
                    .expect("a valid capacity"),
            )
            .build()
            .expect("the keyring configuration is valid")
    }
}

impl HttpConnector for FakeAws {
    fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
        let op = request
            .headers()
            .get("x-amz-target")
            .unwrap_or_default()
            .to_owned();
        let body = request
            .body()
            .bytes()
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .unwrap_or_default();
        let reply = self.answer(&op, &body);
        let mut response = Response::new(
            StatusCode::try_from(reply.status).expect("a valid status"),
            SdkBody::from(reply.body),
        );
        response
            .headers_mut()
            .insert("x-amzn-RequestId", reply.request_id);
        let content_type = if op.starts_with("DynamoDB") {
            "application/x-amz-json-1.0"
        } else {
            "application/x-amz-json-1.1"
        };
        response.headers_mut().insert("content-type", content_type);
        HttpConnectorFuture::ready(Ok(response))
    }
}

/// The string value of DynamoDB attribute `name` in a request body.
pub fn string_attribute<'a>(body: &'a str, name: &str) -> Option<&'a str> {
    let marker = format!(r#""{name}":{{"S":""#);
    let start = body.find(&marker)? + marker.len();
    let len = body[start..].find('"')?;
    Some(&body[start..start + len])
}

/// A branch key record, as DynamoDB `GetItem` returns it, for the requested `type`.
pub fn record(record_type: &str, branch_key_b64_enc: &str, extra: &str) -> String {
    let version = if record_type == "branch:ACTIVE" {
        format!(r#","version":{{"S":"branch:version:{VERSION}"}}"#)
    } else {
        String::new()
    };
    format!(
        r#"{{"Item":{{"branch-key-id":{{"S":"{BRANCH_KEY_ID}"}},"type":{{"S":"{record_type}"}}{version},"create-time":{{"S":"2026-01-01T00:00:00.000000Z"}},"hierarchy-version":{{"N":"1"}},"kms-arn":{{"S":"{KEY_ARN}"}},"enc":{{"B":"{branch_key_b64_enc}"}}{extra}}}}}"#
    )
}

fn default_reply(op: &str, body: &str) -> Reply {
    match op {
        "DynamoDB_20120810.GetItem" => {
            let record_type = string_attribute(body, "type").unwrap_or("branch:ACTIVE");
            Reply::ok(record(record_type, "AAAA", ""))
        }
        "DynamoDB_20120810.TransactWriteItems" => Reply::ok("{}"),
        "TrentService.Decrypt" => Reply::ok(format!(
            r#"{{"KeyId":"{KEY_ARN}","Plaintext":"{BRANCH_KEY_B64}","EncryptionAlgorithm":"SYMMETRIC_DEFAULT"}}"#
        )),
        "TrentService.GenerateDataKeyWithoutPlaintext" | "TrentService.ReEncrypt" => Reply::ok(
            format!(r#"{{"KeyId":"{KEY_ARN}","CiphertextBlob":"AAAA"}}"#),
        ),
        other => Reply::error(400, &format!("UnexpectedOperation{other}"), "unexpected"),
    }
}

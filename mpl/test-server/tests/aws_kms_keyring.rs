// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! AWS KMS keyring construction over the real wire, in process.
//!
//! Building the keyring reads only configuration, so none of these reach KMS.
//! OnEncrypt and OnDecrypt, which do, are in the commons cross-language suite.

use std::sync::Arc;

use aws_mpl_test_server::handlers::AppState;
use aws_mpl_test_server::model::*;
use aws_mpl_test_server::wire::app;
use axum::Router;
use axum::body::Body;
use axum::http::Request;
use ciborium::value::Value;
use tower::ServiceExt;

const REGION: &str = "us-west-2";
const KEY_ID: &str = "9d989aa2-2f9c-438c-a745-cc57d3ad0126";
const KMS_KEY_ARN: &str =
    "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126";

async fn post<Req: serde::Serialize>(
    router: &Router,
    operation: &str,
    req: &Req,
) -> (u16, Vec<u8>) {
    let mut body = Vec::new();
    ciborium::into_writer(req, &mut body).expect("encode request");
    let request = Request::builder()
        .method("POST")
        .uri(format!("/service/MPLTestServer/operation/{operation}"))
        .header("smithy-protocol", "rpc-v2-cbor")
        .header("content-type", "application/cbor")
        .body(Body::from(body))
        .expect("build request");
    let response = router.clone().oneshot(request).await.expect("dispatch");
    let status = response.status().as_u16();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    (status, bytes.to_vec())
}

async fn call<Req: serde::Serialize, Resp: serde::de::DeserializeOwned>(
    router: &Router,
    operation: &str,
    req: &Req,
) -> Resp {
    let (status, body) = post(router, operation, req).await;
    assert_eq!(status, 200, "{operation} failed: {}", error_type(&body));
    ciborium::from_reader(&body[..]).expect("decode response")
}

fn error_type(body: &[u8]) -> String {
    let value: Value = ciborium::from_reader(body).expect("decode error body");
    let Value::Map(entries) = value else {
        panic!("error body is not a CBOR map");
    };
    entries
        .into_iter()
        .find_map(|(k, v)| match (k, v) {
            (Value::Text(k), Value::Text(v)) if k == "__type" => Some(v),
            _ => None,
        })
        .expect("error body has __type")
}

async fn expect_error<Req: serde::Serialize>(
    router: &Router,
    operation: &str,
    req: &Req,
    expected_type: &str,
) {
    let (status, body) = post(router, operation, req).await;
    assert_eq!(status, 400, "{operation} should fail");
    assert_eq!(
        error_type(&body),
        format!("aws.cryptography.mpl.testserver#{expected_type}")
    );
}

fn kms_client() -> KmsClientConfig {
    KmsClientConfig {
        region: REGION.to_owned(),
        endpoint: None,
    }
}

fn keyring_request(kms_key_id: &str) -> CreateAwsKmsKeyringRequest {
    CreateAwsKmsKeyringRequest {
        kms_key_id: Some(kms_key_id.to_owned()),
        kms_client: Some(kms_client()),
        grant_tokens: None,
    }
}

#[tokio::test]
async fn create_keyring_from_each_identifier_form() {
    let router = app(Arc::new(AppState::new()));
    for kms_key_id in [
        KMS_KEY_ARN,
        "arn:aws:kms:us-west-2:370957321024:alias/x",
        KEY_ID,
        "alias/x",
    ] {
        let resp: CreateAwsKmsKeyringResponse =
            call(&router, "CreateAwsKmsKeyring", &keyring_request(kms_key_id)).await;
        assert!(!resp.keyring_id.is_empty(), "{kms_key_id}");
    }
}

#[tokio::test]
async fn create_keyring_with_grant_tokens() {
    let router = app(Arc::new(AppState::new()));
    let resp: CreateAwsKmsKeyringResponse = call(
        &router,
        "CreateAwsKmsKeyring",
        &CreateAwsKmsKeyringRequest {
            grant_tokens: Some(vec!["grant-token".to_owned()]),
            ..keyring_request(KMS_KEY_ARN)
        },
    )
    .await;
    assert!(!resp.keyring_id.is_empty());
}

#[tokio::test]
async fn malformed_key_identifier_is_an_mpl_error() {
    let router = app(Arc::new(AppState::new()));
    for kms_key_id in [
        "",
        "key/9d989aa2",
        "foo/bar",
        "alias/",
        "arn:aws:kms:us-west-2",
    ] {
        expect_error(
            &router,
            "CreateAwsKmsKeyring",
            &keyring_request(kms_key_id),
            "MPLClientError",
        )
        .await;
    }
}

#[tokio::test]
async fn create_keyring_with_a_kms_endpoint() {
    let router = app(Arc::new(AppState::new()));
    let resp: CreateAwsKmsKeyringResponse = call(
        &router,
        "CreateAwsKmsKeyring",
        &CreateAwsKmsKeyringRequest {
            kms_client: Some(KmsClientConfig {
                endpoint: Some("http://127.0.0.1:1".to_owned()),
                ..kms_client()
            }),
            ..keyring_request(KMS_KEY_ARN)
        },
    )
    .await;
    assert!(!resp.keyring_id.is_empty());
}

#[tokio::test]
async fn missing_key_id_or_client_is_an_mpl_error() {
    let router = app(Arc::new(AppState::new()));
    for req in [
        CreateAwsKmsKeyringRequest {
            kms_key_id: None,
            ..keyring_request(KMS_KEY_ARN)
        },
        CreateAwsKmsKeyringRequest {
            kms_client: None,
            ..keyring_request(KMS_KEY_ARN)
        },
    ] {
        expect_error(&router, "CreateAwsKmsKeyring", &req, "MPLClientError").await;
    }
}

#[tokio::test]
async fn invalid_grant_tokens_are_an_mpl_error() {
    let router = app(Arc::new(AppState::new()));
    for grant_tokens in [
        (1..=11).map(|i| format!("grant-token-{i}")).collect(),
        vec![String::new()],
    ] {
        expect_error(
            &router,
            "CreateAwsKmsKeyring",
            &CreateAwsKmsKeyringRequest {
                grant_tokens: Some(grant_tokens),
                ..keyring_request(KMS_KEY_ARN)
            },
            "MPLClientError",
        )
        .await;
    }
}

/// CreateDefaultCmm resolves the handle like any other keyring's.
#[tokio::test]
async fn default_cmm_accepts_an_aws_kms_keyring() {
    let router = app(Arc::new(AppState::new()));
    let keyring: CreateAwsKmsKeyringResponse = call(
        &router,
        "CreateAwsKmsKeyring",
        &keyring_request(KMS_KEY_ARN),
    )
    .await;
    let cmm: CreateDefaultCmmResponse = call(
        &router,
        "CreateDefaultCmm",
        &CreateDefaultCmmRequest {
            keyring_id: keyring.keyring_id,
        },
    )
    .await;
    assert!(!cmm.cmm_id.is_empty());
}

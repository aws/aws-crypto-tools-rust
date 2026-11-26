// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The AWS KMS keyring handle over the real wire, in process.
//!
//! The commons cross-language suite tests the keyring itself.

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

// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Offline: the C++ facade exposes the hierarchical and raw-AES keyrings, so a
//! CreateClient for any other keyring is rejected before the shim is invoked.

use std::sync::Arc;

use aws_esdk_cpp_test_server::backend::CppBackend;
use aws_esdk_cpp_test_server::model::{
    AwsKmsKeyringConfig, CreateClientRequest, CryptographicMaterialsManager, DefaultCmmConfig,
    EsdkClientConfig, EsdkCommitmentPolicy, Keyring,
};
use aws_esdk_cpp_test_server::wire::app;
use axum::body::Body;
use axum::http::Request;
use ciborium::value::Value;
use tower::ServiceExt;

fn text<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a str> {
    map.iter().find_map(|(k, v)| match (k, v) {
        (Value::Text(k), Value::Text(v)) if k == key => Some(v.as_str()),
        _ => None,
    })
}

fn aws_kms_create_client() -> CreateClientRequest {
    CreateClientRequest {
        config: EsdkClientConfig {
            commitment_policy: EsdkCommitmentPolicy::RequireEncryptRequireDecrypt,
            max_encrypted_data_keys: None,
            cmm: CryptographicMaterialsManager {
                default_cmm: Some(DefaultCmmConfig {
                    keyring: Keyring {
                        aws_kms: Some(AwsKmsKeyringConfig {
                            kms_key_id: "arn:aws:kms:us-west-2:000000000000:key/unsupported"
                                .to_owned(),
                            grant_tokens: None,
                        }),
                        ..Default::default()
                    },
                }),
                ..Default::default()
            },
        },
    }
}

#[tokio::test]
async fn aws_kms_keyring_is_rejected_as_unsupported() {
    let router = app(Arc::new(CppBackend::new()));

    let mut body = Vec::new();
    ciborium::into_writer(&aws_kms_create_client(), &mut body).expect("encode request");

    let request = Request::builder()
        .method("POST")
        .uri("/service/ESDKTestServer/operation/CreateClient")
        .header("smithy-protocol", "rpc-v2-cbor")
        .header("content-type", "application/cbor")
        .body(Body::from(body))
        .expect("build request");

    let response = router.oneshot(request).await.expect("dispatch");
    assert_eq!(
        response.status(),
        400,
        "unsupported keyring must be a client error"
    );

    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    let Value::Map(map) = ciborium::from_reader(&bytes[..]).expect("decode cbor error") else {
        panic!("error body was not a CBOR map");
    };
    assert_eq!(
        text(&map, "__type"),
        Some("aws.cryptography.esdk.testserver#GenericServerError"),
        "an unsupported keyring is a framework-side rejection",
    );
    let message = text(&map, "message").expect("error carries a message");
    assert!(
        message.contains("AwsKmsHierarchical"),
        "message must name the supported keyrings, got: {message}",
    );
}

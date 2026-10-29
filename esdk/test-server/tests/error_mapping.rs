// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Which error type each failure returns:
//! a rejected CreateClient configuration is `GenericServerError`,
//! invalid Encrypt input is `ESDKClientError`.

use std::sync::Arc;

use aws_esdk_test_server::handlers::AppState;
use aws_esdk_test_server::model::{
    AesWrappingAlg, CreateClientRequest, CreateClientResponse, CryptographicMaterialsManager,
    DefaultCmmConfig, EncryptRequest, EsdkClientConfig, EsdkCommitmentPolicy, Keyring,
    RawAesKeyringConfig,
};
use aws_esdk_test_server::wire::app;
use axum::body::Body;
use axum::http::Request;
use ciborium::value::Value;
use tower::ServiceExt;

const GENERIC_ERROR: &str = "aws.cryptography.esdk.testserver#GenericServerError";
const ESDK_ERROR: &str = "aws.cryptography.esdk.testserver#ESDKClientError";

fn raw_aes_create_client(
    key_namespace: &str,
    wrapping_key: Vec<u8>,
    wrapping_alg: AesWrappingAlg,
) -> CreateClientRequest {
    CreateClientRequest {
        config: EsdkClientConfig {
            commitment_policy: EsdkCommitmentPolicy::RequireEncryptRequireDecrypt,
            max_encrypted_data_keys: None,
            cmm: CryptographicMaterialsManager {
                default_cmm: Some(DefaultCmmConfig {
                    keyring: Keyring {
                        raw_aes: Some(RawAesKeyringConfig {
                            key_namespace: key_namespace.to_owned(),
                            key_name: "error-mapping-key".to_owned(),
                            wrapping_key,
                            wrapping_alg,
                        }),
                        ..Default::default()
                    },
                }),
                ..Default::default()
            },
        },
    }
}

async fn post<Req: serde::Serialize>(
    state: &Arc<AppState>,
    operation: &str,
    req: &Req,
) -> (u16, Vec<u8>) {
    let mut body = Vec::new();
    ciborium::into_writer(req, &mut body).expect("encode request");
    let request = Request::builder()
        .method("POST")
        .uri(format!("/service/ESDKTestServer/operation/{operation}"))
        .header("smithy-protocol", "rpc-v2-cbor")
        .header("content-type", "application/cbor")
        .body(Body::from(body))
        .expect("build request");
    let response = app(Arc::clone(state))
        .oneshot(request)
        .await
        .expect("dispatch");
    let status = response.status().as_u16();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    (status, bytes.to_vec())
}

fn error_type(body: &[u8]) -> String {
    let Value::Map(map) = ciborium::from_reader(body).expect("decode cbor error") else {
        panic!("error body was not a CBOR map");
    };
    map.iter()
        .find_map(|(k, v)| match (k, v) {
            (Value::Text(k), Value::Text(v)) if k == "__type" => Some(v.clone()),
            _ => None,
        })
        .expect("error carries __type")
}

/// Commons KEYRING-006.
#[tokio::test]
async fn create_client_rejects_short_wrapping_key_as_generic_error() {
    let state = Arc::new(AppState::new());
    let request = raw_aes_create_client("esdk-test-server", vec![0; 16], AesWrappingAlg::Alg256);
    let (status, body) = post(&state, "CreateClient", &request).await;
    assert_eq!(
        status, 400,
        "mismatched wrapping key length must be rejected"
    );
    assert_eq!(
        error_type(&body),
        GENERIC_ERROR,
        "an invalid CreateClient configuration is a framework-side rejection",
    );
}

/// Commons KEYRING-073.
#[tokio::test]
async fn create_client_rejects_reserved_namespace_as_generic_error() {
    let state = Arc::new(AppState::new());
    let request = raw_aes_create_client("aws-kms", vec![0; 32], AesWrappingAlg::Alg256);
    let (status, body) = post(&state, "CreateClient", &request).await;
    assert_eq!(status, 400, "the reserved key namespace must be rejected");
    assert_eq!(
        error_type(&body),
        GENERIC_ERROR,
        "an invalid CreateClient configuration is a framework-side rejection",
    );
}

/// Commons ENC-001.
#[tokio::test]
async fn encrypt_rejects_non_positive_frame_length_as_esdk_error() {
    let state = Arc::new(AppState::new());
    let create = raw_aes_create_client(
        "esdk-test-server",
        (0u8..32).collect(),
        AesWrappingAlg::Alg256,
    );
    let (status, body) = post(&state, "CreateClient", &create).await;
    assert_eq!(
        status,
        200,
        "CreateClient: {}",
        String::from_utf8_lossy(&body)
    );
    let client: CreateClientResponse =
        ciborium::from_reader(&body[..]).expect("decode CreateClient response");

    let encrypt = EncryptRequest {
        client_id: client.client_id,
        plaintext: b"error-mapping plaintext".to_vec(),
        encryption_context: None,
        algorithm_suite_id: None,
        frame_length: Some(-16),
    };
    let (status, body) = post(&state, "Encrypt", &encrypt).await;
    assert_eq!(status, 400, "a non-positive frame length must be rejected");
    assert_eq!(
        error_type(&body),
        ESDK_ERROR,
        "invalid ESDK encrypt input is the modeled ESDK error",
    );
}

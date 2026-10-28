// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Live end-to-end round trip through the C++ facade: CreateClient -> Encrypt
//! -> Decrypt over the real rpcv2Cbor wire, against a hierarchical key store.
//!
//! Needs AWS credentials and a provisioned key store; the required resources are
//! supplied via ESDK_TEST_* env vars and the suite SKIPs cleanly when they are
//! unset, so it never fails credential-less CI.

use std::sync::Arc;

use aws_esdk_cpp_test_server::backend::CppBackend;
use aws_esdk_cpp_test_server::model::{
    AwsKmsHierarchicalKeyringConfig, CreateClientRequest, CreateClientResponse,
    CryptographicMaterialsManager, DecryptRequest, DecryptResponse, DefaultCmmConfig,
    EncryptRequest, EncryptResponse, EsdkClientConfig, EsdkCommitmentPolicy, Keyring,
};
use aws_esdk_cpp_test_server::wire::app;
use axum::body::Body;
use axum::http::Request;
use tower::ServiceExt;

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

async fn call<Resp: serde::de::DeserializeOwned, Req: serde::Serialize>(
    state: &Arc<CppBackend>,
    operation: &str,
    req: &Req,
) -> Resp {
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
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    assert_eq!(
        status,
        200,
        "{operation} failed: {}",
        String::from_utf8_lossy(&bytes)
    );
    ciborium::from_reader(&bytes[..]).expect("decode response")
}

#[tokio::test(flavor = "multi_thread")]
async fn hierarchical_round_trip() {
    let (Some(table), Some(logical), Some(kms_arn), Some(branch_key_id)) = (
        env("ESDK_TEST_DDB_TABLE"),
        env("ESDK_TEST_LOGICAL_KEYSTORE"),
        env("ESDK_TEST_KMS_KEY_ARN"),
        env("ESDK_TEST_BRANCH_KEY_ID"),
    ) else {
        eprintln!("SKIP hierarchical_round_trip: ESDK_TEST_* environment not set");
        return;
    };

    let state = Arc::new(CppBackend::new());

    let create = CreateClientRequest {
        config: EsdkClientConfig {
            commitment_policy: EsdkCommitmentPolicy::RequireEncryptRequireDecrypt,
            max_encrypted_data_keys: None,
            cmm: CryptographicMaterialsManager {
                default_cmm: Some(DefaultCmmConfig {
                    keyring: Keyring {
                        aws_kms_hierarchical: Some(AwsKmsHierarchicalKeyringConfig {
                            branch_key_id,
                            key_store_table_name: table,
                            logical_key_store_name: logical,
                            kms_key_arn: kms_arn,
                            ttl_seconds: 600,
                        }),
                        ..Default::default()
                    },
                }),
                ..Default::default()
            },
        },
    };
    let client: CreateClientResponse = call(&state, "CreateClient", &create).await;

    let plaintext = b"hello from the aws-esdk-cpp test server".to_vec();
    let encrypt = EncryptRequest {
        client_id: client.client_id.clone(),
        plaintext: plaintext.clone(),
        encryption_context: None,
        algorithm_suite_id: None,
        frame_length: None,
    };
    let encrypted: EncryptResponse = call(&state, "Encrypt", &encrypt).await;
    assert_ne!(
        encrypted.ciphertext, plaintext,
        "ciphertext must differ from plaintext"
    );

    let decrypt = DecryptRequest {
        client_id: client.client_id,
        ciphertext: encrypted.ciphertext,
        encryption_context: None,
    };
    let decrypted: DecryptResponse = call(&state, "Decrypt", &decrypt).await;
    assert_eq!(
        decrypted.plaintext, plaintext,
        "round trip must recover the plaintext"
    );
}

// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Full round trip: CreateRawAesKeyring → CreateDefaultCmm →
//! GetEncryptionMaterials → DecryptMaterials.

use std::collections::BTreeMap;
use std::sync::Arc;

use aws_mpl_test_server::handlers::AppState;
use aws_mpl_test_server::model::*;
use aws_mpl_test_server::wire::app;
use axum::body::Body;
use axum::http::Request;
use tower::ServiceExt;

async fn call<Req: serde::Serialize, Resp: serde::de::DeserializeOwned>(
    router: &axum::Router,
    operation: &str,
    req: &Req,
) -> Resp {
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
    assert_eq!(
        response.status(),
        200,
        "{operation} failed with status {}",
        response.status()
    );

    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    ciborium::from_reader(&bytes[..]).expect("decode response")
}

#[tokio::test]
async fn raw_aes_256_full_round_trip() {
    let state = Arc::new(AppState::new());
    let router = app(state);

    // 1. Create a Raw AES keyring (256-bit key)
    let keyring_resp: CreateRawAesKeyringResponse = call(
        &router,
        "CreateRawAesKeyring",
        &CreateRawAesKeyringRequest {
            key_namespace: "mpl-test-server".to_owned(),
            key_name: "raw-aes-256-key".to_owned(),
            wrapping_key: (0u8..32).collect(),
            wrapping_alg: AesWrappingAlg::Aes256,
        },
    )
    .await;
    assert!(!keyring_resp.keyring_id.is_empty());

    // 2. Create a Default CMM wrapping that keyring
    let cmm_resp: CreateDefaultCmmResponse = call(
        &router,
        "CreateDefaultCmm",
        &CreateDefaultCmmRequest {
            keyring_id: keyring_resp.keyring_id,
        },
    )
    .await;
    assert!(!cmm_resp.cmm_id.is_empty());

    // 3. Get encryption materials
    let mut ec = BTreeMap::new();
    ec.insert("purpose".to_owned(), "test".to_owned());

    let enc_resp: GetEncryptionMaterialsResponse = call(
        &router,
        "GetEncryptionMaterials",
        &GetEncryptionMaterialsRequest {
            cmm_id: cmm_resp.cmm_id.clone(),
            encryption_context: ec,
            commitment_policy: CommitmentPolicy::EsdkRequireEncryptRequireDecrypt,
            algorithm_suite_id: None,
            max_plaintext_length: None,
        },
    )
    .await;

    assert!(!enc_resp.plaintext_data_key.is_empty());
    assert!(!enc_resp.encrypted_data_keys.is_empty());
    assert!(enc_resp.encryption_context.contains_key("purpose"));

    // 4. Decrypt materials with the EDKs from step 3
    let dec_resp: DecryptMaterialsResponse = call(
        &router,
        "DecryptMaterials",
        &DecryptMaterialsRequest {
            cmm_id: cmm_resp.cmm_id,
            algorithm_suite_id: enc_resp.algorithm_suite_id,
            encrypted_data_keys: enc_resp.encrypted_data_keys,
            encryption_context: enc_resp.encryption_context,
            commitment_policy: CommitmentPolicy::EsdkRequireEncryptRequireDecrypt,
            reproduced_encryption_context: None,
        },
    )
    .await;

    // The decrypted plaintext data key must match what was generated
    assert_eq!(dec_resp.plaintext_data_key, enc_resp.plaintext_data_key);
}

// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The static keyring over the real wire, in process, through a Default CMM.

use std::collections::BTreeMap;
use std::sync::Arc;

use aws_mpl_test_server::handlers::AppState;
use aws_mpl_test_server::model::*;
use aws_mpl_test_server::wire::app;
use axum::Router;
use axum::body::Body;
use axum::http::Request;
use ciborium::value::Value;
use tower::ServiceExt;

const SUITE: AlgorithmSuiteId = AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey;
const POLICY: CommitmentPolicy = CommitmentPolicy::EsdkRequireEncryptRequireDecrypt;

/// POST one operation and return (status, raw CBOR body).
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

/// The `__type` of an rpcv2Cbor error body.
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

fn ec() -> BTreeMap<String, String> {
    BTreeMap::from([("purpose".to_owned(), "static-keyring-test".to_owned())])
}

fn edk() -> EncryptedDataKeyShape {
    EncryptedDataKeyShape {
        key_provider_id: "static".to_owned(),
        key_provider_info: b"static".to_vec(),
        ciphertext: b"static".to_vec(),
    }
}

/// Encryption materials matching what the Default CMM hands the keyring for
/// `ec()`, with a data key added.
fn encryption_materials(encryption_context: BTreeMap<String, String>) -> EncryptionMaterialsShape {
    EncryptionMaterialsShape {
        algorithm_suite_id: SUITE,
        encryption_context,
        encrypted_data_keys: vec![edk()],
        required_encryption_context_keys: vec![],
        plaintext_data_key: Some(vec![7; 32]),
        signing_key: None,
        symmetric_signing_keys: None,
    }
}

fn decryption_materials() -> DecryptionMaterialsShape {
    DecryptionMaterialsShape {
        algorithm_suite_id: SUITE,
        encryption_context: ec(),
        required_encryption_context_keys: vec![],
        plaintext_data_key: Some(vec![7; 32]),
        verification_key: None,
        symmetric_signing_key: None,
    }
}

/// A Default CMM over a static keyring, returning the CMM's handle.
async fn create_cmm(router: &Router, request: CreateStaticKeyringRequest) -> String {
    let keyring: CreateStaticKeyringResponse = call(router, "CreateStaticKeyring", &request).await;
    let cmm: CreateDefaultCmmResponse = call(
        router,
        "CreateDefaultCmm",
        &CreateDefaultCmmRequest {
            keyring_id: keyring.keyring_id,
        },
    )
    .await;
    cmm.cmm_id
}

fn get_encryption_materials(cmm_id: String) -> GetEncryptionMaterialsRequest {
    GetEncryptionMaterialsRequest {
        cmm_id,
        encryption_context: ec(),
        commitment_policy: POLICY,
        algorithm_suite_id: Some(SUITE),
        max_plaintext_length: None,
    }
}

fn decrypt_materials(cmm_id: String) -> DecryptMaterialsRequest {
    DecryptMaterialsRequest {
        cmm_id,
        algorithm_suite_id: SUITE,
        encrypted_data_keys: vec![edk()],
        encryption_context: ec(),
        commitment_policy: POLICY,
        reproduced_encryption_context: None,
    }
}

#[tokio::test]
async fn default_cmm_returns_the_static_materials() {
    let router = app(Arc::new(AppState::new()));
    let cmm_id = create_cmm(
        &router,
        CreateStaticKeyringRequest {
            encryption_materials: Some(encryption_materials(ec())),
            decryption_materials: Some(decryption_materials()),
        },
    )
    .await;

    let encrypted: GetEncryptionMaterialsResponse = call(
        &router,
        "GetEncryptionMaterials",
        &get_encryption_materials(cmm_id.clone()),
    )
    .await;
    assert_eq!(encrypted.plaintext_data_key, vec![7; 32]);
    assert_eq!(encrypted.encrypted_data_keys.len(), 1);

    let decrypted: DecryptMaterialsResponse =
        call(&router, "DecryptMaterials", &decrypt_materials(cmm_id)).await;
    assert_eq!(decrypted.plaintext_data_key, vec![7; 32]);
}

#[tokio::test]
async fn default_cmm_rejects_a_changed_encryption_context() {
    let router = app(Arc::new(AppState::new()));
    let mut changed = ec();
    changed.insert("added".to_owned(), "by keyring".to_owned());
    let cmm_id = create_cmm(
        &router,
        CreateStaticKeyringRequest {
            encryption_materials: Some(encryption_materials(changed)),
            decryption_materials: None,
        },
    )
    .await;
    expect_error(
        &router,
        "GetEncryptionMaterials",
        &get_encryption_materials(cmm_id),
        "MPLClientError",
    )
    .await;
}

#[tokio::test]
async fn default_cmm_rejects_decryption_materials_without_a_data_key() {
    let router = app(Arc::new(AppState::new()));
    let cmm_id = create_cmm(
        &router,
        CreateStaticKeyringRequest {
            encryption_materials: None,
            decryption_materials: None,
        },
    )
    .await;
    expect_error(
        &router,
        "DecryptMaterials",
        &decrypt_materials(cmm_id),
        "MPLClientError",
    )
    .await;
}

// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Keyring-interface operations over the real wire, in process:
//! InitializeEncryptionMaterials → OnEncrypt → InitializeDecryptionMaterials
//! → OnDecrypt, plus the handle and error contract.

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

const NAMESPACE: &str = "mpl-test-server";
const KEY_NAME: &str = "raw-aes-keyring-key";
const UNKNOWN_ID: &str = "00000000-0000-4000-8000-000000000000";

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
    BTreeMap::from([("purpose".to_owned(), "raw-aes-keyring-test".to_owned())])
}

async fn create_keyring(router: &Router, key_name: &str, key: Vec<u8>) -> String {
    let resp: CreateRawAesKeyringResponse = call(
        router,
        "CreateRawAesKeyring",
        &CreateRawAesKeyringRequest {
            key_namespace: NAMESPACE.to_owned(),
            key_name: key_name.to_owned(),
            wrapping_key: key,
            wrapping_alg: AesWrappingAlg::Aes256,
        },
    )
    .await;
    resp.keyring_id
}

async fn initialize_encryption(router: &Router) -> EncryptionMaterialsShape {
    let resp: InitializeEncryptionMaterialsResponse = call(
        router,
        "InitializeEncryptionMaterials",
        &InitializeEncryptionMaterialsRequest {
            algorithm_suite_id: AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey,
            encryption_context: ec(),
            required_encryption_context_keys: vec![],
        },
    )
    .await;
    resp.materials
}

async fn initialize_decryption(router: &Router) -> DecryptionMaterialsShape {
    let resp: InitializeDecryptionMaterialsResponse = call(
        router,
        "InitializeDecryptionMaterials",
        &InitializeDecryptionMaterialsRequest {
            algorithm_suite_id: AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey,
            encryption_context: ec(),
            required_encryption_context_keys: vec![],
        },
    )
    .await;
    resp.materials
}

#[tokio::test]
async fn on_encrypt_on_decrypt_round_trip() {
    let router = app(Arc::new(AppState::new()));
    let key: Vec<u8> = (0u8..32).collect();

    let initial = initialize_encryption(&router).await;
    assert!(initial.plaintext_data_key.is_none());
    assert!(initial.encrypted_data_keys.is_empty());

    let keyring_id = create_keyring(&router, KEY_NAME, key.clone()).await;
    let encrypted: OnEncryptResponse = call(
        &router,
        "OnEncrypt",
        &OnEncryptRequest {
            keyring_id,
            materials: initial,
        },
    )
    .await;
    let pdk = encrypted
        .materials
        .plaintext_data_key
        .clone()
        .expect("OnEncrypt generated a data key");
    assert_eq!(pdk.len(), 32);
    assert_eq!(encrypted.materials.encrypted_data_keys.len(), 1);

    // Raw AES EDK: provider id = namespace; provider info = key name ||
    // u32 tag bits (128) || u32 IV length (12) || IV; ciphertext = key || tag.
    let edk = &encrypted.materials.encrypted_data_keys[0];
    assert_eq!(edk.key_provider_id, NAMESPACE);
    let name = KEY_NAME.as_bytes();
    assert_eq!(edk.key_provider_info.len(), name.len() + 4 + 4 + 12);
    assert_eq!(&edk.key_provider_info[..name.len()], name);
    assert_eq!(
        &edk.key_provider_info[name.len()..name.len() + 8],
        &[0, 0, 0, 128, 0, 0, 0, 12]
    );
    assert_eq!(edk.ciphertext.len(), 32 + 16);

    let decrypt_keyring = create_keyring(&router, KEY_NAME, key).await;
    let decrypted: OnDecryptResponse = call(
        &router,
        "OnDecrypt",
        &OnDecryptRequest {
            keyring_id: decrypt_keyring,
            materials: initialize_decryption(&router).await,
            encrypted_data_keys: encrypted.materials.encrypted_data_keys,
        },
    )
    .await;
    assert_eq!(decrypted.materials.plaintext_data_key, Some(pdk));
}

#[tokio::test]
async fn on_encrypt_wraps_an_existing_data_key() {
    let router = app(Arc::new(AppState::new()));
    let first = create_keyring(&router, "first-key", (0u8..32).collect()).await;
    let second = create_keyring(&router, "second-key", (100u8..132).collect()).await;

    let once: OnEncryptResponse = call(
        &router,
        "OnEncrypt",
        &OnEncryptRequest {
            keyring_id: first,
            materials: initialize_encryption(&router).await,
        },
    )
    .await;
    let twice: OnEncryptResponse = call(
        &router,
        "OnEncrypt",
        &OnEncryptRequest {
            keyring_id: second,
            materials: once.materials.clone(),
        },
    )
    .await;

    assert_eq!(
        twice.materials.plaintext_data_key,
        once.materials.plaintext_data_key
    );
    assert_eq!(twice.materials.encrypted_data_keys.len(), 2);
}

#[tokio::test]
async fn wrong_wrapping_key_is_an_mpl_error() {
    let router = app(Arc::new(AppState::new()));
    let keyring_id = create_keyring(&router, KEY_NAME, (0u8..32).collect()).await;
    let encrypted: OnEncryptResponse = call(
        &router,
        "OnEncrypt",
        &OnEncryptRequest {
            keyring_id,
            materials: initialize_encryption(&router).await,
        },
    )
    .await;

    let wrong = create_keyring(&router, KEY_NAME, (100u8..132).collect()).await;
    expect_error(
        &router,
        "OnDecrypt",
        &OnDecryptRequest {
            keyring_id: wrong,
            materials: initialize_decryption(&router).await,
            encrypted_data_keys: encrypted.materials.encrypted_data_keys,
        },
        "MPLClientError",
    )
    .await;
}

#[tokio::test]
async fn unknown_and_wrong_kind_handles_are_generic_errors() {
    let router = app(Arc::new(AppState::new()));
    let materials = initialize_encryption(&router).await;

    expect_error(
        &router,
        "OnEncrypt",
        &OnEncryptRequest {
            keyring_id: UNKNOWN_ID.to_owned(),
            materials: materials.clone(),
        },
        "GenericServerError",
    )
    .await;

    let keyring_id = create_keyring(&router, KEY_NAME, (0u8..32).collect()).await;
    let cmm: CreateDefaultCmmResponse = call(
        &router,
        "CreateDefaultCmm",
        &CreateDefaultCmmRequest { keyring_id },
    )
    .await;
    expect_error(
        &router,
        "OnEncrypt",
        &OnEncryptRequest {
            keyring_id: cmm.cmm_id,
            materials,
        },
        "GenericServerError",
    )
    .await;
}

#[tokio::test]
async fn wrong_length_wrapping_key_is_an_mpl_error() {
    let router = app(Arc::new(AppState::new()));
    expect_error(
        &router,
        "CreateRawAesKeyring",
        &CreateRawAesKeyringRequest {
            key_namespace: NAMESPACE.to_owned(),
            key_name: KEY_NAME.to_owned(),
            wrapping_key: vec![0u8; 16],
            wrapping_alg: AesWrappingAlg::Aes256,
        },
        "MPLClientError",
    )
    .await;
}

// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Offline streaming round trips through the C++ facade with a raw-AES keyring
//! over the rpcv2Cbor wire: EncryptStream -> DecryptStream, plus each cross-mode
//! pairing with the blob operations. The multi-frame plaintext spans several
//! frames plus a partial final frame under a non-signing committing suite
//! (streamed decrypt refuses multi-frame signed messages). Needs no AWS access,
//! so it always runs.

use std::sync::Arc;

use aws_esdk_cpp_test_server::backend::CppBackend;
use aws_esdk_cpp_test_server::model::{
    AesWrappingAlg, CreateClientRequest, CreateClientResponse, CryptographicMaterialsManager,
    DecryptRequest, DecryptResponse, DecryptStreamRequest, DecryptStreamResponse, DefaultCmmConfig,
    EncryptRequest, EncryptResponse, EncryptStreamRequest, EncryptStreamResponse,
    EsdkAlgorithmSuiteId, EsdkClientConfig, EsdkCommitmentPolicy, Keyring, RawAesKeyringConfig,
};
use aws_esdk_cpp_test_server::wire::app;
use axum::body::Body;
use axum::http::Request;
use tower::ServiceExt;

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

async fn create_raw_aes_client(state: &Arc<CppBackend>) -> String {
    let create = CreateClientRequest {
        config: EsdkClientConfig {
            commitment_policy: EsdkCommitmentPolicy::RequireEncryptRequireDecrypt,
            max_encrypted_data_keys: None,
            cmm: CryptographicMaterialsManager {
                default_cmm: Some(DefaultCmmConfig {
                    keyring: Keyring {
                        raw_aes: Some(RawAesKeyringConfig {
                            key_namespace: "esdk-cpp-test-server".to_owned(),
                            key_name: "stream-round-trip-key".to_owned(),
                            wrapping_key: (0u8..32).collect(),
                            wrapping_alg: AesWrappingAlg::Alg256,
                        }),
                        ..Default::default()
                    },
                }),
                ..Default::default()
            },
        },
    };
    let client: CreateClientResponse = call(state, "CreateClient", &create).await;
    client.client_id
}

#[tokio::test(flavor = "multi_thread")]
async fn stream_round_trip_multi_frame() {
    let state = Arc::new(CppBackend::new());
    let client_id = create_raw_aes_client(&state).await;

    // Several 1024-byte frames plus a partial final frame.
    let frame_length: i64 = 1024;
    let plaintext: Vec<u8> = (0..(3 * frame_length as usize + 100))
        .map(|i| (i * 31 + 7) as u8)
        .collect();

    let encrypt = EncryptStreamRequest {
        client_id: client_id.clone(),
        plaintext: plaintext.clone(),
        encryption_context: None,
        algorithm_suite_id: Some(EsdkAlgorithmSuiteId::Alg256GcmCommit),
        frame_length: Some(frame_length),
        plaintext_length_bound: None,
    };
    let encrypted: EncryptStreamResponse = call(&state, "EncryptStream", &encrypt).await;
    assert_ne!(
        encrypted.ciphertext, plaintext,
        "ciphertext must differ from plaintext"
    );

    let decrypt = DecryptStreamRequest {
        client_id,
        ciphertext: encrypted.ciphertext,
        encryption_context: None,
    };
    let decrypted: DecryptStreamResponse = call(&state, "DecryptStream", &decrypt).await;
    assert_eq!(
        decrypted.plaintext, plaintext,
        "streamed round trip must recover the plaintext byte for byte"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn stream_encrypt_decrypts_as_blob() {
    let state = Arc::new(CppBackend::new());
    let client_id = create_raw_aes_client(&state).await;

    let plaintext = b"streamed encrypt, one-shot decrypt".to_vec();
    let encrypt = EncryptStreamRequest {
        client_id: client_id.clone(),
        plaintext: plaintext.clone(),
        encryption_context: None,
        algorithm_suite_id: None,
        frame_length: None,
        plaintext_length_bound: None,
    };
    let encrypted: EncryptStreamResponse = call(&state, "EncryptStream", &encrypt).await;

    let decrypt = DecryptRequest {
        client_id,
        ciphertext: encrypted.ciphertext,
        encryption_context: None,
    };
    let decrypted: DecryptResponse = call(&state, "Decrypt", &decrypt).await;
    assert_eq!(
        decrypted.plaintext, plaintext,
        "one-shot decrypt of a streamed-encrypted message must recover the plaintext"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn blob_encrypt_decrypts_as_stream() {
    let state = Arc::new(CppBackend::new());
    let client_id = create_raw_aes_client(&state).await;

    let plaintext = b"one-shot encrypt, streamed decrypt".to_vec();
    let encrypt = EncryptRequest {
        client_id: client_id.clone(),
        plaintext: plaintext.clone(),
        encryption_context: None,
        // Non-signing committing suite: streamed decrypt refuses multi-frame
        // signed messages, and the default suite signs.
        algorithm_suite_id: Some(EsdkAlgorithmSuiteId::Alg256GcmCommit),
        frame_length: None,
    };
    let encrypted: EncryptResponse = call(&state, "Encrypt", &encrypt).await;

    let decrypt = DecryptStreamRequest {
        client_id,
        ciphertext: encrypted.ciphertext,
        encryption_context: None,
    };
    let decrypted: DecryptStreamResponse = call(&state, "DecryptStream", &decrypt).await;
    assert_eq!(
        decrypted.plaintext, plaintext,
        "streamed decrypt of a one-shot-encrypted message must recover the plaintext"
    );
}

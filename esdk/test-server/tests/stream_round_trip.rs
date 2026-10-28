//! Streaming round trips with a raw-AES keyring: EncryptStream <-> DecryptStream
//! and each cross-mode pairing with the blob operations.

use std::sync::Arc;

use aws_esdk_test_server::handlers::AppState;
use aws_esdk_test_server::model::{
    AesWrappingAlg, CreateClientRequest, CreateClientResponse, CryptographicMaterialsManager,
    DecryptRequest, DecryptResponse, DecryptStreamRequest, DecryptStreamResponse, DefaultCmmConfig,
    EncryptRequest, EncryptResponse, EncryptStreamRequest, EncryptStreamResponse,
    EsdkAlgorithmSuiteId, EsdkClientConfig, EsdkCommitmentPolicy, Keyring, RawAesKeyringConfig,
};
use aws_esdk_test_server::wire::app;
use axum::body::Body;
use axum::http::Request;
use tower::ServiceExt;

async fn call<Resp: serde::de::DeserializeOwned, Req: serde::Serialize>(
    state: &Arc<AppState>,
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

async fn create_raw_aes_client(state: &Arc<AppState>) -> String {
    let create = CreateClientRequest {
        config: EsdkClientConfig {
            commitment_policy: EsdkCommitmentPolicy::RequireEncryptRequireDecrypt,
            max_encrypted_data_keys: None,
            cmm: CryptographicMaterialsManager {
                default_cmm: Some(DefaultCmmConfig {
                    keyring: Keyring {
                        raw_aes: Some(RawAesKeyringConfig {
                            key_namespace: "esdk-test-server".to_owned(),
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

#[tokio::test]
async fn stream_round_trip_multi_frame() {
    let state = Arc::new(AppState::new());
    let client_id = create_raw_aes_client(&state).await;

    let frame_length: i64 = 1024;
    let plaintext: Vec<u8> = (0..(3 * frame_length as usize + 100))
        .map(|i| (i * 31 + 7) as u8)
        .collect();

    let encrypt = EncryptStreamRequest {
        client_id: client_id.clone(),
        plaintext: plaintext.clone(),
        encryption_context: None,
        // Streamed decrypt refuses multi-frame signed messages, and the default suite signs.
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

#[tokio::test]
async fn stream_encrypt_decrypts_as_blob() {
    let state = Arc::new(AppState::new());
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

#[tokio::test]
async fn blob_encrypt_decrypts_as_stream() {
    let state = Arc::new(AppState::new());
    let client_id = create_raw_aes_client(&state).await;

    let plaintext = b"one-shot encrypt, streamed decrypt".to_vec();
    let encrypt = EncryptRequest {
        client_id: client_id.clone(),
        plaintext: plaintext.clone(),
        encryption_context: None,
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

/// Commons ENC-007.
#[tokio::test]
async fn stream_encrypt_enforces_plaintext_length_bound() {
    let state = Arc::new(AppState::new());
    let client_id = create_raw_aes_client(&state).await;

    let plaintext = b"plaintext-length-bound plaintext, comfortably over sixteen bytes".to_vec();

    let within_bound = EncryptStreamRequest {
        client_id: client_id.clone(),
        plaintext: plaintext.clone(),
        encryption_context: None,
        algorithm_suite_id: None,
        frame_length: None,
        plaintext_length_bound: Some(plaintext.len() as i64),
    };
    let encrypted: EncryptStreamResponse = call(&state, "EncryptStream", &within_bound).await;
    assert!(!encrypted.ciphertext.is_empty());

    let over_bound = EncryptStreamRequest {
        client_id,
        plaintext: plaintext.clone(),
        encryption_context: None,
        algorithm_suite_id: None,
        frame_length: None,
        plaintext_length_bound: Some(plaintext.len() as i64 - 1),
    };
    let mut body = Vec::new();
    ciborium::into_writer(&over_bound, &mut body).expect("encode request");
    let request = Request::builder()
        .method("POST")
        .uri("/service/ESDKTestServer/operation/EncryptStream")
        .header("smithy-protocol", "rpc-v2-cbor")
        .header("content-type", "application/cbor")
        .body(Body::from(body))
        .expect("build request");
    let response = app(Arc::clone(&state))
        .oneshot(request)
        .await
        .expect("dispatch");
    assert_eq!(
        response.status(),
        400,
        "a plaintext longer than the bound must be rejected"
    );
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    let ciborium::value::Value::Map(map) =
        ciborium::from_reader(&bytes[..]).expect("decode cbor error")
    else {
        panic!("error body was not a CBOR map");
    };
    let error_type = map
        .iter()
        .find_map(|(k, v)| match (k, v) {
            (ciborium::value::Value::Text(k), ciborium::value::Value::Text(v)) if k == "__type" => {
                Some(v.clone())
            }
            _ => None,
        })
        .expect("error carries __type");
    assert_eq!(
        error_type, "aws.cryptography.esdk.testserver#ESDKClientError",
        "an over-bound plaintext is the modeled ESDK error",
    );
}

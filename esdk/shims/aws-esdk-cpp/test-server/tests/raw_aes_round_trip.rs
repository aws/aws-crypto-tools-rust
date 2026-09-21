//! Offline end-to-end round trip through the C++ facade with a raw-AES keyring:
//! CreateClient -> Encrypt -> Decrypt over the rpcv2Cbor wire. Needs no AWS
//! access, so it always runs.

use std::sync::Arc;

use aws_esdk_cpp_test_server::backend::CppBackend;
use aws_esdk_cpp_test_server::model::{
    AesWrappingAlg, CreateClientRequest, CreateClientResponse, CryptographicMaterialsManager,
    DecryptRequest, DecryptResponse, DefaultCmmConfig, EncryptRequest, EncryptResponse,
    EsdkClientConfig, EsdkCommitmentPolicy, Keyring, RawAesKeyringConfig,
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

#[tokio::test(flavor = "multi_thread")]
async fn raw_aes_round_trip() {
    let state = Arc::new(CppBackend::new());

    let create = CreateClientRequest {
        config: EsdkClientConfig {
            commitment_policy: EsdkCommitmentPolicy::RequireEncryptRequireDecrypt,
            max_encrypted_data_keys: None,
            cmm: CryptographicMaterialsManager {
                default_cmm: Some(DefaultCmmConfig {
                    keyring: Keyring {
                        raw_aes: Some(RawAesKeyringConfig {
                            key_namespace: "esdk-cpp-test-server".to_owned(),
                            key_name: "raw-aes-round-trip-key".to_owned(),
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
    let client: CreateClientResponse = call(&state, "CreateClient", &create).await;

    let plaintext = b"hello from the aws-esdk-cpp raw-AES round trip".to_vec();
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

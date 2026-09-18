//! A real rpcv2Cbor `CreateClient` with the offline Raw-AES / Default-CMM config
//! (identical to the commons `BlobRoundTrip` config) drives the server to build
//! a Raw-AES keyring through the Dafny MPL. The server MUST accept it and return
//! a client id.

use std::sync::Arc;

use aws_esdk_test_server::handlers::AppState;
use aws_esdk_test_server::model::{
    AesWrappingAlg, CreateClientRequest, CryptographicMaterialsManager, DefaultCmmConfig,
    EsdkClientConfig, EsdkCommitmentPolicy, Keyring, RawAesKeyringConfig,
};
use aws_esdk_test_server::wire::app;
use axum::body::Body;
use axum::http::Request;
use ciborium::value::Value;
use tower::ServiceExt;

fn raw_aes_create_client() -> CreateClientRequest {
    CreateClientRequest {
        config: EsdkClientConfig {
            commitment_policy: EsdkCommitmentPolicy::RequireEncryptRequireDecrypt,
            max_encrypted_data_keys: None,
            cmm: CryptographicMaterialsManager {
                default_cmm: Some(DefaultCmmConfig {
                    keyring: Keyring {
                        raw_aes: Some(RawAesKeyringConfig {
                            key_namespace: "esdk-test-server".to_owned(),
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
    }
}

fn text<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a str> {
    map.iter().find_map(|(k, v)| match (k, v) {
        (Value::Text(k), Value::Text(v)) if k == key => Some(v.as_str()),
        _ => None,
    })
}

#[tokio::test]
async fn create_client_raw_aes_succeeds() {
    let router = app(Arc::new(AppState::new()));

    let mut body = Vec::new();
    ciborium::into_writer(&raw_aes_create_client(), &mut body).expect("encode request");

    let request = Request::builder()
        .method("POST")
        .uri("/service/ESDKTestServer/operation/CreateClient")
        .header("smithy-protocol", "rpc-v2-cbor")
        .header("content-type", "application/cbor")
        .body(Body::from(body))
        .expect("build request");

    let response = router.oneshot(request).await.expect("dispatch");
    assert_eq!(response.status(), 200, "raw-AES CreateClient must succeed");

    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    let Value::Map(map) = ciborium::from_reader(&bytes[..]).expect("decode cbor response") else {
        panic!("response body was not a CBOR map");
    };
    assert!(
        text(&map, "clientId").is_some_and(|id| !id.is_empty()),
        "CreateClient must return a non-empty clientId",
    );
}

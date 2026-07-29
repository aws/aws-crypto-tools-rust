//! A real rpcv2Cbor `CreateClient` with the offline Raw-AES / Default-CMM config
//! (identical to the commons `BlobRoundTrip` config) drives the server to the
//! vendored MPL, which does not implement keyring construction. The server MUST
//! surface this as an `ESDKClientError` naming the unimplemented constructor.

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
async fn create_client_raw_aes_surfaces_keyring_not_implemented() {
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
    assert_eq!(response.status(), 400, "client error status expected");

    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    let value: Value = ciborium::from_reader(&bytes[..]).expect("decode cbor error");
    let Value::Map(map) = value else {
        panic!("error body was not a CBOR map");
    };

    assert_eq!(
        text(&map, "__type"),
        Some("aws.cryptography.esdk.testserver#ESDKClientError"),
        "keyring construction failure must map to ESDKClientError",
    );
    let message = text(&map, "message").expect("error carries a message");
    assert!(
        message.contains("create_raw_aes_keyring"),
        "message must name the unimplemented keyring constructor, got: {message}",
    );
}

//! AES-GCM encrypt → decrypt round trip via the rpcv2Cbor wire layer.

use aws_prim_test_server::model::{
    AesAlgorithm, AesDecryptRequest, AesDecryptResponse, AesEncryptRequest, AesEncryptResponse,
};
use aws_prim_test_server::wire::app;
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
        .uri(format!(
            "/service/PrimitivesTestServer/operation/{operation}"
        ))
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
async fn aes_256_gcm_round_trip() {
    let router = app();

    let key: Vec<u8> = (0u8..32).collect();
    let iv: Vec<u8> = (0u8..12).collect();
    let plaintext = b"hello, primitives test server!".to_vec();
    let aad = b"additional authenticated data".to_vec();

    // Encrypt
    let enc_resp: AesEncryptResponse = call(
        &router,
        "AesEncrypt",
        &AesEncryptRequest {
            algorithm: AesAlgorithm::Aes256Gcm,
            iv: iv.clone(),
            key: key.clone(),
            message: plaintext.clone(),
            aad: aad.clone(),
        },
    )
    .await;

    assert_eq!(enc_resp.ciphertext.len(), plaintext.len());
    assert_eq!(enc_resp.auth_tag.len(), 16);
    assert_ne!(enc_resp.ciphertext, plaintext);

    // Decrypt
    let dec_resp: AesDecryptResponse = call(
        &router,
        "AesDecrypt",
        &AesDecryptRequest {
            algorithm: AesAlgorithm::Aes256Gcm,
            key,
            ciphertext: enc_resp.ciphertext,
            auth_tag: enc_resp.auth_tag,
            iv,
            aad,
        },
    )
    .await;

    assert_eq!(dec_resp.plaintext, plaintext);
}

#[tokio::test]
async fn aes_128_gcm_round_trip() {
    let router = app();

    let key: Vec<u8> = (0u8..16).collect();
    let iv: Vec<u8> = (100u8..112).collect();
    let plaintext = b"short".to_vec();
    let aad = b"".to_vec();

    let enc_resp: AesEncryptResponse = call(
        &router,
        "AesEncrypt",
        &AesEncryptRequest {
            algorithm: AesAlgorithm::Aes128Gcm,
            iv: iv.clone(),
            key: key.clone(),
            message: plaintext.clone(),
            aad: aad.clone(),
        },
    )
    .await;

    let dec_resp: AesDecryptResponse = call(
        &router,
        "AesDecrypt",
        &AesDecryptRequest {
            algorithm: AesAlgorithm::Aes128Gcm,
            key,
            ciphertext: enc_resp.ciphertext,
            auth_tag: enc_resp.auth_tag,
            iv,
            aad,
        },
    )
    .await;

    assert_eq!(dec_resp.plaintext, plaintext);
}

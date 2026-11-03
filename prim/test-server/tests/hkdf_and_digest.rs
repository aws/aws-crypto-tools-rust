// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! HKDF and digest operations via the rpcv2Cbor wire layer.

use aws_prim_test_server::model::{
    DigestAlgorithm, DigestRequest, DigestResponse, GenerateRandomBytesRequest,
    GenerateRandomBytesResponse, HkdfRequest, HkdfResponse, HmacRequest, HmacResponse,
    KbkdfCtrHmacRequest, KbkdfCtrHmacResponse,
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
async fn digest_sha256() {
    let router = app();

    let resp: DigestResponse = call(
        &router,
        "Digest",
        &DigestRequest {
            algorithm: DigestAlgorithm::Sha256,
            data: b"hello".to_vec(),
        },
    )
    .await;

    // SHA-256("hello") is well-known
    let expected = hex("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    assert_eq!(resp.digest, expected);
}

#[tokio::test]
async fn hmac_sha256() {
    let router = app();

    let resp: HmacResponse = call(
        &router,
        "Hmac",
        &HmacRequest {
            algorithm: DigestAlgorithm::Sha256,
            key: b"key".to_vec(),
            message: b"message".to_vec(),
        },
    )
    .await;

    // HMAC-SHA-256("key", "message") — RFC 4231 inspired
    assert_eq!(resp.digest.len(), 32);
    // Not a zero vec
    assert_ne!(resp.digest, vec![0u8; 32]);
}

#[tokio::test]
async fn hkdf_sha256_produces_correct_length() {
    let router = app();

    let resp: HkdfResponse = call(
        &router,
        "Hkdf",
        &HkdfRequest {
            algorithm: DigestAlgorithm::Sha256,
            salt: vec![0u8; 32],
            ikm: b"input key material".to_vec(),
            info: b"context info".to_vec(),
            expected_length: 32,
        },
    )
    .await;

    assert_eq!(resp.okm.len(), 32);
    assert_ne!(resp.okm, vec![0u8; 32]);
}

#[tokio::test]
async fn kbkdf_ctr_hmac_produces_correct_length() {
    let router = app();

    let resp: KbkdfCtrHmacResponse = call(
        &router,
        "KbkdfCtrHmac",
        &KbkdfCtrHmacRequest {
            algorithm: DigestAlgorithm::Sha256,
            ikm: vec![0xAB; 32],
            info: b"some info".to_vec(),
            expected_length: 32,
        },
    )
    .await;

    assert_eq!(resp.okm.len(), 32);
    assert_ne!(resp.okm, vec![0u8; 32]);
}

#[tokio::test]
async fn generate_random_bytes_returns_requested_length() {
    let router = app();

    let resp: GenerateRandomBytesResponse = call(
        &router,
        "GenerateRandomBytes",
        &GenerateRandomBytesRequest { length: 64 },
    )
    .await;

    assert_eq!(resp.data.len(), 64);
    // Extremely unlikely to be all zeros
    assert_ne!(resp.data, vec![0u8; 64]);
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

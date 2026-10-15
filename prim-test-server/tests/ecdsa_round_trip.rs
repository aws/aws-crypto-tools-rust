//! ECDSA generate → sign → verify round trip via the rpcv2Cbor wire layer.

use aws_prim_test_server::model::{
    EcdsaAlgorithm, EcdsaGenerateKeyPairRequest, EcdsaGenerateKeyPairResponse, EcdsaSignRequest,
    EcdsaSignResponse, EcdsaVerifyRequest, EcdsaVerifyResponse,
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
async fn ecdsa_p384_round_trip() {
    let router = app();

    // Generate key pair
    let gen_resp: EcdsaGenerateKeyPairResponse = call(
        &router,
        "EcdsaGenerateKeyPair",
        &EcdsaGenerateKeyPairRequest {
            algorithm: EcdsaAlgorithm::EcdsaP384,
        },
    )
    .await;

    assert_eq!(gen_resp.verification_key.len(), 49); // compressed P-384 point
    assert!(!gen_resp.signing_key.is_empty());

    let message = b"test message for ECDSA P-384".to_vec();

    // Sign
    let sign_resp: EcdsaSignResponse = call(
        &router,
        "EcdsaSign",
        &EcdsaSignRequest {
            algorithm: EcdsaAlgorithm::EcdsaP384,
            signing_key: gen_resp.signing_key.clone(),
            message: message.clone(),
        },
    )
    .await;

    assert!(!sign_resp.signature.is_empty());

    // Verify (valid)
    let verify_resp: EcdsaVerifyResponse = call(
        &router,
        "EcdsaVerify",
        &EcdsaVerifyRequest {
            algorithm: EcdsaAlgorithm::EcdsaP384,
            verification_key: gen_resp.verification_key.clone(),
            message: message.clone(),
            signature: sign_resp.signature.clone(),
        },
    )
    .await;

    assert!(verify_resp.valid, "signature must verify");

    // Verify (wrong message → false)
    let verify_bad: EcdsaVerifyResponse = call(
        &router,
        "EcdsaVerify",
        &EcdsaVerifyRequest {
            algorithm: EcdsaAlgorithm::EcdsaP384,
            verification_key: gen_resp.verification_key,
            message: b"wrong message".to_vec(),
            signature: sign_resp.signature,
        },
    )
    .await;

    assert!(!verify_bad.valid, "wrong message must not verify");
}

#[tokio::test]
async fn ecdsa_p256_round_trip() {
    let router = app();

    let gen_resp: EcdsaGenerateKeyPairResponse = call(
        &router,
        "EcdsaGenerateKeyPair",
        &EcdsaGenerateKeyPairRequest {
            algorithm: EcdsaAlgorithm::EcdsaP256,
        },
    )
    .await;

    assert_eq!(gen_resp.verification_key.len(), 33); // compressed P-256 point

    let message = b"P-256 test".to_vec();

    let sign_resp: EcdsaSignResponse = call(
        &router,
        "EcdsaSign",
        &EcdsaSignRequest {
            algorithm: EcdsaAlgorithm::EcdsaP256,
            signing_key: gen_resp.signing_key,
            message: message.clone(),
        },
    )
    .await;

    let verify_resp: EcdsaVerifyResponse = call(
        &router,
        "EcdsaVerify",
        &EcdsaVerifyRequest {
            algorithm: EcdsaAlgorithm::EcdsaP256,
            verification_key: gen_resp.verification_key,
            message,
            signature: sign_resp.signature,
        },
    )
    .await;

    assert!(verify_resp.valid);
}

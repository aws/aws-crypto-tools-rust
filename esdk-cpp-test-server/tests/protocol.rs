//! Offline: a request without the rpcv2Cbor protocol header is rejected as a
//! GenericServerError before any backend operation runs.

use std::sync::Arc;

use aws_esdk_cpp_test_server::backend::CppBackend;
use aws_esdk_cpp_test_server::wire::app;
use axum::body::Body;
use axum::http::Request;
use ciborium::value::Value;
use tower::ServiceExt;

fn text<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a str> {
    map.iter().find_map(|(k, v)| match (k, v) {
        (Value::Text(k), Value::Text(v)) if k == key => Some(v.as_str()),
        _ => None,
    })
}

#[tokio::test]
async fn missing_protocol_header_is_generic_error() {
    let router = app(Arc::new(CppBackend::new()));

    let request = Request::builder()
        .method("POST")
        .uri("/service/ESDKTestServer/operation/CreateClient")
        .header("content-type", "application/cbor")
        .body(Body::from(Vec::new()))
        .expect("build request");

    let response = router.oneshot(request).await.expect("dispatch");
    assert_eq!(
        response.status(),
        400,
        "missing protocol must be a client error"
    );

    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    let Value::Map(map) = ciborium::from_reader(&bytes[..]).expect("decode cbor error") else {
        panic!("error body was not a CBOR map");
    };
    assert_eq!(
        text(&map, "__type"),
        Some("aws.cryptography.esdk.testserver#GenericServerError"),
        "a protocol violation must map to GenericServerError",
    );
}

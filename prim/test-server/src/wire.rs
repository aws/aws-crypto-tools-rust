// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! rpcv2Cbor HTTP wire layer.
//!
//! Routes `POST /service/{Service}/operation/{Operation}`, validates the
//! `smithy-protocol` header, decodes the CBOR request body into the operation's
//! input, dispatches to a handler, and encodes the CBOR response or a modeled
//! error.

use crate::error::ServerError;
use crate::handlers;
use crate::model::*;
use axum::body::{Body, Bytes};
use axum::extract::Path;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::post;
use axum::Router;
use serde::de::DeserializeOwned;
use serde::Serialize;

/// Build the router. Shared with tests so they can drive the real wire in-process.
pub fn app() -> Router {
    let router = Router::new().route("/service/:service/operation/:operation", post(dispatch));
    #[cfg(testserver_coverage)]
    let router = router.route("/control/coverage", post(dump_coverage));
    router
}

/// Writes the coverage of the test that just ran to the file named in the body.
#[cfg(testserver_coverage)]
async fn dump_coverage(path: String) -> (axum::http::StatusCode, String) {
    match test_server_control::dump_coverage(&path) {
        Ok(()) => (axum::http::StatusCode::OK, String::new()),
        Err(message) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, message),
    }
}

async fn dispatch(
    Path((service, operation)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if service != "PrimitivesTestServer" {
        return error_response(&ServerError::generic(format!(
            "unknown service: {service}; expected PrimitivesTestServer"
        )));
    }
    let protocol_ok = headers
        .get("smithy-protocol")
        .and_then(|value| value.to_str().ok())
        == Some("rpc-v2-cbor");
    if !protocol_ok {
        return error_response(&ServerError::generic(
            "missing or invalid smithy-protocol header; expected rpc-v2-cbor",
        ));
    }
    let content_type_ok = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        == Some("application/cbor");
    if !content_type_ok {
        return error_response(&ServerError::generic(
            "missing or invalid content-type; expected application/cbor",
        ));
    }

    let outcome = match operation.as_str() {
        "AesEncrypt" => dispatch_op::<AesEncryptRequest, _>(&body, handlers::aes_encrypt),
        "AesDecrypt" => dispatch_op::<AesDecryptRequest, _>(&body, handlers::aes_decrypt),
        "GenerateRandomBytes" => {
            dispatch_op::<GenerateRandomBytesRequest, _>(&body, handlers::generate_random_bytes)
        }
        "Digest" => dispatch_op::<DigestRequest, _>(&body, handlers::digest),
        "Hmac" => dispatch_op::<HmacRequest, _>(&body, handlers::hmac),
        "Hkdf" => dispatch_op::<HkdfRequest, _>(&body, handlers::hkdf),
        "KbkdfCtrHmac" => dispatch_op::<KbkdfCtrHmacRequest, _>(&body, handlers::kbkdf_ctr_hmac),
        "EcdsaGenerateKeyPair" => {
            dispatch_op::<EcdsaGenerateKeyPairRequest, _>(&body, handlers::ecdsa_generate_key_pair)
        }
        "EcdsaSign" => dispatch_op::<EcdsaSignRequest, _>(&body, handlers::ecdsa_sign),
        "EcdsaVerify" => dispatch_op::<EcdsaVerifyRequest, _>(&body, handlers::ecdsa_verify),
        other => Err(ServerError::generic(format!("unknown operation: {other}"))),
    };

    match outcome {
        Ok(body) => build(StatusCode::OK, body),
        Err(e) => error_response(&e),
    }
}

fn dispatch_op<Req, Resp>(
    body: &[u8],
    handler: impl FnOnce(Req) -> Result<Resp, ServerError>,
) -> Result<Vec<u8>, ServerError>
where
    Req: DeserializeOwned,
    Resp: Serialize,
{
    let req = decode::<Req>(body)?;
    // A panicking handler would otherwise drop the connection; report it as a
    // modeled GenericServerError so the client sees a harness failure.
    let resp = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handler(req)))
        .map_err(|_| ServerError::generic("unexpected server error: handler panicked"))??;
    encode(&resp)
}

fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ServerError> {
    ciborium::from_reader(bytes)
        .map_err(|e| ServerError::generic(format!("failed to decode CBOR request: {e}")))
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, ServerError> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf)
        .map_err(|e| ServerError::generic(format!("failed to encode CBOR response: {e}")))?;
    Ok(buf)
}

fn error_response(error: &ServerError) -> Response {
    build(StatusCode::BAD_REQUEST, error.to_cbor())
}

fn build(status: StatusCode, body: Vec<u8>) -> Response {
    Response::builder()
        .status(status)
        .header("smithy-protocol", "rpc-v2-cbor")
        .header(header::CONTENT_TYPE, "application/cbor")
        .body(Body::from(body))
        .expect("response builder")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handler_panic_becomes_generic_server_error() {
        let body = encode(&DigestRequest {
            algorithm: DigestAlgorithm::Sha256,
            data: Vec::new(),
        })
        .unwrap();
        let err = dispatch_op::<DigestRequest, DigestResponse>(&body, |_| {
            panic!("injected handler panic")
        })
        .unwrap_err();
        assert!(matches!(err, ServerError::Generic(_)), "got {err:?}");
        assert_eq!(err.message(), "unexpected server error: handler panicked");
    }
}

// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! rpcv2Cbor HTTP wire layer.

use crate::error::ServerError;
use crate::handlers::AppState;
use crate::model::*;
use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use axum::routing::post;
use futures_util::FutureExt;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;

/// Build the router. Shared with tests so they can drive the real wire in-process.
pub fn app(state: Arc<AppState>) -> Router {
    let router = Router::new().route("/service/:service/operation/:operation", post(dispatch));
    #[cfg(testserver_coverage)]
    let router = router.route("/control/coverage", post(dump_coverage));
    router.with_state(state)
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
    State(state): State<Arc<AppState>>,
    Path((service, operation)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if service != "MPLTestServer" {
        return error_response(&ServerError::generic(format!(
            "unknown service: {service}; expected MPLTestServer"
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
        "CreateRawAesKeyring" => dispatch_op::<CreateRawAesKeyringRequest, _>(&body, |req| {
            state.create_raw_aes_keyring(req)
        }),
        "CreateStaticKeyring" => dispatch_op::<CreateStaticKeyringRequest, _>(&body, |req| {
            state.create_static_keyring(req)
        }),
        "CreateDefaultCmm" => {
            dispatch_op::<CreateDefaultCmmRequest, _>(&body, |req| state.create_default_cmm(req))
        }
        "CreateKeyStoreClient" => {
            dispatch_op_async::<CreateKeyStoreClientRequest, _, _>(&body, |req| {
                state.create_key_store_client(req)
            })
            .await
        }
        "CreateCryptographicMaterialsCache" => {
            dispatch_op::<CreateCryptographicMaterialsCacheRequest, _>(&body, |req| {
                state.create_cryptographic_materials_cache(req)
            })
        }
        "CreateAwsKmsHierarchicalKeyring" => {
            dispatch_op_async::<CreateAwsKmsHierarchicalKeyringRequest, _, _>(&body, |req| {
                state.create_aws_kms_hierarchical_keyring(req)
            })
            .await
        }
        "InitializeEncryptionMaterials" => {
            dispatch_op::<InitializeEncryptionMaterialsRequest, _>(&body, |req| {
                state.initialize_encryption_materials(req)
            })
        }
        "InitializeDecryptionMaterials" => {
            dispatch_op::<InitializeDecryptionMaterialsRequest, _>(&body, |req| {
                state.initialize_decryption_materials(req)
            })
        }
        "OnEncrypt" => {
            dispatch_op_async::<OnEncryptRequest, _, _>(&body, |req| state.on_encrypt(req)).await
        }
        "OnDecrypt" => {
            dispatch_op_async::<OnDecryptRequest, _, _>(&body, |req| state.on_decrypt(req)).await
        }
        "GetEncryptionMaterials" => {
            dispatch_op_async::<GetEncryptionMaterialsRequest, _, _>(&body, |req| {
                state.get_encryption_materials(req)
            })
            .await
        }
        "DecryptMaterials" => {
            dispatch_op_async::<DecryptMaterialsRequest, _, _>(&body, |req| {
                state.decrypt_materials(req)
            })
            .await
        }
        other => Err(ServerError::generic(format!("unknown operation: {other}"))),
    };

    match outcome {
        Ok(body) => build(StatusCode::OK, body),
        Err(e) => error_response(&e),
    }
}

/// Modeled error for a handler that panicked.
fn handler_panicked() -> ServerError {
    ServerError::generic("unexpected server error: handler panicked")
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
        .map_err(|_| handler_panicked())??;
    encode(&resp)
}

/// [`dispatch_op`] for handlers that await.
async fn dispatch_op_async<Req, Resp, Fut>(
    body: &[u8],
    handler: impl FnOnce(Req) -> Fut,
) -> Result<Vec<u8>, ServerError>
where
    Req: DeserializeOwned,
    Resp: Serialize,
    Fut: Future<Output = Result<Resp, ServerError>>,
{
    let req = decode::<Req>(body)?;
    let resp = AssertUnwindSafe(handler(req))
        .catch_unwind()
        .await
        .map_err(|_| handler_panicked())??;
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

    fn request_body() -> Vec<u8> {
        encode(&CreateDefaultCmmRequest {
            keyring_id: "k".to_string(),
        })
        .unwrap()
    }

    fn assert_modeled_panic(err: ServerError) {
        assert!(matches!(err, ServerError::Generic(_)), "got {err:?}");
        assert_eq!(err.message(), "unexpected server error: handler panicked");
    }

    #[test]
    fn handler_panic_becomes_generic_server_error() {
        let err = dispatch_op::<CreateDefaultCmmRequest, CreateDefaultCmmResponse>(
            &request_body(),
            |_| panic!("injected handler panic"),
        )
        .unwrap_err();
        assert_modeled_panic(err);
    }

    #[tokio::test]
    async fn async_handler_panic_becomes_generic_server_error() {
        let err = dispatch_op_async::<CreateDefaultCmmRequest, CreateDefaultCmmResponse, _>(
            &request_body(),
            |_| async { panic!("injected handler panic") },
        )
        .await
        .unwrap_err();
        assert_modeled_panic(err);
    }
}

// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! rpcv2Cbor HTTP wire layer.
//!
//! Routes `POST /service/{Service}/operation/{Operation}`, validates the
//! `smithy-protocol` header, decodes the CBOR request body into the operation's
//! input, dispatches to a handler, and encodes the CBOR response or a modeled
//! error.

use crate::error::ServerError;
use crate::handlers::AppState;
use crate::model::{
    CreateClientRequest, CreateStructuredClientRequest, DecryptItemRequest,
    DecryptPathStructureRequest, DecryptStructureRequest, EncryptItemRequest,
    EncryptPathStructureRequest, EncryptStructureRequest, GetEncryptedDataKeyDescriptionRequest,
    ResolveAuthActionsRequest,
};
use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::post;
use axum::Router;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::sync::Arc;

/// Build the router. Shared with tests so they can drive the real wire in-process.
pub fn app(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/service/{service}/operation/{operation}", post(dispatch))
        .with_state(state)
}

async fn dispatch(
    State(state): State<Arc<AppState>>,
    Path((service, operation)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if service != "DBESDKTestServer" {
        return error_response(&ServerError::generic(format!(
            "unknown service: {service}; expected DBESDKTestServer"
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
        "CreateClient" => match decode::<CreateClientRequest>(&body) {
            Ok(req) => state
                .create_client(req)
                .await
                .and_then(|resp| encode(&resp)),
            Err(e) => Err(e),
        },
        "EncryptItem" => match decode::<EncryptItemRequest>(&body) {
            Ok(req) => state.encrypt_item(req).await.and_then(|resp| encode(&resp)),
            Err(e) => Err(e),
        },
        "DecryptItem" => match decode::<DecryptItemRequest>(&body) {
            Ok(req) => state.decrypt_item(req).await.and_then(|resp| encode(&resp)),
            Err(e) => Err(e),
        },
        "GetEncryptedDataKeyDescription" => {
            match decode::<GetEncryptedDataKeyDescriptionRequest>(&body) {
                Ok(req) => state
                    .get_encrypted_data_key_description(req)
                    .and_then(|resp| encode(&resp)),
                Err(e) => Err(e),
            }
        }
        "CreateStructuredClient" => match decode::<CreateStructuredClientRequest>(&body) {
            Ok(req) => state
                .create_structured_client(req)
                .await
                .and_then(|resp| encode(&resp)),
            Err(e) => Err(e),
        },
        "EncryptStructure" => match decode::<EncryptStructureRequest>(&body) {
            Ok(req) => state
                .encrypt_structure(req)
                .await
                .and_then(|resp| encode(&resp)),
            Err(e) => Err(e),
        },
        "DecryptStructure" => match decode::<DecryptStructureRequest>(&body) {
            Ok(req) => state
                .decrypt_structure(req)
                .await
                .and_then(|resp| encode(&resp)),
            Err(e) => Err(e),
        },
        "EncryptPathStructure" => match decode::<EncryptPathStructureRequest>(&body) {
            Ok(req) => state
                .encrypt_path_structure(req)
                .await
                .and_then(|resp| encode(&resp)),
            Err(e) => Err(e),
        },
        "DecryptPathStructure" => match decode::<DecryptPathStructureRequest>(&body) {
            Ok(req) => state
                .decrypt_path_structure(req)
                .await
                .and_then(|resp| encode(&resp)),
            Err(e) => Err(e),
        },
        "ResolveAuthActions" => match decode::<ResolveAuthActionsRequest>(&body) {
            Ok(req) => state
                .resolve_auth_actions(req)
                .await
                .and_then(|resp| encode(&resp)),
            Err(e) => Err(e),
        },
        other => Err(ServerError::generic(format!(
            "operation {other} is not supported by the native Rust language server"
        ))),
    };

    match outcome {
        Ok(body) => build(StatusCode::OK, body),
        Err(e) => error_response(&e),
    }
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
    // Both modeled errors carry @error("client"); 400 is the client-error status.
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

// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Runnable entry point for the Rust Primitives Language_Server.
//!
//! Binds an rpcv2Cbor HTTP endpoint on a port taken from (in order) the first
//! CLI argument, the `PRIM_TESTSERVER_PORT` env var, or the default 8094.

use std::net::SocketAddr;

use aws_prim_test_server::wire::app;

#[tokio::main]
async fn main() {
    let port = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("PRIM_TESTSERVER_PORT").ok())
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(8094);

    let router = app();

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| panic!("failed to bind {addr}: {e}"));
    eprintln!("listening at http://127.0.0.1:{port}");
    axum::serve(listener, router)
        .with_graceful_shutdown(test_server_control::shutdown_signal())
        .await
        .expect("server error");
}

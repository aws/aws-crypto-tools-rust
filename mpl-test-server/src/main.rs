//! Runnable entry point for the Rust MPL Language_Server.
//!
//! Binds an rpcv2Cbor HTTP endpoint on a port taken from (in order) the first
//! CLI argument, the `MPL_TESTSERVER_PORT` env var, or the default 8093.

use std::net::SocketAddr;
use std::sync::Arc;

use aws_mpl_test_server::handlers::AppState;
use aws_mpl_test_server::wire::app;

#[tokio::main]
async fn main() {
    let port = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("MPL_TESTSERVER_PORT").ok())
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(8093);

    let state = Arc::new(AppState::new());
    let router = app(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| panic!("failed to bind {addr}: {e}"));
    eprintln!("listening at http://127.0.0.1:{port}");
    axum::serve(listener, router).await.expect("server error");
}

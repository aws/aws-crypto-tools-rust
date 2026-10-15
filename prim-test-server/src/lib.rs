//! Hand-rolled Primitives TestServer Language_Server for Rust.
//!
//! Speaks the rpcv2Cbor wire contract and delegates each operation to the
//! cryptographic primitives crate (`aws-mpl-primitives`).

pub mod error;
pub mod handlers;
pub mod model;
pub mod wire;

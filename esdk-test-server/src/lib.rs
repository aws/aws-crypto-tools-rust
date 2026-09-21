//! Hand-rolled ESDK TestServer Language_Server for Rust.
//!
//! Speaks the rpcv2Cbor wire contract of the single source-of-truth Smithy model
//! owned by aws-crypto-tools-commons (`esdk/test-server/model`) and delegates each
//! operation to the AWS Encryption SDK for Rust (`aws-esdk`).

pub mod error;
pub mod handlers;
pub mod keyring;
pub mod model;
pub mod wire;

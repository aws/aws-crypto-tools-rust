// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Hand-rolled DB-ESDK TestServer Language_Server for the native Rust DB-ESDK.
//!
//! Speaks the rpcv2Cbor wire contract of the Smithy model owned by
//! aws-crypto-tools-commons (`dbesdk/test-server/model`) and delegates each
//! operation to the native AWS Database Encryption SDK for DynamoDB (`aws-db-esdk`).

pub mod error;
pub mod handlers;
pub mod keyring;
pub mod model;
pub mod transforms;
pub mod transforms_model;
pub mod wire;

// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Hand-written DB-ESDK TestServer Language_Server for the native Rust DB-ESDK.
//!
//! It speaks rpcv2Cbor for the Smithy model in aws-crypto-tools-commons (`dbesdk/test-server/model`).
//! Each operation calls the native AWS Database Encryption SDK for DynamoDB (`aws-db-esdk`).

pub mod error;
pub mod handlers;
pub mod keyring;
pub mod model;
pub mod search;
pub mod transforms;
pub mod transforms_model;
pub mod wire;

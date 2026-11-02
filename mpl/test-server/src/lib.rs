// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Hand-rolled MPL TestServer Language_Server for Rust.
//!
//! Speaks the rpcv2Cbor wire contract and delegates each operation to the
//! Material Providers Library (`aws-crypto-mpl`).

pub mod error;
pub mod handlers;
pub mod model;
pub mod wire;

// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! `aws-crypto-test-vectors` — CLI runner that generates and consumes
//! test-vector manifests for the AWS Crypto Tools Rust crates.
//!
//! Public modules:
//!
//! * [`cli`]      — the `test-vectors` binary entrypoints (invoked from `main.rs`)
//! * [`error`]    — shared error/result types
//! * [`manifest`] — serde-backed manifest schema (encrypt, decrypt, keys)
//! * [`projects`] — per-project vector generators and the registry
//!
//! The manifest schema is intentionally byte-compatible with the JSON produced
//! by the MPL Dafny tool
//! (`TestVectorsAwsCryptographicMaterialProviders`). See
//! [`manifest`] for details.

pub mod cli;
pub mod error;
pub mod manifest;
pub mod projects;

pub use error::{Result, TestVectorError};

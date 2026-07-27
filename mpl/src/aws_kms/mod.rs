// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! AWS KMS shared utilities.

pub mod mrk_match;

pub(crate) mod branch_key_wrap;

pub(crate) mod cache_entry_identifier;

pub mod hierarchical_keyring;

/// Crate-internal surfaces re-exported for integration tests.
///
/// Hidden from the public API surface; do NOT depend on these from outside
/// the crate's own integration tests — they are not stable API.
#[doc(hidden)]
pub mod __test_internals {
    pub use super::branch_key_wrap::{compute_aad, unwrap, wrap};
    pub use super::cache_entry_identifier::{for_decrypt, for_encrypt};
}

// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! AWS KMS shared utilities.

pub(crate) mod mrk_match;

pub(crate) mod branch_key_wrap;

pub(crate) mod cache_entry_identifier;

pub mod hierarchical_keyring;

#[cfg(feature = "kms")]
pub mod aws_kms_keyring;

#[cfg(feature = "kms")]
pub mod discovery_keyring;

#[cfg(feature = "kms")]
pub mod multi_keyrings;

#[cfg(feature = "kms")]
pub(crate) mod user_agent;

/// Internals that integration tests reach.
/// Not part of the public API and may change in any release.
#[cfg(feature = "test-utils")]
#[doc(hidden)]
pub mod __test_internals {
    pub use super::branch_key_wrap::{compute_aad, unwrap, wrap};
    pub use super::cache_entry_identifier::build_cache_identifier;
    pub use super::mrk_match::aws_kms_mrk_match_for_decrypt;

    use super::hierarchical_keyring::HierarchicalKeyring;
    use crate::cmc::SharedCmc;

    /// The cache-identifier scope byte of OnEncrypt.
    pub const SCOPE_ID_ENCRYPT: u8 = super::hierarchical_keyring::SCOPE_ID_ENCRYPT;

    /// The cache-identifier scope byte of OnDecrypt.
    pub const SCOPE_ID_DECRYPT: u8 = super::hierarchical_keyring::SCOPE_ID_DECRYPT;

    /// The keyring's partition id bytes.
    pub fn partition_id_bytes(keyring: &HierarchicalKeyring) -> &[u8] {
        keyring.partition_id_bytes()
    }

    /// The keyring's cache.
    pub fn cache(keyring: &HierarchicalKeyring) -> &SharedCmc {
        keyring.cache()
    }
}

// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Cache entry identifier formulas for the AWS KMS Hierarchical Keyring.
//!
//! Implements the SHA-384 cache key derivation specified in Appendix A of
//! `aws-kms-hierarchical-keyring.md`. [`build_cache_identifier`] is the only
//! entry point and serves both OnEncrypt and OnDecrypt: the caller passes the
//! scope byte for the operation it is performing.
//!
//! Users of the Hierarchical Keyring MUST NEVER configure two different
//! physical Key Stores with the same Logical Key Store Name — the formulas
//! incorporate the *logical* name, so two physical key stores sharing a
//! logical name will collide in the cache.

use aws_mpl_primitives::{DigestAlg, digest};

const RESOURCE_ID_HIERARCHICAL_KEYRING: u8 = 0x02;

const NULL_BYTE: u8 = 0x00;

/// Build the cache entry identifier for either OnEncrypt or OnDecrypt.
///
/// `scope_id` selects which formula is being computed and is supplied by the
/// caller as `SCOPE_ID_ENCRYPT` or `SCOPE_ID_DECRYPT`, defined next to the
/// call sites in `super::hierarchical_keyring`. It pairs with
/// `branch_key_version`: the encrypt scope takes `None`, the decrypt scope
/// takes `Some(version)`.
///
/// `partition_id` is the bytes recorded by the keyring at construction time
/// (UTF-8 of the caller-provided string, or the 16-byte representation of a
/// freshly-generated v4 UUID). `branch_key_version`, when present, is the
/// version string (typically a UUID, 36 UTF-8 characters) of the branch key
/// that wrapped the data key being decrypted.
///
/// The byte layout is exactly the formula given in
/// `aws-kms-hierarchical-keyring.md#encryption-materials` /
/// `#decryption-materials`:
///
/// ```text
/// SHA-384(
///     resource_id || 0x00 || scope_id || 0x00 ||
///     partition_id || 0x00 ||
///     UTF8(logical_key_store_name) || 0x00 ||
///     UTF8(branch_key_id)
///     [|| 0x00 || UTF8(branch_key_version)]   // OnDecrypt only
/// )
/// ```
pub fn build_cache_identifier(
    scope_id: u8,
    partition_id: &[u8],
    logical_key_store_name: &str,
    branch_key_id: &str,
    branch_key_version: Option<&str>,
) -> [u8; DigestAlg::Sha384.output_len()] {
    let mut buf: Vec<u8> = vec![
        RESOURCE_ID_HIERARCHICAL_KEYRING,
        NULL_BYTE,
        scope_id,
        NULL_BYTE,
    ];

    buf.extend_from_slice(partition_id);
    buf.push(NULL_BYTE);

    buf.extend_from_slice(logical_key_store_name.as_bytes());
    buf.push(NULL_BYTE);

    buf.extend_from_slice(branch_key_id.as_bytes());

    if let Some(version) = branch_key_version {
        buf.push(NULL_BYTE);
        buf.extend_from_slice(version.as_bytes());
    }

    let mut output = [0u8; DigestAlg::Sha384.output_len()];
    digest(DigestAlg::Sha384, &buf, &mut output)
        .expect("output is exactly DigestAlg::Sha384.output_len() bytes");
    output
}

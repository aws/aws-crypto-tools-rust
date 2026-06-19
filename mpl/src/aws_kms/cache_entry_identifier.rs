// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Cache entry identifier formulas for the AWS KMS Hierarchical Keyring.
//!
//! Implements the SHA-384 cache key derivation specified in Appendix A of
//! `aws-kms-hierarchical-keyring.md`. The two public entry points,
//! [`for_encrypt`] and [`for_decrypt`], return the 48-byte SHA-384 digest
//! used as the cache identifier for OnEncrypt and OnDecrypt requests
//! respectively.
//!
//! Users of the Hierarchical Keyring MUST NEVER configure two different
//! physical Key Stores with the same Logical Key Store Name — the formulas
//! incorporate the *logical* name, so two physical key stores sharing a
//! logical name will collide in the cache.

//= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#appendix-a-cache-entry-identifier-formulas
//= type=implication
//# When accessing the underlying cryptographic materials cache,
//# the hierarchical keyring MUST use the formulas specified in this appendix
//# in order to compute the [cache entry identifier](../cryptographic-materials-cache.md#cache-identifier).
//
//= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#logical-key-store-name
//= type=implication
//# > Note: Users MUST NEVER have two different physical Key Stores with the same Logical Key Store Name.
use aws_lc_rs::digest::{SHA384, SHA384_OUTPUT_LEN, digest};

//= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#encryption-materials
//# - MUST be the Resource ID for the Hierarchical Keyring (0x02)
//
//= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#decryption-materials
//# - MUST be the Resource ID for the Hierarchical Keyring (0x02)
const RESOURCE_ID_HIERARCHICAL_KEYRING: u8 = 0x02;

//= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#encryption-materials
//# - MUST be the Scope ID for Encrypt (0x01)
const SCOPE_ID_ENCRYPT: u8 = 0x01;

//= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#decryption-materials
//# - MUST be the Scope ID for Decrypt (0x02)
const SCOPE_ID_DECRYPT: u8 = 0x02;

const NULL_BYTE: u8 = 0x00;

/// Build the cache entry identifier for either OnEncrypt or OnDecrypt.
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
fn build_cache_identifier(
    scope_id: u8,
    partition_id: &[u8],
    logical_key_store_name: &str,
    branch_key_id: &str,
    branch_key_version: Option<&str>,
) -> [u8; SHA384_OUTPUT_LEN] {
    let mut buf: Vec<u8> = vec![
        RESOURCE_ID_HIERARCHICAL_KEYRING,
        NULL_BYTE,
        scope_id,
        NULL_BYTE,
    ];

    //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#encryption-materials
    //# - MUST be the Partition ID for the Hierarchical Keyring
    //
    //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#decryption-materials
    //# - MUST be the Partition ID for the Hierarchical Keyring
    buf.extend_from_slice(partition_id);
    buf.push(NULL_BYTE);

    //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#encryption-materials
    //= type=implication
    //# - MUST be the UTF8 encoded Logical Key Store Name of the keystore for the Hierarchical Keyring
    //
    //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#decryption-materials
    //= type=implication
    //# - MUST be the UTF8 encoded Logical Key Store Name of the keystore for the Hierarchical Keyring
    //
    //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#logical-key-store-name
    //= type=implication
    //# Logical Key Store Name MUST be converted to UTF8 Bytes to be used in
    //# the cache identifiers.
    buf.extend_from_slice(logical_key_store_name.as_bytes());
    buf.push(NULL_BYTE);

    //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#encryption-materials
    //= type=implication
    //# - MUST be the UTF8 encoded branch-key-id
    //
    //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#decryption-materials
    //= type=implication
    //# - MUST be the UTF8 encoded branch-key-id
    buf.extend_from_slice(branch_key_id.as_bytes());

    if let Some(version) = branch_key_version {
        buf.push(NULL_BYTE);
        //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#decryption-materials
        //# - MUST be the UTF8 encoded branch-key-version
        buf.extend_from_slice(version.as_bytes());
    }

    //= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#resource-suffix
    //# The aforementioned 4 definitions ([Resource Identifier](#resource-identifier),
    //# [Scope Identifier](#scope-identifier), [Partition ID](#partition-id-1), and
    //# [Resource Suffix](#resource-suffix)) MUST be appended together with the null byte, 0x00,
    //# and the SHA384 of the result should be taken as the final cache identifier.
    let digest_value = digest(&SHA384, &buf);
    let mut output = [0u8; SHA384_OUTPUT_LEN];
    output.copy_from_slice(digest_value.as_ref());
    output
}

/// Compute the cache entry identifier for an OnEncrypt request.
///
/// `partition_id` is the bytes recorded by the keyring at construction time
/// (UTF-8 of the caller-provided string, or the 16-byte representation of a
/// freshly-generated v4 UUID).
//= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#encryption-materials
//# When the hierarchical keyring receives an OnEncrypt request,
//# the cache entry identifier MUST be calculated as the
//# SHA-384 hash of the following byte strings, in the order listed:
pub fn for_encrypt(
    partition_id: &[u8],
    logical_key_store_name: &str,
    branch_key_id: &str,
) -> [u8; SHA384_OUTPUT_LEN] {
    build_cache_identifier(
        SCOPE_ID_ENCRYPT,
        partition_id,
        logical_key_store_name,
        branch_key_id,
        None,
    )
}

/// Compute the cache entry identifier for an OnDecrypt request.
///
/// `branch_key_version` is the version string (typically a UUID, 36 UTF-8
/// characters) of the branch key used to wrap the data key being decrypted.
//= ../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#decryption-materials
//# When the hierarchical keyring receives an OnDecrypt request,
//# it MUST calculate the cache entry identifier as the
//# SHA-384 hash of the following byte strings, in the order listed:
pub fn for_decrypt(
    partition_id: &[u8],
    logical_key_store_name: &str,
    branch_key_id: &str,
    branch_key_version: &str,
) -> [u8; SHA384_OUTPUT_LEN] {
    build_cache_identifier(
        SCOPE_ID_DECRYPT,
        partition_id,
        logical_key_store_name,
        branch_key_id,
        Some(branch_key_version),
    )
}

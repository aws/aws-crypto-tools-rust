// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Cache entry identifier formulas for the AWS KMS Hierarchical Keyring.
//!
//! [`build_cache_identifier`] is the only entry point and serves both
//! OnEncrypt and OnDecrypt: the caller passes the scope byte for the
//! operation it is performing, and gets back the 48-byte SHA-384 digest used
//! as the cache identifier.
//!
//! Users of the Hierarchical Keyring MUST NEVER configure two different
//! physical Key Stores with the same Logical Key Store Name — the formulas
//! incorporate the *logical* name, so two physical key stores sharing a
//! logical name will collide in the cache.

use aws_mpl_primitives::{DigestAlg, digest};

//= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#encryption-materials
//# - MUST be the Resource ID for the Hierarchical Keyring (0x02)
//
//= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#decryption-materials
//# - MUST be the Resource ID for the Hierarchical Keyring (0x02)
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
pub fn build_cache_identifier(
    scope_id: u8,
    partition_id: &[u8],
    logical_key_store_name: &str,
    branch_key_id: &str,
    branch_key_version: Option<&str>,
) -> [u8; DigestAlg::Sha384.output_len()] {
    //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#appendix-a-cache-entry-identifier-formulas
    //# When accessing the underlying cryptographic materials cache,
    //# the hierarchical keyring MUST use the formulas specified in this appendix
    //# in order to compute the [cache entry identifier](../cryptographic-materials-cache.md#cache-identifier).
    let mut buf: Vec<u8> = vec![
        RESOURCE_ID_HIERARCHICAL_KEYRING,
        NULL_BYTE,
        scope_id,
        NULL_BYTE,
    ];

    //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#encryption-materials
    //# - MUST be the Partition ID for the Hierarchical Keyring
    //
    //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#decryption-materials
    //# - MUST be the Partition ID for the Hierarchical Keyring
    buf.extend_from_slice(partition_id);
    buf.push(NULL_BYTE);

    //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#encryption-materials
    //# - MUST be the UTF8 encoded Logical Key Store Name of the keystore for the Hierarchical Keyring
    //
    //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#decryption-materials
    //# - MUST be the UTF8 encoded Logical Key Store Name of the keystore for the Hierarchical Keyring
    //
    //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#logical-key-store-name
    //# Logical Key Store Name MUST be converted to UTF8 Bytes to be used in
    //# the cache identifiers.
    buf.extend_from_slice(logical_key_store_name.as_bytes());
    buf.push(NULL_BYTE);

    //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#encryption-materials
    //# - MUST be the UTF8 encoded branch-key-id
    //
    //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#decryption-materials
    //# - MUST be the UTF8 encoded branch-key-id
    buf.extend_from_slice(branch_key_id.as_bytes());

    if let Some(version) = branch_key_version {
        buf.push(NULL_BYTE);
        //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#decryption-materials
        //# - MUST be the UTF8 encoded branch-key-version
        buf.extend_from_slice(version.as_bytes());
    }

    let mut output = [0u8; DigestAlg::Sha384.output_len()];
    //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#encryption-materials
    //# When the hierarchical keyring receives an OnEncrypt request,
    //# the cache entry identifier MUST be calculated as the
    //# SHA-384 hash of the following byte strings, in the order listed:
    //
    //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#decryption-materials
    //# When the hierarchical keyring receives an OnDecrypt request,
    //# it MUST calculate the cache entry identifier as the
    //# SHA-384 hash of the following byte strings, in the order listed:
    //
    //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#resource-suffix
    //# The aforementioned 4 definitions ([Resource Identifier](#resource-identifier),
    //# [Scope Identifier](#scope-identifier), [Partition ID](#partition-id-1), and
    //# [Resource Suffix](#resource-suffix)) MUST be appended together with the null byte, 0x00,
    //# and the SHA384 of the result should be taken as the final cache identifier.
    digest(DigestAlg::Sha384, &buf, &mut output)
        .expect("output is exactly DigestAlg::Sha384.output_len() bytes");
    output
}

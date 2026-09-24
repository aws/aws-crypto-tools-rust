// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Type aliases and helper functions for message serialization.

use crate::error::{Error, val_err};
use crate::types::EncryptionContext;
use aws_crypto_mpl::structures::AlgorithmSuite;
use aws_crypto_mpl::structures::EncryptedDataKey;

/// Unordered encryption context from the public API.
pub(crate) type ESDKEncryptionContext = EncryptionContext;
pub(crate) type ESDKEncryptionContextPair = (String, String);
/// Sorted-by-key encryption context used for on-wire serialization.
pub(crate) type ESDKCanonicalEncryptionContext = Vec<ESDKEncryptionContextPair>;

/// Max total key-value-pairs body length: the outer `UInt16` length field (2 bytes)
/// plus the count `UInt16` (2 bytes) must together still fit in a `UInt16`, leaving
/// `u16::MAX` - 2 for the payload.
const ESDK_CANONICAL_ENCRYPTION_CONTEXT_MAX_LENGTH: u64 = u16::MAX as u64 - 2;

pub(crate) const fn get_iv_length(a: &AlgorithmSuite) -> usize {
    a.iv_length()
}

pub(crate) const fn get_tag_length(a: &AlgorithmSuite) -> usize {
    a.authentication_tag_length()
}

pub(crate) const fn get_encrypt_key_length(a: &AlgorithmSuite) -> usize {
    a.encryption_key_length()
}

// Length properties of the Encryption Context.
// The Encryption Context has a complex relationship with length.
// Each key or value MUST be less than Uint16,
// However the entire thing MUST also serialize to less than Uint16.
// In practice, this means than the longest value,
// given a key of 1 bytes is Uint16-2-2-1.
// e.g.
// 2 for the key length
// 1 for the key data
// 2 for the value length
// Uint16-2-2-1 for the value data

/// Serialized byte length of the key-value-pairs body (no outer length prefix).
///
/// Accumulates in `usize` and casts to `u64` on return. Per the ESDK message
/// format, the AAD's maximum allowed length is `2^16 - 1` bytes, so a legal
/// encryption context never produces a sum that overflows even a 16-bit
/// accumulator — the `usize` sum and `as u64` cast are safe by construction.
pub(crate) fn length(encryption_context: &ESDKEncryptionContext) -> u64 {
    let mut length: usize = 0;
    for (key, value) in encryption_context.iter() {
        length += 2 + key.len() + 2 + value.len();
    }
    length as u64
}

/// Decode to the canonical on-wire ordering.
///
/// The encryption context is a `BTreeMap` keyed by the raw bytes, so iteration
/// already yields the ascending-by-UTF-8-byte-value order the format requires
/// and no sort is needed.
///
/// # Errors
/// Returns an error if any key or value is not valid UTF-8. The specification
/// defines encryption context entries as UTF-8 encoded strings, and this is the
/// boundary where they become the strings the header serializer writes.
// https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/structures.md#encryption-context
pub(crate) fn to_canonical_pairs(
    encryption_context: &ESDKEncryptionContext,
) -> Result<ESDKCanonicalEncryptionContext, Error> {
    encryption_context
        .iter()
        .map(|(key, value)| {
            let key = String::from_utf8(key.clone())
                .map_err(|_| val_err("Encryption context key is not valid UTF-8"))?;
            let value = String::from_utf8(value.clone())
                .map_err(|_| val_err("Encryption context value is not valid UTF-8"))?;
            Ok((key, value))
        })
        .collect()
}

pub(crate) fn from_canonical_pairs(pairs: ESDKCanonicalEncryptionContext) -> ESDKEncryptionContext {
    let mut map = ESDKEncryptionContext::new();
    for (key, value) in pairs {
        map.insert(key.into_bytes(), value.into_bytes());
    }
    map
}

/// True iff `ec` fits the on-wire encoding: pair count, each key/value length,
/// and total serialized length all fit in a `UInt16`.
pub(crate) fn is_esdk_encryption_context(ec: &EncryptionContext) -> bool {
    if ec.len() > usize::from(u16::MAX) {
        return false;
    }
    if length(ec) > ESDK_CANONICAL_ENCRYPTION_CONTEXT_MAX_LENGTH {
        return false;
    }
    for (key, value) in ec.iter() {
        if key.len() > usize::from(u16::MAX) {
            return false;
        }
        if value.len() > usize::from(u16::MAX) {
            return false;
        }
    }
    true
}

/// True iff every EDK field length fits in a `UInt16`.
pub(crate) fn is_esdk_encrypted_data_key(edk: &EncryptedDataKey) -> bool {
    u16::try_from(edk.key_provider_id.len()).is_ok()
        && u16::try_from(edk.key_provider_info.len()).is_ok()
        && u16::try_from(edk.ciphertext.len()).is_ok()
}

/// True iff the EDK count and each entry fit in `UInt16`.
pub(crate) fn is_esdk_encrypted_data_keys(edks: &[EncryptedDataKey]) -> bool {
    if edks.len() > usize::from(u16::MAX) {
        return false;
    }
    for edk in edks {
        if !is_esdk_encrypted_data_key(edk) {
            return false;
        }
    }
    true
}

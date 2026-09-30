// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for spec/data-format/message-header.md#aad,
//! #key-value-pairs-length, and #key-value-pairs

#[allow(clippy::duplicate_mod)]
mod fixtures;
mod test_helpers;

use aws_esdk::*;
use fixtures::*;
use test_helpers::*;

/// V1 header AAD offset: Version(1) + Type(1) + AlgSuiteID(2) + MessageID(16) = 20.
const V1_AAD_OFFSET: usize = 20;
/// V2 header AAD offset: Version(1) + AlgSuiteID(2) + MessageID(32) = 35.
const V2_AAD_OFFSET: usize = 35;

fn aad_offset(version: Version) -> usize {
    match version {
        Version::V1 => V1_AAD_OFFSET,
        Version::V2 => V2_AAD_OFFSET,
    }
}

/// Assert that every (key, value) pair in `expected` is present in `actual`.
/// Used to verify the encryption context survives the round trip intact,
/// while ignoring any keys the SDK may add (e.g. `aws-crypto-public-key`)
fn assert_ec_contains(actual: &EncryptionContext, expected: &EncryptionContext, version: Version) {
    for (k, v) in expected.iter() {
        assert_eq!(
            actual.get(k),
            Some(v),
            "{version:?}: decrypted EC missing or mismatched for key {k:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_aad_serialization_order() {
    for version in VERSIONS {
        let ec = small_encryption_context(SmallEncryptionContextVariation::AB);
        let pt = b"aad serialization order";
        let ct = encrypt_no_sign_with_ec(pt, ec.clone(), version).await;
        let off = aad_offset(version);

        //= spec/data-format/message-header.md#aad
        //= type=test
        //# The AAD MUST consist of, in order,
        //# Key Value Pairs Length,
        //# and Key Value Pairs.

        // 1. Key Value Pairs Length (2 bytes at the AAD offset)
        let kvp_len = u16::from_be_bytes([ct[off], ct[off + 1]]) as usize;
        assert!(
            kvp_len > 0,
            "{version:?}: non-empty EC must have non-zero KVP length"
        );

        // 2. Key Value Pairs (immediately follow the length field)
        let kvp_count_offset = off + 2;
        let kvp_count =
            u16::from_be_bytes([ct[kvp_count_offset], ct[kvp_count_offset + 1]]) as usize;
        assert_eq!(
            kvp_count, 2,
            "{version:?}: AB encryption context has 2 key-value pairs"
        );

        // Cross-check: the decrypt path recovers the same encryption context, which is
        // only possible if the on-wire ordering agreed with the spec on both sides.
        let dec = decrypt_with_version(&ct, version).await;
        assert_ec_contains(&dec.encryption_context, &ec, version);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_aad_key_value_pairs_length_field_size() {
    for version in VERSIONS {
        let ec = small_encryption_context(SmallEncryptionContextVariation::A);
        let pt = b"kvp length field size";
        let ct = encrypt_no_sign_with_ec(pt, ec.clone(), version).await;
        let off = aad_offset(version);

        //= spec/data-format/message-header.md#key-value-pairs-length
        //= type=test
        //# The length of the serialized key value pairs length field MUST be 2 bytes.

        // The KVP length field occupies exactly 2 bytes at [off..off+2].
        let kvp_len = u16::from_be_bytes([ct[off], ct[off + 1]]) as usize;
        // For "A" (keyA=valA) the Key Value Pairs field is:
        // count(2) + key_len(2) + key(4) + val_len(2) + val(4) = 14 bytes.
        // The length field covers the entire Key Value Pairs structure, including
        // the Key Value Pair Count.
        assert_eq!(
            kvp_len, 14,
            "{version:?}: KVP length for single pair keyA=valA must be 14"
        );

        // Cross-check: the decrypted EC matches what we encrypted, confirming the 2-byte
        // length field was parsed correctly on the decrypt side too.
        let dec = decrypt_with_version(&ct, version).await;
        assert_ec_contains(&dec.encryption_context, &ec, version);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_aad_key_value_pairs_length_uint16() {
    for version in VERSIONS {
        let ec = small_encryption_context(SmallEncryptionContextVariation::A);
        let pt = b"kvp length uint16";
        let ct = encrypt_no_sign_with_ec(pt, ec.clone(), version).await;
        let off = aad_offset(version);

        //= spec/data-format/message-header.md#key-value-pairs-length
        //= type=test
        //# The key value pairs length MUST be interpreted as a UInt16.

        // Read the 2 bytes as big-endian u16 and verify the value.
        let kvp_len = u16::from_be_bytes([ct[off], ct[off + 1]]);
        // keyA=valA: count(2) + key_len(2) + key(4) + val_len(2) + val(4) = 14.
        assert_eq!(
            kvp_len, 14,
            "{version:?}: UInt16 KVP length for keyA=valA must be 14"
        );

        // Cross-check: the decrypted EC round-trips, confirming both sides agree that
        // the field is a big-endian UInt16.
        let dec = decrypt_with_version(&ct, version).await;
        assert_ec_contains(&dec.encryption_context, &ec, version);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_aad_empty_encryption_context_length_zero() {
    for version in VERSIONS {
        let ec = small_encryption_context(SmallEncryptionContextVariation::Empty);
        let pt = b"empty ec length zero";
        let ct = encrypt_no_sign_with_ec(pt, ec.clone(), version).await;
        let off = aad_offset(version);

        //= spec/data-format/message-header.md#key-value-pairs-length
        //= type=test
        //# When the [encryption context](../framework/structures.md#encryption-context) is empty, the value of this field MUST be 0.

        // The 2 bytes at the AAD offset must be [0x00, 0x00].
        assert_eq!(
            ct[off], 0x00,
            "{version:?}: empty EC KVP length high byte must be 0"
        );
        assert_eq!(
            ct[off + 1],
            0x00,
            "{version:?}: empty EC KVP length low byte must be 0"
        );

        // Cross-check: decrypt returns an empty encryption context (non-signing suite
        // means the SDK added no entries of its own).
        let dec = decrypt_with_version(&ct, version).await;
        assert!(
            dec.encryption_context.is_empty(),
            "{version:?}: decrypted EC must be empty, got {:?}",
            dec.encryption_context
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_aad_key_value_pairs_serialization() {
    for version in VERSIONS {
        let ec = small_encryption_context(SmallEncryptionContextVariation::AB);
        let pt = b"kvp serialization";
        let ct = encrypt_no_sign_with_ec(pt, ec.clone(), version).await;
        let off = aad_offset(version);

        //= spec/data-format/message-header.md#key-value-pairs
        //= type=test
        //# The encryption context key-value pairs MUST be serialized according to its [specification for serialization](../framework/structures.md#serialization).

        // Parse the KVP section: after 2-byte length, 2-byte count, then pairs.
        let kvp_len = u16::from_be_bytes([ct[off], ct[off + 1]]) as usize;
        assert!(kvp_len > 0, "{version:?}: non-empty KVP length");
        let mut pos = off + 2;
        let count = u16::from_be_bytes([ct[pos], ct[pos + 1]]) as usize;
        assert_eq!(count, 2, "{version:?}: AB has 2 pairs");
        pos += 2;

        // Pairs must be sorted by key: keyA < keyB.
        let key1_len = u16::from_be_bytes([ct[pos], ct[pos + 1]]) as usize;
        pos += 2;
        let key1 = std::str::from_utf8(&ct[pos..pos + key1_len]).unwrap();
        pos += key1_len;
        let val1_len = u16::from_be_bytes([ct[pos], ct[pos + 1]]) as usize;
        pos += 2;
        let val1 = std::str::from_utf8(&ct[pos..pos + val1_len]).unwrap();
        pos += val1_len;

        let key2_len = u16::from_be_bytes([ct[pos], ct[pos + 1]]) as usize;
        pos += 2;
        let key2 = std::str::from_utf8(&ct[pos..pos + key2_len]).unwrap();
        pos += key2_len;
        let val2_len = u16::from_be_bytes([ct[pos], ct[pos + 1]]) as usize;
        pos += 2;
        let val2 = std::str::from_utf8(&ct[pos..pos + val2_len]).unwrap();

        assert_eq!(key1, "keyA", "{version:?}: first key in sorted order");
        assert_eq!(val1, "valA", "{version:?}: first value");
        assert_eq!(key2, "keyB", "{version:?}: second key in sorted order");
        assert_eq!(val2, "valB", "{version:?}: second value");

        // Cross-check: decrypted EC contains the same key/value pairs we encrypted.
        let dec = decrypt_with_version(&ct, version).await;
        assert_ec_contains(&dec.encryption_context, &ec, version);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_aad_empty_encryption_context_no_kvp_field() {
    for version in VERSIONS {
        let ec = small_encryption_context(SmallEncryptionContextVariation::Empty);
        let pt = b"empty ec no kvp";
        let ct = encrypt_no_sign_with_ec(pt, ec.clone(), version).await;
        let off = aad_offset(version);

        //= spec/data-format/message-header.md#key-value-pairs
        //= type=test
        //# When the [encryption context](../framework/structures.md#encryption-context) is empty,
        //# this field MUST NOT be included in the [AAD](#aad).

        // KVP Length is 0, and the next field (EDK count) starts immediately after.
        let kvp_len = u16::from_be_bytes([ct[off], ct[off + 1]]);
        assert_eq!(kvp_len, 0, "{version:?}: empty EC must have KVP length 0");
        // The bytes right after the 2-byte KVP Length field are the EDK count (not KVP data).
        let edk_count_offset = off + 2;
        let edk_count = u16::from_be_bytes([ct[edk_count_offset], ct[edk_count_offset + 1]]);
        assert!(
            edk_count >= 1,
            "{version:?}: EDK count must be at least 1, proving no KVP field between AAD length and EDKs"
        );

        // Cross-check: decrypt recovers an empty encryption context.
        let dec = decrypt_with_version(&ct, version).await;
        assert!(
            dec.encryption_context.is_empty(),
            "{version:?}: decrypted EC must be empty, got {:?}",
            dec.encryption_context
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_aad_non_ascii_keys_serialize_in_utf8_byte_order() {
    // U+FF5E (EF BD 9E) sorts before U+1F600 (F0 9F 98 80) by UTF-8 bytes.
    // By UTF-16 code units it sorts after: U+1F600 is the surrogate pair D83D DE00.
    let ec = EncryptionContext::from([("\u{1F600}", "\u{1F980}"), ("\u{FF5E}", "caf\u{E9}")]);
    let expected_aad: &[u8] = &[
        0x00, 0x1A, // key value pairs length = 26
        0x00, 0x02, // count = 2
        0x00, 0x03, 0xEF, 0xBD, 0x9E, // key U+FF5E
        0x00, 0x05, b'c', b'a', b'f', 0xC3, 0xA9, // value "caf" U+00E9
        0x00, 0x04, 0xF0, 0x9F, 0x98, 0x80, // key U+1F600
        0x00, 0x04, 0xF0, 0x9F, 0xA6, 0x80, // value U+1F980
    ];
    for version in VERSIONS {
        let ct = encrypt_no_sign_with_ec(b"utf-8 order", ec.clone(), version).await;
        let off = aad_offset(version);
        assert_eq!(
            &ct[off..off + expected_aad.len()],
            expected_aad,
            "{version:?}: header AAD must list keys in UTF-8 byte order"
        );

        let dec = decrypt_with_version(&ct, version).await;
        assert_eq!(dec.encryption_context, ec, "{version:?}: round trip");
    }
}

/// Encrypt `{"keyA": "valA", "keyB": "valB"}`,
/// overwrite the header's second key with `second_key`,
/// and return the decrypt error.
/// Every key is 4 bytes, so the edit changes no length field.
async fn decrypt_err_with_second_key(version: Version, second_key: &[u8; 4]) -> Error {
    let keyring = test_keyring().await;
    let ec = small_encryption_context(SmallEncryptionContextVariation::AB);
    let mut ct = encrypt_no_sign_ec_keyring(b"strict order", ec, version, &keyring).await;

    // Length(2) + count(2) + first entry(2 + 4 + 2 + 4) + second key length(2).
    let key2 = aad_offset(version) + 2 + 2 + 12 + 2;
    assert_eq!(&ct[key2..key2 + 4], b"keyB", "{version:?}: fixture layout");
    ct[key2..key2 + 4].copy_from_slice(second_key);

    let result = match version {
        Version::V1 => try_decrypt_v1_with_keyring(&ct, &keyring).await,
        Version::V2 => try_decrypt_with_keyring(&ct, &keyring).await,
    };
    result.expect_err("header with non-ascending keys must not decrypt")
}

#[tokio::test(flavor = "multi_thread")]
async fn test_decrypt_rejects_duplicate_encryption_context_key() {
    for version in VERSIONS {
        let err = decrypt_err_with_second_key(version, b"keyA").await;
        assert_eq!(err.kind(), ErrorKind::Serialization, "{version:?}: {err:?}");
        let source = std::error::Error::source(&err)
            .and_then(|e| e.downcast_ref::<aws_crypto_mpl::Error>())
            .expect("the MPL error is the source");
        assert_eq!(source.kind(), aws_crypto_mpl::ErrorKind::Validation);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_decrypt_rejects_out_of_order_encryption_context_keys() {
    for version in VERSIONS {
        let err = decrypt_err_with_second_key(version, b"key0").await;
        assert_eq!(err.kind(), ErrorKind::Serialization, "{version:?}: {err:?}");
        let source = std::error::Error::source(&err)
            .and_then(|e| e.downcast_ref::<aws_crypto_mpl::Error>())
            .expect("the MPL error is the source");
        assert_eq!(source.kind(), aws_crypto_mpl::ErrorKind::Validation);
    }
}

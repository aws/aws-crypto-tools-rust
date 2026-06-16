// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use aws_crypto_mpl::structures::EncryptionContext;

#[test]
fn test_empty_serializes_to_empty_bytes() {
    let ec = EncryptionContext::new();

    assert!(ec.serialize().unwrap().is_empty());
}

#[test]
fn test_single_entry_round_trip() {
    let mut ec = EncryptionContext::new();
    ec.insert(b"key1".to_vec(), b"value1".to_vec());

    let serialized = ec.serialize().unwrap();
    let deserialized = EncryptionContext::deserialize(&serialized).unwrap();
    assert_eq!(ec, deserialized);
}

#[test]
fn test_multiple_entries_serialized_in_sorted_order() {
    let mut ec = EncryptionContext::new();
    // Insert in reverse order
    ec.insert(b"zebra".to_vec(), b"z".to_vec());
    ec.insert(b"apple".to_vec(), b"a".to_vec());
    ec.insert(b"mango".to_vec(), b"m".to_vec());

    // Type-system enforcement (implication in source); test exists for regression coverage.
    let serialized = ec.serialize().unwrap();
    // Verify count is 3
    let count = u16::from_be_bytes([serialized[0], serialized[1]]);
    assert_eq!(count, 3);

    // Parse first key — should be "apple" (sorted first)
    let key_len = u16::from_be_bytes([serialized[2], serialized[3]]);
    assert_eq!(key_len, 5);
    assert_eq!(&serialized[4..9], b"apple");
}

#[test]
fn test_duplicate_key_rejected_on_deserialize() {
    // Manually construct a serialized context with duplicate keys
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&2u16.to_be_bytes()); // count = 2
    // First entry: key="a", value="1"
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes.push(b'a');
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes.push(b'1');
    // Second entry: key="a", value="2" (duplicate key)
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes.push(b'a');
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes.push(b'2');

    // Type-system enforcement (implication in source); test exists for regression coverage.
    let result = EncryptionContext::deserialize(&bytes);
    assert!(result.is_err());
    assert!(result.unwrap_err().message.contains("Duplicate key"));
}

#[test]
fn test_round_trip_preserves_all_entries() {
    let mut ec = EncryptionContext::new();
    ec.insert(b"key1".to_vec(), b"value1".to_vec());
    ec.insert(b"key2".to_vec(), b"value2".to_vec());
    ec.insert(b"key3".to_vec(), b"value3".to_vec());

    let serialized = ec.serialize().unwrap();
    let deserialized = EncryptionContext::deserialize(&serialized).unwrap();
    assert_eq!(ec, deserialized);
    assert_eq!(deserialized.len(), 3);
}

#[test]
fn test_key_value_pair_count_must_be_greater_than_zero() {
    // Construct bytes with count = 0
    let bytes = 0u16.to_be_bytes();

    let result = EncryptionContext::deserialize(&bytes);
    assert!(result.is_err());
    assert!(result.unwrap_err().message.contains("greater than 0"),);
}

#[test]
fn test_from_map_round_trip() {
    let mut map = std::collections::BTreeMap::new();
    map.insert(b"alpha".to_vec(), b"one".to_vec());
    map.insert(b"beta".to_vec(), b"two".to_vec());

    let ec = EncryptionContext::from_map(map);
    assert_eq!(ec.len(), 2);
    assert_eq!(ec.get(b"alpha").unwrap(), &b"one".to_vec());
}

#[test]
fn test_get_returns_none_for_absent_key() {
    let mut ec = EncryptionContext::new();
    ec.insert(b"present".to_vec(), b"val".to_vec());
    assert!(ec.get(b"missing").is_none());
}

#[test]
fn test_iter_yields_all_entries() {
    let mut ec = EncryptionContext::new();
    ec.insert(b"a".to_vec(), b"1".to_vec());
    ec.insert(b"b".to_vec(), b"2".to_vec());
    ec.insert(b"c".to_vec(), b"3".to_vec());

    let entries: Vec<_> = ec.iter().collect();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0], (&b"a".to_vec(), &b"1".to_vec()));
    assert_eq!(entries[1], (&b"b".to_vec(), &b"2".to_vec()));
    assert_eq!(entries[2], (&b"c".to_vec(), &b"3".to_vec()));
}

#[test]
fn test_as_map_returns_inner_btreemap() {
    let mut ec = EncryptionContext::new();
    ec.insert(b"k".to_vec(), b"v".to_vec());

    let map = ec.as_map();
    assert_eq!(map.len(), 1);
    assert_eq!(map.get(&b"k".to_vec()).unwrap(), &b"v".to_vec());
}

#[test]
fn test_is_empty_branches() {
    let ec = EncryptionContext::new();
    assert!(ec.is_empty());

    let mut ec2 = EncryptionContext::new();
    ec2.insert(b"x".to_vec(), b"y".to_vec());
    assert!(!ec2.is_empty());
}

#[test]
fn test_debug_format() {
    let mut ec = EncryptionContext::new();
    ec.insert(b"key".to_vec(), b"val".to_vec());
    let debug_str = format!("{:?}", ec);
    assert!(debug_str.contains("EncryptionContext"));
}

#[test]
fn test_deserialize_insufficient_bytes_for_count() {
    let result = EncryptionContext::deserialize(&[0xAB]);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .message
            .contains("Insufficient bytes for count")
    );
}

#[test]
fn test_deserialize_insufficient_bytes_for_key_length() {
    // count=1, but no body bytes for key length
    let bytes = 1u16.to_be_bytes();
    let result = EncryptionContext::deserialize(&bytes);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .message
            .contains("Insufficient bytes for key length")
    );
}

#[test]
fn test_deserialize_insufficient_bytes_for_key() {
    // count=1, key_len=10, but only 2 bytes of key data
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&1u16.to_be_bytes()); // count = 1
    bytes.extend_from_slice(&10u16.to_be_bytes()); // key_len = 10
    bytes.extend_from_slice(&[0x41, 0x42]); // only 2 bytes of key

    let result = EncryptionContext::deserialize(&bytes);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .message
            .contains("Insufficient bytes for key")
    );
}

#[test]
fn test_deserialize_insufficient_bytes_for_value_length() {
    // count=1, key_len=1, key="a", then no value length bytes
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&1u16.to_be_bytes()); // count = 1
    bytes.extend_from_slice(&1u16.to_be_bytes()); // key_len = 1
    bytes.push(b'a'); // key

    let result = EncryptionContext::deserialize(&bytes);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .message
            .contains("Insufficient bytes for value length")
    );
}

#[test]
fn test_deserialize_insufficient_bytes_for_value() {
    // count=1, key_len=1, key="a", val_len=5, but only 1 byte of value
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&1u16.to_be_bytes()); // count = 1
    bytes.extend_from_slice(&1u16.to_be_bytes()); // key_len = 1
    bytes.push(b'a'); // key
    bytes.extend_from_slice(&5u16.to_be_bytes()); // val_len = 5
    bytes.push(0x01); // only 1 byte of value

    let result = EncryptionContext::deserialize(&bytes);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .message
            .contains("Insufficient bytes for value")
    );
}

#[test]
fn test_serialize_rejects_oversize_key() {
    let mut ec = EncryptionContext::new();
    ec.insert(vec![0xAA; 70_000], b"val".to_vec());

    let result = ec.serialize();
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.message.contains("key length"));
    assert!(err.message.contains("u16::MAX"));
}

#[test]
fn test_serialize_rejects_oversize_value() {
    let mut ec = EncryptionContext::new();
    ec.insert(b"key".to_vec(), vec![0xBB; 70_000]);

    let result = ec.serialize();
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.message.contains("value length"));
    assert!(err.message.contains("u16::MAX"));
}

#[test]
fn test_deserialize_empty_bytes_returns_empty_context() {
    let ec = EncryptionContext::deserialize(&[]).unwrap();
    assert!(ec.is_empty());
}

#[test]
fn test_serialize_rejects_too_many_entries() {
    let mut ec = EncryptionContext::new();
    for i in 0..=u16::MAX as u32 {
        ec.insert(i.to_be_bytes().to_vec(), b"v".to_vec());
    }

    let result = ec.serialize();
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.message.contains("entry count"));
    assert!(err.message.contains("u16::MAX"));
}

#[test]
fn test_contains_key() {
    let mut ec = EncryptionContext::new();
    ec.insert(b"present".to_vec(), b"v".to_vec());
    assert!(ec.contains_key(b"present"));
    assert!(!ec.contains_key(b"absent"));
}

#[test]
fn test_default_produces_empty_context() {
    let ec = EncryptionContext::default();
    assert!(ec.is_empty());
    assert_eq!(ec.len(), 0);
    // Default should also serialize to empty bytes (matches new()).
    assert!(ec.serialize().unwrap().is_empty());
}

#[test]
fn test_insert_overwrites_existing_key() {
    let mut ec = EncryptionContext::new();
    ec.insert(b"k".to_vec(), b"v1".to_vec());
    ec.insert(b"k".to_vec(), b"v2".to_vec());
    assert_eq!(ec.get(b"k"), Some(&b"v2".to_vec()));
    assert_eq!(ec.len(), 1);
}

#[test]
fn test_equality_is_order_independent() {
    let mut ec_a = EncryptionContext::new();
    ec_a.insert(b"b".to_vec(), b"2".to_vec());
    ec_a.insert(b"a".to_vec(), b"1".to_vec());
    ec_a.insert(b"c".to_vec(), b"3".to_vec());

    let mut ec_b = EncryptionContext::new();
    ec_b.insert(b"a".to_vec(), b"1".to_vec());
    ec_b.insert(b"b".to_vec(), b"2".to_vec());
    ec_b.insert(b"c".to_vec(), b"3".to_vec());

    assert_eq!(ec_a, ec_b);

    // Both iterate in canonical sorted-by-byte order regardless of insert order.
    let entries_a: Vec<_> = ec_a.iter().collect();
    let entries_b: Vec<_> = ec_b.iter().collect();
    assert_eq!(entries_a, entries_b);
}

#[test]
fn test_serialize_produces_known_bytes() {
    // Pin the wire format with a hand-computed vector for {"a" -> "1"}.
    let mut ec = EncryptionContext::new();
    ec.insert(b"a".to_vec(), b"1".to_vec());

    let expected: &[u8] = &[
        0x00, 0x01, // count = 1
        0x00, 0x01, // key_len = 1
        b'a', // key
        0x00, 0x01, // val_len = 1
        b'1', // value
    ];
    assert_eq!(ec.serialize().unwrap().as_slice(), expected);
}

#[test]
fn test_deserialize_known_bytes_produces_expected_context() {
    // Same wire form as test_serialize_produces_known_bytes, decoded.
    let bytes: &[u8] = &[0x00, 0x01, 0x00, 0x01, b'a', 0x00, 0x01, b'1'];
    let ec = EncryptionContext::deserialize(bytes).unwrap();
    assert_eq!(ec.len(), 1);
    assert_eq!(ec.get(b"a"), Some(&b"1".to_vec()));
}

#[test]
fn test_serialize_accepts_max_u16_key_length() {
    // Existing tests prove >u16::MAX is rejected; lock the at-max success path.
    let mut ec = EncryptionContext::new();
    let max_key = vec![0xAA; u16::MAX as usize];
    ec.insert(max_key.clone(), b"v".to_vec());

    let serialized = ec.serialize().unwrap();
    let deserialized = EncryptionContext::deserialize(&serialized).unwrap();
    assert_eq!(deserialized.get(&max_key), Some(&b"v".to_vec()));
}

#[test]
fn test_serialize_accepts_max_u16_value_length() {
    let mut ec = EncryptionContext::new();
    let max_val = vec![0xBB; u16::MAX as usize];
    ec.insert(b"k".to_vec(), max_val.clone());

    let serialized = ec.serialize().unwrap();
    let deserialized = EncryptionContext::deserialize(&serialized).unwrap();
    assert_eq!(deserialized.get(b"k"), Some(&max_val));
}

#[test]
fn test_serialize_accepts_max_u16_entry_count() {
    let mut ec = EncryptionContext::new();
    // Insert exactly u16::MAX (65_535) distinct entries.
    for i in 0..u16::MAX as u32 {
        ec.insert(i.to_be_bytes().to_vec(), b"v".to_vec());
    }
    assert_eq!(ec.len(), u16::MAX as usize);

    let serialized = ec.serialize().unwrap();
    // Leading two bytes encode the count.
    assert_eq!(u16::from_be_bytes([serialized[0], serialized[1]]), u16::MAX);
}

#[test]
fn test_round_trip_preserves_multibyte_utf8() {
    // Representative codepoints across all four UTF-8 byte-length classes:
    //   1-byte ASCII  : 'a'  (U+0061)  -> [0x61]
    //   2-byte Latin  : 'é'  (U+00E9)  -> [0xC3, 0xA9]
    //   3-byte CJK    : '日' (U+65E5)  -> [0xE6, 0x97, 0xA5]
    //   4-byte emoji  : '🦀' (U+1F980) -> [0xF0, 0x9F, 0xA6, 0x80]
    let mut ec = EncryptionContext::new();
    ec.insert(b"a".to_vec(), "ascii".as_bytes().to_vec());
    ec.insert("é".as_bytes().to_vec(), "latín".as_bytes().to_vec());
    ec.insert("日".as_bytes().to_vec(), "中文".as_bytes().to_vec());
    ec.insert("🦀".as_bytes().to_vec(), "🎉🦀".as_bytes().to_vec());

    let serialized = ec.serialize().unwrap();
    let deserialized = EncryptionContext::deserialize(&serialized).unwrap();
    assert_eq!(ec, deserialized);

    // UTF-8 has the property that lexicographic byte order matches Unicode
    // codepoint order. The structures.md spec mandates "ascending order
    // according to the UTF-8 encoded binary value", and BTreeMap iterates by
    // binary byte order; this asserts both agree across byte-length boundaries.
    let keys: Vec<_> = deserialized.iter().map(|(k, _)| k.clone()).collect();
    assert_eq!(keys[0], b"a");
    assert_eq!(keys[1], "é".as_bytes());
    assert_eq!(keys[2], "日".as_bytes());
    assert_eq!(keys[3], "🦀".as_bytes());
}

#[test]
fn test_serialize_known_bytes_for_4byte_utf8() {
    // Lock the wire format for a 4-byte UTF-8 codepoint on both halves of an
    // entry. Complements test_serialize_produces_known_bytes (1-byte ASCII).
    let mut ec = EncryptionContext::new();
    ec.insert("🦀".as_bytes().to_vec(), "🦀".as_bytes().to_vec());

    let expected: &[u8] = &[
        0x00, 0x01, // count = 1
        0x00, 0x04, // key_len = 4
        0xF0, 0x9F, 0xA6, 0x80, // "🦀" UTF-8
        0x00, 0x04, // val_len = 4
        0xF0, 0x9F, 0xA6, 0x80, // "🦀" UTF-8
    ];
    assert_eq!(ec.serialize().unwrap().as_slice(), expected);
}

#[test]
fn test_deserialize_rejects_trailing_bytes() {
    // Build a valid wire form for {"a" -> "1"} and append one junk byte.
    let mut bytes: Vec<u8> = vec![0x00, 0x01, 0x00, 0x01, b'a', 0x00, 0x01, b'1'];
    bytes.push(0xFF); // trailing junk

    let result = EncryptionContext::deserialize(&bytes);
    assert!(result.is_err());
    assert!(result.unwrap_err().message.contains("Trailing bytes"));
}

#[test]
fn test_deserialize_rejects_trailing_bytes_after_multi_entry() {
    // Two-entry wire form followed by junk; ensures the check fires regardless
    // of where the entry loop terminates.
    let bytes: Vec<u8> = vec![
        0x00, 0x02, // count = 2
        0x00, 0x01, b'a', 0x00, 0x01, b'1', // a -> 1
        0x00, 0x01, b'b', 0x00, 0x01, b'2', // b -> 2
        0xDE, 0xAD, // trailing junk
    ];
    let result = EncryptionContext::deserialize(&bytes);
    assert!(result.is_err());
    assert!(result.unwrap_err().message.contains("Trailing bytes"));
}

// ============================================================================
// EncryptionContext spec gap: empty keys
// ============================================================================
//
// The structures.md framework specification describes encryption-context
// entries as non-empty UTF-8 byte strings — keys are conceptually identifiers
// and are therefore expected to have at least one byte. The current Rust
// implementation does NOT enforce this invariant at any of the four entry
// points to the type:
//
//   1. EncryptionContext::insert(...)   — accepts an empty Vec<u8> key
//   2. EncryptionContext::from_map(...) — accepts a BTreeMap with an empty key
//   3. EncryptionContext::deserialize() — accepts a wire form with key_len = 0
//   4. EncryptionContext::serialize()   — by symmetry with (1)/(2), will emit
//                                         key_len = 0 for any empty-keyed entry
//
// The three tests below pin the *current* (permissive) behavior so that any
// future tightening of the contract — i.e., adding empty-key rejection at
// these entry points — produces a deliberate, reviewable test failure rather
// than silently changing observable behavior.
//
// These are NOT spec-conformance tests. When/if the contract is tightened,
// these tests should be flipped: each `assert! / assert_eq!` should become an
// assertion that the entry point returns an `Err(MaterialsError { kind:
// Validation, .. })`, and the source updated to match. Doing so will also
// require changing `from_map`'s return type from `Self` to
// `Result<Self, MaterialsError>` (a breaking API change).
//
// Why we are not enforcing now:
//   - Rejection is a behavioral change at four entry points and changes one
//     public signature (from_map -> Result<_, _>).
//   - The validation belongs in the same review as a broader
//     EncryptionContext invariant pass (e.g., key/value max-length in the
//     spec, value emptiness rules) rather than as a one-off here.
//   - PR #11 is scoped to the structures-slice review; expanding scope risks
//     the slice's stack-level snapshot diverging from neighboring slices.
//
// Tracked: revisit as part of a future EncryptionContext-invariants pass.
// ============================================================================

#[test]
fn test_insert_accepts_empty_key_currently_unenforced() {
    // CURRENT BEHAVIOR (not spec-conformant): insert accepts an empty key.
    // If/when empty keys are rejected, flip to assert that some sentinel
    // error path is taken (e.g., insert is changed to return Result and
    // returns Err on empty input).
    let mut ec = EncryptionContext::new();
    ec.insert(Vec::new(), b"value".to_vec());
    assert_eq!(ec.len(), 1);
    assert_eq!(ec.get(&[]), Some(&b"value".to_vec()));
}

#[test]
fn test_from_map_accepts_empty_key_currently_unenforced() {
    // CURRENT BEHAVIOR (not spec-conformant): from_map silently accepts a
    // BTreeMap whose keys include an empty Vec<u8>.
    // If/when empty keys are rejected, from_map's signature must change to
    // Result<Self, MaterialsError>; this test would become an Err assertion.
    let mut map = std::collections::BTreeMap::new();
    map.insert(Vec::new(), b"value".to_vec());
    let ec = EncryptionContext::from_map(map);
    assert_eq!(ec.len(), 1);
    assert!(ec.contains_key(&[]));
}

#[test]
fn test_deserialize_accepts_empty_key_length_currently_unenforced() {
    // CURRENT BEHAVIOR (not spec-conformant): deserialize accepts a wire
    // form with key_len = 0. If/when empty keys are rejected, this test
    // should be flipped to assert deserialize returns Err with a message
    // identifying the empty-key violation.
    let bytes: &[u8] = &[
        0x00, 0x01, // count = 1
        0x00, 0x00, // key_len = 0 (EMPTY KEY — current impl accepts this)
        0x00, 0x01, // val_len = 1
        b'1', // value
    ];
    let ec = EncryptionContext::deserialize(bytes).unwrap();
    assert_eq!(ec.len(), 1);
    assert_eq!(ec.get(&[]), Some(&b"1".to_vec()));
}

// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, HashMap};

use aws_crypto_mpl::structures::{EncryptionContext, MaterialsErrorKind};

#[test]
fn test_empty_serializes_to_empty_bytes() {
    let ec = EncryptionContext::new();

    assert!(ec.serialize().unwrap().is_empty());
}

#[test]
fn test_single_entry_round_trip() {
    let mut ec = EncryptionContext::new();
    ec.insert("key1", "value1");

    let serialized = ec.serialize().unwrap();
    let deserialized = EncryptionContext::deserialize(&serialized).unwrap();
    assert_eq!(ec, deserialized);
}

#[test]
fn test_multiple_entries_serialized_in_sorted_order() {
    let mut ec = EncryptionContext::new();
    // Insert in reverse order
    ec.insert("zebra", "z");
    ec.insert("apple", "a");
    ec.insert("mango", "m");

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
fn test_out_of_order_keys_rejected_on_deserialize() {
    let bytes: &[u8] = &[
        0x00, 0x02, // count = 2
        0x00, 0x01, b'b', 0x00, 0x01, b'2', // b -> 2
        0x00, 0x01, b'a', 0x00, 0x01, b'1', // a -> 1
    ];
    let err = EncryptionContext::deserialize(bytes).unwrap_err();
    assert_eq!(err.kind, MaterialsErrorKind::Validation);
    assert!(err.message.contains("not in ascending order"));
}

#[test]
fn test_round_trip_preserves_all_entries() {
    let mut ec = EncryptionContext::new();
    ec.insert("key1", "value1");
    ec.insert("key2", "value2");
    ec.insert("key3", "value3");

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
fn test_from_btreemap_round_trip() {
    let mut map = BTreeMap::new();
    map.insert("alpha".to_string(), "one".to_string());
    map.insert("beta".to_string(), "two".to_string());

    let ec = EncryptionContext::from(map.clone());
    assert_eq!(ec.len(), 2);
    assert_eq!(ec.get("alpha"), Some("one"));
    assert_eq!(ec.as_map(), &map);
}

#[test]
fn test_get_returns_none_for_absent_key() {
    let mut ec = EncryptionContext::new();
    ec.insert("present", "val");
    assert!(ec.get("missing").is_none());
}

#[test]
fn test_iter_yields_all_entries() {
    let mut ec = EncryptionContext::new();
    ec.insert("a", "1");
    ec.insert("b", "2");
    ec.insert("c", "3");

    let entries: Vec<_> = ec.iter().collect();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries, vec![("a", "1"), ("b", "2"), ("c", "3")]);
}

#[test]
fn test_as_map_returns_inner_btreemap() {
    let mut ec = EncryptionContext::new();
    ec.insert("k", "v");

    let map = ec.as_map();
    assert_eq!(map.len(), 1);
    assert_eq!(map.get("k").map(String::as_str), Some("v"));
}

#[test]
fn test_is_empty_branches() {
    let ec = EncryptionContext::new();
    assert!(ec.is_empty());

    let mut ec2 = EncryptionContext::new();
    ec2.insert("x", "y");
    assert!(!ec2.is_empty());
}

#[test]
fn test_debug_format() {
    let mut ec = EncryptionContext::new();
    ec.insert("key", "val");
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
    ec.insert("a".repeat(70_000), "val");

    let result = ec.serialize();
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.message.contains("key length"));
    assert!(err.message.contains("u16::MAX"));
}

#[test]
fn test_serialize_rejects_oversize_value() {
    let mut ec = EncryptionContext::new();
    ec.insert("key", "b".repeat(70_000));

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
        ec.insert(i.to_string(), "v");
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
    ec.insert("present", "v");
    assert!(ec.contains_key("present"));
    assert!(!ec.contains_key("absent"));
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
    ec.insert("k", "v1");
    ec.insert("k", "v2");
    assert_eq!(ec.get("k"), Some("v2"));
    assert_eq!(ec.len(), 1);
}

#[test]
fn test_equality_is_order_independent() {
    let mut ec_a = EncryptionContext::new();
    ec_a.insert("b", "2");
    ec_a.insert("a", "1");
    ec_a.insert("c", "3");

    let mut ec_b = EncryptionContext::new();
    ec_b.insert("a", "1");
    ec_b.insert("b", "2");
    ec_b.insert("c", "3");

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
    ec.insert("a", "1");

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
    assert_eq!(ec.get("a"), Some("1"));
}

#[test]
fn test_serialize_accepts_max_u16_key_length() {
    // Existing tests prove >u16::MAX is rejected; lock the at-max success path.
    let mut ec = EncryptionContext::new();
    let max_key = "a".repeat(u16::MAX as usize);
    ec.insert(max_key.clone(), "v");

    let serialized = ec.serialize().unwrap();
    let deserialized = EncryptionContext::deserialize(&serialized).unwrap();
    assert_eq!(deserialized.get(&max_key), Some("v"));
}

#[test]
fn test_serialize_accepts_max_u16_value_length() {
    let mut ec = EncryptionContext::new();
    let max_val = "b".repeat(u16::MAX as usize);
    ec.insert("k", max_val.clone());

    let serialized = ec.serialize().unwrap();
    let deserialized = EncryptionContext::deserialize(&serialized).unwrap();
    assert_eq!(deserialized.get("k"), Some(max_val.as_str()));
}

#[test]
fn test_serialize_accepts_max_u16_entry_count() {
    let mut ec = EncryptionContext::new();
    // Insert exactly u16::MAX (65_535) distinct entries.
    for i in 0..u16::MAX as u32 {
        ec.insert(i.to_string(), "v");
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
    ec.insert("a", "ascii");
    ec.insert("é", "latín");
    ec.insert("日", "中文");
    ec.insert("🦀", "🎉🦀");

    let serialized = ec.serialize().unwrap();
    let deserialized = EncryptionContext::deserialize(&serialized).unwrap();
    assert_eq!(ec, deserialized);

    // UTF-8 has the property that lexicographic byte order matches Unicode
    // codepoint order. The structures.md spec mandates "ascending order
    // according to the UTF-8 encoded binary value", and BTreeMap iterates by
    // binary byte order; this asserts both agree across byte-length boundaries.
    let keys: Vec<_> = deserialized.keys().collect();
    assert_eq!(keys, vec!["a", "é", "日", "🦀"]);
}

#[test]
fn test_serialize_known_bytes_for_4byte_utf8() {
    // Lock the wire format for a 4-byte UTF-8 codepoint on both halves of an
    // entry. Complements test_serialize_produces_known_bytes (1-byte ASCII).
    let mut ec = EncryptionContext::new();
    ec.insert("🦀", "🦀");

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
// EncryptionContext: current behavior on empty keys
// ============================================================================
//
// EncryptionContext accepts an empty key at every entry point:
// insert, From<BTreeMap>, deserialize (key_len = 0), and serialize.
// structures.md does not require non-empty keys.
// These tests pin the permissive behavior so tightening it fails a test instead of changing silently.
// ============================================================================

#[test]
fn test_insert_accepts_empty_key_currently_unenforced() {
    // CURRENT BEHAVIOR (permissive): insert accepts an empty key.
    // If/when empty keys are rejected, flip to assert that some sentinel
    // error path is taken (e.g., insert is changed to return Result and
    // returns Err on empty input).
    let mut ec = EncryptionContext::new();
    ec.insert("", "value");
    assert_eq!(ec.len(), 1);
    assert_eq!(ec.get(""), Some("value"));
}

#[test]
fn test_from_btreemap_accepts_empty_key_currently_unenforced() {
    // CURRENT BEHAVIOR (permissive): From<BTreeMap> accepts an empty key.
    // If empty keys are ever rejected, this conversion becomes TryFrom and this test asserts Err.
    let mut map = BTreeMap::new();
    map.insert(String::new(), "value".to_string());
    let ec = EncryptionContext::from(map);
    assert_eq!(ec.len(), 1);
    assert!(ec.contains_key(""));
}

#[test]
fn test_deserialize_accepts_empty_key_length_currently_unenforced() {
    // CURRENT BEHAVIOR (permissive): deserialize accepts a wire form with
    // key_len = 0. If/when empty keys are rejected, this test should be
    // flipped to assert deserialize returns Err with a message identifying
    // the empty-key violation.
    let bytes: &[u8] = &[
        0x00, 0x01, // count = 1
        0x00, 0x00, // key_len = 0 (EMPTY KEY — current impl accepts this)
        0x00, 0x01, // val_len = 1
        b'1', // value
    ];
    let ec = EncryptionContext::deserialize(bytes).unwrap();
    assert_eq!(ec.len(), 1);
    assert_eq!(ec.get(""), Some("1"));
}

#[test]
fn test_serialize_orders_by_utf8_bytes_not_utf16_code_units() {
    // U+FF5E (EF BD 9E) sorts before U+1F600 (F0 9F 98 80) by UTF-8 bytes.
    // By UTF-16 code units it sorts after: U+1F600 is the surrogate pair D83D DE00.
    let ec = EncryptionContext::from([("\u{1F600}", "b"), ("\u{FF5E}", "a")]);

    let expected: &[u8] = &[
        0x00, 0x02, // count = 2
        0x00, 0x03, 0xEF, 0xBD, 0x9E, // key U+FF5E
        0x00, 0x01, b'a', // value
        0x00, 0x04, 0xF0, 0x9F, 0x98, 0x80, // key U+1F600
        0x00, 0x01, b'b', // value
    ];
    assert_eq!(ec.serialize().unwrap().as_slice(), expected);
    assert_eq!(EncryptionContext::deserialize(expected).unwrap(), ec);
}

#[test]
fn test_deserialize_rejects_invalid_utf8_key() {
    let bytes: &[u8] = &[0x00, 0x01, 0x00, 0x01, 0xFF, 0x00, 0x01, b'1'];
    let err = EncryptionContext::deserialize(bytes).unwrap_err();
    assert_eq!(err.kind, MaterialsErrorKind::Validation);
    assert!(err.message.contains("key is not valid UTF-8"));
}

#[test]
fn test_deserialize_rejects_invalid_utf8_value() {
    let bytes: &[u8] = &[0x00, 0x01, 0x00, 0x01, b'a', 0x00, 0x01, 0xFF];
    let err = EncryptionContext::deserialize(bytes).unwrap_err();
    assert_eq!(err.kind, MaterialsErrorKind::Validation);
    assert!(err.message.contains("value is not valid UTF-8"));
}

#[test]
fn test_try_from_byte_map_rejects_invalid_utf8() {
    let valid = BTreeMap::from([(b"k".to_vec(), "\u{1F600}".as_bytes().to_vec())]);
    assert_eq!(
        EncryptionContext::try_from(valid).unwrap(),
        EncryptionContext::from([("k", "\u{1F600}")])
    );

    let bad_key = BTreeMap::from([(vec![0xC3], b"v".to_vec())]);
    let err = EncryptionContext::try_from(bad_key).unwrap_err();
    assert!(err.message.contains("key is not valid UTF-8"));

    let bad_value = BTreeMap::from([(b"k".to_vec(), vec![0xC3])]);
    let err = EncryptionContext::try_from(bad_value).unwrap_err();
    assert!(err.message.contains("value is not valid UTF-8"));
}

#[test]
fn test_try_insert_utf8_rejects_invalid_utf8_and_leaves_context_unchanged() {
    let mut ec = EncryptionContext::new();
    assert_eq!(ec.try_insert_utf8(b"k", b"v").unwrap(), None);

    let err = ec.try_insert_utf8(&[0xFF], b"v").unwrap_err();
    assert!(err.message.contains("key is not valid UTF-8"));
    let err = ec.try_insert_utf8(b"k", &[0xFF]).unwrap_err();
    assert!(err.message.contains("value is not valid UTF-8"));

    assert_eq!(ec, EncryptionContext::from([("k", "v")]));
}

#[test]
fn test_string_conversions_agree() {
    let expected = EncryptionContext::from([("a", "1"), ("b", "2")]);

    let hash: HashMap<String, String> =
        HashMap::from([("b".into(), "2".into()), ("a".into(), "1".into())]);
    assert_eq!(EncryptionContext::from(hash), expected);
    assert_eq!(
        [("b", "2"), ("a", "1")]
            .into_iter()
            .collect::<EncryptionContext>(),
        expected
    );

    let mut extended = EncryptionContext::from([("a", "1")]);
    extended.extend([("b".to_string(), "2".to_string())]);
    assert_eq!(extended, expected);

    let owned: Vec<(String, String)> = expected.clone().into_iter().collect();
    assert_eq!(
        owned,
        vec![("a".into(), "1".into()), ("b".into(), "2".into())]
    );
    assert_eq!((&expected).into_iter().count(), 2);
}

#[test]
fn test_remove_returns_value() {
    let mut ec = EncryptionContext::from([("k", "v")]);
    assert_eq!(ec.remove("k"), Some("v".to_string()));
    assert_eq!(ec.remove("k"), None);
    assert!(ec.is_empty());
}

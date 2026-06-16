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

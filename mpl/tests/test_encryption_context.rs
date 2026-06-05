// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use aws_crypto_mpl::structures::EncryptionContext;

#[test]
fn test_empty_serializes_to_empty_bytes() {
    let ec = EncryptionContext::new();

    //= ../spec/framework/structures.md#serialization
    //= type=test
    //# If the encryption context is empty, its serialization MUST be
    //# an empty byte sequence.
    assert!(ec.serialize().unwrap().is_empty());
}

#[test]
fn test_single_entry_round_trip() {
    let mut ec = EncryptionContext::new();
    ec.insert(b"key1".to_vec(), b"value1".to_vec());

    //= ../spec/framework/structures.md#serialization
    //= type=test
    //# If the encryption context is not empty, its serialization MUST
    //# take the following form:
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

    //= ../spec/framework/structures.md#key-value-pair-count
    //= type=test
    //# The value of this field MUST be greater than 0.
    let result = EncryptionContext::deserialize(&bytes);
    assert!(result.is_err());
    assert!(result.unwrap_err().message.contains("greater than 0"),);
}

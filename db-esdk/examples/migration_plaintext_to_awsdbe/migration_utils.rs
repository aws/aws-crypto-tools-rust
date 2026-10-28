// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared values and helpers for the plaintext-to-AWS-DBE migration steps.

use std::collections::HashMap;

use aws_db_esdk::aws_sdk_dynamodb::types::AttributeValue;

// One value per crypto action, written by every step.
pub const ENCRYPTED_AND_SIGNED_VALUE: &str = "this will be encrypted and signed";
pub const SIGN_ONLY_VALUE: &str = "this will never be encrypted, but it will be signed";
pub const DO_NOTHING_VALUE: &str = "this will never be encrypted nor signed";

/// The item every step writes: the primary key plus one attribute per action.
pub fn sample_item(
    partition_key_value: &str,
    sort_key_value: &str,
) -> HashMap<String, AttributeValue> {
    HashMap::from([
        (
            "partition_key".to_string(),
            AttributeValue::S(partition_key_value.to_string()),
        ),
        (
            "sort_key".to_string(),
            AttributeValue::N(sort_key_value.to_string()),
        ),
        (
            "attribute1".to_string(),
            AttributeValue::S(ENCRYPTED_AND_SIGNED_VALUE.to_string()),
        ),
        (
            "attribute2".to_string(),
            AttributeValue::S(SIGN_ONLY_VALUE.to_string()),
        ),
        (
            "attribute3".to_string(),
            AttributeValue::S(DO_NOTHING_VALUE.to_string()),
        ),
    ])
}

/// The primary key used to read a single item back.
pub fn primary_key(
    partition_key_value: &str,
    sort_key_value: &str,
) -> HashMap<String, AttributeValue> {
    HashMap::from([
        (
            "partition_key".to_string(),
            AttributeValue::S(partition_key_value.to_string()),
        ),
        (
            "sort_key".to_string(),
            AttributeValue::N(sort_key_value.to_string()),
        ),
    ])
}

/// Check that a returned item matches what the steps write.
///
/// Fails if any attribute is missing or has the wrong value. In particular,
/// reading a client-side-encrypted item with a plaintext reader leaves
/// `attribute1` absent, which surfaces here as
/// "attribute1 not found or not a string".
pub fn verify_returned_item(
    item: &HashMap<String, AttributeValue>,
    partition_key_value: &str,
    sort_key_value: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(AttributeValue::S(pk)) = item.get("partition_key") {
        if pk != partition_key_value {
            return Err(format!(
                "partition_key mismatch: expected {partition_key_value}, got {pk}"
            )
            .into());
        }
    } else {
        return Err("partition_key not found or not a string".into());
    }

    if let Some(AttributeValue::N(sk)) = item.get("sort_key") {
        if sk != sort_key_value {
            return Err(format!("sort_key mismatch: expected {sort_key_value}, got {sk}").into());
        }
    } else {
        return Err("sort_key not found or not a number".into());
    }

    if let Some(AttributeValue::S(attr1)) = item.get("attribute1") {
        if attr1 != ENCRYPTED_AND_SIGNED_VALUE {
            return Err(format!(
                "attribute1 mismatch: expected {ENCRYPTED_AND_SIGNED_VALUE}, got {attr1}"
            )
            .into());
        }
    } else {
        return Err("attribute1 not found or not a string".into());
    }

    if let Some(AttributeValue::S(attr2)) = item.get("attribute2") {
        if attr2 != SIGN_ONLY_VALUE {
            return Err(
                format!("attribute2 mismatch: expected {SIGN_ONLY_VALUE}, got {attr2}").into(),
            );
        }
    } else {
        return Err("attribute2 not found or not a string".into());
    }

    if let Some(AttributeValue::S(attr3)) = item.get("attribute3") {
        if attr3 != DO_NOTHING_VALUE {
            return Err(
                format!("attribute3 mismatch: expected {DO_NOTHING_VALUE}, got {attr3}").into(),
            );
        }
    } else {
        return Err("attribute3 not found or not a string".into());
    }

    Ok(())
}

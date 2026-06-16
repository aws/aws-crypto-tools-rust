// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Encryption context key-value mapping.

use std::collections::BTreeMap;

use super::error::MaterialsError;

/// A key-value mapping of arbitrary, non-secret, UTF-8 encoded strings used as AAD.
///
#[derive(Clone, Default, PartialEq, Eq)]
pub struct EncryptionContext(BTreeMap<Vec<u8>, Vec<u8>>);

impl std::fmt::Debug for EncryptionContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("EncryptionContext").field(&self.0).finish()
    }
}

impl EncryptionContext {
    /// Create a new empty encryption context.
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Create from an existing BTreeMap.
    pub fn from_map(map: BTreeMap<Vec<u8>, Vec<u8>>) -> Self {
        Self(map)
    }

    /// Insert a key-value pair.
    pub fn insert(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.0.insert(key, value);
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Get a value by key.
    pub fn get(&self, key: &[u8]) -> Option<&Vec<u8>> {
        self.0.get(key)
    }

    /// Check if a key exists.
    pub fn contains_key(&self, key: &[u8]) -> bool {
        self.0.contains_key(key)
    }

    /// Iterate over entries.
    pub fn iter(&self) -> impl Iterator<Item = (&Vec<u8>, &Vec<u8>)> {
        self.0.iter()
    }

    /// Returns the underlying map reference.
    pub fn as_map(&self) -> &BTreeMap<Vec<u8>, Vec<u8>> {
        &self.0
    }

    /// Serialize the encryption context to bytes.
    ///
    pub fn serialize(&self) -> Result<Vec<u8>, MaterialsError> {
        if self.0.is_empty() {
            return Ok(Vec::new());
        }

        let mut result = Vec::new();
        // NOTE: Entry count, key lengths, and value lengths are bounded by u16::MAX.
        // In practice these limits are unreachable for encryption contexts, but we
        // return errors rather than silently producing invalid output.
        let Ok(count) = u16::try_from(self.0.len()) else {
            return Err(MaterialsError::new(format!(
                "Encryption context entry count {} exceeds u16::MAX",
                self.0.len()
            )));
        };
        result.extend_from_slice(&count.to_be_bytes());

        for (key, value) in &self.0 {
            let Ok(key_len) = u16::try_from(key.len()) else {
                return Err(MaterialsError::new(format!(
                    "Encryption context key length {} exceeds u16::MAX",
                    key.len()
                )));
            };
            result.extend_from_slice(&key_len.to_be_bytes());
            result.extend_from_slice(key);

            let Ok(val_len) = u16::try_from(value.len()) else {
                return Err(MaterialsError::new(format!(
                    "Encryption context value length {} exceeds u16::MAX",
                    value.len()
                )));
            };
            result.extend_from_slice(&val_len.to_be_bytes());
            result.extend_from_slice(value);
        }
        Ok(result)
    }

    /// Deserialize an encryption context from bytes.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, MaterialsError> {
        if bytes.is_empty() {
            return Ok(Self::new());
        }

        if bytes.len() < 2 {
            return Err(MaterialsError::new("Insufficient bytes for count"));
        }

        let count = u16::from_be_bytes([bytes[0], bytes[1]]);
        if count == 0 {
            return Err(MaterialsError::new(
                "Key-value pair count must be greater than 0",
            ));
        }

        let mut map = BTreeMap::new();
        let mut offset = 2;

        for _ in 0..count {
            if offset + 2 > bytes.len() {
                return Err(MaterialsError::new("Insufficient bytes for key length"));
            }
            let key_len = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
            offset += 2;

            let key_end = offset + usize::from(key_len);
            if key_end > bytes.len() {
                return Err(MaterialsError::new("Insufficient bytes for key"));
            }
            let key = bytes[offset..key_end].to_vec();
            offset = key_end;

            if offset + 2 > bytes.len() {
                return Err(MaterialsError::new("Insufficient bytes for value length"));
            }
            let val_len = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
            offset += 2;

            let val_end = offset + usize::from(val_len);
            if val_end > bytes.len() {
                return Err(MaterialsError::new("Insufficient bytes for value"));
            }
            let value = bytes[offset..val_end].to_vec();
            offset = val_end;

            if map.insert(key.clone(), value).is_some() {
                return Err(MaterialsError::new(format!(
                    "Duplicate key in encryption context: {:?}",
                    key
                )));
            }
        }

        Ok(Self(map))
    }
}

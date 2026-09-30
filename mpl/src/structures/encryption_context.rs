// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Encryption context key-value mapping.

use crate::{Error, ErrorKind};
use std::collections::{BTreeMap, HashMap};

/// A key-value mapping of arbitrary, non-secret, UTF-8 encoded strings used as AAD.
///
/// Iteration and [`serialize`](Self::serialize) visit keys in ascending UTF-8 byte order,
/// the order the message format requires.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct EncryptionContext(BTreeMap<String, String>);

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

    /// Insert a key-value pair, returning the previous value for `key`, if any.
    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<String>) -> Option<String> {
        self.0.insert(key.into(), value.into())
    }

    /// Insert a key-value pair given as raw bytes.
    ///
    /// # Errors
    /// Returns a `Validation` error if `key` or `value` is not valid UTF-8.
    /// The context is left unchanged.
    pub fn try_insert_utf8(&mut self, key: &[u8], value: &[u8]) -> Result<Option<String>, Error> {
        let key = utf8(key, "key")?;
        let value = utf8(value, "value")?;
        Ok(self.insert(key, value))
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
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }

    /// Check if a key exists.
    pub fn contains_key(&self, key: &str) -> bool {
        self.0.contains_key(key)
    }

    /// Remove a key, returning its value, if present.
    pub fn remove(&mut self, key: &str) -> Option<String> {
        self.0.remove(key)
    }

    /// Iterate over entries in ascending key order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Iterate over keys in ascending order.
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.0.keys().map(String::as_str)
    }

    /// Returns the underlying map reference.
    pub fn as_map(&self) -> &BTreeMap<String, String> {
        &self.0
    }

    /// Serialize the encryption context to bytes.
    ///
    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        if self.0.is_empty() {
            return Ok(Vec::new());
        }

        let mut result = Vec::new();
        // NOTE: Entry count, key lengths, and value lengths are bounded by u16::MAX.
        // In practice these limits are unreachable for encryption contexts, but we
        // return errors rather than silently producing invalid output.
        let Ok(count) = u16::try_from(self.0.len()) else {
            return Err(Error::new(
                ErrorKind::Validation,
                format!(
                    "encryption context entry count {} exceeds u16::MAX",
                    self.0.len()
                ),
            ));
        };
        result.extend_from_slice(&count.to_be_bytes());

        for (key, value) in &self.0 {
            let Ok(key_len) = u16::try_from(key.len()) else {
                return Err(Error::new(
                    ErrorKind::Validation,
                    format!(
                        "encryption context key length {} exceeds u16::MAX",
                        key.len()
                    ),
                ));
            };
            result.extend_from_slice(&key_len.to_be_bytes());
            result.extend_from_slice(key.as_bytes());

            let Ok(val_len) = u16::try_from(value.len()) else {
                return Err(Error::new(
                    ErrorKind::Validation,
                    format!(
                        "encryption context value length {} exceeds u16::MAX",
                        value.len()
                    ),
                ));
            };
            result.extend_from_slice(&val_len.to_be_bytes());
            result.extend_from_slice(value.as_bytes());
        }
        Ok(result)
    }

    /// Deserialize an encryption context from bytes.
    ///
    /// # Errors
    /// Returns a `Validation` error if the bytes are malformed,
    /// list keys out of ascending order or repeat one,
    /// or hold a key or value that is not valid UTF-8.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() {
            return Ok(Self::new());
        }

        if bytes.len() < 2 {
            return Err(Error::new(
                ErrorKind::Validation,
                "insufficient bytes for count",
            ));
        }

        let count = u16::from_be_bytes([bytes[0], bytes[1]]);
        if count == 0 {
            return Err(Error::new(
                ErrorKind::Validation,
                "key-value pair count must be greater than 0",
            ));
        }

        let mut map = BTreeMap::new();
        let mut offset = 2;

        for _ in 0..count {
            if offset + 2 > bytes.len() {
                return Err(Error::new(
                    ErrorKind::Validation,
                    "insufficient bytes for key length",
                ));
            }
            let key_len = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
            offset += 2;

            let key_end = offset + usize::from(key_len);
            if key_end > bytes.len() {
                return Err(Error::new(
                    ErrorKind::Validation,
                    "insufficient bytes for key",
                ));
            }
            let key = utf8(&bytes[offset..key_end], "key")?;
            offset = key_end;

            if offset + 2 > bytes.len() {
                return Err(Error::new(
                    ErrorKind::Validation,
                    "insufficient bytes for value length",
                ));
            }
            let val_len = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
            offset += 2;

            let val_end = offset + usize::from(val_len);
            if val_end > bytes.len() {
                return Err(Error::new(
                    ErrorKind::Validation,
                    "insufficient bytes for value",
                ));
            }
            let value = utf8(&bytes[offset..val_end], "value")?;
            offset = val_end;

            if let Some((previous, _)) = map.last_key_value() {
                if key == *previous {
                    return Err(Error::new(
                        ErrorKind::Validation,
                        format!("duplicate key in encryption context: {key:?}"),
                    ));
                }
                if key < *previous {
                    return Err(Error::new(
                        ErrorKind::Validation,
                        "encryption context keys are not in ascending order",
                    ));
                }
            }
            map.insert(key, value);
        }

        if offset != bytes.len() {
            return Err(Error::new(
                ErrorKind::Validation,
                format!(
                    "trailing bytes after deserialization: {} byte(s) left over",
                    bytes.len() - offset
                ),
            ));
        }

        Ok(Self(map))
    }
}

/// Decode an encryption context `field` ("key" or "value") as UTF-8.
fn utf8(bytes: &[u8], field: &str) -> Result<String, Error> {
    match std::str::from_utf8(bytes) {
        Ok(s) => Ok(s.to_owned()),
        Err(e) => Err(Error::with_cause(
            ErrorKind::Validation,
            format!("encryption context {field} is not valid UTF-8"),
            e,
        )),
    }
}

impl TryFrom<BTreeMap<Vec<u8>, Vec<u8>>> for EncryptionContext {
    type Error = Error;

    /// # Errors
    /// Returns a `Validation` error if any key or value is not valid UTF-8.
    fn try_from(map: BTreeMap<Vec<u8>, Vec<u8>>) -> Result<Self, Self::Error> {
        let mut ec = Self::new();
        for (key, value) in &map {
            ec.try_insert_utf8(key, value)?;
        }
        Ok(ec)
    }
}

impl From<BTreeMap<String, String>> for EncryptionContext {
    fn from(map: BTreeMap<String, String>) -> Self {
        Self(map)
    }
}

impl From<HashMap<String, String>> for EncryptionContext {
    fn from(map: HashMap<String, String>) -> Self {
        Self(map.into_iter().collect())
    }
}

impl<K: Into<String>, V: Into<String>, const N: usize> From<[(K, V); N]> for EncryptionContext {
    fn from(pairs: [(K, V); N]) -> Self {
        pairs.into_iter().collect()
    }
}

impl<K: Into<String>, V: Into<String>> FromIterator<(K, V)> for EncryptionContext {
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        let mut ec = Self::new();
        ec.extend(iter);
        ec
    }
}

impl<K: Into<String>, V: Into<String>> Extend<(K, V)> for EncryptionContext {
    fn extend<I: IntoIterator<Item = (K, V)>>(&mut self, iter: I) {
        for (key, value) in iter {
            self.insert(key, value);
        }
    }
}

impl IntoIterator for EncryptionContext {
    type Item = (String, String);
    type IntoIter = std::collections::btree_map::IntoIter<String, String>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a EncryptionContext {
    type Item = (&'a String, &'a String);
    type IntoIter = std::collections::btree_map::Iter<'a, String, String>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The set of encryption context keys that must be supplied again on decrypt.

use std::collections::BTreeSet;

/// Encryption context keys that are left out of the message
/// and must be supplied again on decrypt.
///
/// Each key appears once. Iteration visits keys in ascending UTF-8 byte order,
/// the same order as [`EncryptionContext`](crate::structures::EncryptionContext).
///
/// Build it from a list or a set:
///
/// ```
/// # use aws_crypto_mpl::types::RequiredEncryptionContextKeys;
/// # use std::collections::BTreeSet;
/// let from_vec = RequiredEncryptionContextKeys::from(vec!["a".to_string()]);
/// let from_set = RequiredEncryptionContextKeys::from(BTreeSet::from(["a".to_string()]));
/// let from_array = RequiredEncryptionContextKeys::from(["a"]);
/// assert_eq!(from_vec, from_set);
/// assert_eq!(from_set, from_array);
/// ```
#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub struct RequiredEncryptionContextKeys(BTreeSet<String>);

impl std::fmt::Debug for RequiredEncryptionContextKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("RequiredEncryptionContextKeys")
            .field(&self.0)
            .finish()
    }
}

impl RequiredEncryptionContextKeys {
    /// Create a new empty set of keys.
    #[must_use]
    pub const fn new() -> Self {
        Self(BTreeSet::new())
    }

    /// Add a key. Returns `false` if the key was already present.
    pub fn insert(&mut self, key: impl Into<String>) -> bool {
        self.0.insert(key.into())
    }

    /// Remove a key. Returns `true` if the key was present.
    pub fn remove(&mut self, key: &str) -> bool {
        self.0.remove(key)
    }

    /// Check if a key is present.
    pub fn contains(&self, key: &str) -> bool {
        self.0.contains(key)
    }

    /// Check if empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Number of keys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Iterate over keys in ascending order.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(String::as_str)
    }

    /// Returns the underlying set reference.
    #[must_use]
    pub fn as_set(&self) -> &BTreeSet<String> {
        &self.0
    }

    /// Returns the keys as a list, in ascending order.
    #[must_use]
    pub fn to_vec(&self) -> Vec<String> {
        self.0.iter().cloned().collect()
    }
}

impl From<BTreeSet<String>> for RequiredEncryptionContextKeys {
    fn from(set: BTreeSet<String>) -> Self {
        Self(set)
    }
}

impl From<Vec<String>> for RequiredEncryptionContextKeys {
    fn from(keys: Vec<String>) -> Self {
        keys.into_iter().collect()
    }
}

impl From<&[String]> for RequiredEncryptionContextKeys {
    fn from(keys: &[String]) -> Self {
        keys.iter().cloned().collect()
    }
}

impl<K: Into<String>, const N: usize> From<[K; N]> for RequiredEncryptionContextKeys {
    fn from(keys: [K; N]) -> Self {
        keys.into_iter().collect()
    }
}

impl From<RequiredEncryptionContextKeys> for BTreeSet<String> {
    fn from(keys: RequiredEncryptionContextKeys) -> Self {
        keys.0
    }
}

impl From<RequiredEncryptionContextKeys> for Vec<String> {
    fn from(keys: RequiredEncryptionContextKeys) -> Self {
        keys.0.into_iter().collect()
    }
}

impl<K: Into<String>> FromIterator<K> for RequiredEncryptionContextKeys {
    fn from_iter<I: IntoIterator<Item = K>>(iter: I) -> Self {
        let mut keys = Self::new();
        keys.extend(iter);
        keys
    }
}

impl<K: Into<String>> Extend<K> for RequiredEncryptionContextKeys {
    fn extend<I: IntoIterator<Item = K>>(&mut self, iter: I) {
        for key in iter {
            self.insert(key);
        }
    }
}

impl IntoIterator for RequiredEncryptionContextKeys {
    type Item = String;
    type IntoIter = std::collections::btree_set::IntoIter<String>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a RequiredEncryptionContextKeys {
    type Item = &'a String;
    type IntoIter = std::collections::btree_set::Iter<'a, String>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

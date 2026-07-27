// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Error types for the [`Keystore`](super::Keystore) trait.

use std::fmt;

/// Categorisation of a [`KeystoreError`]. New kinds may be added in minor
/// releases, hence `#[non_exhaustive]`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeystoreErrorKind {
    /// Invalid configuration combination or missing required field.
    Configuration,
    /// Wrapped AWS KMS error.
    Kms,
    /// Wrapped DynamoDB error.
    Dynamodb,
    /// No record found for the given branch-key-id.
    RecordNotFound,
    /// Record format violation (missing field, wrong type, bad version).
    RecordMalformed,
    /// ReEncrypt authentication or decrypt-round-trip failure.
    Authentication,
    /// DDB conditional-write failure on VersionKey.
    VersionConflict,
    /// Internal invariant violation.
    Internal,
}

/// Error type for keystore operations.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct KeystoreError {
    /// Categorisation of this error.
    pub kind: KeystoreErrorKind,
    /// Free-form human-readable message.
    pub message: String,
}

impl KeystoreError {
    /// Construct a new `KeystoreError`.
    pub fn new(kind: KeystoreErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// Borrow the categorisation of this error.
    pub const fn kind(&self) -> &KeystoreErrorKind {
        &self.kind
    }

    /// Borrow the message of this error.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for KeystoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeystoreError({:?}): {}", self.kind, self.message)
    }
}

impl std::error::Error for KeystoreError {}

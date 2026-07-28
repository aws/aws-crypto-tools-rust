// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Error types for the [`KeyStore`](super::KeyStore) trait.

use std::fmt;
use std::sync::Arc;

/// Categorisation of a [`KeyStoreError`]. New kinds may be added in minor
/// releases, hence `#[non_exhaustive]`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyStoreErrorKind {
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
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct KeyStoreError {
    /// Categorisation of this error.
    pub kind: KeyStoreErrorKind,
    /// Free-form human-readable message.
    pub message: String,
    /// The underlying error that produced this `KeyStoreError`, if any.
    /// Surfaced by [`std::error::Error::source`].
    pub cause: Option<Arc<dyn std::error::Error + Send + Sync + 'static>>,
}

impl KeyStoreError {
    /// Construct a new `KeyStoreError` with no underlying cause.
    pub fn new(kind: KeyStoreErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            cause: None,
        }
    }

    /// Construct a new `KeyStoreError` wrapping an underlying cause.
    /// The cause is surfaced through [`std::error::Error::source`].
    pub fn with_cause(
        kind: KeyStoreErrorKind,
        message: impl Into<String>,
        cause: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            kind,
            message: message.into(),
            cause: Some(Arc::new(cause)),
        }
    }

    pub const fn kind(&self) -> &KeyStoreErrorKind {
        &self.kind
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn cause(&self) -> Option<&(dyn std::error::Error + Send + Sync + 'static)> {
        self.cause.as_deref()
    }
}

impl PartialEq for KeyStoreError {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind && self.message == other.message
    }
}

impl Eq for KeyStoreError {}

impl fmt::Display for KeyStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyStoreError({:?}): {}", self.kind, self.message)
    }
}

impl std::error::Error for KeyStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cause
            .as_ref()
            .map(|c| c.as_ref() as &(dyn std::error::Error + 'static))
    }
}

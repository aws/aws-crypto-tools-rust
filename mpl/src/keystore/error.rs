// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Error types for the [`Keystore`](super::Keystore) trait.

use std::fmt;
use std::sync::Arc;

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
///
/// Carries a categorisation ([`KeystoreErrorKind`]), a human-readable
/// message, and an optional causal error chain — the underlying error
/// (e.g. an AWS SDK error, an I/O failure) that produced this
/// `KeystoreError`. The cause is surfaced through
/// [`std::error::Error::source`], so downstream loggers / reporters that
/// walk the source chain (`anyhow`, `tracing`, `eyre`, etc.) print the
/// full context without callers having to string-concatenate it into
/// `message`.
///
/// [`PartialEq`] and [`Eq`] compare `kind` and `message` only; the
/// `cause` chain is intentionally not part of equality because the
/// wrapped underlying errors are often not themselves `Eq`.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct KeystoreError {
    /// Categorisation of this error.
    pub kind: KeystoreErrorKind,
    /// Free-form human-readable message.
    pub message: String,
    /// The underlying error that produced this `KeystoreError`, if any.
    /// Surfaced by [`std::error::Error::source`].
    pub cause: Option<Arc<dyn std::error::Error + Send + Sync + 'static>>,
}

impl KeystoreError {
    /// Construct a new `KeystoreError` with no underlying cause.
    pub fn new(kind: KeystoreErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            cause: None,
        }
    }

    /// Construct a new `KeystoreError` wrapping an underlying cause.
    /// The cause is surfaced through [`std::error::Error::source`].
    pub fn with_cause(
        kind: KeystoreErrorKind,
        message: impl Into<String>,
        cause: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            kind,
            message: message.into(),
            cause: Some(Arc::new(cause)),
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

    /// Borrow the causal error chain, if any.
    pub fn cause(&self) -> Option<&(dyn std::error::Error + Send + Sync + 'static)> {
        self.cause.as_deref()
    }
}

impl PartialEq for KeystoreError {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind && self.message == other.message
    }
}

impl Eq for KeystoreError {}

impl fmt::Display for KeystoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeystoreError({:?}): {}", self.kind, self.message)
    }
}

impl std::error::Error for KeystoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cause
            .as_ref()
            .map(|c| c.as_ref() as &(dyn std::error::Error + 'static))
    }
}

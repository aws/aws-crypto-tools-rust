// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//! Error types for the AWS Encryption SDK.

use std::backtrace::Backtrace;
use std::sync::Arc;

/// What went wrong, as a caller would act on it.
///
/// Which component failed, and the underlying library or service error, are in
/// [`Error::message`] and [`std::error::Error::source`].
/// The kinds a keyring, CMM, key store, or cache reports are
/// [`aws_crypto_mpl::ErrorKind`]'s, under the same names.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// An input or configuration value is invalid.
    /// No cryptography has been attempted.
    Validation,
    /// The message bytes are malformed and could not be read or written.
    Serialization,
    /// A cryptographic check failed, such as an authentication tag or a
    /// signature.
    Cryptographic,
    /// The materials a keyring or CMM returned are inconsistent with each
    /// other or with the algorithm suite.
    InvalidMaterials,
    /// A required encryption context key is missing, or a caller-supplied
    /// encryption context value differs from the message's.
    EncryptionContextMismatch,
    /// No configured key wrapped any of the message's encrypted data keys.
    NoMatchingDataKey,
    /// A remote service denied access to a resource.
    RemoteAccessDenied,
    /// A remote resource, such as a KMS key, `DynamoDB` table, or branch key,
    /// does not exist.
    RemoteResourceNotFound,
    /// A remote service throttled the request.
    RemoteThrottled,
    /// A request to a remote service could not be sent, or its response did
    /// not arrive.
    RemoteTransport,
    /// Any other failure reported by, or read from, a remote service.
    Remote,
    /// An internal invariant was violated.
    Internal,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
/// Base error type for [`aws_esdk`](crate)
pub struct Error {
    pub(crate) kind: ErrorKind,
    pub(crate) message: String,
    pub(crate) retryable: bool,
    pub(crate) backtrace: Arc<Backtrace>,
    pub(crate) cause: Option<Arc<dyn std::error::Error + Send + Sync + 'static>>,
}

impl Error {
    #[track_caller]
    fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            retryable: false,
            backtrace: Arc::new(Backtrace::capture()),
            cause: None,
        }
    }

    /// What went wrong.
    #[must_use]
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// The error message, without the kind prefix that `Display` adds.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Whether the same call might succeed if retried.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        self.retryable
    }

    /// The backtrace captured when this error was created.
    pub fn backtrace(&self) -> &Backtrace {
        &self.backtrace
    }
}

impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind && self.message == other.message
    }
}
impl Eq for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.message)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.cause {
            Some(cause) => Some(cause.as_ref()),
            None => None,
        }
    }
}

#[track_caller]
pub(crate) fn val_err(msg: impl Into<String>) -> Error {
    Error::new(ErrorKind::Validation, msg)
}

#[track_caller]
pub(crate) fn val_err_with_cause(
    msg: impl Into<String>,
    cause: impl std::error::Error + Send + Sync + 'static,
) -> Error {
    err_with_cause(ErrorKind::Validation, msg, cause)
}

#[track_caller]
pub(crate) fn err(kind: ErrorKind, msg: impl Into<String>) -> Error {
    Error::new(kind, msg)
}

#[track_caller]
pub(crate) fn err_with_cause(
    kind: ErrorKind,
    msg: impl Into<String>,
    cause: impl std::error::Error + Send + Sync + 'static,
) -> Error {
    Error {
        cause: Some(Arc::new(cause)),
        ..Error::new(kind, msg)
    }
}

#[track_caller]
pub(crate) fn ser_err<T>(msg: &str) -> Result<T, Error> {
    Err(Error::new(ErrorKind::Serialization, msg))
}

impl From<aws_crypto_mpl::Error> for Error {
    #[track_caller]
    fn from(item: aws_crypto_mpl::Error) -> Self {
        use aws_crypto_mpl::ErrorKind as Mpl;
        let kind = match item.kind() {
            Mpl::Validation => ErrorKind::Validation,
            Mpl::InvalidMaterials => ErrorKind::InvalidMaterials,
            Mpl::EncryptionContextMismatch => ErrorKind::EncryptionContextMismatch,
            Mpl::NoMatchingDataKey => ErrorKind::NoMatchingDataKey,
            Mpl::Cryptographic => ErrorKind::Cryptographic,
            Mpl::RemoteAccessDenied => ErrorKind::RemoteAccessDenied,
            Mpl::RemoteResourceNotFound => ErrorKind::RemoteResourceNotFound,
            Mpl::RemoteThrottled => ErrorKind::RemoteThrottled,
            Mpl::RemoteTransport => ErrorKind::RemoteTransport,
            Mpl::Remote => ErrorKind::Remote,
            _ => ErrorKind::Internal,
        };
        let message = item.to_string();
        Self {
            retryable: item.is_retryable(),
            cause: Some(Arc::new(item)),
            ..Self::new(kind, message)
        }
    }
}

impl From<aws_mpl_primitives::Error> for Error {
    #[track_caller]
    fn from(item: aws_mpl_primitives::Error) -> Self {
        Self {
            kind: ErrorKind::Cryptographic,
            message: item.message,
            retryable: false,
            backtrace: item.backtrace,
            cause: None,
        }
    }
}

impl From<aws_smithy_types::error::operation::BuildError> for Error {
    #[track_caller]
    fn from(item: aws_smithy_types::error::operation::BuildError) -> Self {
        let message = format!("{item:?}");
        Self {
            cause: Some(Arc::new(item)),
            ..Self::new(ErrorKind::Validation, message)
        }
    }
}

impl From<&str> for Error {
    #[track_caller]
    fn from(item: &str) -> Self {
        Self::new(ErrorKind::Internal, item)
    }
}

impl From<String> for Error {
    #[track_caller]
    fn from(item: String) -> Self {
        Self::new(ErrorKind::Internal, item)
    }
}

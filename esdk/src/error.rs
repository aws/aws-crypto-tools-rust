// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//! Error types for the AWS Encryption SDK.

use std::backtrace::Backtrace;
use std::sync::Arc;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
/// Individual error types for [`aws_esdk`](crate)
pub enum ErrorKind {
    /// Higher level ESDK errors
    Esdk,
    /// Error in serializing or deserializing the data
    SerializationError,
    /// Low level cryptographic error from `aws_mpl_primitives`
    CryptographicError,
    /// Error surfaced by the Material Providers Library while obtaining
    /// encryption or decryption materials (from a keyring or CMM).
    MplError,
    /// Error surfaced by the MPL branch key store.
    KeystoreError,
    /// Error surfaced by the MPL cryptographic materials cache.
    CacheError,
    /// Malformed input. No cryptography has been attempted.
    ValidationError,
}
#[derive(Debug, Clone)]
#[non_exhaustive]
/// Base error type for [`aws_esdk`](crate)
pub struct Error {
    pub(crate) kind: ErrorKind,
    pub(crate) message: String,
    pub(crate) backtrace: Arc<Backtrace>,
    pub(crate) cause: Option<Arc<dyn std::error::Error + Send + Sync + 'static>>,
}

impl Error {
    /// The category of this error.
    #[must_use]
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// The error message, without the category prefix that `Display` adds.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The backtrace captured when this error was created.
    #[must_use]
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
        match &self.kind {
            ErrorKind::Esdk => write!(f, "Esdk Error {}", self.message),
            ErrorKind::SerializationError => write!(f, "Serialization Error {}", self.message),
            ErrorKind::CryptographicError => write!(f, "Cryptographic Error {}", self.message),
            ErrorKind::MplError => write!(f, "MPL Error {}", self.message),
            ErrorKind::KeystoreError => write!(f, "Keystore Error {}", self.message),
            ErrorKind::CacheError => write!(f, "Cache Error {}", self.message),
            ErrorKind::ValidationError => write!(f, "Validation Error {}", self.message),
        }
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
    Error {
        kind: ErrorKind::ValidationError,
        message: msg.into(),
        backtrace: Arc::new(Backtrace::capture()),
        cause: None,
    }
}

#[track_caller]
pub(crate) fn val_err_with_cause(
    msg: impl Into<String>,
    cause: impl std::error::Error + Send + Sync + 'static,
) -> Error {
    Error {
        kind: ErrorKind::ValidationError,
        message: msg.into(),
        backtrace: Arc::new(Backtrace::capture()),
        cause: Some(Arc::new(cause)),
    }
}

#[track_caller]
pub(crate) fn esdk_err(msg: impl Into<String>) -> Error {
    Error {
        kind: ErrorKind::Esdk,
        message: msg.into(),
        backtrace: Arc::new(Backtrace::capture()),
        cause: None,
    }
}

#[track_caller]
pub(crate) fn ser_err<T>(msg: &str) -> Result<T, Error> {
    Err(Error {
        kind: ErrorKind::SerializationError,
        message: msg.into(),
        backtrace: Arc::new(Backtrace::capture()),
        cause: None,
    })
}

impl From<aws_crypto_mpl::structures::MaterialsError> for Error {
    #[track_caller]
    fn from(item: aws_crypto_mpl::structures::MaterialsError) -> Self {
        Self {
            kind: ErrorKind::MplError,
            message: item.to_string(),
            backtrace: Arc::new(Backtrace::capture()),
            cause: Some(Arc::new(item)),
        }
    }
}

impl From<aws_crypto_mpl::keystore::KeystoreError> for Error {
    #[track_caller]
    fn from(item: aws_crypto_mpl::keystore::KeystoreError) -> Self {
        Self {
            kind: ErrorKind::KeystoreError,
            message: item.to_string(),
            backtrace: Arc::new(Backtrace::capture()),
            cause: Some(Arc::new(item)),
        }
    }
}

impl From<aws_crypto_mpl::cmc::CmcError> for Error {
    #[track_caller]
    fn from(item: aws_crypto_mpl::cmc::CmcError) -> Self {
        Self {
            kind: ErrorKind::CacheError,
            message: item.to_string(),
            backtrace: Arc::new(Backtrace::capture()),
            cause: Some(Arc::new(item)),
        }
    }
}

impl From<aws_mpl_primitives::Error> for Error {
    #[track_caller]
    fn from(item: aws_mpl_primitives::Error) -> Self {
        Self {
            kind: ErrorKind::CryptographicError,
            message: item.message,
            backtrace: item.backtrace,
            cause: None,
        }
    }
}

impl From<aws_smithy_types::error::operation::BuildError> for Error {
    #[track_caller]
    fn from(item: aws_smithy_types::error::operation::BuildError) -> Self {
        Self {
            kind: ErrorKind::ValidationError,
            message: format!("{item:?}"),
            backtrace: Arc::new(Backtrace::capture()),
            cause: Some(Arc::new(item)),
        }
    }
}

impl From<&str> for Error {
    #[track_caller]
    fn from(item: &str) -> Self {
        Self {
            kind: ErrorKind::Esdk,
            message: item.to_string(),
            backtrace: Arc::new(Backtrace::capture()),
            cause: None,
        }
    }
}

impl From<String> for Error {
    #[track_caller]
    fn from(item: String) -> Self {
        Self {
            kind: ErrorKind::Esdk,
            message: item,
            backtrace: Arc::new(Backtrace::capture()),
            cause: None,
        }
    }
}

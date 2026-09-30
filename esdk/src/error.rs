// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//! Error types for the AWS Encryption SDK.

aws_mpl_primitives::define_error! {
    /// Base error type for [`aws_esdk`](crate).
    ///
    /// Which component failed, and the underlying library or service error,
    /// are in [`Error::message`] and [`std::error::Error::source`].
    Error,
    /// What went wrong, as a caller would act on it.
    ///
    /// The kinds a keyring, CMM, key store, or cache reports are
    /// [`aws_crypto_mpl::ErrorKind`]'s, under the same names.
    ErrorKind;
    /// The message bytes are malformed and could not be read or written.
    Serialization,
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
    Error::with_cause(ErrorKind::Validation, msg, cause)
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
    Error::with_cause(kind, msg, cause)
}

#[track_caller]
pub(crate) fn ser_err<T>(msg: &str) -> Result<T, Error> {
    Err(Error::new(ErrorKind::Serialization, msg))
}

impl From<aws_crypto_mpl::Error> for Error {
    #[track_caller]
    fn from(item: aws_crypto_mpl::Error) -> Self {
        Self::from_inner("the material providers library failed", item)
    }
}

impl From<aws_mpl_primitives::Error> for Error {
    #[track_caller]
    fn from(item: aws_mpl_primitives::Error) -> Self {
        Self::from_inner("a cryptographic operation failed", item)
    }
}

impl From<aws_smithy_types::error::operation::BuildError> for Error {
    #[track_caller]
    fn from(item: aws_smithy_types::error::operation::BuildError) -> Self {
        Self::with_cause(ErrorKind::Validation, "could not build the request", item)
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

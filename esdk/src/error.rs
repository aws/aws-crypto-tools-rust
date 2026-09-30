// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//! Error types for the AWS Encryption SDK.

aws_mpl_primitives::define_error! {
    /// An error from the AWS Encryption SDK.
    ///
    /// The message says what failed.
    /// The [`source`](std::error::Error::source) chain holds the underlying library or service error.
    Error,
    /// What went wrong, as a caller would act on it.
    ///
    /// An error from a keyring, CMM, key store, or cache keeps its kind:
    /// each [`aws_crypto_mpl::ErrorKind`] has a kind here with the same name.
    ErrorKind;
    /// The bytes are not a well-formed encrypted message,
    /// for example truncated input, an unsupported message version, or data after the footer.
    ///
    /// Treat the message as corrupt; retrying cannot succeed.
    Serialization,
    /// A caller-supplied reader or writer failed while streaming,
    /// for example a closed connection or a full disk.
    ///
    /// The [`source`](std::error::Error::source) is the [`std::io::Error`].
    Io,
}

#[track_caller]
pub(crate) fn val_err(msg: impl Into<String>) -> Error {
    Error::new(ErrorKind::Validation, msg)
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

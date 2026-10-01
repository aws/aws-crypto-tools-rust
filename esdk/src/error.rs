// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//! Error types for the AWS Encryption SDK.

pub use aws_mpl_primitives::error::{
    DisplayErrorContext, ErrorBuilder, Resource, RetryKind, Service,
};
pub use aws_sdk_kms::error::{ErrorMetadata, ProvideErrorMetadata};
pub use aws_sdk_kms::operation::RequestId;
pub use aws_smithy_types::retry::{ErrorKind as RetryErrorKind, ProvideErrorKind};

aws_mpl_primitives::define_error! {
    /// An error from the AWS Encryption SDK.
    ///
    /// The message says what failed.
    /// The [`source`](std::error::Error::source) chain holds the underlying library or service error.
    /// An error from a keyring, CMM, key store, or cache keeps its variant:
    /// each [`aws_crypto_mpl::Error`] variant has one here with the same name.
    pub enum Error {
        Validation(ValidationError, is_validation),
        InvalidMaterials(InvalidMaterialsError, is_invalid_materials),
        EncryptionContextMismatch(EncryptionContextMismatchError, is_encryption_context_mismatch),
        NoMatchingDataKey(NoMatchingDataKeyError, is_no_matching_data_key),
        Cryptographic(CryptographicError, is_cryptographic),
        AccessDenied(AccessDeniedError, is_access_denied, remote),
        ResourceNotFound(ResourceNotFoundError, is_resource_not_found, remote),
        Service(ServiceError, is_service, remote),
        Dispatch(DispatchError, is_dispatch, remote),
        /// The bytes are not a well-formed encrypted message,
        /// for example truncated input, an unsupported message version, or data after the footer.
        ///
        /// Treat the message as corrupt; retrying cannot succeed.
        Serialization(SerializationError, is_serialization),
        /// A caller-supplied reader or writer failed while streaming,
        /// for example a closed connection or a full disk.
        ///
        /// The [`source`](std::error::Error::source) is the [`std::io::Error`].
        Io(IoError, is_io),
        Internal(InternalError, is_internal),
    }
    sdk(aws_smithy_types, RequestId);
}

#[track_caller]
pub(crate) fn val_err(msg: impl Into<String>) -> Error {
    Error::new(Kind::Validation, msg)
}

#[track_caller]
pub(crate) fn err(kind: Kind, msg: impl Into<String>) -> Error {
    Error::new(kind, msg)
}

#[track_caller]
pub(crate) fn err_with_cause(
    kind: Kind,
    msg: impl Into<String>,
    cause: impl std::error::Error + Send + Sync + 'static,
) -> Error {
    Error::with_cause(kind, msg, cause)
}

#[track_caller]
pub(crate) fn ser_err<T>(msg: &str) -> Result<T, Error> {
    Err(Error::new(Kind::Serialization, msg))
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
        Self::with_cause(Kind::Validation, "could not build the request", item)
    }
}

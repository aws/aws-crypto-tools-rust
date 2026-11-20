// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//! Error types for the AWS Database Encryption SDK for DynamoDB.
//!
//! # Handling errors
//!
//! Every operation fails with [`Error`]:
//! a `#[non_exhaustive]` enum with one struct per variant, like an AWS SDK for Rust service error.
//!
//! **Decide in two steps.**
//! 1. Check [`is_retryable`](Error::is_retryable).
//!    A retryable error might succeed if the same call is made again later,
//!    and [`retry_kind`](Error::retry_kind) says how to back off.
//! 2. Otherwise match on the variant; each variant's docs say what to do.
//!
//! **Read the details from accessors.**
//! - [`resource`](Error::resource): the resource that you need to act on.
//! - [`service`](Error::service): the AWS service that the failed call went to.
//! - [`code`](Error::code): that service's error code.
//! - [`request_id`](Error::request_id): the request ID that AWS Support asks for.
//!
//! **Messages are for people and logs.**
//! The text of [`message`](Error::message) and `Display` can change in any release, even a patch release.
//! Handle errors from the variant and its accessors, never from the message.
//!
//! ## What a minor or patch release can change
//!
//! - **Message text.**
//!   Any message, and anything that `{}`, `{:#}`, or `{:?}` prints, can change.
//! - **Failures without a specific variant.**
//!   An [`Internal`](Error::Internal) error, or any failure that is not an [`Error`], is a bug.
//!   A release can give that failure a specific variant.
//! - **The shape of the source chain.**
//!   Reach a source with [`find_source`](Error::find_source),
//!   not by calling `source()` a fixed number of times.
//! - **Which variant a collection of failures gets.**
//!   To act on each failure, use [`failures`](Error::failures).
//! - **New variants and values.**
//!   `Error`, `Service`, `Resource`, `ConflictReason`, `RetryKind`, and `Collection` are `#[non_exhaustive]`,
//!   so every `match` needs a catch-all arm.
//!
//! ## Logging
//!
//! Log with `{:#}`: it includes each error in the source chain.
//!
//! ## Example
//!
//! ```
//! use aws_db_esdk::Error;
//! use aws_db_esdk::error::{AccessDeniedError, KmsKey, Resource, Service};
//!
//! let err = Error::from(
//!     AccessDeniedError::builder()
//!         .message("AWS KMS Decrypt failed")
//!         .service(Service::Kms)
//!         .resource(Resource::KmsKey(KmsKey::new("arn:aws:kms:us-west-2:111122223333:key/1234abcd")))
//!         .code("ExpiredTokenException")
//!         .build(),
//! );
//! assert!(matches!(&err, Error::AccessDenied(e) if e.is_credentials()));
//! ```

// `cargo xtask gen-errors` writes `generated.rs` from `errors.toml` at the repository root.
pub(crate) mod generated;

pub use generated::{
    AccessDeniedError, ConflictError, CryptographicError, DispatchError,
    EncryptionContextMismatchError, ErrorParts, InternalError, InvalidMaterialsError,
    NoMatchingDataKeyError, ResourceNotFoundError, SerializationError, ServiceError,
    ThrottlingError, ValidationError, builders,
};
pub(crate) use generated::{Error, Kind};

pub use aws_mpl_primitives::error::{
    BranchKey, Cache, CmmResource, Collection, ConflictReason, DataKeyInfo, DynamoDbTable,
    KeyringResource, KmsKey, Resource, RetryKind, Service,
};
pub use aws_smithy_types::error::display::DisplayErrorContext;
pub use aws_smithy_types::error::metadata::{ErrorMetadata, ProvideErrorMetadata};
pub use aws_smithy_types::retry::{ErrorKind, ProvideErrorKind};
pub use aws_types::request_id::RequestId;

/// A `Validation` error: the configuration or input is invalid.
#[track_caller]
pub(crate) fn val_err(msg: impl Into<String>) -> Error {
    Error::new(Kind::Validation, msg)
}

/// A `Serialization` error: the stored item is not a well-formed encrypted item.
#[track_caller]
pub(crate) fn ser_err(msg: impl Into<String>) -> Error {
    Error::new(Kind::Serialization, msg)
}

/// A `Cryptographic` error: the item failed an integrity or authenticity check.
#[track_caller]
pub(crate) fn crypt_err(msg: impl Into<String>) -> Error {
    Error::new(Kind::Cryptographic, msg)
}

/// An `InvalidMaterials` error: a CMM or keyring returned unusable materials.
#[track_caller]
pub(crate) fn materials_err(msg: impl Into<String>) -> Error {
    Error::new(Kind::InvalidMaterials, msg)
}

/// An `Internal` error: an invariant of this library does not hold.
#[track_caller]
pub(crate) fn internal_err(msg: impl Into<String>) -> Error {
    Error::new(Kind::Internal, msg)
}

/// The DynamoDB error codes that mean the request conflicts with the item's current state.
const DDB_CONFLICT_CODES: [&str; 2] = [
    "ConditionalCheckFailedException",
    "TransactionConflictException",
];

impl Error {
    /// Classify a failed DynamoDB call `operation` on `table`.
    ///
    /// The result keeps the SDK error as its source, so [`as_service_error`](Self::as_service_error) finds it.
    #[track_caller]
    pub(crate) fn from_ddb<E>(
        operation: &str,
        table: Option<&str>,
        err: aws_crypto_mpl::aws_sdk_dynamodb::error::SdkError<E>,
    ) -> Self
    where
        E: ProvideErrorMetadata + std::error::Error + Send + Sync + 'static,
    {
        let resource = table.map(|t| Resource::DynamoDbTable(DynamoDbTable::new(t)));
        let meta = err.as_service_error().map(|e| e.meta().clone());
        let code = meta.as_ref().and_then(|m| m.code()).map(str::to_owned);
        if let Some(code) = code.as_deref()
            && DDB_CONFLICT_CODES.contains(&code)
        {
            let concurrent = code == "TransactionConflictException";
            let request_id = err.request_id().map(str::to_owned);
            let mut error =
                Self::with_cause(Kind::Conflict, format!("DynamoDB {operation} failed"), err)
                    .about(Some(Service::DynamoDb), resource);
            error.set_sdk(Some(code.to_owned()), request_id, meta);
            if concurrent {
                error.set_reason(ConflictReason::ConcurrentModification);
            }
            return error;
        }
        let error = aws_crypto_mpl::Error::from_sdk(
            Service::DynamoDb,
            &format!("DynamoDB {operation}"),
            err,
        );
        let error = match resource {
            Some(resource) => error.with_resource(resource),
            None => error,
        };
        Self::from_mpl_parts(&error)
    }

    /// DynamoDB's own error, when this error comes from a failed DynamoDB call.
    ///
    /// `E` is the operation's error type, such as
    /// [`PutItemError`](crate::aws_sdk_dynamodb::operation::put_item::PutItemError).
    /// Match it the same way as an error from `aws_sdk_dynamodb`.
    ///
    /// Returns `None` when DynamoDB did not fail (for example, when encryption failed),
    /// or when `E` is a different operation's error type.
    ///
    /// ```
    /// use aws_db_esdk::Error;
    /// use aws_db_esdk::aws_sdk_dynamodb::operation::put_item::PutItemError;
    ///
    /// fn already_exists(err: &Error) -> bool {
    ///     matches!(
    ///         err.as_service_error(),
    ///         Some(PutItemError::ConditionalCheckFailedException(_))
    ///     )
    /// }
    /// ```
    #[must_use]
    pub fn as_service_error<E: std::error::Error + 'static>(&self) -> Option<&E> {
        std::error::Error::source(self)?
            .downcast_ref::<aws_crypto_mpl::aws_sdk_dynamodb::error::SdkError<E>>()?
            .as_service_error()
    }
}

impl From<aws_crypto_mpl::Error> for Error {
    #[track_caller]
    fn from(item: aws_crypto_mpl::Error) -> Self {
        Self::from_mpl("a keyring, CMM, key store, or cache failed", item)
    }
}

impl From<aws_mpl_primitives::Error> for Error {
    #[track_caller]
    fn from(item: aws_mpl_primitives::Error) -> Self {
        Self::from_prim("a cryptographic operation failed", item)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_crypto_mpl::aws_sdk_dynamodb::config::http::HttpResponse;
    use aws_crypto_mpl::aws_sdk_dynamodb::error::SdkError;
    use aws_crypto_mpl::aws_sdk_dynamodb::operation::get_item::GetItemError;
    use aws_crypto_mpl::aws_sdk_dynamodb::operation::put_item::PutItemError;
    use aws_crypto_mpl::aws_sdk_dynamodb::types::error::ConditionalCheckFailedException;
    use aws_smithy_types::body::SdkBody;

    fn response(status: u16) -> HttpResponse {
        HttpResponse::new(status.try_into().unwrap(), SdkBody::empty())
    }

    fn generic(code: &str, status: u16) -> SdkError<PutItemError, HttpResponse> {
        SdkError::service_error(
            PutItemError::generic(ErrorMetadata::builder().code(code).build()),
            response(status),
        )
    }

    fn table(err: &Error) -> Option<&str> {
        match err.resource() {
            Some(Resource::DynamoDbTable(t)) => Some(t.name()),
            _ => None,
        }
    }

    #[test]
    fn conditional_check_failure_is_a_conflict_with_the_service_error() {
        let exception = ConditionalCheckFailedException::builder()
            .message("The conditional request failed")
            .meta(
                ErrorMetadata::builder()
                    .code("ConditionalCheckFailedException")
                    .build(),
            )
            .build();
        let sdk = SdkError::service_error(
            PutItemError::ConditionalCheckFailedException(exception),
            response(400),
        );
        let err = Error::from_ddb("PutItem", Some("table1"), sdk);
        let Error::Conflict(conflict) = &err else {
            panic!("{err:?}");
        };
        assert_eq!(conflict.reason(), None);
        assert_eq!(err.message(), "DynamoDB PutItem failed");
        assert_eq!(err.code(), Some("ConditionalCheckFailedException"));
        assert_eq!(err.service(), Some(&Service::DynamoDb));
        assert_eq!(table(&err), Some("table1"));
        assert!(!err.is_retryable());
        assert!(matches!(
            err.as_service_error(),
            Some(PutItemError::ConditionalCheckFailedException(_))
        ));
    }

    #[test]
    fn transaction_conflict_is_a_concurrent_modification() {
        let err = Error::from_ddb(
            "PutItem",
            None,
            generic("TransactionConflictException", 400),
        );
        let Error::Conflict(conflict) = &err else {
            panic!("{err:?}");
        };
        assert_eq!(
            conflict.reason(),
            Some(&ConflictReason::ConcurrentModification)
        );
        assert_eq!(table(&err), None);
    }

    #[test]
    fn other_failures_are_classified_like_the_mpl() {
        let err = Error::from_ddb(
            "GetItem",
            Some("t"),
            generic("ProvisionedThroughputExceededException", 400),
        );
        assert!(matches!(err, Error::Throttling(_)), "{err:?}");
        assert!(err.is_retryable());
        assert_eq!(err.code(), Some("ProvisionedThroughputExceededException"));
        assert_eq!(table(&err), Some("t"));

        let err = Error::from_ddb("GetItem", None, generic("ResourceNotFoundException", 400));
        assert!(matches!(err, Error::ResourceNotFound(_)), "{err:?}");

        let err = Error::from_ddb(
            "GetItem",
            None,
            SdkError::<PutItemError, HttpResponse>::timeout_error("slow"),
        );
        assert!(matches!(err, Error::Dispatch(_)), "{err:?}");
        assert!(err.is_retryable());
        // DynamoDB did not answer, so there is no service error to match.
        assert!(err.as_service_error::<PutItemError>().is_none());
    }

    #[test]
    fn as_service_error_needs_the_matching_operation() {
        let err = Error::from_ddb("PutItem", None, generic("ValidationException", 400));
        assert!(err.as_service_error::<PutItemError>().is_some());
        assert!(err.as_service_error::<GetItemError>().is_none());
        assert!(val_err("x").as_service_error::<PutItemError>().is_none());
    }

    #[test]
    fn constructors_set_the_variant_and_message() {
        assert!(matches!(val_err("v"), Error::Validation(e) if e.message() == "v"));
        assert!(matches!(ser_err("s"), Error::Serialization(e) if e.message() == "s"));
        assert!(matches!(crypt_err("c"), Error::Cryptographic(e) if e.message() == "c"));
        assert!(matches!(materials_err("m"), Error::InvalidMaterials(e) if e.message() == "m"));
        assert!(matches!(internal_err("i"), Error::Internal(e) if e.message() == "i"));
    }

    #[test]
    fn mpl_errors_keep_their_variant() {
        let err = Error::from(aws_crypto_mpl::Error::no_matching_data_key("none"));
        assert!(matches!(err, Error::NoMatchingDataKey(_)), "{err:?}");
        assert_eq!(err.message(), "a keyring, CMM, key store, or cache failed");
        let err = Error::from(aws_crypto_mpl::Error::validation("bad"));
        assert!(matches!(err, Error::Validation(_)), "{err:?}");
    }
}

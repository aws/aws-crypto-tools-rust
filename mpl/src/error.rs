// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The error type every operation in this crate returns.
//!
//! # Handling errors
//!
//! Every keyring, CMM, key store, and cache operation returns [`Error`],
//! one `#[non_exhaustive]` enum with one struct per variant,
//! like an AWS SDK for Rust service error.
//! The AWS Encryption SDK keeps each variant under the same name.
//!
//! **Decide in two steps.**
//! First check [`is_retryable`](Error::is_retryable):
//! a retryable error might succeed if the same call is made again later,
//! and [`retry_kind`](Error::retry_kind) says how to back off.
//! Otherwise match on the variant; each variant's docs say what to do.
//! Later releases can add variants, so a `match` needs a catch-all arm.
//!
//! **Read the details from accessors.**
//! [`service`](Error::service) is the AWS service a failed call went to,
//! [`code`](Error::code) is that service's error code,
//! and [`request_id`](Error::request_id) is the ID AWS Support asks for.
//! [`resource`](Error::resource) is the resource you need to act on.
//! Other resources involved are named in the message:
//! when AWS KMS denies decrypting a branch key, `resource()` is the KMS key,
//! because the fix is a KMS permission, and the message names the branch key.
//!
//! **Messages are for people.**
//! [`message`](Error::message) and `Display` are for people and logs,
//! and their text can change in any release.
//! Decide from the variant and its accessors, never from the message.
//!
//! **`{}` and `{:#}`.**
//! `{}` prints this error: `Variant: message (details)`.
//! `{:#}` adds each error in the source chain, without repeating what the previous one said.
//! Log `{:#}`.
//! [`DisplayErrorContext`] prints the chain of an error that is not one of these.
//!
//! **Reaching the AWS SDK error.**
//! The error from AWS KMS or DynamoDB stays in the source chain.
//! [`find_source`](Error::find_source) returns it by type;
//! use the re-exported `aws_crypto_mpl::aws_sdk_kms` and
//! `aws_crypto_mpl::aws_sdk_dynamodb`, so the versions match.
//!
//! ## Key store conflicts
//!
//! `create_key` and `version_key` write conditionally.
//! When the condition fails, the error is [`Conflict`](Error::Conflict),
//! and [`reason`](ConflictError::reason) says why:
//!
//! ```no_run
//! # async fn example(store: aws_crypto_mpl::BranchKeyStore) -> Result<(), aws_crypto_mpl::Error> {
//! use aws_crypto_mpl::Keystore;
//! use aws_crypto_mpl::error::{ConflictReason, Error};
//!
//! match store.version_key("my-branch-key".into()).await {
//!     // Another caller rotated the branch key first; it has a new version already.
//!     Err(Error::Conflict(e)) if e.reason() == Some(ConflictReason::ConcurrentModification) => Ok(()),
//!     other => other,
//! }?;
//!
//! match store.create_key(Some("my-branch-key".into()), Some(Default::default())).await {
//!     Ok(_) => {}
//!     // The branch key ID is in use; use the existing key or pick another ID.
//!     Err(Error::Conflict(e)) if e.reason() == Some(ConflictReason::AlreadyExists) => {}
//!     Err(e) => return Err(e),
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Throttling
//!
//! A [`Throttling`](Error::Throttling) error is always retryable.
//! Match it only to learn what was throttled, for example to record it:
//!
//! ```
//! # fn record_throttle(_: &str) {}
//! use aws_crypto_mpl::error::{Error, Resource};
//!
//! fn record(err: &Error) {
//!     if let Error::Throttling(e) = err {
//!         match (e.service(), e.resource()) {
//!             (Some(service), _) => record_throttle(service.as_str()),
//!             (None, Some(Resource::Cache)) => record_throttle("materials-cache"),
//!             _ => record_throttle("other"),
//!         }
//!     }
//! }
//! ```
//!
//! For errors from AWS KMS or DynamoDB, the AWS SDK client has already retried
//! according to its `RetryConfig`, so retry only at a higher level with your own backoff.
//! Materials-cache throttling is not retried internally.
//!
//! ## Testing your error handling
//!
//! Every variant struct has `new` and a [builder](builders), so you can construct
//! the errors this crate returns, for example from a fake key store:
//!
//! ```
//! use aws_crypto_mpl::error::{ConflictError, ConflictReason, Error, Resource, Service};
//!
//! let err = Error::from(
//!     ConflictError::builder()
//!         .message("branch key my-branch-key was rotated concurrently")
//!         .service(Service::DynamoDb)
//!         .resource(Resource::BranchKey("my-branch-key".into()))
//!         .reason(ConflictReason::ConcurrentModification)
//!         .build(),
//! );
//! assert!(!err.is_retryable());
//! ```
//!
//! Keyring and CMM authors: see [Errors for keyring and CMM authors](crate::keyring#errors-for-keyring-and-cmm-authors).
//!
//! [`Error`] and its variant structs are generated from `errors.toml`
//! at the repository root by `cargo xtask gen-errors`.

use aws_sdk_kms::config::http::HttpResponse;
use aws_sdk_kms::error::SdkError;

mod generated;

pub use generated::*;

pub use aws_mpl_primitives::error::{ConflictReason, Resource, RetryKind, Service};
pub use aws_smithy_types::error::display::DisplayErrorContext;
pub use aws_smithy_types::error::metadata::{ErrorMetadata, ProvideErrorMetadata};
pub use aws_smithy_types::retry::{ErrorKind as RetryErrorKind, ProvideErrorKind};
pub use aws_types::request_id::RequestId;

impl Error {
    /// Classify a failed AWS SDK call to `service` about `resource`.
    ///
    /// The message is "`operation` failed", and the SDK error becomes the source.
    #[track_caller]
    pub(crate) fn from_sdk<E>(
        service: Service,
        operation: &str,
        resource: Option<Resource>,
        err: SdkError<E, HttpResponse>,
    ) -> Self
    where
        E: ProvideErrorMetadata + std::error::Error + Send + Sync + 'static,
    {
        let (kind, retry) = classify_sdk_error(&err);
        let meta = err.as_service_error().map(|e| e.meta().clone());
        let code = meta.as_ref().and_then(|m| m.code()).map(str::to_owned);
        let request_id = err.request_id().map(str::to_owned);
        let mut error = Self::with_cause(kind, format!("{operation} failed"), err)
            .about(Some(service), resource);
        error.set_retry(retry);
        error.set_sdk(code, request_id, meta);
        error
    }

    /// An error that aggregates `errors`,
    /// for a keyring or CMM that tried several things and every one failed.
    ///
    /// With exactly one error, returns it unchanged.
    /// Otherwise the variant is the one every error shares or, for a mix,
    /// the first present of `AccessDenied`, `ResourceNotFound`, `Throttling`, `Dispatch`,
    /// `Service`, `InvalidMaterials`, `EncryptionContextMismatch`, `Cryptographic`,
    /// and `NoMatchingDataKey`.
    /// The result is retryable if any error is,
    /// and keeps each detail, such as `resource()`, that every error shares.
    ///
    /// ```
    /// use aws_crypto_mpl::Error;
    ///
    /// let err = Error::aggregate(
    ///     "no encrypted data key could be decrypted",
    ///     vec![
    ///         Error::no_matching_data_key("encrypted data key 0 belongs to another keyring"),
    ///         Error::cryptographic("encrypted data key 1 did not decrypt"),
    ///     ],
    /// );
    /// assert!(err.is_cryptographic());
    /// assert_eq!(err.collected().len(), 2);
    /// ```
    #[track_caller]
    #[must_use]
    pub fn aggregate(message: impl Into<String>, mut errors: Vec<Self>) -> Self {
        if errors.len() == 1
            && let Some(only) = errors.pop()
        {
            return only;
        }
        if errors.is_empty() {
            return Self::new(Kind::Internal, message);
        }
        let kind = Self::aggregate_kind(&errors);
        Self::collection(kind, message, errors)
    }

    /// The variant for an error that aggregates `errors`.
    ///
    /// The variant every error shares,
    /// or for a mix the first present in the order of `AGGREGATE_PRIORITY`,
    /// or else the first error's.
    pub(crate) fn aggregate_kind(errors: &[Self]) -> Kind {
        let Some((first, rest)) = errors.split_first() else {
            return Kind::Internal;
        };
        if rest.iter().all(|e| e.kind() == first.kind()) {
            return first.kind();
        }
        AGGREGATE_PRIORITY
            .iter()
            .copied()
            .find(|k| errors.iter().any(|e| e.kind() == *k))
            .unwrap_or_else(|| first.kind())
    }
}

/// Which variant a collection of mixed errors gets: the first present.
const AGGREGATE_PRIORITY: &[Kind] = &[
    Kind::AccessDenied,
    Kind::ResourceNotFound,
    Kind::Throttling,
    Kind::Dispatch,
    Kind::Service,
    Kind::InvalidMaterials,
    Kind::EncryptionContextMismatch,
    Kind::Cryptographic,
    Kind::NoMatchingDataKey,
];

// The codes the AWS SDK for Rust's retry classifier retries as throttling.
use aws_runtime::retries::classifiers::THROTTLING_ERRORS as THROTTLING_CODES;

/// The codes the AWS SDK for Rust's retry classifier retries as transient
/// (`aws_runtime::retries::classifiers::TRANSIENT_ERRORS`),
/// plus the failures AWS KMS and DynamoDB document as transient.
const TRANSIENT_CODES: &[&str] = &[
    "RequestTimeout",
    "RequestTimeoutException",
    "KMSInternalException",
    "KeyUnavailableException",
    "DependencyTimeoutException",
    "InternalServerError",
    "ServiceUnavailable",
];

/// The codes AWS KMS and DynamoDB return when the caller's credentials or permissions are refused.
const ACCESS_DENIED_CODES: &[&str] = &[
    "AccessDeniedException",
    "NotAuthorized",
    "UnrecognizedClientException",
    "InvalidSignatureException",
    "IncompleteSignature",
    "IncompleteSignatureException",
    "MissingAuthenticationTokenException",
    "ExpiredTokenException",
    "InvalidGrantTokenException",
];

const NOT_FOUND_CODES: &[&str] = &["NotFoundException", "ResourceNotFoundException"];

fn classify_sdk_error<E: ProvideErrorMetadata>(
    err: &SdkError<E, HttpResponse>,
) -> (Kind, Option<RetryKind>) {
    match err {
        SdkError::ConstructionFailure(_) => (Kind::Internal, None),
        SdkError::TimeoutError(_) => (Kind::Dispatch, Some(RetryKind::Transient)),
        SdkError::DispatchFailure(failure) => {
            // Missing credentials or region arrive as user or other connector errors,
            // which retrying cannot fix.
            let transient = failure.is_io() || failure.is_timeout();
            (Kind::Dispatch, transient.then_some(RetryKind::Transient))
        }
        SdkError::ResponseError(_) => (Kind::Service, Some(RetryKind::Transient)),
        SdkError::ServiceError(ctx) => {
            let code = ctx.err().code().unwrap_or_default();
            if THROTTLING_CODES.contains(&code) {
                (Kind::Throttling, Some(RetryKind::Throttling))
            } else if ACCESS_DENIED_CODES.contains(&code) {
                (Kind::AccessDenied, None)
            } else if NOT_FOUND_CODES.contains(&code) {
                (Kind::ResourceNotFound, None)
            } else if TRANSIENT_CODES.contains(&code) {
                (Kind::Service, Some(RetryKind::Transient))
            } else if ctx.raw().status().is_server_error() {
                (Kind::Service, Some(RetryKind::Server))
            } else {
                (Kind::Service, None)
            }
        }
        _ => (Kind::Service, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_kms::operation::decrypt::DecryptError;
    use aws_smithy_runtime_api::http::StatusCode;
    use aws_smithy_types::body::SdkBody;

    fn service_error(code: &str, status: u16) -> SdkError<DecryptError, HttpResponse> {
        SdkError::service_error(
            DecryptError::generic(ErrorMetadata::builder().code(code).build()),
            HttpResponse::new(StatusCode::try_from(status).unwrap(), SdkBody::empty()),
        )
    }

    fn from_kms(err: SdkError<DecryptError, HttpResponse>) -> Error {
        Error::from_sdk(
            Service::Kms,
            "AWS KMS Decrypt",
            Some(Resource::KmsKey("arn".into())),
            err,
        )
    }

    #[test]
    fn classifies_service_errors_by_code_and_status() {
        let cases = [
            (
                "ThrottlingException",
                400,
                Kind::Throttling,
                Some(RetryKind::Throttling),
            ),
            (
                "EC2ThrottledException",
                400,
                Kind::Throttling,
                Some(RetryKind::Throttling),
            ),
            ("AccessDeniedException", 400, Kind::AccessDenied, None),
            ("ExpiredTokenException", 400, Kind::AccessDenied, None),
            ("NotFoundException", 400, Kind::ResourceNotFound, None),
            (
                "ResourceNotFoundException",
                400,
                Kind::ResourceNotFound,
                None,
            ),
            (
                "KMSInternalException",
                500,
                Kind::Service,
                Some(RetryKind::Transient),
            ),
            (
                "SomeUnlistedServerError",
                503,
                Kind::Service,
                Some(RetryKind::Server),
            ),
            ("IncorrectKeyException", 400, Kind::Service, None),
        ];
        for (code, status, kind, retry) in cases {
            let err = from_kms(service_error(code, status));
            assert_eq!(err.kind(), kind, "{code}");
            assert_eq!(err.retry_kind(), retry, "{code}");
            assert_eq!(err.code(), Some(code));
            assert_eq!(ProvideErrorMetadata::code(&err), Some(code));
            assert_eq!(err.service(), Some(Service::Kms));
            assert_eq!(err.resource(), Some(&Resource::KmsKey("arn".into())));
            assert!(
                std::error::Error::source(&err).is_some(),
                "{code}: SDK error is the source"
            );
        }
    }

    #[test]
    fn a_throttled_error_reports_the_sdk_retry_kind() {
        let err = from_kms(service_error("ThrottlingException", 400));
        assert_eq!(
            err.retryable_error_kind(),
            Some(RetryErrorKind::ThrottlingError)
        );
        assert!(err.is_throttling());
    }

    #[test]
    fn classifies_timeouts_as_retryable_dispatch_errors() {
        let err = from_kms(SdkError::<DecryptError, HttpResponse>::timeout_error(
            "timed out",
        ));
        assert!(err.is_dispatch());
        assert_eq!(err.retry_kind(), Some(RetryKind::Transient));
        assert_eq!(err.code(), None);
        assert_eq!(err.service(), Some(Service::Kms));
    }

    #[test]
    fn aggregate_kind_prefers_the_shared_kind_then_the_priority_order() {
        let e = Error::new;
        assert_eq!(Error::aggregate_kind(&[]), Kind::Internal);
        assert_eq!(
            Error::aggregate_kind(&[e(Kind::Cryptographic, "a"), e(Kind::Cryptographic, "b")]),
            Kind::Cryptographic
        );
        assert_eq!(
            Error::aggregate_kind(&[
                e(Kind::NoMatchingDataKey, "a"),
                e(Kind::Cryptographic, "b"),
                e(Kind::Throttling, "c"),
                e(Kind::AccessDenied, "d"),
            ]),
            Kind::AccessDenied
        );
        assert_eq!(
            Error::aggregate_kind(&[e(Kind::NoMatchingDataKey, "a"), e(Kind::Cryptographic, "b")]),
            Kind::Cryptographic
        );
        assert_eq!(
            Error::aggregate_kind(&[e(Kind::Validation, "a"), e(Kind::Internal, "b")]),
            Kind::Validation
        );
    }
}

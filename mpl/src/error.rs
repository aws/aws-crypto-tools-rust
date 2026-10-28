// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The error type every operation in this crate returns.
//!
//! # Handling errors
//!
//! Every keyring, CMM, key store, and cache operation returns [`Error`]:
//! a `#[non_exhaustive]` enum with one struct per variant, like an AWS SDK for Rust service error.
//! When one of these errors reaches you through the AWS Encryption SDK,
//! it has the ESDK variant of the same name.
//!
//! **Decide in two steps.**
//! 1. Check [`is_retryable`](Error::is_retryable).
//!    A retryable error might succeed if the same call is made again later,
//!    and [`retry_kind`](Error::retry_kind) says how to back off.
//! 2. Otherwise match on the variant; each variant's docs say what to do.
//!    Later releases can add variants, so a `match` needs a catch-all arm.
//!
//! **Read the details from accessors.**
//! - [`resource`](Error::resource): the resource you need to act on.
//!   The message names any other resources involved.
//!   For example, when AWS KMS denies decrypting a branch key, `resource()` is the KMS key,
//!   because the fix is a KMS permission, and the message names the branch key.
//!   A [`KmsKey`] also has the [`region`](KmsKey::region) and [`account`](KmsKey::account) of its ARN,
//!   and a [`BranchKey`] has the [`version`](BranchKey::version) the failing call was about.
//! - [`service`](Error::service): the AWS service the failed call went to.
//! - [`code`](Error::code): that service's error code.
//! - [`request_id`](Error::request_id): the ID AWS Support asks for.
//! - [`encrypted_data_keys`](NoMatchingDataKeyError::encrypted_data_keys),
//!   on a [`NoMatchingDataKey`](Error::NoMatchingDataKey) error:
//!   the message's encrypted data keys by key provider, so you can tell which keyring would decrypt it.
//!
//! **Messages are for people.**
//! [`message`](Error::message) and `Display` are for people and logs:
//! their text can change in any release, even a patch release.
//! Handle errors in your application from the variant and its accessors, never from the error message.
//!
//! ## What a minor or patch release can change
//!
//! Error handling that follows these rules keeps working across minor and patch releases.
//! Code that depends on any of the following can break in one:
//!
//! - **Message text.** Any message, and anything `{}`, `{:#}`, or `{:?}` prints, can change.
//!   Do not attempt to parse an error message string in your error handling logic.
//!   Always inspect the fields of the error structure itself.
//! - **Failures without a specific variant.** An MPL operation should only ever return [`Error`].
//!   Any non-[`Error`] (or an [`Internal`](Error::Internal) error) is a bug.
//!   A minor or patch release can turn these into an [`Error`] variant.
//! - **The shape of the source chain.** Levels can be added or removed.
//!   Reach a source with [`find_source`](Error::find_source),
//!   not by calling `source()` a fixed number of times.
//! - **Which variant a collection of failures gets.** When several failures resolve to one error,
//!   the priority between variants, and whose retry kind is kept, can change.
//!   To act on each failure, use [`failures`](Error::failures).
//! - **New variants and values.** `Error`, `Service`, `Resource`, `ConflictReason`, `RetryKind`,
//!   and `Collection` are `#[non_exhaustive]`, so every `match` needs a catch-all arm.
//!
//! **Logging.**
//! Log `{:#}`.
//! `{}` prints this error as `Variant: message (details)`;
//! `{:#}` adds each error in the source chain, leaving out what the previous one already said.
//! [`DisplayErrorContext`] prints the chain of any other error type, such as an AWS SDK error.
//!
//! **Reaching the AWS SDK error.**
//! The error from AWS KMS or DynamoDB stays in the source chain,
//! and [`find_source`](Error::find_source) returns it by type.
//! Name that type through the re-exported `aws_crypto_mpl::aws_sdk_kms` and `aws_crypto_mpl::aws_sdk_dynamodb`:
//! `find_source` matches the exact type, and a different version of an SDK crate defines different types.
//!
//! ## Key store conflicts
//!
//! `create_key` and `version_key` write conditionally.
//! When the condition fails, they return [`Conflict`](Error::Conflict),
//! and [`reason`](ConflictError::reason) says why:
//!
//! ```no_run
//! # async fn example(key_store: aws_crypto_mpl::key_store::DynamoDbKeyStore) -> Result<(), aws_crypto_mpl::Error> {
//! use aws_crypto_mpl::error::ConflictReason;
//! use aws_crypto_mpl::Error;
//!
//! match key_store.version_key().branch_key_id("my-branch-key").send().await {
//!     Ok(_) => {}
//!     // Another caller rotated the branch key first; it has a new version already.
//!     Err(Error::Conflict(e)) if e.reason() == Some(&ConflictReason::ConcurrentModification) => {}
//!     Err(e) => return Err(e),
//! }
//!
//! let create = key_store
//!     .create_key()
//!     .branch_key_id("my-branch-key")
//!     .set_encryption_context(Some(aws_crypto_mpl::types::EncryptionContext::new()));
//! match create.send().await {
//!     Ok(_) => {}
//!     // The branch key ID is in use; use the existing key or pick another ID.
//!     Err(Error::Conflict(e)) if e.reason() == Some(&ConflictReason::AlreadyExists) => {}
//!     Err(e) => return Err(e),
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Throttling
//!
//! A [`Throttling`](Error::Throttling) error is always retryable.
//! For errors from AWS KMS or DynamoDB, the AWS SDK client has already retried according to its `RetryConfig`,
//! so retry only at a higher level, with your own backoff.
//! Nothing retries materials-cache throttling for you.
//!
//! Match `Throttling` only to learn what was throttled, for example to record it:
//!
//! ```
//! # fn record_throttle(_: &str) {}
//! use aws_crypto_mpl::Error;
//! use aws_crypto_mpl::error::{Resource, Service};
//!
//! fn record(err: &Error) {
//!     if let Error::Throttling(e) = err {
//!         match e.service() {
//!             Some(Service::Kms) => record_throttle("kms"),
//!             Some(Service::DynamoDb) => record_throttle("dynamodb"),
//!             // The materials cache is not an AWS service.
//!             None => match e.resource() {
//!                 Some(Resource::Cache(_)) => record_throttle("materials-cache"),
//!                 _ => record_throttle("other"),
//!             },
//!             _ => record_throttle("other"),
//!         }
//!     }
//! }
//! ```
//!
//! ## Testing your error handling
//!
//! Every variant struct has `new` and a [builder](builders),
//! so you can construct the errors this crate returns, for example from a fake key store:
//!
//! ```
//! use aws_crypto_mpl::error::{BranchKey, ConflictError, ConflictReason, Resource, Service};
//! use aws_crypto_mpl::Error;
//!
//! let err = Error::from(
//!     ConflictError::builder()
//!         .message("branch key my-branch-key was rotated concurrently")
//!         .service(Service::DynamoDb)
//!         .resource(Resource::BranchKey(BranchKey::new("my-branch-key")))
//!         .reason(ConflictReason::ConcurrentModification)
//!         .build(),
//! );
//! assert!(!err.is_retryable());
//! ```
//!
//! Keyring and CMM authors: see [Errors for keyring and CMM authors](crate::keyring#errors-for-keyring-and-cmm-authors).

use aws_smithy_runtime_api::client::orchestrator::HttpResponse;
use aws_smithy_runtime_api::client::result::SdkError;

// `cargo xtask gen-errors` writes `generated.rs` from `errors.toml` at the repository root.
pub(crate) mod generated;

pub use generated::{
    AccessDeniedError, ConflictError, CryptographicError, DispatchError,
    EncryptionContextMismatchError, ErrorParts, InternalError, InvalidMaterialsError,
    NoMatchingDataKeyError, ResourceNotFoundError, ServiceError, ThrottlingError, ValidationError,
    builders,
};
pub(crate) use generated::{Error, Kind};

pub use aws_mpl_primitives::error::{
    BranchKey, Cache, CmmResource, Collection, ConflictReason, DataKeyInfo, DynamoDbTable,
    KeyringResource, KmsKey, Resource, RetryKind, Service,
};
pub use aws_smithy_types::error::display::DisplayErrorContext;
pub use aws_smithy_types::error::metadata::{ErrorMetadata, ProvideErrorMetadata};
pub use aws_smithy_types::retry::{ErrorKind as RetryErrorKind, ProvideErrorKind};
pub use aws_types::request_id::RequestId;

impl Error {
    /// Classify a failed AWS SDK call to `service` about `resource`.
    ///
    /// The variant, retry kind, error code, and request ID come from the SDK error,
    /// the same way this library's own keyrings and key store classify theirs.
    /// The message is "`operation` failed", and the source is the SDK error.
    ///
    /// A custom keyring or CMM that calls an AWS service returns this,
    /// so callers can match its failures by variant and [`service`](Self::service).
    #[track_caller]
    pub fn from_sdk<E>(
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

    /// Add `version` to the branch key `id` this error names, if it names that branch key without one.
    pub(crate) fn at_branch_key_version(mut self, id: &str, version: &str) -> Self {
        if let Some(Resource::BranchKey(branch_key)) = self.resource()
            && branch_key.id() == id
            && branch_key.version().is_none()
        {
            let branch_key = branch_key.clone().with_version(version);
            self.set_resource(Some(Resource::BranchKey(branch_key)));
        }
        self
    }

    /// An error for several attempts at one goal that all failed,
    /// such as a keyring trying to decrypt each encrypted data key.
    /// Any one attempt succeeding would have been enough.
    ///
    /// With exactly one error, returns it unchanged.
    /// Otherwise [`collected`](Self::collected) holds every error,
    /// [`collection`](Self::collection) is [`Collection::AllFailed`],
    /// and the result keeps each detail every attempt shares, such as `resource()`.
    ///
    /// The result's variant and retry kind:
    /// - If any attempt is retryable, the first retryable attempt's,
    ///   since retrying could make that attempt succeed.
    /// - Otherwise not retryable, with the variant every attempt shares or, for a mix,
    ///   the first present of `AccessDenied`, `ResourceNotFound`, `Throttling`, `Dispatch`,
    ///   `Service`, `InvalidMaterials`, `EncryptionContextMismatch`, `Cryptographic`, and `NoMatchingDataKey`.
    ///
    /// This rule can change in a minor or patch release.
    /// To act on each failure, use [`failures`](Self::failures).
    ///
    /// ```
    /// use aws_crypto_mpl::Error;
    /// use aws_crypto_mpl::error::Collection;
    ///
    /// let err = Error::all_failed(
    ///     "no encrypted data key could be decrypted",
    ///     vec![
    ///         Error::no_matching_data_key("encrypted data key 0 belongs to another keyring"),
    ///         Error::cryptographic("encrypted data key 1 did not decrypt"),
    ///     ],
    /// );
    /// assert!(err.is_cryptographic());
    /// assert_eq!(err.collection(), Some(Collection::AllFailed));
    /// assert_eq!(err.collected().len(), 2);
    /// ```
    #[track_caller]
    #[must_use]
    pub fn all_failed(message: impl Into<String>, errors: impl IntoIterator<Item = Self>) -> Self {
        Self::collect_failures(
            Collection::AllFailed,
            message,
            errors.into_iter().collect(),
            |errors| match errors.iter().find(|e| e.is_retryable()) {
                Some(retryable) => (retryable.kind(), retryable.retry_kind()),
                None => (Self::shared_or_priority_kind(errors.iter()), None),
            },
        )
    }

    /// An error for an operation that needed several steps to succeed;
    /// `errors` are the steps that failed, and any one failing was enough to fail it.
    ///
    /// With exactly one error, returns it unchanged.
    /// Otherwise [`collected`](Self::collected) holds every error,
    /// [`collection`](Self::collection) is [`Collection::AnyFailed`],
    /// and the result keeps each detail every step shares.
    ///
    /// The result's variant and retry kind:
    /// - If any step is not retryable, neither is the result, since retrying cannot make that step succeed.
    ///   The variant is chosen among the non-retryable steps as for [`all_failed`](Self::all_failed).
    /// - Otherwise the variant is chosen the same way among every step,
    ///   with the retry kind of the first step that has that variant.
    ///
    /// This rule can change in a minor or patch release.
    /// To act on each failure, use [`failures`](Self::failures).
    ///
    /// ```
    /// use aws_crypto_mpl::Error;
    /// use aws_crypto_mpl::error::Collection;
    ///
    /// let err = Error::any_failed(
    ///     "two keyrings could not wrap the data key",
    ///     [
    ///         Error::validation("the first keyring is misconfigured"),
    ///         Error::internal("the second keyring hit a bug"),
    ///     ],
    /// );
    /// assert!(err.is_validation());
    /// assert_eq!(err.collection(), Some(Collection::AnyFailed));
    /// ```
    #[track_caller]
    #[must_use]
    pub fn any_failed(message: impl Into<String>, errors: impl IntoIterator<Item = Self>) -> Self {
        Self::collect_failures(
            Collection::AnyFailed,
            message,
            errors.into_iter().collect(),
            |errors| {
                if errors.iter().any(|e| !e.is_retryable()) {
                    let permanent = errors.iter().filter(|e| !e.is_retryable());
                    (Self::shared_or_priority_kind(permanent), None)
                } else {
                    let kind = Self::shared_or_priority_kind(errors.iter());
                    let retry = errors
                        .iter()
                        .find(|e| e.kind() == kind)
                        .and_then(Self::retry_kind);
                    (kind, retry)
                }
            },
        )
    }

    #[track_caller]
    fn collect_failures(
        collection: Collection,
        message: impl Into<String>,
        mut errors: Vec<Self>,
        choose: impl FnOnce(&[Self]) -> (Kind, Option<RetryKind>),
    ) -> Self {
        if errors.len() == 1
            && let Some(only) = errors.pop()
        {
            return only;
        }
        if errors.is_empty() {
            return Self::new(Kind::Internal, message);
        }
        let (kind, retry) = choose(&errors);
        Self::collect(kind, retry, collection, message, errors)
    }

    /// The variant every error shares,
    /// or for a mix the first present in the order of `AGGREGATE_PRIORITY`,
    /// or else the first error's.
    pub(crate) fn shared_or_priority_kind<'a>(
        errors: impl Iterator<Item = &'a Self> + Clone,
    ) -> Kind {
        let Some(first) = errors.clone().next() else {
            return Kind::Internal;
        };
        if errors.clone().all(|e| e.kind() == first.kind()) {
            return first.kind();
        }
        AGGREGATE_PRIORITY
            .iter()
            .copied()
            .find(|k| errors.clone().any(|e| e.kind() == *k))
            .unwrap_or_else(|| first.kind())
    }
}

/// Which variant a collection of mixed errors gets: the first present.
/// The `Error::all_failed` docs list this order; keep them in sync.
/// Those docs say the order can change in a minor or patch release.
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

/// The codes the AWS SDK for Rust's retry classifier retries as throttling.
/// Keep in sync with `aws_runtime::retries::classifiers::THROTTLING_ERRORS`.
const THROTTLING_CODES: &[&str] = &[
    "Throttling",
    "ThrottlingException",
    "ThrottledException",
    "RequestThrottledException",
    "TooManyRequestsException",
    "ProvisionedThroughputExceededException",
    "TransactionInProgressException",
    "RequestLimitExceeded",
    "BandwidthLimitExceeded",
    "LimitExceededException",
    "RequestThrottled",
    "SlowDown",
    "PriorRequestNotComplete",
    "EC2ThrottledException",
];

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

#[cfg(all(test, feature = "kms"))]
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
            Some(Resource::KmsKey(KmsKey::new("arn"))),
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
            assert_eq!(err.service(), Some(&Service::Kms));
            assert_eq!(err.resource(), Some(&Resource::KmsKey(KmsKey::new("arn"))));
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
        assert_eq!(err.service(), Some(&Service::Kms));
    }

    #[test]
    fn shared_or_priority_kind_prefers_the_shared_kind_then_the_priority_order() {
        let e = Error::new;
        let k = |errors: &[Error]| Error::shared_or_priority_kind(errors.iter());
        assert_eq!(k(&[]), Kind::Internal);
        assert_eq!(
            k(&[e(Kind::Cryptographic, "a"), e(Kind::Cryptographic, "b")]),
            Kind::Cryptographic
        );
        assert_eq!(
            k(&[
                e(Kind::NoMatchingDataKey, "a"),
                e(Kind::Cryptographic, "b"),
                e(Kind::Throttling, "c"),
                e(Kind::AccessDenied, "d"),
            ]),
            Kind::AccessDenied
        );
        assert_eq!(
            k(&[e(Kind::NoMatchingDataKey, "a"), e(Kind::Cryptographic, "b")]),
            Kind::Cryptographic
        );
        assert_eq!(
            k(&[e(Kind::Validation, "a"), e(Kind::Internal, "b")]),
            Kind::Validation
        );
    }
}

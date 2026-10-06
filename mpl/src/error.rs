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
//! A [`KmsKey`] also has the [`region`](KmsKey::region) and [`account`](KmsKey::account)
//! of its ARN, and a [`BranchKey`] the [`version`](BranchKey::version) the failing call was about.
//! A [`NoMatchingDataKey`](Error::NoMatchingDataKey) error's
//! [`encrypted_data_keys`](NoMatchingDataKeyError::encrypted_data_keys) lists the message's
//! encrypted data keys by key provider, so you can tell which keyring would decrypt it.
//!
//! **Messages are for people.**
//! [`message`](Error::message) and `Display` are for people and logs,
//! and their text can change in any release.
//! Decide from the variant and its accessors, never from the message.
//!
//! ## What a minor or patch release can change
//!
//! Error handling that follows these rules keeps working across minor and patch releases.
//! Code that depends on any of the following can break in one:
//!
//! - **Message text.** Any message, and what `{}`, `{:#}` and `{:?}` print, can change.
//!   Decide from the variant and its accessors, never from the text.
//! - **Errors that are not this library's own.** An MPL operation returns only [`Error`], never any other type.
//!   A failure that reaches you any other way is a bug:
//!   a panic, an [`Internal`](Error::Internal) error,
//!   or a failure you can only recognize by a type in its source chain.
//!   A minor or patch release can turn it into a specific variant,
//!   so handle it in the catch-all arm rather than matching on it.
//! - **The shape of the source chain.** Levels can be added or removed.
//!   Reach a source with [`find_source`](Error::find_source),
//!   not by calling `source()` a fixed number of times.
//! - **Which variant a collection of failures gets.** When several failures resolve to one error,
//!   the priority order between variants, and whose retry kind is kept, can change.
//!   To act on each failure, use [`failures`](Error::failures).
//! - **New variants and values.** `Error`, `Service`, `Resource`, `ConflictReason`, `RetryKind`
//!   and `Collection` are `#[non_exhaustive]`, so every `match` needs a catch-all arm.
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
//!     Err(Error::Conflict(e)) if e.reason() == Some(&ConflictReason::ConcurrentModification) => Ok(()),
//!     other => other,
//! }?;
//!
//! match store.create_key(Some("my-branch-key".into()), Some(Default::default())).await {
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
//!             (None, Some(Resource::Cache(_))) => record_throttle("materials-cache"),
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
//! use aws_crypto_mpl::error::{BranchKey, ConflictError, ConflictReason, Error, Resource, Service};
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
//!
//! [`Error`] and its variant structs are generated from `errors.toml`
//! at the repository root by `cargo xtask gen-errors`.

use aws_sdk_kms::config::http::HttpResponse;
use aws_sdk_kms::error::SdkError;

mod generated;

pub use generated::*;

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

    /// An error for several attempts at the same goal, every one of which failed,
    /// such as a keyring's attempt to decrypt each encrypted data key.
    /// Any one attempt succeeding would have been enough.
    ///
    /// With exactly one error, returns it unchanged.
    /// Otherwise [`collected`](Self::collected) holds every error and
    /// [`collection`](Self::collection) is [`Collection::AllFailed`].
    /// If any attempt is retryable, the result takes the first retryable attempt's variant and retry kind,
    /// since retrying could make that attempt succeed.
    /// Otherwise the variant is the one every attempt shares or, for a mix,
    /// the first present of `AccessDenied`, `ResourceNotFound`, `Throttling`, `Dispatch`,
    /// `Service`, `InvalidMaterials`, `EncryptionContextMismatch`, `Cryptographic`,
    /// and `NoMatchingDataKey`, and the result is not retryable.
    /// Each detail every attempt shares, such as `resource()`, is kept.
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
    /// The rule that picks the variant and retry kind can change in a minor or patch release;
    /// callers that act on each failure use [`failures`](Self::failures).
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

    /// An error for several steps an operation needed, where any one failing was enough to fail it,
    /// and `errors` are the steps that failed.
    ///
    /// With exactly one error, returns it unchanged.
    /// Otherwise [`collected`](Self::collected) holds every error and
    /// [`collection`](Self::collection) is [`Collection::AnyFailed`].
    /// If any step is not retryable, the result is not retryable and takes the variant of the
    /// non-retryable steps, chosen as for [`all_failed`](Self::all_failed), since retrying cannot make
    /// that step succeed.
    /// Otherwise the variant is chosen the same way among every step, with that step's retry kind.
    /// Each detail every step shares is kept.
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
    /// The rule that picks the variant and retry kind can change in a minor or patch release;
    /// callers that act on each failure use [`failures`](Self::failures).
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
/// Documented as changeable in a minor or patch release.
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

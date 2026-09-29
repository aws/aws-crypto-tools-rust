// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The error type every operation in this crate returns.

use std::backtrace::Backtrace;
use std::fmt;
use std::sync::Arc;

use aws_sdk_kms::config::http::HttpResponse;
use aws_sdk_kms::error::{ProvideErrorMetadata, SdkError};

/// What went wrong, as a caller would act on it.
///
/// Which component failed, and the underlying service or library error, are in
/// [`Error::message`] and [`std::error::Error::source`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// An input or configuration value is invalid.
    Validation,
    /// The materials, or the request for them, are inconsistent with each
    /// other or with the algorithm suite.
    InvalidMaterials,
    /// A required encryption context key is missing, or a caller-supplied
    /// encryption context value differs from the one being checked.
    EncryptionContextMismatch,
    /// No configured key wrapped any of the encrypted data keys.
    NoMatchingDataKey,
    /// A cryptographic check failed, such as an AES-GCM tag or a branch key's
    /// authentication.
    Cryptographic,
    /// A remote service denied access to a resource.
    RemoteAccessDenied,
    /// A remote resource, such as a KMS key, DynamoDB table, or branch key,
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

impl ErrorKind {
    const fn retryable_by_default(self) -> bool {
        matches!(self, Self::RemoteThrottled | Self::RemoteTransport)
    }
}

/// An error from a keyring, CMM, key store, or cache.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Error {
    kind: ErrorKind,
    message: String,
    retryable: bool,
    cause: Option<Arc<dyn std::error::Error + Send + Sync + 'static>>,
    collected: Vec<Error>,
    backtrace: Arc<Backtrace>,
}

impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        // `cause` is excluded because `dyn Error` does not implement `Eq`.
        self.kind == other.kind
            && self.message == other.message
            && self.retryable == other.retryable
            && self.collected == other.collected
    }
}
impl Eq for Error {}

impl Error {
    /// Construct an error of `kind`.
    #[track_caller]
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self::build(kind, message.into(), kind.retryable_by_default(), None)
    }

    /// Construct an error of `kind` caused by `cause`, which
    /// [`std::error::Error::source`] returns.
    #[track_caller]
    pub fn with_cause(
        kind: ErrorKind,
        message: impl Into<String>,
        cause: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::build(
            kind,
            message.into(),
            kind.retryable_by_default(),
            Some(Arc::new(cause)),
        )
    }

    /// Add context to `inner`, keeping its kind and retryability.
    /// `inner` becomes the [`std::error::Error::source`].
    #[track_caller]
    pub fn wrap(message: impl Into<String>, inner: Self) -> Self {
        Self::build(
            inner.kind,
            message.into(),
            inner.retryable,
            Some(Arc::new(inner)),
        )
    }

    /// Construct an error of `kind` that carries every failure collected while
    /// attempting an operation that ultimately failed, such as a keyring
    /// trying each encrypted data key.
    ///
    /// `message` describes the overall failure; [`fmt::Display`] renders the
    /// collected errors after it. A single collected failure is also the
    /// [`std::error::Error::source`].
    #[track_caller]
    pub fn collection(kind: ErrorKind, message: impl Into<String>, collected: Vec<Self>) -> Self {
        debug_assert!(
            !collected.is_empty(),
            "an aggregate must collect at least one failure; an operation with \
             nothing to report should use Error::new",
        );
        let cause = match collected.as_slice() {
            [only] => {
                Some(Arc::new(only.clone()) as Arc<dyn std::error::Error + Send + Sync + 'static>)
            }
            _ => None,
        };
        let retryable = !collected.is_empty() && collected.iter().all(|e| e.retryable);
        Self {
            collected,
            ..Self::build(kind, message.into(), retryable, cause)
        }
    }

    /// The kind every error in `errors` shares, if there is one.
    pub(crate) fn common_kind(errors: &[Self]) -> Option<ErrorKind> {
        let (first, rest) = errors.split_first()?;
        rest.iter()
            .all(|e| e.kind == first.kind)
            .then_some(first.kind)
    }

    /// Classify a failed AWS SDK call, naming the failed `operation` in the
    /// message. The SDK error is the [`std::error::Error::source`].
    #[track_caller]
    pub(crate) fn from_sdk<E>(operation: &str, err: SdkError<E, HttpResponse>) -> Self
    where
        E: ProvideErrorMetadata + std::error::Error + Send + Sync + 'static,
    {
        let (kind, retryable) = classify_sdk_error(&err);
        Self::build(
            kind,
            format!("{operation} failed"),
            retryable,
            Some(Arc::new(err)),
        )
    }

    #[track_caller]
    fn build(
        kind: ErrorKind,
        message: String,
        retryable: bool,
        cause: Option<Arc<dyn std::error::Error + Send + Sync + 'static>>,
    ) -> Self {
        Self {
            kind,
            message,
            retryable,
            cause,
            collected: Vec::new(),
            backtrace: Arc::new(Backtrace::capture()),
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

    /// The failures collected by an operation that tried several things,
    /// such as a keyring trying each encrypted data key. Empty otherwise.
    #[must_use]
    pub fn collected(&self) -> &[Self] {
        &self.collected
    }

    /// The backtrace captured when this error was created.
    pub fn backtrace(&self) -> &Backtrace {
        &self.backtrace
    }
}

// Codes from the AWS SDK for Rust's own retry classifier
// (aws-runtime `retries::classifiers`), plus the service-side failures
// AWS KMS and DynamoDB document as transient.
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
];
const TRANSIENT_CODES: &[&str] = &[
    "RequestTimeout",
    "RequestTimeoutException",
    "KMSInternalException",
    "KeyUnavailableException",
    "DependencyTimeoutException",
    "InternalServerError",
    "ServiceUnavailable",
];
const ACCESS_DENIED_CODES: &[&str] = &[
    "AccessDeniedException",
    "UnrecognizedClientException",
    "InvalidSignatureException",
    "ExpiredTokenException",
    "InvalidGrantTokenException",
];
const NOT_FOUND_CODES: &[&str] = &["NotFoundException", "ResourceNotFoundException"];

fn classify_sdk_error<E: ProvideErrorMetadata>(
    err: &SdkError<E, HttpResponse>,
) -> (ErrorKind, bool) {
    match err {
        SdkError::ConstructionFailure(_) => (ErrorKind::Internal, false),
        SdkError::TimeoutError(_) => (ErrorKind::RemoteTransport, true),
        SdkError::DispatchFailure(failure) => {
            // Missing credentials or region surface here as user or other
            // connector errors; retrying cannot fix those.
            let transient = failure.is_io() || failure.is_timeout();
            (ErrorKind::RemoteTransport, transient)
        }
        SdkError::ResponseError(_) => (ErrorKind::Remote, true),
        SdkError::ServiceError(ctx) => {
            let code = ctx.err().code().unwrap_or_default();
            if THROTTLING_CODES.contains(&code) {
                (ErrorKind::RemoteThrottled, true)
            } else if ACCESS_DENIED_CODES.contains(&code) {
                (ErrorKind::RemoteAccessDenied, false)
            } else if NOT_FOUND_CODES.contains(&code) {
                (ErrorKind::RemoteResourceNotFound, false)
            } else {
                let transient =
                    TRANSIENT_CODES.contains(&code) || ctx.raw().status().is_server_error();
                (ErrorKind::Remote, transient)
            }
        }
        _ => (ErrorKind::Remote, false),
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.message)?;
        if let [first, rest @ ..] = self.collected.as_slice() {
            write!(f, " (collected errors: [{first}")?;
            for err in rest {
                write!(f, "; {err}")?;
            }
            f.write_str("])")?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cause
            .as_ref()
            .map(|c| c.as_ref() as &(dyn std::error::Error + 'static))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_kms::error::ErrorMetadata;
    use aws_sdk_kms::operation::decrypt::DecryptError;
    use aws_smithy_runtime_api::http::StatusCode;
    use aws_smithy_types::body::SdkBody;

    fn service_error(code: &str, status: u16) -> SdkError<DecryptError, HttpResponse> {
        SdkError::service_error(
            DecryptError::generic(ErrorMetadata::builder().code(code).build()),
            HttpResponse::new(StatusCode::try_from(status).unwrap(), SdkBody::empty()),
        )
    }

    #[test]
    fn classifies_service_errors_by_code_and_status() {
        let cases = [
            ("ThrottlingException", 400, ErrorKind::RemoteThrottled, true),
            (
                "AccessDeniedException",
                400,
                ErrorKind::RemoteAccessDenied,
                false,
            ),
            (
                "NotFoundException",
                400,
                ErrorKind::RemoteResourceNotFound,
                false,
            ),
            (
                "ResourceNotFoundException",
                400,
                ErrorKind::RemoteResourceNotFound,
                false,
            ),
            ("KMSInternalException", 500, ErrorKind::Remote, true),
            ("SomeUnlistedServerError", 503, ErrorKind::Remote, true),
            ("IncorrectKeyException", 400, ErrorKind::Remote, false),
        ];
        for (code, status, kind, retryable) in cases {
            let err = Error::from_sdk("AWS KMS Decrypt", service_error(code, status));
            assert_eq!(err.kind(), kind, "{code}");
            assert_eq!(err.is_retryable(), retryable, "{code}");
            assert_eq!(err.message(), "AWS KMS Decrypt failed");
            assert!(
                std::error::Error::source(&err).is_some(),
                "{code}: SDK error is the source"
            );
        }
    }

    #[test]
    fn classifies_timeouts_as_retryable_transport_errors() {
        let err = Error::from_sdk(
            "AWS KMS Decrypt",
            SdkError::<DecryptError, HttpResponse>::timeout_error("timed out"),
        );
        assert_eq!(err.kind(), ErrorKind::RemoteTransport);
        assert!(err.is_retryable());
    }
}

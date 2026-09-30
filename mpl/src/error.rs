// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The error type every operation in this crate returns.

use aws_sdk_kms::config::http::HttpResponse;
use aws_sdk_kms::error::{ProvideErrorMetadata, SdkError};

aws_mpl_primitives::define_error! {
    /// An error from a keyring, CMM, key store, or cache.
    ///
    /// The message says what failed.
    /// The [`source`](std::error::Error::source) chain holds the underlying service or library error.
    Error,
    /// What went wrong, as a caller would act on it.
    ErrorKind;
}

impl Error {
    /// Classify a failed AWS SDK call by its error code.
    /// The message names `operation`, and the SDK error becomes the source.
    #[track_caller]
    pub(crate) fn from_sdk<E>(operation: &str, err: SdkError<E, HttpResponse>) -> Self
    where
        E: ProvideErrorMetadata + std::error::Error + Send + Sync + 'static,
    {
        let (kind, retryable) = classify_sdk_error(&err);
        let mut error = Self::with_cause(kind, format!("{operation} failed"), err);
        error.set_retryable(retryable);
        error
    }

    /// The kind for an error that aggregates `errors`.
    ///
    /// The shared kind when they all agree.
    /// Otherwise the kind of the first retryable one, so a caller still sees a retryable kind.
    /// Otherwise `fallback`.
    pub(crate) fn aggregate_kind(errors: &[Self], fallback: ErrorKind) -> ErrorKind {
        let Some((first, rest)) = errors.split_first() else {
            return fallback;
        };
        if rest.iter().all(|e| e.kind() == first.kind()) {
            return first.kind();
        }
        errors
            .iter()
            .find(|e| e.is_retryable())
            .map_or(fallback, Self::kind)
    }
}

// Codes the AWS SDK for Rust's retry classifier (aws-runtime `retries::classifiers`) retries,
// plus the failures AWS KMS and DynamoDB document as transient.
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
            // Missing credentials or region arrive as user or other connector errors,
            // which retrying cannot fix.
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
            assert!(
                std::error::Error::source(&err).is_some(),
                "{code}: SDK error is the source"
            );
        }
    }

    #[test]
    fn aggregate_kind_prefers_the_shared_kind_then_a_retryable_one() {
        let tag = Error::new(ErrorKind::Cryptographic, "tag");
        let throttled = Error::new(ErrorKind::RemoteThrottled, "throttled");
        let denied = Error::new(ErrorKind::RemoteAccessDenied, "denied");
        let f = ErrorKind::Internal;
        assert_eq!(Error::aggregate_kind(&[], f), f);
        assert_eq!(
            Error::aggregate_kind(&[tag.clone(), tag.clone()], f),
            ErrorKind::Cryptographic
        );
        assert_eq!(
            Error::aggregate_kind(&[tag.clone(), throttled], f),
            ErrorKind::RemoteThrottled
        );
        assert_eq!(Error::aggregate_kind(&[tag, denied], f), f);
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

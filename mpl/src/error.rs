// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The error type every operation in this crate returns.

use std::sync::Arc;

use aws_mpl_primitives::error::RemoteInfo;
use aws_sdk_kms::config::http::HttpResponse;
use aws_sdk_kms::error::SdkError;

pub use aws_mpl_primitives::error::{
    DisplayErrorContext, ErrorBuilder, Resource, RetryKind, Service,
};
pub use aws_sdk_kms::error::{ErrorMetadata, ProvideErrorMetadata};
pub use aws_sdk_kms::operation::RequestId;
pub use aws_smithy_types::retry::{ErrorKind as RetryErrorKind, ProvideErrorKind};

aws_mpl_primitives::define_error! {
    /// An error from a keyring, CMM, key store, or cache.
    ///
    /// The message says what failed.
    /// The [`source`](std::error::Error::source) chain holds the underlying service or library error.
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
        Internal(InternalError, is_internal),
    }
    sdk(aws_smithy_types, aws_sdk_kms::operation::RequestId);
}

impl Error {
    /// Classify a failed AWS SDK call to `service` about `resource`.
    /// The message names `operation`, and the SDK error becomes the source.
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
        let mut remote = RemoteInfo::new(service, resource);
        let meta = err.as_service_error().map(|e| e.meta().clone());
        remote.code = meta.as_ref().and_then(|m| m.code()).map(str::to_owned);
        remote.request_id = err.request_id().map(str::to_owned);
        let mut error = Self::with_cause(kind, format!("{operation} failed"), err);
        error.set_retry(retry);
        if kind != Kind::Internal {
            error.set_remote(remote);
        }
        if let Some(meta) = meta {
            error.set_sdk_meta(Arc::new(meta));
        }
        error
    }

    /// Name the AWS `service` and `resource` this error is about.
    #[must_use]
    pub(crate) fn about(mut self, service: Service, resource: Option<Resource>) -> Self {
        self.set_remote(RemoteInfo::new(service, resource));
        self
    }

    /// The kind for an error that aggregates `errors`.
    ///
    /// The shared kind when they all agree.
    /// Otherwise the kind of the first retryable one, so a caller still sees a retryable kind.
    /// Otherwise `fallback`.
    pub(crate) fn aggregate_kind(errors: &[Self], fallback: Kind) -> Kind {
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
                (Kind::Service, Some(RetryKind::Throttling))
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
                Kind::Service,
                Some(RetryKind::Throttling),
            ),
            ("AccessDeniedException", 400, Kind::AccessDenied, None),
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
            assert_eq!(err.__retry_kind(), retry, "{code}");
            assert_eq!(err.code(), Some(code));
            assert_eq!(ProvideErrorMetadata::code(&err), Some(code));
            let remote = err.__remote().expect("a service error is remote");
            assert_eq!(remote.service, Service::Kms);
            assert_eq!(remote.resource, Some(Resource::KmsKey("arn".into())));
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
        assert!(err.is_retryable());
    }

    #[test]
    fn classifies_timeouts_as_retryable_dispatch_errors() {
        let err = from_kms(SdkError::<DecryptError, HttpResponse>::timeout_error(
            "timed out",
        ));
        assert!(err.is_dispatch());
        assert!(err.is_retryable());
        assert_eq!(err.code(), None);
    }

    #[test]
    fn aggregate_kind_prefers_the_shared_kind_then_a_retryable_one() {
        let tag = || Error::new(Kind::Cryptographic, "tag");
        let mut throttled = Error::new(Kind::Service, "throttled");
        throttled.set_retry(Some(RetryKind::Throttling));
        let denied = Error::new(Kind::AccessDenied, "denied");
        let f = Kind::Internal;
        assert_eq!(Error::aggregate_kind(&[], f), f);
        assert_eq!(
            Error::aggregate_kind(&[tag(), tag()], f),
            Kind::Cryptographic
        );
        assert_eq!(Error::aggregate_kind(&[tag(), throttled], f), Kind::Service);
        assert_eq!(Error::aggregate_kind(&[tag(), denied], f), f);
    }
}

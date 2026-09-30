// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The error shape every AWS Crypto Tools library shares.
//!
//! A library defines its own `Error` enum with [`define_error!`](crate::define_error).
//! Each variant holds a struct for that kind of failure, the way an AWS SDK for Rust
//! service error holds one struct per modeled exception.

use std::any::Any;
use std::backtrace::Backtrace;
use std::fmt;
use std::sync::Arc;

/// The AWS service a remote error came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Service {
    /// AWS Key Management Service.
    Kms,
    /// Amazon `DynamoDB`.
    DynamoDb,
}

/// The AWS resource a remote error is about.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Resource {
    /// A KMS key, by ARN.
    KmsKey(String),
    /// A `DynamoDB` table, by name.
    DynamoDbTable(String),
    /// A hierarchical keyring branch key, by ID.
    BranchKey(String),
}

/// Why an error might succeed if the same call is made again later.
///
/// Mirrors `aws_smithy_types::retry::ErrorKind`,
/// which libraries that use the AWS SDK return from `ProvideErrorKind::retryable_error_kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RetryKind {
    /// A connection-level failure, such as a timeout.
    Transient,
    /// The service throttled the request.
    Throttling,
    /// The service failed on its side.
    Server,
    /// The request failed but a retry can succeed.
    Client,
}

/// The AWS call behind a remote error.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RemoteInfo {
    pub service: Service,
    pub resource: Option<Resource>,
    pub code: Option<String>,
    pub request_id: Option<String>,
}

impl RemoteInfo {
    #[must_use]
    pub const fn new(service: Service, resource: Option<Resource>) -> Self {
        Self {
            service,
            resource,
            code: None,
            request_id: None,
        }
    }
}

/// The variants every library shares, by name.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[expect(clippy::exhaustive_structs)]
pub struct BaseVariant(pub &'static str);

/// The fields behind every variant struct.
#[doc(hidden)]
#[non_exhaustive]
pub struct ErrorCore<E> {
    pub message: String,
    pub retry: Option<RetryKind>,
    pub remote: Option<RemoteInfo>,
    /// The AWS SDK's `ErrorMetadata` for a remote error, stored untyped so this crate has no SDK dependency.
    pub sdk_meta: Option<Arc<dyn Any + Send + Sync>>,
    pub source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    pub collected: Vec<E>,
    pub backtrace: Backtrace,
}

impl<E: std::error::Error + 'static> ErrorCore<E> {
    #[track_caller]
    #[must_use]
    pub fn new(message: String) -> Self {
        Self {
            message,
            retry: None,
            remote: None,
            sdk_meta: None,
            source: None,
            collected: Vec::new(),
            backtrace: Backtrace::capture(),
        }
    }

    pub fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(source) = &self.source {
            let source: &(dyn std::error::Error + 'static) = source.as_ref();
            return Some(source);
        }
        match self.collected.as_slice() {
            [only] => Some(only),
            _ => None,
        }
    }
}

impl<E: fmt::Debug> fmt::Debug for ErrorCore<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("ErrorCore");
        self.debug_fields(&mut d);
        d.finish()
    }
}

impl<E: fmt::Debug> ErrorCore<E> {
    pub fn debug_fields(&self, d: &mut fmt::DebugStruct<'_, '_>) {
        d.field("message", &self.message);
        if let Some(retry) = &self.retry {
            d.field("retry", retry);
        }
        if let Some(remote) = &self.remote {
            d.field("remote", remote);
        }
        if let Some(source) = &self.source {
            d.field("source", source);
        }
        if !self.collected.is_empty() {
            d.field("collected", &self.collected);
        }
    }
}

/// Builds an error of kind `T`.
///
/// Get one from `T::builder()`, for example `ValidationError::builder()`.
#[must_use]
pub struct ErrorBuilder<T> {
    message: Option<String>,
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    retry: Option<RetryKind>,
    remote: Option<RemoteInfo>,
    _kind: std::marker::PhantomData<fn() -> T>,
}

impl<T> fmt::Debug for ErrorBuilder<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ErrorBuilder")
            .field("message", &self.message)
            .field("retry", &self.retry)
            .field("remote", &self.remote)
            .finish_non_exhaustive()
    }
}

#[doc(hidden)]
pub trait FromParts: Sized {
    #[track_caller]
    fn from_parts(
        message: String,
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
        retry: Option<RetryKind>,
        remote: Option<RemoteInfo>,
    ) -> Self;
}

/// An error struct that describes an AWS call.
#[doc(hidden)]
pub trait RemoteKind {}

impl<T> ErrorBuilder<T> {
    #[doc(hidden)]
    pub const fn new() -> Self {
        Self {
            message: None,
            source: None,
            retry: None,
            remote: None,
            _kind: std::marker::PhantomData,
        }
    }

    /// What went wrong, for people and logs.
    pub fn message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }

    /// The error that caused this one, which [`source`](std::error::Error::source) returns.
    pub fn source(mut self, source: impl std::error::Error + Send + Sync + 'static) -> Self {
        self.source = Some(Box::new(source));
        self
    }

    /// Mark the error retryable, and why.
    pub const fn retry_kind(mut self, retry: RetryKind) -> Self {
        self.retry = Some(retry);
        self
    }
}

impl<T: RemoteKind> ErrorBuilder<T> {
    /// The AWS service the failed call went to.
    pub fn service(mut self, service: Service) -> Self {
        self.remote
            .get_or_insert_with(|| RemoteInfo::new(service, None))
            .service = service;
        self
    }

    /// The AWS resource the failed call was about.
    ///
    /// Takes effect only after [`service`](Self::service).
    pub fn resource(mut self, resource: Resource) -> Self {
        if let Some(remote) = &mut self.remote {
            remote.resource = Some(resource);
        }
        self
    }
}

impl<T: FromParts> ErrorBuilder<T> {
    /// Build the error.
    #[track_caller]
    #[must_use]
    pub fn build(self) -> T {
        T::from_parts(
            self.message.unwrap_or_default(),
            self.source,
            self.retry,
            self.remote,
        )
    }
}

/// A library's `Error`, as another library's `Error` sees it when wrapping it.
#[doc(hidden)]
pub trait LibraryError: std::error::Error + Send + Sync + 'static {
    fn base_variant(&self) -> BaseVariant;
    fn retry(&self) -> Option<RetryKind>;
    fn remote(&self) -> Option<&RemoteInfo>;
    fn sdk_meta(&self) -> Option<Arc<dyn Any + Send + Sync>>;
}

/// Shared-variant docs, looked up by variant name.
#[doc(hidden)]
#[macro_export]
macro_rules! __error_doc {
    (Validation) => {
        "An input or configuration value is invalid,\n\
         for example an input with no keyring or CMM, a zero TTL, or a wrapping key of the wrong length.\n\n\
         Fix the input; the same call cannot succeed."
    };
    (InvalidMaterials) => {
        "A keyring or CMM returned materials inconsistent with each other or with the algorithm suite,\n\
         for example no plaintext data key after encryption, or a signing key for a suite that does not sign.\n\n\
         Usually a bug in a custom keyring or CMM."
    };
    (EncryptionContextMismatch) => {
        "An encryption context does not match,\n\
         for example a required key is missing, or a value passed to decrypt differs from the message's.\n\n\
         Check the encryption context passed to the call."
    };
    (NoMatchingDataKey) => {
        "None of the configured keys wrapped any of the message's encrypted data keys,\n\
         for example when decrypting with a keyring that did not encrypt the message.\n\n\
         Decrypt with a keyring that has one of the message's keys."
    };
    (Cryptographic) => {
        "A cryptographic check failed,\n\
         for example an AES-GCM authentication tag or a message signature did not verify.\n\n\
         The message is corrupt or modified, or is being decrypted with the wrong key;\n\
         retrying cannot succeed."
    };
    (Internal) => {
        "An internal invariant was violated, for example a poisoned lock.\n\n\
         A bug; report it."
    };
    (AccessDenied) => {
        "AWS KMS or DynamoDB denied access,\n\
         for example because of missing IAM permissions or expired credentials.\n\n\
         Fix the permissions or credentials for the `service` and `resource`."
    };
    (ResourceNotFound) => {
        "A KMS key, DynamoDB table, or branch key does not exist.\n\n\
         Fix the configuration that names the `resource`."
    };
    (Service) => {
        "AWS KMS or DynamoDB rejected or failed the request for any other reason,\n\
         for example throttling, an internal service error, or a KMS `IncorrectKeyException`.\n\n\
         `code` is the service's error code.\n\
         A throttled or server-side failure is retryable."
    };
    (Dispatch) => {
        "A request to AWS KMS or DynamoDB was not sent, or its response did not arrive,\n\
         for example because of a network error, a timeout, or missing credentials or region.\n\n\
         Retryable for a network error or timeout."
    };
    ($other:ident) => {
        ""
    };
}

/// Define a library's `Error` enum and one struct per variant.
///
/// Each variant is `Name(NameError, is_name)`, plus `, remote` for a variant that describes an AWS call.
/// The optional `sdk(aws_smithy_types, RequestIdTrait);` line implements the AWS SDK for Rust's
/// `ProvideErrorMetadata`, `ProvideErrorKind`, and `RequestId` traits.
/// Every library must have an `Internal` variant.
///
/// ```ignore
/// aws_mpl_primitives::define_error! {
///     /// Docs for the error type.
///     pub enum Error {
///         Validation(ValidationError, is_validation),
///         AccessDenied(AccessDeniedError, is_access_denied, remote),
///         Internal(InternalError, is_internal),
///     }
///     sdk(aws_smithy_types, aws_sdk_kms::operation::RequestId);
/// }
/// ```
#[macro_export]
macro_rules! define_error {
    (
        $(#[$err_meta:meta])*
        pub enum $error:ident {
            $( $(#[$v_meta:meta])* $variant:ident($strukt:ident, $is:ident $(, $remote:ident)?), )*
        }
        $( sdk($smithy:ident, $request_id:path); )?
    ) => {
        $(#[$err_meta])*
        ///
        /// Match on the variant to decide what to do,
        /// and check [`is_retryable`](Self::is_retryable) first:
        /// a retryable error might succeed if the same call is made again later.
        /// Later releases can add variants, so a `match` needs a catch-all arm.
        ///
        /// Messages are for people, not code.
        /// Their text can change in any release, including a minor or patch release.
        /// Decide from the variant and its fields, never from the message.
        #[derive(Debug)]
        #[non_exhaustive]
        pub enum $error {
            $(
                $(#[$v_meta])*
                #[doc = $crate::__error_doc!($variant)]
                $variant($strukt),
            )*
        }

        /// Which variant an error is, for this crate's own constructors.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        #[allow(dead_code, clippy::enum_variant_names)]
        pub(crate) enum Kind {
            $( $variant, )*
        }

        #[allow(dead_code, clippy::same_name_method)]
        impl $error {
            #[track_caller]
            fn from_core(kind: Kind, core: $crate::error::ErrorCore<$error>) -> Self {
                match kind {
                    $( Kind::$variant => Self::$variant($strukt { core: Box::new(core) }), )*
                }
            }

            fn core(&self) -> &$crate::error::ErrorCore<$error> {
                match self {
                    $( Self::$variant(e) => &*e.core, )*
                }
            }

            fn core_mut(&mut self) -> &mut $crate::error::ErrorCore<$error> {
                match self {
                    $( Self::$variant(e) => &mut *e.core, )*
                }
            }

            /// Construct an error of `kind`.
            /// It is retryable only if the kind's retry defaults say so.
            #[track_caller]
            pub(crate) fn new(kind: Kind, message: impl Into<String>) -> Self {
                Self::from_core(kind, $crate::error::ErrorCore::new(message.into()))
            }

            /// Like [`new`](Self::new), with `cause` as the source.
            #[track_caller]
            pub(crate) fn with_cause(
                kind: Kind,
                message: impl Into<String>,
                cause: impl std::error::Error + Send + Sync + 'static,
            ) -> Self {
                let mut core = $crate::error::ErrorCore::new(message.into());
                core.source = Some(Box::new(cause));
                Self::from_core(kind, core)
            }

            /// Add context to `inner`, keeping its variant, retryability, and AWS details.
            #[track_caller]
            pub(crate) fn wrap(message: impl Into<String>, inner: Self) -> Self {
                let kind = inner.kind();
                let mut core = $crate::error::ErrorCore::new(message.into());
                core.retry = inner.core().retry;
                core.remote = inner.core().remote.clone();
                core.sdk_meta = inner.core().sdk_meta.clone();
                core.source = Some(Box::new(inner));
                Self::from_core(kind, core)
            }

            /// Construct an error of `kind` that carries the failures behind it.
            /// With exactly one, it is also the source.
            /// The error is retryable if any collected failure is.
            #[track_caller]
            pub(crate) fn collection(
                kind: Kind,
                message: impl Into<String>,
                collected: Vec<Self>,
            ) -> Self {
                debug_assert!(!collected.is_empty(), "a collection must hold at least one failure");
                let mut core = $crate::error::ErrorCore::new(message.into());
                core.retry = collected.iter().find_map(|e| e.core().retry);
                core.collected = collected;
                Self::from_core(kind, core)
            }

            /// Convert another library's error into this library's error.
            /// `message` says what this library was doing.
            /// The variant is the one with the same name, or `Internal` if this library has none.
            #[track_caller]
            pub(crate) fn from_inner(
                message: impl Into<String>,
                inner: impl $crate::error::LibraryError,
            ) -> Self {
                let name = inner.base_variant().0;
                let kind = [$( (stringify!($variant), Kind::$variant), )*]
                    .into_iter()
                    .find_map(|(n, k)| (n == name).then_some(k))
                    .unwrap_or(Kind::Internal);
                let mut core = $crate::error::ErrorCore::new(message.into());
                core.retry = inner.retry();
                core.remote = inner.remote().cloned();
                core.sdk_meta = inner.sdk_meta();
                core.source = Some(Box::new(inner));
                Self::from_core(kind, core)
            }

            pub(crate) const fn kind(&self) -> Kind {
                match self {
                    $( Self::$variant(_) => Kind::$variant, )*
                }
            }

            pub(crate) fn set_retry(&mut self, retry: Option<$crate::error::RetryKind>) {
                self.core_mut().retry = retry;
            }

            pub(crate) fn set_remote(&mut self, remote: $crate::error::RemoteInfo) {
                self.core_mut().remote = Some(remote);
            }

            pub(crate) fn set_sdk_meta(&mut self, meta: std::sync::Arc<dyn std::any::Any + Send + Sync>) {
                self.core_mut().sdk_meta = Some(meta);
            }

            /// This error's message, without its sources.
            /// For people and logs: the text can change in any release.
            #[must_use]
            pub fn message(&self) -> &str {
                &self.core().message
            }

            /// Whether the same call might succeed if retried.
            #[must_use]
            pub fn is_retryable(&self) -> bool {
                self.core().retry.is_some()
            }

            /// The failures behind an error that aggregates several,
            /// such as a keyring's failure for each encrypted data key it tried.
            /// Empty for any other error.
            #[must_use]
            pub fn collected(&self) -> &[Self] {
                &self.core().collected
            }

            /// The backtrace captured when this error was created.
            /// Disabled unless `RUST_BACKTRACE` or `RUST_LIB_BACKTRACE` is set.
            pub fn backtrace(&self) -> &std::backtrace::Backtrace {
                &self.core().backtrace
            }

            /// Why the error might succeed if retried, if it might.
            #[doc(hidden)]
            #[must_use]
            pub fn __retry_kind(&self) -> Option<$crate::error::RetryKind> {
                self.core().retry
            }

            /// The AWS call behind a remote error.
            #[doc(hidden)]
            #[must_use]
            pub fn __remote(&self) -> Option<&$crate::error::RemoteInfo> {
                self.core().remote.as_ref()
            }

            $(
                #[doc = concat!("Whether this is a [`", stringify!($variant), "`](Self::", stringify!($variant), ") error.")]
                #[must_use]
                pub const fn $is(&self) -> bool {
                    matches!(self, Self::$variant(_))
                }
            )*
        }

        impl std::fmt::Display for $error {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    $( Self::$variant(e) => std::fmt::Display::fmt(e, f), )*
                }
            }
        }

        impl std::error::Error for $error {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                self.core().source()
            }
        }

        impl $crate::error::LibraryError for $error {
            fn base_variant(&self) -> $crate::error::BaseVariant {
                match self {
                    $( Self::$variant(_) => $crate::error::BaseVariant(stringify!($variant)), )*
                }
            }

            fn retry(&self) -> Option<$crate::error::RetryKind> {
                self.core().retry
            }

            fn remote(&self) -> Option<&$crate::error::RemoteInfo> {
                self.core().remote.as_ref()
            }

            fn sdk_meta(&self) -> Option<std::sync::Arc<dyn std::any::Any + Send + Sync>> {
                self.core().sdk_meta.clone()
            }
        }

        $(
            $crate::define_error!(@struct $error, $variant, $strukt, [$($remote)?]);
        )*

        $( $crate::define_error!(@sdk $error, $smithy, $request_id); )?
    };

    (@struct $error:ident, $variant:ident, $strukt:ident, [$($remote:ident)?]) => {
        #[doc = $crate::__error_doc!($variant)]
        pub struct $strukt {
            core: Box<$crate::error::ErrorCore<$error>>,
        }

        impl $strukt {
            /// Construct this error with `message`.
            #[track_caller]
            pub fn new(message: impl Into<String>) -> Self {
                Self { core: Box::new($crate::error::ErrorCore::new(message.into())) }
            }

            /// A builder for this error.
            pub const fn builder() -> $crate::error::ErrorBuilder<Self> {
                $crate::error::ErrorBuilder::new()
            }

            /// Set the error that caused this one, which [`source`](std::error::Error::source) returns.
            #[must_use]
            pub fn with_source(mut self, source: impl std::error::Error + Send + Sync + 'static) -> Self {
                self.core.source = Some(Box::new(source));
                self
            }

            /// This error's message, without its sources.
            /// For people and logs: the text can change in any release.
            #[must_use]
            pub fn message(&self) -> &str {
                &self.core.message
            }

            /// Whether the same call might succeed if retried.
            #[must_use]
            pub const fn is_retryable(&self) -> bool {
                self.core.retry.is_some()
            }
        }

        impl $crate::error::FromParts for $strukt {
            #[track_caller]
            fn from_parts(
                message: String,
                source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
                retry: Option<$crate::error::RetryKind>,
                remote: Option<$crate::error::RemoteInfo>,
            ) -> Self {
                let mut core = $crate::error::ErrorCore::new(message);
                core.source = source;
                core.retry = retry;
                core.remote = remote;
                Self { core: Box::new(core) }
            }
        }

        impl std::fmt::Debug for $strukt {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                let mut d = f.debug_struct(stringify!($strukt));
                self.core.debug_fields(&mut d);
                d.finish()
            }
        }

        impl std::fmt::Display for $strukt {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, concat!(stringify!($variant), ": {}"), self.core.message)
            }
        }

        impl std::error::Error for $strukt {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                self.core.source()
            }
        }

        impl From<$strukt> for $error {
            fn from(e: $strukt) -> Self {
                Self::$variant(e)
            }
        }

        $( $crate::define_error!(@$remote $strukt); )?
    };

    (@remote $strukt:ident) => {
        impl $crate::error::RemoteKind for $strukt {}

        impl $strukt {
            /// The AWS service the failed call went to.
            #[must_use]
            pub fn service(&self) -> Option<$crate::error::Service> {
                self.core.remote.as_ref().map(|r| r.service)
            }

            /// The AWS resource the failed call was about.
            #[must_use]
            pub fn resource(&self) -> Option<&$crate::error::Resource> {
                self.core.remote.as_ref()?.resource.as_ref()
            }

            /// The AWS service's error code, such as `"AccessDeniedException"`.
            /// `None` when the service did not answer.
            #[must_use]
            pub fn code(&self) -> Option<&str> {
                self.core.remote.as_ref()?.code.as_deref()
            }

            /// The AWS request ID, which AWS Support asks for.
            /// `None` when the service did not answer.
            #[must_use]
            pub fn request_id(&self) -> Option<&str> {
                self.core.remote.as_ref()?.request_id.as_deref()
            }
        }
    };

    (@sdk $error:ident, $smithy:ident, $request_id:path) => {
        // Inherent `code` and `request_id` resolve the call when several of the traits below are in scope.
        #[allow(clippy::same_name_method)]
        impl $error {
            /// The AWS service's error code, such as `"AccessDeniedException"`.
            /// `None` unless an AWS service answered.
            #[must_use]
            pub fn code(&self) -> Option<&str> {
                self.core().remote.as_ref()?.code.as_deref()
            }

            /// The AWS request ID, which AWS Support asks for.
            /// `None` unless an AWS service answered.
            #[must_use]
            pub fn request_id(&self) -> Option<&str> {
                self.core().remote.as_ref()?.request_id.as_deref()
            }
        }

        #[allow(clippy::same_name_method)]
        impl $smithy::error::metadata::ProvideErrorMetadata for $error {
            /// The AWS service's own error metadata; empty unless an AWS service answered.
            fn meta(&self) -> &$smithy::error::metadata::ErrorMetadata {
                static EMPTY: std::sync::LazyLock<$smithy::error::metadata::ErrorMetadata> =
                    std::sync::LazyLock::new($smithy::error::metadata::ErrorMetadata::default);
                self.core()
                    .sdk_meta
                    .as_deref()
                    .and_then(|m| m.downcast_ref::<$smithy::error::metadata::ErrorMetadata>())
                    .unwrap_or(&EMPTY)
            }
        }

        #[allow(clippy::same_name_method)]
        impl $smithy::retry::ProvideErrorKind for $error {
            fn retryable_error_kind(&self) -> Option<$smithy::retry::ErrorKind> {
                use $crate::error::RetryKind as R;
                use $smithy::retry::ErrorKind as K;
                Some(match self.core().retry? {
                    R::Transient => K::TransientError,
                    R::Throttling => K::ThrottlingError,
                    R::Server => K::ServerError,
                    _ => K::ClientError,
                })
            }

            fn code(&self) -> Option<&str> {
                Self::code(self)
            }
        }

        #[allow(clippy::same_name_method)]
        impl $request_id for $error {
            fn request_id(&self) -> Option<&str> {
                Self::request_id(self)
            }
        }
    };
}

/// Displays an error, then each error in its [`source`](std::error::Error::source) chain, separated by `": "`.
///
/// ```
/// # use aws_mpl_primitives::error::DisplayErrorContext;
/// # let err = std::io::Error::other("example");
/// eprintln!("error: {}", DisplayErrorContext(&err));
/// ```
#[derive(Debug)]
#[expect(clippy::exhaustive_structs)]
pub struct DisplayErrorContext<E>(pub E);

impl<E: std::error::Error> fmt::Display for DisplayErrorContext<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)?;
        let mut cause = self.0.source();
        while let Some(c) = cause {
            write!(f, ": {c}")?;
            cause = c.source();
        }
        Ok(())
    }
}

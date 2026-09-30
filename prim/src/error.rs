// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The error shape every AWS Crypto Tools library shares.
//!
//! A library defines its own error type with [`define_error!`]. It gets the
//! shared error kinds plus any it adds, and every method, without writing
//! them. Each library's `Error` and `ErrorKind` are their own types.

use std::backtrace::Backtrace;
use std::fmt;
use std::sync::Arc;

/// The error kinds every library defines. [`define_error!`] copies these into
/// each library's `ErrorKind` under the same names, where they are documented.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BaseErrorKind {
    Validation,
    InvalidMaterials,
    EncryptionContextMismatch,
    NoMatchingDataKey,
    Cryptographic,
    RemoteAccessDenied,
    RemoteResourceNotFound,
    RemoteThrottled,
    RemoteTransport,
    Remote,
    Internal,
}

/// A library's `ErrorKind`, as the shared core sees it.
#[doc(hidden)]
pub trait ErrorKindLike: Copy + fmt::Debug + PartialEq + Send + Sync + 'static {
    /// The shared kind with this kind's name, if there is one.
    fn base(self) -> Option<BaseErrorKind>;
    /// This library's kind with `base`'s name.
    fn from_base(base: BaseErrorKind) -> Self;
    /// Whether an error of this kind is retryable unless a constructor says
    /// otherwise.
    fn retryable_by_default(self) -> bool {
        matches!(
            self.base(),
            Some(BaseErrorKind::RemoteThrottled | BaseErrorKind::RemoteTransport)
        )
    }
}

/// A library's `Error`, as another library's `Error` sees it when wrapping it.
#[doc(hidden)]
pub trait LibraryError: std::error::Error + Send + Sync + 'static {
    fn base_kind(&self) -> Option<BaseErrorKind>;
    fn retryable(&self) -> bool;
    fn error_message(&self) -> &str;
}

/// The fields behind every library's `Error`.
#[doc(hidden)]
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ErrorCore<K> {
    pub kind: K,
    pub message: String,
    pub retryable: bool,
    pub cause: Option<Arc<dyn std::error::Error + Send + Sync + 'static>>,
    pub backtrace: Arc<Backtrace>,
}

impl<K: ErrorKindLike> ErrorCore<K> {
    #[track_caller]
    pub fn build(
        kind: K,
        message: String,
        retryable: bool,
        cause: Option<Arc<dyn std::error::Error + Send + Sync + 'static>>,
    ) -> Self {
        Self {
            kind,
            message,
            retryable,
            cause,
            backtrace: Arc::new(Backtrace::capture()),
        }
    }

    pub fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let cause: &(dyn std::error::Error + Send + Sync + 'static) = self.cause.as_deref()?;
        Some(cause)
    }
}

impl<K: ErrorKindLike> PartialEq for ErrorCore<K> {
    fn eq(&self, other: &Self) -> bool {
        // `cause` is excluded because `dyn Error` does not implement `Eq`.
        self.kind == other.kind
            && self.message == other.message
            && self.retryable == other.retryable
    }
}

/// Define a library's `Error` and `ErrorKind`.
///
/// `ErrorKind` has the shared kinds plus the extra ones listed after the `;`.
/// `Error` has `new`, `with_cause`, `wrap`, `collection`, `kind`, `message`,
/// `is_retryable`, `collected`, `backtrace`, `source`, `Display`, `Debug`,
/// `Clone`, and `PartialEq`, and `Error::from_inner` converts another
/// library's error into this one, keeping its kind by name.
///
/// ```ignore
/// aws_mpl_primitives::define_error! {
///     /// Docs for the error type.
///     Error,
///     /// Docs for the kind enum.
///     ErrorKind;
///     /// A kind only this library reports.
///     Serialization,
/// }
/// ```
#[macro_export]
macro_rules! define_error {
    (
        $(#[$err_meta:meta])* $error:ident,
        $(#[$kind_meta:meta])* $kind:ident;
        $( $(#[$extra_meta:meta])* $extra:ident, )*
    ) => {
        $(#[$kind_meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[non_exhaustive]
        pub enum $kind {
            /// An input or configuration value is invalid.
            Validation,
            /// The materials, or the request for them, are inconsistent with
            /// each other or with the algorithm suite.
            InvalidMaterials,
            /// A required encryption context key is missing, or a
            /// caller-supplied encryption context value differs from the one
            /// being checked.
            EncryptionContextMismatch,
            /// No configured key wrapped any of the encrypted data keys.
            NoMatchingDataKey,
            /// A cryptographic check failed, such as an AES-GCM tag or a
            /// signature.
            Cryptographic,
            /// A remote service denied access to a resource.
            RemoteAccessDenied,
            /// A remote resource, such as a KMS key, `DynamoDB` table, or
            /// branch key, does not exist.
            RemoteResourceNotFound,
            /// A remote service throttled the request.
            RemoteThrottled,
            /// A request to a remote service could not be sent, or its
            /// response did not arrive.
            RemoteTransport,
            /// Any other failure reported by, or read from, a remote service.
            Remote,
            /// An internal invariant was violated.
            Internal,
            $( $(#[$extra_meta])* $extra, )*
        }

        impl $crate::error::ErrorKindLike for $kind {
            fn base(self) -> Option<$crate::error::BaseErrorKind> {
                use $crate::error::BaseErrorKind as B;
                match self {
                    Self::Validation => Some(B::Validation),
                    Self::InvalidMaterials => Some(B::InvalidMaterials),
                    Self::EncryptionContextMismatch => Some(B::EncryptionContextMismatch),
                    Self::NoMatchingDataKey => Some(B::NoMatchingDataKey),
                    Self::Cryptographic => Some(B::Cryptographic),
                    Self::RemoteAccessDenied => Some(B::RemoteAccessDenied),
                    Self::RemoteResourceNotFound => Some(B::RemoteResourceNotFound),
                    Self::RemoteThrottled => Some(B::RemoteThrottled),
                    Self::RemoteTransport => Some(B::RemoteTransport),
                    Self::Remote => Some(B::Remote),
                    Self::Internal => Some(B::Internal),
                    #[allow(unreachable_patterns)]
                    _ => None,
                }
            }

            fn from_base(base: $crate::error::BaseErrorKind) -> Self {
                use $crate::error::BaseErrorKind as B;
                match base {
                    B::Validation => Self::Validation,
                    B::InvalidMaterials => Self::InvalidMaterials,
                    B::EncryptionContextMismatch => Self::EncryptionContextMismatch,
                    B::NoMatchingDataKey => Self::NoMatchingDataKey,
                    B::Cryptographic => Self::Cryptographic,
                    B::RemoteAccessDenied => Self::RemoteAccessDenied,
                    B::RemoteResourceNotFound => Self::RemoteResourceNotFound,
                    B::RemoteThrottled => Self::RemoteThrottled,
                    B::RemoteTransport => Self::RemoteTransport,
                    B::Remote => Self::Remote,
                    _ => Self::Internal,
                }
            }
        }

        $(#[$err_meta])*
        #[derive(Clone, PartialEq)]
        pub struct $error {
            core: $crate::error::ErrorCore<$kind>,
            collected: Vec<$error>,
        }

        impl $error {
            /// Construct an error of `kind`.
            #[track_caller]
            pub fn new(kind: $kind, message: impl Into<String>) -> Self {
                use $crate::error::ErrorKindLike as _;
                Self::from_core($crate::error::ErrorCore::build(
                    kind,
                    message.into(),
                    kind.retryable_by_default(),
                    None,
                ))
            }

            /// Construct an error of `kind` caused by `cause`, which
            /// [`std::error::Error::source`] returns.
            #[track_caller]
            pub fn with_cause(
                kind: $kind,
                message: impl Into<String>,
                cause: impl std::error::Error + Send + Sync + 'static,
            ) -> Self {
                use $crate::error::ErrorKindLike as _;
                Self::from_core($crate::error::ErrorCore::build(
                    kind,
                    message.into(),
                    kind.retryable_by_default(),
                    Some(std::sync::Arc::new(cause)),
                ))
            }

            /// Add context to `inner`, keeping its kind and retryability.
            /// `inner` becomes the [`std::error::Error::source`].
            #[track_caller]
            pub fn wrap(message: impl Into<String>, inner: Self) -> Self {
                Self::from_core($crate::error::ErrorCore::build(
                    inner.core.kind,
                    message.into(),
                    inner.core.retryable,
                    Some(std::sync::Arc::new(inner)),
                ))
            }

            /// Construct an error of `kind` that carries every failure
            /// collected while attempting an operation that ultimately
            /// failed, such as a keyring trying each encrypted data key.
            ///
            /// `message` describes the overall failure; [`Self::collected`]
            /// returns each one. A single collected failure is also the
            /// [`std::error::Error::source`].
            #[track_caller]
            pub fn collection(
                kind: $kind,
                message: impl Into<String>,
                collected: Vec<Self>,
            ) -> Self {
                debug_assert!(
                    !collected.is_empty(),
                    "an aggregate must collect at least one failure; an operation with \
                     nothing to report should use Error::new",
                );
                let cause: Option<std::sync::Arc<dyn std::error::Error + Send + Sync + 'static>> =
                    match collected.as_slice() {
                        [only] => Some(std::sync::Arc::new(only.clone())),
                        _ => None,
                    };
                let retryable =
                    !collected.is_empty() && collected.iter().all(|e| e.core.retryable);
                Self {
                    core: $crate::error::ErrorCore::build(kind, message.into(), retryable, cause),
                    collected,
                }
            }

            /// Convert another library's error into this library's error, with
            /// `message` saying what this library was doing.
            /// The kind is the one with the same name here, or `Internal` when
            /// there is none; `inner` becomes the [`std::error::Error::source`].
            #[track_caller]
            pub fn from_inner(
                message: impl Into<String>,
                inner: impl $crate::error::LibraryError,
            ) -> Self {
                use $crate::error::ErrorKindLike as _;
                let kind = inner
                    .base_kind()
                    .map_or($kind::Internal, $kind::from_base);
                let retryable = $crate::error::LibraryError::retryable(&inner);
                Self::from_core($crate::error::ErrorCore::build(
                    kind,
                    message.into(),
                    retryable,
                    Some(std::sync::Arc::new(inner)),
                ))
            }

            const fn from_core(core: $crate::error::ErrorCore<$kind>) -> Self {
                Self {
                    core,
                    collected: Vec::new(),
                }
            }

            /// What went wrong.
            #[must_use]
            pub const fn kind(&self) -> $kind {
                self.core.kind
            }

            /// The error message, without the kind prefix that `Display` adds.
            #[must_use]
            pub fn message(&self) -> &str {
                &self.core.message
            }

            /// Whether the same call might succeed if retried.
            #[must_use]
            pub const fn is_retryable(&self) -> bool {
                self.core.retryable
            }

            /// The failures collected by an operation that tried several
            /// things, such as a keyring trying each encrypted data key.
            /// Empty otherwise.
            #[must_use]
            pub fn collected(&self) -> &[Self] {
                &self.collected
            }

            /// The backtrace captured when this error was created.
            pub fn backtrace(&self) -> &std::backtrace::Backtrace {
                &self.core.backtrace
            }

            /// Override whether this error is retryable.
            #[doc(hidden)]
            pub const fn set_retryable(&mut self, retryable: bool) {
                self.core.retryable = retryable;
            }
        }

        impl $crate::error::LibraryError for $error {
            fn base_kind(&self) -> Option<$crate::error::BaseErrorKind> {
                $crate::error::ErrorKindLike::base(self.core.kind)
            }

            fn retryable(&self) -> bool {
                self.core.retryable
            }

            fn error_message(&self) -> &str {
                &self.core.message
            }
        }

        impl std::fmt::Debug for $error {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct(stringify!($error))
                    .field("kind", &self.core.kind)
                    .field("message", &self.core.message)
                    .field("retryable", &self.core.retryable)
                    .field("source", &self.core.cause)
                    .field("collected", &self.collected)
                    .finish()
            }
        }

        impl std::fmt::Display for $error {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.core.message)
            }
        }

        impl std::error::Error for $error {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                self.core.source()
            }
        }
    };
}

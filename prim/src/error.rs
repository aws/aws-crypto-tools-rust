// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The error shape every AWS Crypto Tools library shares.
//!
//! A library defines its own `Error` and `ErrorKind` with [`define_error!`](crate::define_error).
//! Every library gets the shared kinds and the same methods, and can add kinds of its own.

use std::backtrace::Backtrace;
use std::fmt;
use std::sync::Arc;

/// The kinds [`define_error!`](crate::define_error) puts in every library's `ErrorKind`, under the same names.
/// Their docs live in the macro.
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
    /// The retryability `new` and `with_cause` give an error of this kind.
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
        // `cause` and `backtrace` have no `PartialEq`.
        self.kind == other.kind
            && self.message == other.message
            && self.retryable == other.retryable
    }
}

/// Define a library's `Error` and `ErrorKind`.
///
/// `ErrorKind` has the shared kinds, then the kinds listed after the `;`.
/// `Error::from_inner` converts another library's error into this one and keeps its kind by name.
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
        ///
        /// Check [`is_retryable`](Error::is_retryable) first:
        /// a retryable error might succeed if the same call is made again later.
        /// Then match on the kind to decide what to do.
        /// The message and the [`source`](std::error::Error::source) chain say which component or service failed, for logs.
        ///
        /// Later releases can add kinds, so a `match` needs a catch-all arm.
        ///
        /// Messages are for people, not code.
        /// Their text can change in any release, including a minor or patch release.
        /// Decide from the kind, [`is_retryable`](Error::is_retryable), and the types in the source chain, never from the message.
        ///
        /// ```ignore
        /// if err.is_retryable() {
        ///     // back off and retry
        /// }
        /// match err.kind() {
        ///     ErrorKind::Validation => { /* fix the input */ }
        ///     ErrorKind::RemoteAccessDenied | ErrorKind::RemoteResourceNotFound => {
        ///         /* fix the permissions or configuration */
        ///     }
        ///     ErrorKind::Cryptographic | ErrorKind::NoMatchingDataKey => {
        ///         /* reject the message */
        ///     }
        ///     _ => { /* log and fail */ }
        /// }
        /// ```
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[non_exhaustive]
        pub enum $kind {
            /// An input or configuration value is invalid,
            /// for example an input with no keyring or CMM, a zero TTL, or a wrapping key of the wrong length.
            ///
            /// Fix the input; the same call cannot succeed.
            Validation,
            /// A keyring or CMM returned materials inconsistent with each other or with the algorithm suite,
            /// for example no plaintext data key after encryption, or a signing key for a suite that does not sign.
            ///
            /// Usually a bug in a custom keyring or CMM.
            InvalidMaterials,
            /// An encryption context does not match,
            /// for example a required key is missing, or a value passed to decrypt differs from the message's.
            ///
            /// Check the encryption context passed to the call.
            EncryptionContextMismatch,
            /// None of the configured keys wrapped any of the message's encrypted data keys,
            /// for example when decrypting with a keyring that did not encrypt the message.
            ///
            /// Decrypt with a keyring that has one of the message's keys.
            NoMatchingDataKey,
            /// A cryptographic check failed,
            /// for example an AES-GCM authentication tag or a message signature did not verify.
            ///
            /// The message is corrupt or modified, or is being decrypted with the wrong key;
            /// retrying cannot succeed.
            Cryptographic,
            /// AWS KMS or `DynamoDB` denied access,
            /// for example because of missing IAM permissions or expired credentials.
            ///
            /// Fix the permissions or credentials.
            RemoteAccessDenied,
            /// A KMS key, `DynamoDB` table, or branch key does not exist.
            ///
            /// Fix the configuration that names the resource.
            RemoteResourceNotFound,
            /// AWS KMS or `DynamoDB` throttled the request.
            ///
            /// Retryable: back off and try again.
            RemoteThrottled,
            /// A request to a remote service was not sent, or its response did not arrive,
            /// for example because of a network error, a timeout, or missing credentials or region.
            ///
            /// Retryable for a network error or timeout; check [`is_retryable`](Error::is_retryable).
            RemoteTransport,
            /// Any other failure from a remote service,
            /// for example a KMS `IncorrectKeyException`, a KMS internal error, or a malformed key store record.
            ///
            /// When a service reported the failure, the [`source`](std::error::Error::source) is its SDK error.
            /// A server-side failure is retryable.
            Remote,
            /// An internal invariant was violated, for example a poisoned lock.
            ///
            /// A bug; report it.
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
            /// It is retryable only if `kind` is `RemoteThrottled` or `RemoteTransport`.
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

            /// Like [`new`](Self::new), with `cause` as the [`source`](std::error::Error::source).
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
            /// `inner` becomes the [`source`](std::error::Error::source).
            #[track_caller]
            pub fn wrap(message: impl Into<String>, inner: Self) -> Self {
                Self::from_core($crate::error::ErrorCore::build(
                    inner.core.kind,
                    message.into(),
                    inner.core.retryable,
                    Some(std::sync::Arc::new(inner)),
                ))
            }

            /// Construct an error of `kind` that carries the failures behind it,
            /// such as a keyring's failure for each encrypted data key it tried.
            ///
            /// [`collected`](Self::collected) returns the failures.
            /// With exactly one, it is also the [`source`](std::error::Error::source).
            /// The error is retryable if any collected failure is.
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
                let retryable = collected.iter().any(|e| e.core.retryable);
                Self {
                    core: $crate::error::ErrorCore::build(kind, message.into(), retryable, cause),
                    collected,
                }
            }

            /// Convert another library's error into this library's error.
            /// `message` says what this library was doing.
            /// The kind is the one with the same name, or `Internal` if this library has none.
            /// The error keeps `inner`'s retryability, and `inner` becomes the [`source`](std::error::Error::source).
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

            /// This error's message, without its sources.
            #[must_use]
            pub fn message(&self) -> &str {
                &self.core.message
            }

            /// Whether the same call might succeed if retried.
            #[must_use]
            pub const fn is_retryable(&self) -> bool {
                self.core.retryable
            }

            /// The failures behind an error from [`collection`](Self::collection).
            /// Empty for any other error.
            #[must_use]
            pub fn collected(&self) -> &[Self] {
                &self.collected
            }

            /// The backtrace captured when this error was created.
            /// Disabled unless `RUST_BACKTRACE` or `RUST_LIB_BACKTRACE` is set.
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

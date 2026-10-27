// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//! Error types for the AWS Database Encryption SDK for DynamoDB.
//!
//! # Handling errors
//!
//! Every operation returns [`Error`]:
//! a `#[non_exhaustive]` enum with one struct per variant, like an AWS SDK for Rust service error.
//!
//! **Decide in two steps.**
//! 1. Check [`is_retryable`](Error::is_retryable).
//!    A retryable error might succeed if the same call is made again later,
//!    and [`retry_kind`](Error::retry_kind) says how to back off.
//! 2. Otherwise match on the variant; each variant's docs say what to do.
//!    Later releases can add variants, so a `match` needs a catch-all arm.
//!
//! **Read the details from accessors.**
//! [`resource`](Error::resource) is the resource you need to act on,
//! [`service`](Error::service) the AWS service the failed call went to,
//! [`code`](Error::code) that service's error code,
//! and [`request_id`](Error::request_id) the ID AWS Support asks for.
//!
//! **Messages are for people.**
//! [`message`](Error::message) and `Display` are for people and logs:
//! their text can change in any release, even a patch release.
//! Handle errors from the variant and its accessors, never from the message.
//!
//! ## What a minor or patch release can change
//!
//! - **Message text.** Any message, and anything `{}`, `{:#}`, or `{:?}` prints, can change.
//! - **Failures without a specific variant.** An operation should only ever return [`Error`].
//!   An [`Internal`](Error::Internal) error is a bug, and a release can give it a specific variant.
//! - **The shape of the source chain.** Reach a source with [`find_source`](Error::find_source),
//!   not by calling `source()` a fixed number of times.
//! - **Which variant a collection of failures gets.** To act on each failure, use [`failures`](Error::failures).
//! - **New variants and values.** `Error`, `Service`, `Resource`, `ConflictReason`, `RetryKind`,
//!   and `Collection` are `#[non_exhaustive]`, so every `match` needs a catch-all arm.
//!
//! **Logging.** Log `{:#}`: it adds each error in the source chain.
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
pub use aws_smithy_types::retry::{ErrorKind as RetryErrorKind, ProvideErrorKind};
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

/// An `Internal` error: an invariant of this library was violated.
#[track_caller]
pub(crate) fn internal_err(msg: impl Into<String>) -> Error {
    Error::new(Kind::Internal, msg)
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

// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//! Error types for the AWS Encryption SDK.
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
//! - [`resource`](Error::resource): the resource you need to act on.
//!   The message names any other resources involved.
//!   For example, when AWS KMS denies decrypting a branch key, `resource()` is the KMS key,
//!   because the fix is a KMS permission, and the message names the branch key.
//!   When a keyring or CMM you passed returns bad materials or none,
//!   `resource()` is [`Resource::Keyring`] or [`Resource::Cmm`] with its name,
//!   unless it names something more specific, such as a corrupt branch key.
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
//! - **Failures without a specific variant.** An ESDK operation should only ever return [`Error`].
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
//! `{}` prints this error as `Variant: message (details)`, for example
//! `AccessDenied: decrypt could not get decryption materials (AWS KMS, KMS key arn:..., AccessDeniedException, request 6f1c2e9a)`.
//! `{:#}` adds each error in the source chain, leaving out what the previous one already said, for example
//! `...: AWS KMS Decrypt of branch key my-branch-key failed: service error: ...`.
//!
//! **Reaching the AWS SDK error.**
//! The error from AWS KMS or `DynamoDB` stays in the source chain,
//! and [`find_source`](Error::find_source) returns it by type.
//! Name that type through the AWS SDK crates [`aws_crypto_mpl`] re-exports:
//! `find_source` matches the exact type, and a different version of an SDK crate defines different types.
//!
//! For complete error handling with the hierarchical keyring,
//! see the [`handling_errors`](https://github.com/aws/aws-crypto-tools-rust/blob/main/esdk/examples/handling_errors.rs) example.
//!
//! ## Throttling
//!
//! A [`Throttling`](Error::Throttling) error is always retryable.
//! For errors from AWS KMS or `DynamoDB`, the AWS SDK client has already retried according to its `RetryConfig`,
//! so retry only at a higher level, with your own backoff.
//! Nothing retries materials-cache throttling for you.
//!
//! Match `Throttling` only to learn what was throttled, for example to record it:
//!
//! ```no_run
//! # fn record_throttle(_: &str) {}
//! # async fn example(esdk: aws_esdk::Client, keyring: aws_esdk::types::SharedKeyring) {
//! use aws_esdk::Error;
//! use aws_esdk::error::{Resource, Service};
//!
//! if let Err(Error::Throttling(e)) = esdk.encrypt().plaintext(b"data").keyring(keyring).send().await {
//!     match e.service() {
//!         Some(Service::Kms) => record_throttle("kms"),
//!         Some(Service::DynamoDb) => record_throttle("dynamodb"),
//!         // The materials cache is not an AWS service.
//!         None => match e.resource() {
//!             Some(Resource::Cache(_)) => record_throttle("materials-cache"),
//!             _ => record_throttle("other"),
//!         },
//!         _ => record_throttle("other"),
//!     }
//! }
//! # }
//! ```
//!
//! ## Seeing every failure
//!
//! When a keyring fails on every encrypted data key it tries,
//! its error collects one failure per attempt.
//! The ESDK error keeps that error as its [`source`](std::error::Error::source),
//! so the ESDK error's own [`collected`](Error::collected) is empty.
//! To act on each attempt, use [`failures`](Error::failures):
//! it returns every failure behind an error, at any depth, as this crate's [`Error`].
//! An error with no collection yields itself.
//!
//! ```no_run
//! # async fn example(esdk: aws_esdk::Client, keyring: aws_esdk::types::SharedKeyring, ciphertext: &[u8]) {
//! use aws_esdk::Error;
//! use aws_esdk::error::{Resource, Service};
//!
//! if let Err(e) = esdk.decrypt().ciphertext(ciphertext).keyring(keyring).send().await {
//!     for attempt in e.failures() {
//!         match attempt {
//!             Error::AccessDenied(a) => match a.service() {
//!                 Some(Service::Kms) => match a.resource() {
//!                     Some(Resource::KmsKey(key)) => { /* handle AWS KMS denying the KMS key `key.arn()` */ }
//!                     _ => { /* handle AWS KMS denying any other resource */ }
//!                 },
//!                 _ => { /* handle any other service denying access */ }
//!             },
//!             Error::Throttling(_) => { /* handle this attempt being throttled */ }
//!             _ => { /* handle any other failure of this attempt */ }
//!         }
//!     }
//! }
//! # }
//! ```
//!
//! ## Testing your error handling
//!
//! Every variant struct has `new` and a [builder](builders),
//! so you can construct the errors this crate returns, for example from a fake keyring or CMM:
//!
//! ```
//! use aws_esdk::error::{AccessDeniedError, KmsKey, Resource, Service};
//! use aws_esdk::Error;
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
    EncryptionContextMismatchError, ErrorParts, InternalError, InvalidMaterialsError, IoError,
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

#[track_caller]
pub(crate) fn val_err(msg: impl Into<String>) -> Error {
    Error::new(Kind::Validation, msg)
}

#[track_caller]
pub(crate) fn err(kind: Kind, msg: impl Into<String>) -> Error {
    Error::new(kind, msg)
}

#[track_caller]
pub(crate) fn err_with_cause(
    kind: Kind,
    msg: impl Into<String>,
    cause: impl std::error::Error + Send + Sync + 'static,
) -> Error {
    Error::with_cause(kind, msg, cause)
}

#[track_caller]
pub(crate) fn ser_err<T>(msg: &str) -> Result<T, Error> {
    Err(Error::new(Kind::Serialization, msg))
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

impl From<aws_smithy_types::error::operation::BuildError> for Error {
    #[track_caller]
    fn from(item: aws_smithy_types::error::operation::BuildError) -> Self {
        Self::with_cause(Kind::Validation, "could not build the request", item)
    }
}

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
//! This example handles each variant of a decrypt error:
//!
//! ```no_run
//! # mod log { macro_rules! error { ($($t:tt)*) => { eprintln!($($t)*) } } pub(crate) use error; }
//! # fn use_plaintext(_: Vec<u8>) {}
//! # fn backoff(_: Option<aws_esdk::error::RetryKind>) {}
//! # fn refresh_credentials() {}
//! # fn grant_kms_decrypt(_: &str) {}
//! # fn grant_ddb_access(_: &str) {}
//! # fn provision_branch_key(_: &str) {}
//! # fn fix_key_store_table(_: &str) {}
//! # fn fix_kms_key(_: &str) {}
//! # fn alert_corrupt_branch_key(_: &str) {}
//! # fn report_keyring_bug(_: &str, _: String) {}
//! # fn try_another_keyring(_: Option<&aws_esdk::error::Resource>) {}
//! # fn reject(_: &str) {}
//! # fn fix_input(_: &str) {}
//! # async fn example(input: aws_esdk::DecryptInput<'_>) {
//! use aws_esdk::error::{Error, Resource, Service};
//!
//! match aws_esdk::decrypt(&input).await {
//!     Ok(out) => use_plaintext(out.plaintext),
//!     Err(e) if e.is_retryable() => backoff(e.retry_kind()),
//!     Err(Error::AccessDenied(e)) if e.is_credentials() => refresh_credentials(),
//!     Err(Error::AccessDenied(e)) => match (e.service(), e.resource()) {
//!         (Some(Service::Kms), Some(Resource::KmsKey(key))) => grant_kms_decrypt(key.arn()),
//!         (Some(Service::DynamoDb), Some(Resource::DynamoDbTable(table))) => grant_ddb_access(table.name()),
//!         _ => log::error!("{e}"),
//!     },
//!     Err(Error::ResourceNotFound(e)) => match e.resource() {
//!         Some(Resource::BranchKey(branch_key)) => provision_branch_key(branch_key.id()),
//!         Some(Resource::DynamoDbTable(table)) => fix_key_store_table(table.name()),
//!         Some(Resource::KmsKey(key)) => fix_kms_key(key.arn()),
//!         _ => log::error!("{e}"),
//!     },
//!     Err(Error::InvalidMaterials(e)) => match e.resource() {
//!         Some(Resource::BranchKey(branch_key)) => alert_corrupt_branch_key(branch_key.id()),
//!         Some(Resource::Keyring(keyring)) => report_keyring_bug(keyring.name(), format!("{e:#}")),
//!         _ => log::error!("{e:#}"),
//!     },
//!     Err(Error::NoMatchingDataKey(e)) => try_another_keyring(e.resource()),
//!     Err(Error::EncryptionContextMismatch(e)) => reject(&format!("{e:#}")),
//!     Err(Error::Cryptographic(_) | Error::Serialization(_)) => reject("bad message"),
//!     Err(Error::Service(e)) => log::error!("{e}"),
//!     Err(Error::Validation(e)) => fix_input(e.message()),
//!     Err(e) => log::error!("decrypt failed: {e:#}"),   // Internal, and variants added later
//! }
//! # }
//! ```
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
//! # async fn example(input: aws_esdk::EncryptInput<'_>) {
//! use aws_esdk::error::{Error, Resource};
//!
//! if let Err(Error::Throttling(e)) = aws_esdk::encrypt(&input).await {
//!     match (e.service(), e.resource()) {
//!         (Some(service), _) => record_throttle(service.as_str()),
//!         (None, Some(Resource::Cache(_))) => record_throttle("materials-cache"),
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
//! # fn grant_kms_decrypt(_: &str) {}
//! # fn backoff() {}
//! # async fn example(input: aws_esdk::DecryptInput<'_>) {
//! use aws_esdk::error::{Error, Resource};
//!
//! if let Err(e) = aws_esdk::decrypt(&input).await {
//!     for attempt in e.failures() {
//!         match attempt {
//!             Error::AccessDenied(a) => match a.resource() {
//!                 Some(Resource::KmsKey(key)) => grant_kms_decrypt(key.arn()),
//!                 _ => {}
//!             },
//!             Error::Throttling(_) => backoff(),
//!             _ => {}
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
//! use aws_esdk::error::{AccessDeniedError, Error, KmsKey, Resource, Service};
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

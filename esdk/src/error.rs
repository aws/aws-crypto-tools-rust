// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//! Error types for the AWS Encryption SDK.
//!
//! # Handling errors
//!
//! Every operation returns [`Error`], one `#[non_exhaustive]` enum
//! with one struct per variant, like an AWS SDK for Rust service error.
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
//! When a keyring or CMM you passed returns bad materials or none, `resource()` is
//! [`Resource::Keyring`] or [`Resource::Cmm`] with its name, unless it names
//! something more specific, such as a corrupt branch key.
//!
//! **Messages are for people.**
//! [`message`](Error::message) and `Display` are for people and logs,
//! and their text can change in any release.
//! Decide from the variant and its accessors, never from the message.
//!
//! **`{}` and `{:#}`.**
//! `{}` prints this error: `Variant: message (details)`,
//! for example `AccessDenied: decrypt could not get decryption materials (AWS KMS, KMS key arn:..., AccessDeniedException, request 6f1c2e9a)`.
//! `{:#}` adds each error in the source chain, without repeating what the previous one said,
//! for example `...: AWS KMS Decrypt of branch key my-branch-key failed: service error: ...`.
//! Log `{:#}`.
//!
//! **Reaching the AWS SDK error.**
//! The error from AWS KMS or `DynamoDB` stays in the source chain.
//! [`find_source`](Error::find_source) returns it by type;
//! use the SDK crates [`aws_crypto_mpl`] re-exports, so the versions match.
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
//! Match it only to learn what was throttled, for example to record it:
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
//! For errors from AWS KMS or `DynamoDB`, the AWS SDK client has already retried
//! according to its `RetryConfig`, so retry only at a higher level with your own backoff.
//! Materials-cache throttling is not retried internally.
//!
//! ## Seeing every failure
//!
//! A keyring that tries several encrypted data keys, and fails on every one,
//! returns one error that collects each attempt's failure.
//! The ESDK error's [`collected`](Error::collected) is empty: the keyring's error is its
//! [`source`](std::error::Error::source), and that error holds the attempts.
//! [`failures`](Error::failures) returns every failure behind an error,
//! at any depth, as this crate's [`Error`]; a single failure yields itself:
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
//! Every variant struct has `new` and a [builder](builders), so you can construct
//! the errors this crate returns, for example from a fake keyring or CMM:
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
//!
//! [`Error`] and its variant structs are generated from `errors.toml`
//! at the repository root by `cargo xtask gen-errors`.

mod generated;

pub use generated::*;

pub use aws_mpl_primitives::error::{
    BranchKey, Cache, CmmResource, Collection, ConflictReason, DynamoDbTable, KeyringResource,
    KmsKey, Resource, RetryKind, Service,
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

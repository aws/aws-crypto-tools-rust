// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The error type every function in this crate returns,
//! and the types every AWS Crypto Tools library's errors share.
//!
//! [`Error`] and its variant structs are generated from `errors.toml`
//! at the repository root by `cargo xtask gen-errors`.

use std::fmt;

mod generated;

pub use generated::*;

/// The AWS service an error is about.
///
/// ```
/// use aws_mpl_primitives::error::Service;
///
/// assert_eq!(Service::Kms.to_string(), "AWS KMS");
/// assert_eq!(Service::DynamoDb.as_str(), "dynamodb");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Service {
    /// AWS Key Management Service.
    Kms,
    /// Amazon `DynamoDB`.
    DynamoDb,
}

impl Service {
    /// A short, stable identifier: `"kms"` or `"dynamodb"`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Kms => "kms",
            Self::DynamoDb => "dynamodb",
        }
    }
}

impl fmt::Display for Service {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Kms => "AWS KMS",
            Self::DynamoDb => "Amazon DynamoDB",
        })
    }
}

/// The resource an error is about.
///
/// Not limited to AWS resources: a keyring, a CMM, or the materials cache can be one.
///
/// An error's `resource()` is the resource you need to act on.
/// Other resources involved are named in the message.
///
/// ```
/// use aws_mpl_primitives::error::Resource;
///
/// assert_eq!(Resource::BranchKey("my-branch-key".into()).to_string(), "branch key my-branch-key");
/// assert_eq!(Resource::Cache.to_string(), "materials cache");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Resource {
    /// A KMS key, by ARN.
    KmsKey(String),
    /// A `DynamoDB` table, by name.
    DynamoDbTable(String),
    /// A hierarchical keyring branch key, by ID.
    BranchKey(String),
    /// A cryptographic materials cache.
    Cache,
    /// A keyring, by its `name()`.
    Keyring(String),
    /// A CMM, by its `name()`.
    Cmm(String),
}

impl fmt::Display for Resource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KmsKey(arn) => write!(f, "KMS key {arn}"),
            Self::DynamoDbTable(name) => write!(f, "table {name}"),
            Self::BranchKey(id) => write!(f, "branch key {id}"),
            Self::Cache => f.write_str("materials cache"),
            Self::Keyring(name) => write!(f, "keyring {name}"),
            Self::Cmm(name) => write!(f, "CMM {name}"),
        }
    }
}

/// How to back off before retrying an error that might succeed later.
///
/// Mirrors `aws_smithy_types::retry::ErrorKind`,
/// which the libraries that use the AWS SDK return from `ProvideErrorKind::retryable_error_kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RetryKind {
    /// A connection-level failure, such as a timeout.
    Transient,
    /// A service or resource throttled the request.
    Throttling,
    /// The service failed on its side.
    Server,
    /// The request failed but a retry can succeed.
    Client,
}

impl RetryKind {
    /// `"transient"`, `"throttling"`, `"server"`, or `"client"`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Transient => "transient",
            Self::Throttling => "throttling",
            Self::Server => "server",
            Self::Client => "client",
        }
    }
}

impl fmt::Display for RetryKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How the failures an error collects relate to the operation that failed.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Collection {
    /// Each collected error is one attempt at the same goal, and every attempt failed;
    /// any one succeeding would have been enough,
    /// for example a keyring trying each encrypted data key.
    /// Retrying can help if any attempt could succeed later.
    AllFailed,
    /// Each collected error is a step the operation needed, and any one failing was enough to fail it.
    /// Retrying cannot help if any step can never succeed.
    AnyFailed,
}

/// Why a request conflicts with the current state of a resource.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConflictReason {
    /// The resource already exists,
    /// for example `create_key` with a branch key ID that is in use.
    AlreadyExists,
    /// Another caller changed the resource between this call's read and its write,
    /// for example two `version_key` calls on the same branch key.
    ConcurrentModification,
}

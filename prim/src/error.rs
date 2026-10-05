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
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
    pub const fn as_str(&self) -> &'static str {
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
/// Each variant carries a struct with private fields, read through accessors,
/// so a later release can add detail about a resource without breaking callers.
///
/// ```
/// use aws_mpl_primitives::error::{BranchKey, Cache, Resource};
///
/// assert_eq!(Resource::BranchKey(BranchKey::new("my-branch-key")).to_string(), "branch key my-branch-key");
/// assert_eq!(Resource::Cache(Cache::new()).to_string(), "materials cache");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Resource {
    /// A KMS key, by ARN.
    KmsKey(KmsKey),
    /// A `DynamoDB` table, by name.
    DynamoDbTable(DynamoDbTable),
    /// A hierarchical keyring branch key, by ID.
    BranchKey(BranchKey),
    /// A cryptographic materials cache.
    Cache(Cache),
    /// A keyring, by its `name()`.
    Keyring(KeyringResource),
    /// A CMM, by its `name()`.
    Cmm(CmmResource),
}

impl fmt::Display for Resource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KmsKey(key) => write!(f, "KMS key {}", key.arn()),
            Self::DynamoDbTable(table) => write!(f, "table {}", table.name()),
            Self::BranchKey(branch_key) => write!(f, "branch key {}", branch_key.id()),
            Self::Cache(_) => f.write_str("materials cache"),
            Self::Keyring(keyring) => write!(f, "keyring {}", keyring.name()),
            Self::Cmm(cmm) => write!(f, "CMM {}", cmm.name()),
        }
    }
}

/// A KMS key, by ARN.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct KmsKey {
    arn: String,
}

impl KmsKey {
    /// A KMS key identified by `arn`.
    #[must_use]
    pub fn new(arn: impl Into<String>) -> Self {
        Self { arn: arn.into() }
    }

    /// The KMS key's ARN.
    #[must_use]
    pub fn arn(&self) -> &str {
        &self.arn
    }
}

impl From<KmsKey> for Resource {
    fn from(key: KmsKey) -> Self {
        Self::KmsKey(key)
    }
}

/// A `DynamoDB` table, by name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct DynamoDbTable {
    name: String,
}

impl DynamoDbTable {
    /// A `DynamoDB` table identified by `name`.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }

    /// The table's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl From<DynamoDbTable> for Resource {
    fn from(table: DynamoDbTable) -> Self {
        Self::DynamoDbTable(table)
    }
}

/// A hierarchical keyring branch key, by ID.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct BranchKey {
    id: String,
}

impl BranchKey {
    /// A branch key identified by `id`.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self { id: id.into() }
    }

    /// The branch key's ID.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
}

impl From<BranchKey> for Resource {
    fn from(branch_key: BranchKey) -> Self {
        Self::BranchKey(branch_key)
    }
}

/// A cryptographic materials cache.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Cache {}

impl Cache {
    /// The cryptographic materials cache.
    #[must_use]
    #[expect(
        clippy::missing_const_for_fn,
        reason = "not const, so later releases can add fields that need a runtime constructor"
    )]
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for Cache {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Cache> for Resource {
    fn from(cache: Cache) -> Self {
        Self::Cache(cache)
    }
}

/// A keyring, by its `name()`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct KeyringResource {
    name: String,
}

impl KeyringResource {
    /// A keyring identified by `name`.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }

    /// The keyring's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl From<KeyringResource> for Resource {
    fn from(keyring: KeyringResource) -> Self {
        Self::Keyring(keyring)
    }
}

/// A CMM, by its `name()`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct CmmResource {
    name: String,
}

impl CmmResource {
    /// A CMM identified by `name`.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }

    /// The CMM's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl From<CmmResource> for Resource {
    fn from(cmm: CmmResource) -> Self {
        Self::Cmm(cmm)
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
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ConflictReason {
    /// The resource already exists,
    /// for example `create_key` with a branch key ID that is in use.
    AlreadyExists,
    /// Another caller changed the resource between this call's read and its write,
    /// for example two `version_key` calls on the same branch key.
    ConcurrentModification,
}

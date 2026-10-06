// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The error type every function in this crate returns,
//! and the types every AWS Crypto Tools library's errors share.

use std::fmt;

// `cargo xtask gen-errors` writes `generated.rs` from `errors.toml` at the repository root.
mod generated;

pub use generated::*;

/// The AWS service an error is about.
///
/// ```
/// use aws_mpl_primitives::error::Service;
///
/// fn handle(service: &Service) {
///     match service {
///         Service::Kms => {}
///         Service::DynamoDb => {}
///         // Later releases add services.
///         _ => {}
///     }
/// }
/// ```
///
/// `Display` prints `AWS KMS` or `Amazon DynamoDB`; [`as_str`](Self::as_str) returns `kms` or `dynamodb`.
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

/// The resource you need to act on, which an error's `resource()` returns.
///
/// The message names any other resources involved.
/// A resource need not be an AWS resource: a keyring, a CMM, or the materials cache can be one.
///
/// Each variant holds a struct with private fields, read through accessors,
/// so a later release can add detail about a resource without breaking callers.
///
/// ```
/// use aws_mpl_primitives::error::Resource;
///
/// fn handle(resource: &Resource) {
///     match resource {
///         Resource::BranchKey(branch_key) => println!("branch key {}", branch_key.id()),
///         Resource::KmsKey(key) => println!("KMS key {}", key.arn()),
///         // Later releases add resource kinds.
///         _ => {}
///     }
/// }
/// ```
///
/// `Display` prints, for example, `branch key my-branch-key` or `KMS key arn:aws:kms:...`.
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
///
/// ```
/// use aws_mpl_primitives::error::KmsKey;
///
/// fn handle(key: &KmsKey) {
///     // `region()` and `account()` are `None` for an alias name or bare key ID.
///     if key.region() != Some("us-west-2") {
///         println!("the KMS key {} is in another region", key.arn());
///     }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct KmsKey {
    arn: String,
    region: Option<String>,
    account: Option<String>,
}

impl KmsKey {
    /// A KMS key identified by `arn`.
    ///
    /// When `arn` is a KMS ARN, `region()` and `account()` return its region and account.
    #[must_use]
    pub fn new(arn: impl Into<String>) -> Self {
        let arn = arn.into();
        let (region, account) = match parse_kms_arn(&arn) {
            Some((region, account)) => (Some(region.to_owned()), Some(account.to_owned())),
            None => (None, None),
        };
        Self {
            arn,
            region,
            account,
        }
    }

    /// The KMS key's ARN, or the key ID or alias it was named by.
    #[must_use]
    pub fn arn(&self) -> &str {
        &self.arn
    }

    /// The ARN's region, or `None` when [`arn`](Self::arn) is not a KMS ARN.
    #[must_use]
    pub fn region(&self) -> Option<&str> {
        self.region.as_deref()
    }

    /// The ARN's AWS account ID, or `None` when [`arn`](Self::arn) is not a KMS ARN.
    #[must_use]
    pub fn account(&self) -> Option<&str> {
        self.account.as_deref()
    }
}

/// The region and account of `arn:<partition>:kms:<region>:<account>:<key|alias>/<name>`.
fn parse_kms_arn(arn: &str) -> Option<(&str, &str)> {
    let mut parts = arn.splitn(6, ':');
    let (Some("arn"), Some(partition), Some("kms"), Some(region), Some(account), Some(resource)) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return None;
    };
    let (resource_type, name) = resource.split_once('/')?;
    let valid = !partition.is_empty()
        && !region.is_empty()
        && !account.is_empty()
        && matches!(resource_type, "key" | "alias")
        && !name.is_empty();
    valid.then_some((region, account))
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
///
/// ```
/// use aws_mpl_primitives::error::BranchKey;
///
/// fn handle(branch_key: &BranchKey) {
///     match branch_key.version() {
///         // The failed call asked for this version of the branch key.
///         Some(version) => println!("branch key {} version {version}", branch_key.id()),
///         None => println!("branch key {}", branch_key.id()),
///     }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct BranchKey {
    id: String,
    version: Option<String>,
}

impl BranchKey {
    /// A branch key identified by `id`.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            version: None,
        }
    }

    /// The same branch key, at `version`.
    #[must_use]
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// The branch key's ID.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The branch key version the failing call was about, or `None` when it was not about one.
    #[must_use]
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
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

/// An encrypted data key in a message, by its key provider.
///
/// Holds the key's provider ID and info, never the wrapped key.
///
/// ```
/// use aws_mpl_primitives::error::DataKeyInfo;
///
/// fn handle(key: &DataKeyInfo) {
///     if key.key_provider_id() == "aws-kms" {
///         // For AWS KMS keyrings, the provider info is the KMS key ARN.
///         println!("{}", String::from_utf8_lossy(key.key_provider_info()));
///     }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct DataKeyInfo {
    key_provider_id: String,
    key_provider_info: KeyProviderInfo,
}

impl DataKeyInfo {
    /// An encrypted data key with key provider ID `id` and key provider info `info`.
    #[must_use]
    pub fn new(id: impl Into<String>, info: impl Into<Vec<u8>>) -> Self {
        Self {
            key_provider_id: id.into(),
            key_provider_info: KeyProviderInfo(info.into()),
        }
    }

    /// The key provider ID, for example `aws-kms`.
    #[must_use]
    pub fn key_provider_id(&self) -> &str {
        &self.key_provider_id
    }

    /// The key provider info, for example a KMS key ARN or a branch key ID.
    #[must_use]
    pub fn key_provider_info(&self) -> &[u8] {
        &self.key_provider_info.0
    }
}

/// Key provider info, which `Debug` shows as text when it is UTF-8 and as hex otherwise.
#[derive(Clone, PartialEq, Eq, Hash)]
struct KeyProviderInfo(Vec<u8>);

impl fmt::Debug for KeyProviderInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Ok(text) = std::str::from_utf8(&self.0) {
            return fmt::Debug::fmt(text, f);
        }
        f.write_str("0x")?;
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// How to back off before retrying an error that might succeed later.
///
/// Each value matches one `aws_smithy_types::retry::ErrorKind`, such as `Transient` and `TransientError`.
/// An error from a library that uses the AWS SDK returns that `ErrorKind` from `ProvideErrorKind::retryable_error_kind`.
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
    /// The collected errors are attempts at one goal, and every attempt failed.
    /// Any one attempt succeeding would have been enough,
    /// for example a keyring trying each encrypted data key.
    /// Retrying can help if any attempt could succeed later.
    AllFailed,
    /// The collected errors are steps the operation needed, and any one failing was enough to fail it.
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

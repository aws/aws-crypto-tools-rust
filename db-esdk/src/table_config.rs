// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! How the items of one table are encrypted and signed.

use std::collections::HashMap;

use aws_crypto_mpl::cmm::SharedCmm;
use aws_crypto_mpl::keyring::SharedKeyring;
use aws_crypto_mpl::shared::IntoShared;

use crate::error::{Error, val_err};
use crate::search::SearchConfig;
use crate::types::{AlgorithmSuiteId, CryptoAction, PlaintextOverride};

/// The encryption configuration of one table.
///
/// Build it with [`TableConfig::builder`], then pass it to
/// [`ItemEncryptor::builder`](crate::ItemEncryptor::builder).
///
/// ```
/// use aws_db_esdk::keyring::RawAesKeyring;
/// use aws_db_esdk::types::{AesWrappingAlg, CryptoAction};
/// use aws_db_esdk::TableConfig;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let keyring = RawAesKeyring::builder()
///     .key_namespace("my-key-namespace")
///     .key_name("my-key-name")
///     .wrapping_key(vec![0x01u8; 32])
///     .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
///     .build()?;
/// let table = TableConfig::builder()
///     .partition_key_name("partition_key")
///     .attribute_actions_on_encrypt("partition_key", CryptoAction::SignOnly)
///     .attribute_actions_on_encrypt("secret", CryptoAction::EncryptAndSign)
///     .keyring(keyring)
///     .build()?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
#[non_exhaustive]
//= spec/dynamodb-encryption-client/ddb-table-encryption-config.md#legacy-config
//= type=exception
//= reason=The native crate has no Legacy Config; the legacy encryptor is the Java DynamoDBEncryptor
//# This config MUST contain:
//
//= spec/dynamodb-encryption-client/ddb-table-encryption-config.md#attribute-flags
//= type=exception
//= reason=The native crate has no Legacy Config, so it has no Attribute Flags
//# This map MAY be different from the top level [Attribute Actions](#attribute-actions).
pub struct TableConfig {
    pub(crate) logical_table_name: Option<String>,
    pub(crate) partition_key_name: String,
    pub(crate) sort_key_name: Option<String>,
    pub(crate) attribute_actions_on_encrypt: HashMap<String, CryptoAction>,
    pub(crate) allowed_unsigned_attributes: Option<Vec<String>>,
    //= spec/dynamodb-encryption-client/ddb-table-encryption-config.md#unauthenticated-attribute-prefix
    //= type=implication
    //# Unauthenticated Attribute Prefix MUST be a string.
    pub(crate) allowed_unsigned_attribute_prefix: Option<String>,
    //= spec/dynamodb-encryption-client/ddb-table-encryption-config.md#algorithm-suite
    //= type=implication
    //= reason=AlgorithmSuiteId is the MPL's DbeAlgorithmSuiteId, which has only DBE suites
    //# This algorithm suite MUST be a [Structured Encryption Library Supported algorithm suite](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/algorithm-suites.md).
    pub(crate) algorithm_suite_id: Option<AlgorithmSuiteId>,
    pub(crate) materials: Materials,
    pub(crate) plaintext_override: Option<PlaintextOverride>,
    //= spec/searchable-encryption/search-config.md#overview
    //= type=implication
    //= reason=the table config holds its search config as an Option
    //# The search config MUST be an optional part of the [item encryptor config](../dynamodb-encryption-client/ddb-item-encryptor.md).
    pub(crate) search: Option<SearchConfig>,
}

/// Where a table's cryptographic materials come from.
#[derive(Clone, Debug)]
pub(crate) enum Materials {
    Keyring(SharedKeyring),
    Cmm(SharedCmm),
}

impl TableConfig {
    /// A builder for a table configuration.
    #[must_use]
    pub fn builder() -> TableConfigBuilder {
        TableConfigBuilder::default()
    }

    /// The name bound into every item, if set.
    /// When it is unset, items are bound to the table's name.
    #[must_use]
    pub fn logical_table_name(&self) -> Option<&str> {
        self.logical_table_name.as_deref()
    }

    /// The partition key attribute's name.
    #[must_use]
    pub fn partition_key_name(&self) -> &str {
        &self.partition_key_name
    }

    /// The sort key attribute's name, if the table has one.
    #[must_use]
    pub fn sort_key_name(&self) -> Option<&str> {
        self.sort_key_name.as_deref()
    }

    /// The action taken on each attribute when encrypting.
    #[must_use]
    pub const fn attribute_actions_on_encrypt(&self) -> &HashMap<String, CryptoAction> {
        &self.attribute_actions_on_encrypt
    }

    /// The attributes left out of the signature by name.
    #[must_use]
    pub fn allowed_unsigned_attributes(&self) -> &[String] {
        self.allowed_unsigned_attributes
            .as_deref()
            .unwrap_or_default()
    }

    /// The prefix of the attributes left out of the signature.
    #[must_use]
    pub fn allowed_unsigned_attribute_prefix(&self) -> Option<&str> {
        self.allowed_unsigned_attribute_prefix.as_deref()
    }

    /// The algorithm suite new items are written with, if set.
    #[must_use]
    pub const fn algorithm_suite_id(&self) -> Option<AlgorithmSuiteId> {
        self.algorithm_suite_id
    }

    /// Whether plaintext items are written and read.
    #[must_use]
    pub fn plaintext_override(&self) -> PlaintextOverride {
        self.plaintext_override.unwrap_or_default()
    }

    /// The searchable-encryption configuration, if set.
    #[must_use]
    pub const fn search(&self) -> Option<&SearchConfig> {
        self.search.as_ref()
    }
}

/// The most characters a DynamoDB attribute name may have.
pub(crate) const MAX_ATTRIBUTE_NAME_LEN: usize = 65535;

/// The most characters a DynamoDB key attribute name may have.
const MAX_KEY_SCHEMA_NAME_LEN: usize = 255;

/// The fewest characters a DynamoDB table name may have.
const MIN_TABLE_NAME_LEN: usize = 3;

/// The most characters a DynamoDB table name may have.
const MAX_TABLE_NAME_LEN: usize = 255;

/// Reject `name` when it is not a valid DynamoDB table name.
///
/// Like the Dafny implementation, this checks only the length, in UTF-16 code units.
pub(crate) fn check_table_name(name: &str) -> Result<(), Error> {
    let len = name.encode_utf16().count();
    if !(MIN_TABLE_NAME_LEN..=MAX_TABLE_NAME_LEN).contains(&len) {
        return Err(val_err(format!(
            "table name must have between {MIN_TABLE_NAME_LEN} and {MAX_TABLE_NAME_LEN} characters"
        )));
    }
    Ok(())
}

/// Reject `name` in `field` when it is not a valid DynamoDB attribute name.
pub(crate) fn check_attribute_name(field: &str, name: &str) -> Result<(), Error> {
    if name.encode_utf16().count() > MAX_ATTRIBUTE_NAME_LEN {
        return Err(val_err(format!(
            "{field} has an attribute name longer than {MAX_ATTRIBUTE_NAME_LEN} characters"
        )));
    }
    Ok(())
}

/// Reject `name` in `field` when it is not a valid DynamoDB key attribute name.
fn check_key_schema_name(field: &str, name: &str) -> Result<(), Error> {
    let len = name.encode_utf16().count();
    if !(1..=MAX_KEY_SCHEMA_NAME_LEN).contains(&len) {
        return Err(val_err(format!(
            "{field} must have between 1 and {MAX_KEY_SCHEMA_NAME_LEN} characters"
        )));
    }
    Ok(())
}

/// A builder for [`TableConfig`].
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct TableConfigBuilder {
    logical_table_name: Option<String>,
    partition_key_name: Option<String>,
    sort_key_name: Option<String>,
    attribute_actions_on_encrypt: Option<HashMap<String, CryptoAction>>,
    allowed_unsigned_attributes: Option<Vec<String>>,
    allowed_unsigned_attribute_prefix: Option<String>,
    algorithm_suite_id: Option<AlgorithmSuiteId>,
    keyring: Option<SharedKeyring>,
    cmm: Option<SharedCmm>,
    //= spec/dynamodb-encryption-client/ddb-table-encryption-config.md#structure
    //= type=exception
    //= reason=The native crate has no Legacy Config, so it cannot be set with a Plaintext Policy
    //# A [Legacy Config](#legacy-config)
    //# and a [Plaintext Policy](#plaintext-policy)
    //# both specified on the same config is invalid,
    //# and MUST result in an error.
    plaintext_override: Option<PlaintextOverride>,
    //= spec/dynamodb-encryption-client/ddb-table-encryption-config.md#structure
    //= type=exception
    //= reason=Dafny accepts search with a plaintext policy (TestPutItemInputMultiForceAllow), and the cross-language tests need Rust to accept it too; there is no Legacy Config
    //# A [Searchable Encryption Config](../searchable-encryption/search-config.md)
    //# and either a [Legacy Config](./ddb-table-encryption-config.md#legacy-config)
    //# or a [Plaintext Policy](./ddb-table-encryption-config.md#plaintext-policy)
    //# being specified on the same config is invalid,
    //# and MUST result in an error.
    search: Option<SearchConfig>,
}

impl TableConfigBuilder {
    /// The name bound into every item, so an item decrypts only under the same name.
    ///
    /// Optional: it defaults to the name of the table that this configuration is for.
    /// Set it only when the physical table name changes, for example after a restore.
    #[must_use]
    pub fn logical_table_name(mut self, name: impl Into<String>) -> Self {
        self.logical_table_name = Some(name.into());
        self
    }

    /// The name bound into every item.
    /// See [`Self::logical_table_name`].
    #[must_use]
    pub fn set_logical_table_name(mut self, name: Option<String>) -> Self {
        self.logical_table_name = name;
        self
    }

    /// The partition key attribute's name.
    /// Required.
    #[must_use]
    pub fn partition_key_name(mut self, name: impl Into<String>) -> Self {
        self.partition_key_name = Some(name.into());
        self
    }

    /// The partition key attribute's name.
    /// See [`Self::partition_key_name`].
    #[must_use]
    pub fn set_partition_key_name(mut self, name: Option<String>) -> Self {
        self.partition_key_name = name;
        self
    }

    /// The sort key attribute's name, when the table has one.
    #[must_use]
    pub fn sort_key_name(mut self, name: impl Into<String>) -> Self {
        self.sort_key_name = Some(name.into());
        self
    }

    /// The sort key attribute's name.
    /// See [`Self::sort_key_name`].
    #[must_use]
    pub fn set_sort_key_name(mut self, name: Option<String>) -> Self {
        self.sort_key_name = name;
        self
    }

    /// Add the action taken on attribute `name` when encrypting.
    ///
    /// Every attribute an item can have needs an action,
    /// unless it is allowed unsigned (it then gets `DO_NOTHING`).
    /// The partition and sort keys must be `SIGN_ONLY`,
    /// or `SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT` when any attribute is.
    #[must_use]
    pub fn attribute_actions_on_encrypt(
        mut self,
        name: impl Into<String>,
        action: CryptoAction,
    ) -> Self {
        self.attribute_actions_on_encrypt
            .get_or_insert_with(HashMap::new)
            .insert(name.into(), action);
        self
    }

    /// Replace every attribute action.
    /// See [`Self::attribute_actions_on_encrypt`].
    #[must_use]
    pub fn set_attribute_actions_on_encrypt(
        mut self,
        actions: Option<HashMap<String, CryptoAction>>,
    ) -> Self {
        self.attribute_actions_on_encrypt = actions;
        self
    }

    /// Add an attribute that is left out of the signature.
    ///
    /// Once items are written, never remove a name: older items may carry the attribute.
    #[must_use]
    pub fn allowed_unsigned_attributes(mut self, name: impl Into<String>) -> Self {
        self.allowed_unsigned_attributes
            .get_or_insert_with(Vec::new)
            .push(name.into());
        self
    }

    /// Replace the attributes left out of the signature.
    /// See [`Self::allowed_unsigned_attributes`].
    #[must_use]
    pub fn set_allowed_unsigned_attributes(mut self, names: Option<Vec<String>>) -> Self {
        self.allowed_unsigned_attributes = names;
        self
    }

    /// The prefix of attributes left out of the signature, for example `":"`.
    ///
    /// Unlike [`Self::allowed_unsigned_attributes`], new unsigned attributes need no configuration change.
    #[must_use]
    pub fn allowed_unsigned_attribute_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.allowed_unsigned_attribute_prefix = Some(prefix.into());
        self
    }

    /// The prefix of attributes left out of the signature.
    /// See [`Self::allowed_unsigned_attribute_prefix`].
    #[must_use]
    pub fn set_allowed_unsigned_attribute_prefix(mut self, prefix: Option<String>) -> Self {
        self.allowed_unsigned_attribute_prefix = prefix;
        self
    }

    /// The algorithm suite new items are written with.
    ///
    /// Optional: the default signs with ECDSA P-384 and HMAC-SHA-384.
    /// Reads take the suite from each item.
    #[must_use]
    pub const fn algorithm_suite_id(mut self, id: AlgorithmSuiteId) -> Self {
        self.algorithm_suite_id = Some(id);
        self
    }

    /// The algorithm suite new items are written with.
    /// See [`Self::algorithm_suite_id`].
    #[must_use]
    pub const fn set_algorithm_suite_id(mut self, id: Option<AlgorithmSuiteId>) -> Self {
        self.algorithm_suite_id = id;
        self
    }

    /// The keyring that protects each item's data key.
    /// Set this or [`Self::cmm`].
    #[must_use]
    pub fn keyring(mut self, keyring: impl IntoShared<SharedKeyring>) -> Self {
        self.keyring = Some(keyring.into_shared());
        self
    }

    /// The keyring.
    /// See [`Self::keyring`].
    #[must_use]
    pub fn set_keyring(mut self, keyring: Option<SharedKeyring>) -> Self {
        self.keyring = keyring;
        self
    }

    /// The cryptographic materials manager that supplies each item's materials.
    /// Set this or [`Self::keyring`].
    #[must_use]
    pub fn cmm(mut self, cmm: impl IntoShared<SharedCmm>) -> Self {
        self.cmm = Some(cmm.into_shared());
        self
    }

    /// The cryptographic materials manager.
    /// See [`Self::cmm`].
    #[must_use]
    pub fn set_cmm(mut self, cmm: Option<SharedCmm>) -> Self {
        self.cmm = cmm;
        self
    }

    /// Whether plaintext items are written and read, while migrating a plaintext table.
    #[must_use]
    pub const fn plaintext_override(mut self, policy: PlaintextOverride) -> Self {
        self.plaintext_override = Some(policy);
        self
    }

    /// Whether plaintext items are written and read.
    /// See [`Self::plaintext_override`].
    #[must_use]
    pub const fn set_plaintext_override(mut self, policy: Option<PlaintextOverride>) -> Self {
        self.plaintext_override = policy;
        self
    }

    /// The beacons that make encrypted attributes searchable.
    ///
    /// Only a [`Client`](crate::Client) writes and queries beacons;
    /// an [`ItemEncryptor`](crate::ItemEncryptor) ignores them.
    #[must_use]
    pub fn search(mut self, search: SearchConfig) -> Self {
        self.search = Some(search);
        self
    }

    /// The beacons.
    /// See [`Self::search`].
    #[must_use]
    pub fn set_search(mut self, search: Option<SearchConfig>) -> Self {
        self.search = search;
        self
    }

    /// Build the configuration.
    ///
    /// # Errors
    ///
    /// A `Validation` error when the partition key name or the attribute actions are missing,
    /// when a key name is empty or longer than 255 characters,
    /// when an attribute name is longer than 65535 characters,
    /// or when not exactly one of a keyring and a CMM is set.
    pub fn build(self) -> Result<TableConfig, Error> {
        //= spec/dynamodb-encryption-client/ddb-table-encryption-config.md#structure
        //# The following are REQUIRED for DynamoDb Table Encryption Configuration:
        //
        //= spec/dynamodb-encryption-client/ddb-table-encryption-config.md#structure
        //# - [DynamoDB Partition Key Name](#dynamodb-partition-key-name)
        let partition_key_name = self
            .partition_key_name
            .ok_or_else(|| val_err("partition_key_name is required"))?;
        //= spec/dynamodb-encryption-client/ddb-table-encryption-config.md#dynamodb-partition-key-name
        //# This Partition Key Name MUST be a valid DynamoDB Key Schema Attribute Name
        check_key_schema_name("partition_key_name", &partition_key_name)?;
        if let Some(sort) = &self.sort_key_name {
            //= spec/dynamodb-encryption-client/ddb-table-encryption-config.md#dynamodb-sort-key-name
            //# This Sort Key Name MUST be a valid DynamoDB Key Schema Attribute Name
            check_key_schema_name("sort_key_name", sort)?;
        }
        //= spec/dynamodb-encryption-client/ddb-table-encryption-config.md#structure
        //# - [Attribute Actions](#attribute-actions)
        let attribute_actions_on_encrypt = self
            .attribute_actions_on_encrypt
            .ok_or_else(|| val_err("attribute_actions_on_encrypt is required"))?;
        for name in attribute_actions_on_encrypt.keys() {
            check_attribute_name("attribute_actions_on_encrypt", name)?;
        }
        if let Some(names) = &self.allowed_unsigned_attributes {
            for name in names {
                //= spec/dynamodb-encryption-client/ddb-table-encryption-config.md#unauthenticated-attributes
                //# Unauthenticated Attributes MUST be a set of Attribute Names.
                check_attribute_name("allowed_unsigned_attributes", name)?;
            }
        }
        let materials = match (self.keyring, self.cmm) {
            (Some(_), Some(_)) => return Err(val_err("Cannot provide both a keyring and a CMM")),
            //= spec/dynamodb-encryption-client/ddb-table-encryption-config.md#structure
            //# - A [CMM](#cmm) or [Keyring](#keyring)
            (None, None) => return Err(val_err("Must provide either a keyring or a CMM")),
            (Some(k), None) => Materials::Keyring(k),
            (None, Some(c)) => Materials::Cmm(c),
        };
        //= spec/dynamodb-encryption-client/ddb-table-encryption-config.md#structure
        //# The following are OPTIONAL for DynamoDb Table Encryption Configuration:
        Ok(TableConfig {
            logical_table_name: self.logical_table_name,
            partition_key_name,
            sort_key_name: self.sort_key_name,
            attribute_actions_on_encrypt,
            allowed_unsigned_attributes: self.allowed_unsigned_attributes,
            allowed_unsigned_attribute_prefix: self.allowed_unsigned_attribute_prefix,
            algorithm_suite_id: self.algorithm_suite_id,
            materials,
            plaintext_override: self.plaintext_override,
            search: self.search,
        })
    }
}

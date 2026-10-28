// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The searchable-encryption configuration: beacon versions, beacons, parts, and virtual fields.

use std::time::Duration;

use aws_crypto_mpl::cmc::SharedCmc;
use aws_crypto_mpl::key_store;
use aws_crypto_mpl::shared::IntoShared;

use crate::error::{Error, val_err};

/// `value`, or a `Validation` error naming the missing `field`.
fn required<T>(value: Option<T>, field: &str) -> Result<T, Error> {
    value.ok_or_else(|| val_err(format!("{field} is required")))
}

/// Reject an empty list in `field`.
fn non_empty<T>(list: Option<&Vec<T>>, field: &str) -> Result<(), Error> {
    if list.is_some_and(Vec::is_empty) {
        return Err(val_err(format!("{field} must not be empty")));
    }
    Ok(())
}

/// Reject an empty string in `field`.
fn non_empty_str(value: Option<&str>, field: &str) -> Result<(), Error> {
    if value.is_some_and(str::is_empty) {
        return Err(val_err(format!("{field} must not be empty")));
    }
    Ok(())
}

/// The one character of `value`, or a `Validation` error for `field`.
fn one_char(value: &str, field: &str) -> Result<char, Error> {
    let mut chars = value.chars();
    match (chars.next(), chars.next()) {
        (Some(c), None) => Ok(c),
        _ => Err(val_err(format!("{field} must be exactly one character"))),
    }
}

/// Reject a partition count outside `1..=255`.
fn check_partitions(value: Option<u8>, field: &str) -> Result<(), Error> {
    if value == Some(0) {
        return Err(val_err(format!("{field} must be between 1 and 255")));
    }
    Ok(())
}

/// Reject a version number below 1.
fn check_version(value: u32, field: &str) -> Result<(), Error> {
    if value == 0 {
        return Err(val_err(format!("{field} must be at least 1")));
    }
    Ok(())
}

/// The searchable-encryption configuration of a table.
///
/// Set it on a table with [`TableConfigBuilder::search`](crate::TableConfigBuilder::search).
/// Beacons are written and queried only through [`Client`](crate::Client).
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct SearchConfig {
    pub(crate) versions: Vec<BeaconVersion>,
    pub(crate) write_version: u32,
}

impl SearchConfig {
    /// A builder for a search configuration.
    #[must_use]
    pub fn builder() -> SearchConfigBuilder {
        SearchConfigBuilder::default()
    }

    /// The beacon versions items can be read with. Exactly one, version 1.
    #[must_use]
    pub fn versions(&self) -> &[BeaconVersion] {
        &self.versions
    }

    /// The beacon version new items are written with. Must be 1.
    #[must_use]
    pub const fn write_version(&self) -> u32 {
        self.write_version
    }
}

/// A builder for [`SearchConfig`].
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct SearchConfigBuilder {
    versions: Option<Vec<BeaconVersion>>,
    write_version: Option<u32>,
}

impl SearchConfigBuilder {
    /// Add a beacon version. Required: exactly one, version 1.
    #[must_use]
    pub fn versions(mut self, version: BeaconVersion) -> Self {
        self.versions.get_or_insert_with(Vec::new).push(version);
        self
    }

    /// Replace the beacon versions. See [`Self::versions`].
    #[must_use]
    pub fn set_versions(mut self, versions: Option<Vec<BeaconVersion>>) -> Self {
        self.versions = versions;
        self
    }

    /// The beacon version new items are written with. Required; must be 1.
    #[must_use]
    pub const fn write_version(mut self, version: u32) -> Self {
        self.write_version = Some(version);
        self
    }

    /// The beacon version new items are written with. See [`Self::write_version`].
    #[must_use]
    pub const fn set_write_version(mut self, version: Option<u32>) -> Self {
        self.write_version = version;
        self
    }

    /// Build the configuration.
    ///
    /// # Errors
    ///
    /// A `Validation` error when the versions or the write version are missing,
    /// when there is not exactly one version, or when the write version is 0.
    pub fn build(self) -> Result<SearchConfig, Error> {
        let versions = required(self.versions, "versions")?;
        if versions.len() != 1 {
            return Err(val_err("versions must have exactly one beacon version"));
        }
        let write_version = required(self.write_version, "write_version")?;
        check_version(write_version, "write_version")?;
        Ok(SearchConfig {
            versions,
            write_version,
        })
    }
}

/// One version of a table's beacons: the beacons, and where their keys come from.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct BeaconVersion {
    pub(crate) version: u32,
    pub(crate) key_store: key_store::Client,
    pub(crate) key_source: BeaconKeySource,
    pub(crate) standard_beacons: Vec<StandardBeacon>,
    pub(crate) compound_beacons: Option<Vec<CompoundBeacon>>,
    pub(crate) virtual_fields: Option<Vec<VirtualField>>,
    pub(crate) encrypted_parts: Option<Vec<EncryptedPart>>,
    pub(crate) signed_parts: Option<Vec<SignedPart>>,
    pub(crate) maximum_number_of_partitions: Option<u8>,
    pub(crate) default_number_of_partitions: Option<u8>,
}

impl BeaconVersion {
    /// A builder for a beacon version.
    #[must_use]
    pub fn builder() -> BeaconVersionBuilder {
        BeaconVersionBuilder::default()
    }

    /// The version number. Must be 1.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// The key store that holds the beacon keys.
    #[must_use]
    pub const fn key_store(&self) -> &key_store::Client {
        &self.key_store
    }

    /// Which beacon keys are used.
    #[must_use]
    pub const fn key_source(&self) -> &BeaconKeySource {
        &self.key_source
    }

    /// The standard beacons.
    #[must_use]
    pub fn standard_beacons(&self) -> &[StandardBeacon] {
        &self.standard_beacons
    }

    /// The compound beacons.
    #[must_use]
    pub fn compound_beacons(&self) -> &[CompoundBeacon] {
        self.compound_beacons.as_deref().unwrap_or_default()
    }

    /// The virtual fields.
    #[must_use]
    pub fn virtual_fields(&self) -> &[VirtualField] {
        self.virtual_fields.as_deref().unwrap_or_default()
    }

    /// The encrypted parts any compound beacon can use.
    #[must_use]
    pub fn encrypted_parts(&self) -> &[EncryptedPart] {
        self.encrypted_parts.as_deref().unwrap_or_default()
    }

    /// The signed parts any compound beacon can use.
    #[must_use]
    pub fn signed_parts(&self) -> &[SignedPart] {
        self.signed_parts.as_deref().unwrap_or_default()
    }

    /// The most partitions any beacon is divided across, if set.
    #[must_use]
    pub const fn maximum_number_of_partitions(&self) -> Option<u8> {
        self.maximum_number_of_partitions
    }

    /// The partitions of a beacon that sets none of its own, if set.
    #[must_use]
    pub const fn default_number_of_partitions(&self) -> Option<u8> {
        self.default_number_of_partitions
    }
}

/// A builder for [`BeaconVersion`].
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct BeaconVersionBuilder {
    version: Option<u32>,
    key_store: Option<key_store::Client>,
    key_source: Option<BeaconKeySource>,
    standard_beacons: Option<Vec<StandardBeacon>>,
    compound_beacons: Option<Vec<CompoundBeacon>>,
    virtual_fields: Option<Vec<VirtualField>>,
    encrypted_parts: Option<Vec<EncryptedPart>>,
    signed_parts: Option<Vec<SignedPart>>,
    maximum_number_of_partitions: Option<u8>,
    default_number_of_partitions: Option<u8>,
}

impl BeaconVersionBuilder {
    /// The version number. Required; must be 1.
    #[must_use]
    pub const fn version(mut self, version: u32) -> Self {
        self.version = Some(version);
        self
    }

    /// The version number. See [`Self::version`].
    #[must_use]
    pub const fn set_version(mut self, version: Option<u32>) -> Self {
        self.version = version;
        self
    }

    /// The key store that holds the beacon keys. Required.
    #[must_use]
    pub fn key_store(mut self, key_store: impl Into<key_store::Client>) -> Self {
        self.key_store = Some(key_store.into());
        self
    }

    /// The key store. See [`Self::key_store`].
    #[must_use]
    pub fn set_key_store(mut self, key_store: Option<key_store::Client>) -> Self {
        self.key_store = key_store;
        self
    }

    /// Which beacon keys are used. Required.
    #[must_use]
    pub fn key_source(mut self, key_source: BeaconKeySource) -> Self {
        self.key_source = Some(key_source);
        self
    }

    /// Which beacon keys are used. See [`Self::key_source`].
    #[must_use]
    pub fn set_key_source(mut self, key_source: Option<BeaconKeySource>) -> Self {
        self.key_source = key_source;
        self
    }

    /// Add a standard beacon. At least one is required.
    #[must_use]
    pub fn standard_beacons(mut self, beacon: StandardBeacon) -> Self {
        self.standard_beacons
            .get_or_insert_with(Vec::new)
            .push(beacon);
        self
    }

    /// Replace the standard beacons. See [`Self::standard_beacons`].
    #[must_use]
    pub fn set_standard_beacons(mut self, beacons: Option<Vec<StandardBeacon>>) -> Self {
        self.standard_beacons = beacons;
        self
    }

    /// Add a compound beacon.
    #[must_use]
    pub fn compound_beacons(mut self, beacon: CompoundBeacon) -> Self {
        self.compound_beacons
            .get_or_insert_with(Vec::new)
            .push(beacon);
        self
    }

    /// Replace the compound beacons. See [`Self::compound_beacons`].
    #[must_use]
    pub fn set_compound_beacons(mut self, beacons: Option<Vec<CompoundBeacon>>) -> Self {
        self.compound_beacons = beacons;
        self
    }

    /// Add a virtual field.
    #[must_use]
    pub fn virtual_fields(mut self, field: VirtualField) -> Self {
        self.virtual_fields.get_or_insert_with(Vec::new).push(field);
        self
    }

    /// Replace the virtual fields. See [`Self::virtual_fields`].
    #[must_use]
    pub fn set_virtual_fields(mut self, fields: Option<Vec<VirtualField>>) -> Self {
        self.virtual_fields = fields;
        self
    }

    /// Add an encrypted part any compound beacon can use.
    #[must_use]
    pub fn encrypted_parts(mut self, part: EncryptedPart) -> Self {
        self.encrypted_parts.get_or_insert_with(Vec::new).push(part);
        self
    }

    /// Replace the encrypted parts. See [`Self::encrypted_parts`].
    #[must_use]
    pub fn set_encrypted_parts(mut self, parts: Option<Vec<EncryptedPart>>) -> Self {
        self.encrypted_parts = parts;
        self
    }

    /// Add a signed part any compound beacon can use.
    #[must_use]
    pub fn signed_parts(mut self, part: SignedPart) -> Self {
        self.signed_parts.get_or_insert_with(Vec::new).push(part);
        self
    }

    /// Replace the signed parts. See [`Self::signed_parts`].
    #[must_use]
    pub fn set_signed_parts(mut self, parts: Option<Vec<SignedPart>>) -> Self {
        self.signed_parts = parts;
        self
    }

    /// The most partitions any beacon is divided across. Optional: the default is 1.
    #[must_use]
    pub const fn maximum_number_of_partitions(mut self, count: u8) -> Self {
        self.maximum_number_of_partitions = Some(count);
        self
    }

    /// The most partitions. See [`Self::maximum_number_of_partitions`].
    #[must_use]
    pub const fn set_maximum_number_of_partitions(mut self, count: Option<u8>) -> Self {
        self.maximum_number_of_partitions = count;
        self
    }

    /// The partitions of a beacon that sets none of its own.
    /// Optional: the default is the maximum. Must be less than the maximum.
    #[must_use]
    pub const fn default_number_of_partitions(mut self, count: u8) -> Self {
        self.default_number_of_partitions = Some(count);
        self
    }

    /// The default partitions. See [`Self::default_number_of_partitions`].
    #[must_use]
    pub const fn set_default_number_of_partitions(mut self, count: Option<u8>) -> Self {
        self.default_number_of_partitions = count;
        self
    }

    /// Build the beacon version.
    ///
    /// The beacons are checked against the table's attribute actions when the
    /// [`Client`](crate::Client) is built.
    ///
    /// # Errors
    ///
    /// A `Validation` error when the version, key store, key source, or standard beacons are missing,
    /// when the version is 0, when a list is empty, or when a partition count is 0.
    pub fn build(self) -> Result<BeaconVersion, Error> {
        let version = required(self.version, "version")?;
        check_version(version, "version")?;
        let standard_beacons = required(self.standard_beacons, "standard_beacons")?;
        non_empty(Some(&standard_beacons), "standard_beacons")?;
        non_empty(self.compound_beacons.as_ref(), "compound_beacons")?;
        non_empty(self.virtual_fields.as_ref(), "virtual_fields")?;
        non_empty(self.encrypted_parts.as_ref(), "encrypted_parts")?;
        non_empty(self.signed_parts.as_ref(), "signed_parts")?;
        check_partitions(
            self.maximum_number_of_partitions,
            "maximum_number_of_partitions",
        )?;
        check_partitions(
            self.default_number_of_partitions,
            "default_number_of_partitions",
        )?;
        Ok(BeaconVersion {
            version,
            key_store: required(self.key_store, "key_store")?,
            key_source: required(self.key_source, "key_source")?,
            standard_beacons,
            compound_beacons: self.compound_beacons,
            virtual_fields: self.virtual_fields,
            encrypted_parts: self.encrypted_parts,
            signed_parts: self.signed_parts,
            maximum_number_of_partitions: self.maximum_number_of_partitions,
            default_number_of_partitions: self.default_number_of_partitions,
        })
    }
}

/// Which beacon keys a beacon version uses.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum BeaconKeySource {
    /// One beacon key for every item.
    Single(SingleKeyStore),
    /// A beacon key per item, named by an attribute of the item.
    Multi(MultiKeyStore),
}

/// One beacon key for every item of the table.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct SingleKeyStore {
    pub(crate) key_id: String,
    pub(crate) cache_ttl: Duration,
    pub(crate) cache: Option<SharedCmc>,
    pub(crate) partition_id: Option<String>,
}

impl SingleKeyStore {
    /// A builder for a single key store.
    #[must_use]
    pub fn builder() -> SingleKeyStoreBuilder {
        SingleKeyStoreBuilder::default()
    }

    /// The id of the beacon key.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// How long the beacon key is cached before it is fetched again.
    #[must_use]
    pub const fn cache_ttl(&self) -> Duration {
        self.cache_ttl
    }

    /// The cache for the beacon key, if set.
    #[must_use]
    pub const fn cache(&self) -> Option<&SharedCmc> {
        self.cache.as_ref()
    }

    /// The partition id that separates this key source's entries in a shared cache, if set.
    #[must_use]
    pub fn partition_id(&self) -> Option<&str> {
        self.partition_id.as_deref()
    }
}

/// A builder for [`SingleKeyStore`].
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct SingleKeyStoreBuilder {
    key_id: Option<String>,
    cache_ttl: Option<Duration>,
    cache: Option<SharedCmc>,
    partition_id: Option<String>,
}

impl SingleKeyStoreBuilder {
    /// The id of the beacon key: the id of a branch key in the key store. Required.
    #[must_use]
    pub fn key_id(mut self, key_id: impl Into<String>) -> Self {
        self.key_id = Some(key_id.into());
        self
    }

    /// The id of the beacon key. See [`Self::key_id`].
    #[must_use]
    pub fn set_key_id(mut self, key_id: Option<String>) -> Self {
        self.key_id = key_id;
        self
    }

    /// How long the beacon key is cached before it is fetched again. Required; not zero.
    #[must_use]
    pub const fn cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = Some(ttl);
        self
    }

    /// How long the beacon key is cached. See [`Self::cache_ttl`].
    #[must_use]
    pub const fn set_cache_ttl(mut self, ttl: Option<Duration>) -> Self {
        self.cache_ttl = ttl;
        self
    }

    /// The cache for the beacon key. Optional: the default holds one entry.
    #[must_use]
    pub fn cache(mut self, cache: impl IntoShared<SharedCmc>) -> Self {
        self.cache = Some(cache.into_shared());
        self
    }

    /// The cache for the beacon key. See [`Self::cache`].
    #[must_use]
    pub fn set_cache(mut self, cache: Option<SharedCmc>) -> Self {
        self.cache = cache;
        self
    }

    /// The partition id that separates this key source's entries in a shared cache.
    /// Optional: the default is a random id. Key sources with the same id share entries.
    #[must_use]
    pub fn partition_id(mut self, partition_id: impl Into<String>) -> Self {
        self.partition_id = Some(partition_id.into());
        self
    }

    /// The partition id. See [`Self::partition_id`].
    #[must_use]
    pub fn set_partition_id(mut self, partition_id: Option<String>) -> Self {
        self.partition_id = partition_id;
        self
    }

    /// Build the single key store.
    ///
    /// # Errors
    ///
    /// A `Validation` error when the key id or the cache TTL is missing.
    pub fn build(self) -> Result<SingleKeyStore, Error> {
        Ok(SingleKeyStore {
            key_id: required(self.key_id, "key_id")?,
            cache_ttl: required(self.cache_ttl, "cache_ttl")?,
            cache: self.cache,
            partition_id: self.partition_id,
        })
    }
}

/// A beacon key per item: an attribute of the item names the key.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct MultiKeyStore {
    pub(crate) key_field_name: String,
    pub(crate) cache_ttl: Duration,
    pub(crate) cache: Option<SharedCmc>,
    pub(crate) partition_id: Option<String>,
}

impl MultiKeyStore {
    /// A builder for a multi key store.
    #[must_use]
    pub fn builder() -> MultiKeyStoreBuilder {
        MultiKeyStoreBuilder::default()
    }

    /// The attribute, or virtual field, that holds each item's beacon key id.
    #[must_use]
    pub fn key_field_name(&self) -> &str {
        &self.key_field_name
    }

    /// How long a beacon key is cached before it is fetched again.
    #[must_use]
    pub const fn cache_ttl(&self) -> Duration {
        self.cache_ttl
    }

    /// The cache for the beacon keys, if set.
    #[must_use]
    pub const fn cache(&self) -> Option<&SharedCmc> {
        self.cache.as_ref()
    }

    /// The partition id that separates this key source's entries in a shared cache, if set.
    #[must_use]
    pub fn partition_id(&self) -> Option<&str> {
        self.partition_id.as_deref()
    }
}

/// A builder for [`MultiKeyStore`].
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct MultiKeyStoreBuilder {
    key_field_name: Option<String>,
    cache_ttl: Option<Duration>,
    cache: Option<SharedCmc>,
    partition_id: Option<String>,
}

impl MultiKeyStoreBuilder {
    /// The attribute, or virtual field, that holds each item's beacon key id. Required.
    #[must_use]
    pub fn key_field_name(mut self, name: impl Into<String>) -> Self {
        self.key_field_name = Some(name.into());
        self
    }

    /// The attribute that holds the key id. See [`Self::key_field_name`].
    #[must_use]
    pub fn set_key_field_name(mut self, name: Option<String>) -> Self {
        self.key_field_name = name;
        self
    }

    /// How long a beacon key is cached before it is fetched again. Required; not zero.
    #[must_use]
    pub const fn cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = Some(ttl);
        self
    }

    /// How long a beacon key is cached. See [`Self::cache_ttl`].
    #[must_use]
    pub const fn set_cache_ttl(mut self, ttl: Option<Duration>) -> Self {
        self.cache_ttl = ttl;
        self
    }

    /// The cache for the beacon keys. Optional: the default holds 1000 entries.
    #[must_use]
    pub fn cache(mut self, cache: impl IntoShared<SharedCmc>) -> Self {
        self.cache = Some(cache.into_shared());
        self
    }

    /// The cache for the beacon keys. See [`Self::cache`].
    #[must_use]
    pub fn set_cache(mut self, cache: Option<SharedCmc>) -> Self {
        self.cache = cache;
        self
    }

    /// The partition id that separates this key source's entries in a shared cache.
    /// Optional: the default is a random id. Key sources with the same id share entries.
    #[must_use]
    pub fn partition_id(mut self, partition_id: impl Into<String>) -> Self {
        self.partition_id = Some(partition_id.into());
        self
    }

    /// The partition id. See [`Self::partition_id`].
    #[must_use]
    pub fn set_partition_id(mut self, partition_id: Option<String>) -> Self {
        self.partition_id = partition_id;
        self
    }

    /// Build the multi key store.
    ///
    /// # Errors
    ///
    /// A `Validation` error when the key field name or the cache TTL is missing.
    pub fn build(self) -> Result<MultiKeyStore, Error> {
        Ok(MultiKeyStore {
            key_field_name: required(self.key_field_name, "key_field_name")?,
            cache_ttl: required(self.cache_ttl, "cache_ttl")?,
            cache: self.cache,
            partition_id: self.partition_id,
        })
    }
}

/// A beacon over one value: the attribute named by the beacon, or another location.
///
/// Its value is written to `aws_dbe_b_<name>`.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct StandardBeacon {
    pub(crate) name: String,
    pub(crate) bits: u8,
    pub(crate) location: Option<String>,
    pub(crate) style: Option<BeaconStyle>,
    pub(crate) number_of_partitions: Option<u8>,
}

impl StandardBeacon {
    /// A builder for a standard beacon.
    #[must_use]
    pub fn builder() -> StandardBeaconBuilder {
        StandardBeaconBuilder::default()
    }

    /// The beacon's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The number of bits of the beacon value.
    #[must_use]
    pub const fn bits(&self) -> u8 {
        self.bits
    }

    /// The location of the value, if not the attribute named by the beacon.
    #[must_use]
    pub fn location(&self) -> Option<&str> {
        self.location.as_deref()
    }

    /// The beacon's style, if set.
    #[must_use]
    pub const fn style(&self) -> Option<&BeaconStyle> {
        self.style.as_ref()
    }

    /// The partitions this beacon is divided across, if set.
    #[must_use]
    pub const fn number_of_partitions(&self) -> Option<u8> {
        self.number_of_partitions
    }
}

/// A builder for [`StandardBeacon`].
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct StandardBeaconBuilder {
    name: Option<String>,
    bits: Option<u8>,
    location: Option<String>,
    style: Option<BeaconStyle>,
    number_of_partitions: Option<u8>,
}

impl StandardBeaconBuilder {
    /// The beacon's name, and the attribute it beacons unless a location is set. Required.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// The beacon's name. See [`Self::name`].
    #[must_use]
    pub fn set_name(mut self, name: Option<String>) -> Self {
        self.name = name;
        self
    }

    /// The number of bits of the beacon value, from 1 to 63. Required.
    ///
    /// Fewer bits make more values share a beacon value, which hides more and matches more.
    #[must_use]
    pub const fn bits(mut self, bits: u8) -> Self {
        self.bits = Some(bits);
        self
    }

    /// The number of bits. See [`Self::bits`].
    #[must_use]
    pub const fn set_bits(mut self, bits: Option<u8>) -> Self {
        self.bits = bits;
        self
    }

    /// The DynamoDB document path of the value, for example `"a.b[2]"` or a virtual field's name.
    /// Optional: the default is the beacon's name.
    #[must_use]
    pub fn location(mut self, location: impl Into<String>) -> Self {
        self.location = Some(location.into());
        self
    }

    /// The location of the value. See [`Self::location`].
    #[must_use]
    pub fn set_location(mut self, location: Option<String>) -> Self {
        self.location = location;
        self
    }

    /// The beacon's style.
    #[must_use]
    pub fn style(mut self, style: BeaconStyle) -> Self {
        self.style = Some(style);
        self
    }

    /// The beacon's style. See [`Self::style`].
    #[must_use]
    pub fn set_style(mut self, style: Option<BeaconStyle>) -> Self {
        self.style = style;
        self
    }

    /// The partitions this beacon is divided across, less than the version's maximum.
    /// Never change it once items are written.
    #[must_use]
    pub const fn number_of_partitions(mut self, count: u8) -> Self {
        self.number_of_partitions = Some(count);
        self
    }

    /// The partitions. See [`Self::number_of_partitions`].
    #[must_use]
    pub const fn set_number_of_partitions(mut self, count: Option<u8>) -> Self {
        self.number_of_partitions = count;
        self
    }

    /// Build the standard beacon.
    ///
    /// # Errors
    ///
    /// A `Validation` error when the name or the bits are missing,
    /// when the bits are not from 1 to 63, when the location is empty,
    /// or when the number of partitions is 0.
    pub fn build(self) -> Result<StandardBeacon, Error> {
        let bits = required(self.bits, "bits")?;
        if !(1..=63).contains(&bits) {
            return Err(val_err("bits must be between 1 and 63"));
        }
        non_empty_str(self.location.as_deref(), "location")?;
        check_partitions(self.number_of_partitions, "number_of_partitions")?;
        Ok(StandardBeacon {
            name: required(self.name, "name")?,
            bits,
            location: self.location,
            style: self.style,
            number_of_partitions: self.number_of_partitions,
        })
    }
}

/// How a standard beacon is used.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum BeaconStyle {
    /// Used only as a part of compound beacons, never written on its own.
    PartOnly(PartOnly),
    /// Computes its values as another beacon does, so the two can be compared.
    Shared(Shared),
    /// Beacons each element of a set attribute, and is written as a set.
    AsSet(AsSet),
    /// Both [`Shared`](Self::Shared) and [`AsSet`](Self::AsSet).
    SharedSet(SharedSet),
}

impl BeaconStyle {
    /// A [`PartOnly`](Self::PartOnly) style.
    #[must_use]
    pub fn part_only() -> Self {
        Self::PartOnly(PartOnly::new())
    }

    /// A [`Shared`](Self::Shared) style, computing values as beacon `other` does.
    #[must_use]
    pub fn shared(other: impl Into<String>) -> Self {
        Self::Shared(Shared {
            other: other.into(),
        })
    }

    /// An [`AsSet`](Self::AsSet) style.
    #[must_use]
    pub fn as_set() -> Self {
        Self::AsSet(AsSet::new())
    }

    /// A [`SharedSet`](Self::SharedSet) style, computing element values as beacon `other` does.
    #[must_use]
    pub fn shared_set(other: impl Into<String>) -> Self {
        Self::SharedSet(SharedSet {
            other: other.into(),
        })
    }
}

/// The [`BeaconStyle::PartOnly`] style.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct PartOnly {}

impl PartOnly {
    /// The part-only style.
    #[must_use]
    pub const fn new() -> Self {
        Self {}
    }
}

/// The [`BeaconStyle::AsSet`] style.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct AsSet {}

impl AsSet {
    /// The as-set style.
    #[must_use]
    pub const fn new() -> Self {
        Self {}
    }
}

/// The [`BeaconStyle::Shared`] style.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Shared {
    pub(crate) other: String,
}

impl Shared {
    /// A builder for the shared style.
    #[must_use]
    pub fn builder() -> SharedBuilder {
        SharedBuilder::default()
    }

    /// The beacon whose values this beacon computes.
    #[must_use]
    pub fn other(&self) -> &str {
        &self.other
    }
}

/// A builder for [`Shared`].
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct SharedBuilder {
    other: Option<String>,
}

impl SharedBuilder {
    /// The standard beacon whose values this beacon computes. Required.
    #[must_use]
    pub fn other(mut self, other: impl Into<String>) -> Self {
        self.other = Some(other.into());
        self
    }

    /// The other beacon. See [`Self::other`].
    #[must_use]
    pub fn set_other(mut self, other: Option<String>) -> Self {
        self.other = other;
        self
    }

    /// Build the style.
    ///
    /// # Errors
    ///
    /// A `Validation` error when the other beacon is missing.
    pub fn build(self) -> Result<Shared, Error> {
        Ok(Shared {
            other: required(self.other, "other")?,
        })
    }
}

/// The [`BeaconStyle::SharedSet`] style.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct SharedSet {
    pub(crate) other: String,
}

impl SharedSet {
    /// A builder for the shared-set style.
    #[must_use]
    pub fn builder() -> SharedSetBuilder {
        SharedSetBuilder::default()
    }

    /// The beacon whose values this beacon computes.
    #[must_use]
    pub fn other(&self) -> &str {
        &self.other
    }
}

/// A builder for [`SharedSet`].
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct SharedSetBuilder {
    other: Option<String>,
}

impl SharedSetBuilder {
    /// The standard beacon whose values this beacon computes. Required.
    #[must_use]
    pub fn other(mut self, other: impl Into<String>) -> Self {
        self.other = Some(other.into());
        self
    }

    /// The other beacon. See [`Self::other`].
    #[must_use]
    pub fn set_other(mut self, other: Option<String>) -> Self {
        self.other = other;
        self
    }

    /// Build the style.
    ///
    /// # Errors
    ///
    /// A `Validation` error when the other beacon is missing.
    pub fn build(self) -> Result<SharedSet, Error> {
        Ok(SharedSet {
            other: required(self.other, "other")?,
        })
    }
}

/// A beacon built from several parts, joined by a split character.
///
/// Its value is written to `aws_dbe_b_<name>`, or to `<name>` when every part is signed.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct CompoundBeacon {
    pub(crate) name: String,
    pub(crate) split: char,
    pub(crate) encrypted: Option<Vec<EncryptedPart>>,
    pub(crate) signed: Option<Vec<SignedPart>>,
    pub(crate) constructors: Option<Vec<Constructor>>,
}

impl CompoundBeacon {
    /// A builder for a compound beacon.
    #[must_use]
    pub fn builder() -> CompoundBeaconBuilder {
        CompoundBeaconBuilder::default()
    }

    /// The beacon's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The character that joins the parts.
    #[must_use]
    pub const fn split(&self) -> char {
        self.split
    }

    /// The encrypted parts only this beacon uses.
    #[must_use]
    pub fn encrypted(&self) -> &[EncryptedPart] {
        self.encrypted.as_deref().unwrap_or_default()
    }

    /// The signed parts only this beacon uses.
    #[must_use]
    pub fn signed(&self) -> &[SignedPart] {
        self.signed.as_deref().unwrap_or_default()
    }

    /// The ways to build the beacon, in order.
    #[must_use]
    pub fn constructors(&self) -> &[Constructor] {
        self.constructors.as_deref().unwrap_or_default()
    }
}

/// A builder for [`CompoundBeacon`].
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct CompoundBeaconBuilder {
    name: Option<String>,
    split: Option<String>,
    encrypted: Option<Vec<EncryptedPart>>,
    signed: Option<Vec<SignedPart>>,
    constructors: Option<Vec<Constructor>>,
}

impl CompoundBeaconBuilder {
    /// The beacon's name. Required.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// The beacon's name. See [`Self::name`].
    #[must_use]
    pub fn set_name(mut self, name: Option<String>) -> Self {
        self.name = name;
        self
    }

    /// The one character that joins the parts, for example `"."`. Required.
    /// It must not appear in any prefix or signed value.
    #[must_use]
    pub fn split(mut self, split: impl Into<String>) -> Self {
        self.split = Some(split.into());
        self
    }

    /// The split character. See [`Self::split`].
    #[must_use]
    pub fn set_split(mut self, split: Option<String>) -> Self {
        self.split = split;
        self
    }

    /// Add an encrypted part only this beacon uses.
    #[must_use]
    pub fn encrypted(mut self, part: EncryptedPart) -> Self {
        self.encrypted.get_or_insert_with(Vec::new).push(part);
        self
    }

    /// Replace this beacon's encrypted parts. See [`Self::encrypted`].
    #[must_use]
    pub fn set_encrypted(mut self, parts: Option<Vec<EncryptedPart>>) -> Self {
        self.encrypted = parts;
        self
    }

    /// Add a signed part only this beacon uses.
    #[must_use]
    pub fn signed(mut self, part: SignedPart) -> Self {
        self.signed.get_or_insert_with(Vec::new).push(part);
        self
    }

    /// Replace this beacon's signed parts. See [`Self::signed`].
    #[must_use]
    pub fn set_signed(mut self, parts: Option<Vec<SignedPart>>) -> Self {
        self.signed = parts;
        self
    }

    /// Add a way to build the beacon. The first that the item has every required part for is used.
    ///
    /// Optional: the default builds from every signed part, then every encrypted part,
    /// all required. Only this beacon's own parts are used for the default.
    #[must_use]
    pub fn constructors(mut self, constructor: Constructor) -> Self {
        self.constructors
            .get_or_insert_with(Vec::new)
            .push(constructor);
        self
    }

    /// Replace the constructors. See [`Self::constructors`].
    #[must_use]
    pub fn set_constructors(mut self, constructors: Option<Vec<Constructor>>) -> Self {
        self.constructors = constructors;
        self
    }

    /// Build the compound beacon.
    ///
    /// # Errors
    ///
    /// A `Validation` error when the name or the split character is missing,
    /// when the split is not exactly one character, or when a list is empty.
    pub fn build(self) -> Result<CompoundBeacon, Error> {
        let split = one_char(&required(self.split, "split")?, "split")?;
        non_empty(self.encrypted.as_ref(), "encrypted")?;
        non_empty(self.signed.as_ref(), "signed")?;
        non_empty(self.constructors.as_ref(), "constructors")?;
        Ok(CompoundBeacon {
            name: required(self.name, "name")?,
            split,
            encrypted: self.encrypted,
            signed: self.signed,
            constructors: self.constructors,
        })
    }
}

/// A compound beacon part holding a standard beacon's value.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct EncryptedPart {
    pub(crate) name: String,
    pub(crate) prefix: String,
}

impl EncryptedPart {
    /// A builder for an encrypted part.
    #[must_use]
    pub fn builder() -> EncryptedPartBuilder {
        EncryptedPartBuilder::default()
    }

    /// The standard beacon whose value the part holds.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The prefix written before the part's value.
    #[must_use]
    pub fn prefix(&self) -> &str {
        &self.prefix
    }
}

/// A builder for [`EncryptedPart`].
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct EncryptedPartBuilder {
    name: Option<String>,
    prefix: Option<String>,
}

impl EncryptedPartBuilder {
    /// The standard beacon whose value the part holds. Required.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// The standard beacon. See [`Self::name`].
    #[must_use]
    pub fn set_name(mut self, name: Option<String>) -> Self {
        self.name = name;
        self
    }

    /// The prefix written before the part's value. Required; not empty.
    /// No part's prefix may begin with another part's prefix.
    #[must_use]
    pub fn prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = Some(prefix.into());
        self
    }

    /// The prefix. See [`Self::prefix`].
    #[must_use]
    pub fn set_prefix(mut self, prefix: Option<String>) -> Self {
        self.prefix = prefix;
        self
    }

    /// Build the encrypted part.
    ///
    /// # Errors
    ///
    /// A `Validation` error when the name or the prefix is missing, or the prefix is empty.
    pub fn build(self) -> Result<EncryptedPart, Error> {
        let prefix = required(self.prefix, "prefix")?;
        non_empty_str(Some(&prefix), "prefix")?;
        Ok(EncryptedPart {
            name: required(self.name, "name")?,
            prefix,
        })
    }
}

/// A compound beacon part holding a signed, unencrypted value.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct SignedPart {
    pub(crate) name: String,
    pub(crate) prefix: String,
    pub(crate) location: Option<String>,
}

impl SignedPart {
    /// A builder for a signed part.
    #[must_use]
    pub fn builder() -> SignedPartBuilder {
        SignedPartBuilder::default()
    }

    /// The part's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The prefix written before the part's value.
    #[must_use]
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// The location of the value, if not the attribute named by the part.
    #[must_use]
    pub fn location(&self) -> Option<&str> {
        self.location.as_deref()
    }
}

/// A builder for [`SignedPart`].
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct SignedPartBuilder {
    name: Option<String>,
    prefix: Option<String>,
    location: Option<String>,
}

impl SignedPartBuilder {
    /// The part's name, and the attribute it holds unless a location is set. Required.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// The part's name. See [`Self::name`].
    #[must_use]
    pub fn set_name(mut self, name: Option<String>) -> Self {
        self.name = name;
        self
    }

    /// The prefix written before the part's value. Required; not empty.
    /// No part's prefix may begin with another part's prefix.
    #[must_use]
    pub fn prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = Some(prefix.into());
        self
    }

    /// The prefix. See [`Self::prefix`].
    #[must_use]
    pub fn set_prefix(mut self, prefix: Option<String>) -> Self {
        self.prefix = prefix;
        self
    }

    /// The DynamoDB document path of the value, which must be `SIGN_ONLY` or
    /// `SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT`. Optional: the default is the part's name.
    #[must_use]
    pub fn location(mut self, location: impl Into<String>) -> Self {
        self.location = Some(location.into());
        self
    }

    /// The location of the value. See [`Self::location`].
    #[must_use]
    pub fn set_location(mut self, location: Option<String>) -> Self {
        self.location = location;
        self
    }

    /// Build the signed part.
    ///
    /// # Errors
    ///
    /// A `Validation` error when the name or the prefix is missing,
    /// or the prefix or the location is empty.
    pub fn build(self) -> Result<SignedPart, Error> {
        let prefix = required(self.prefix, "prefix")?;
        non_empty_str(Some(&prefix), "prefix")?;
        non_empty_str(self.location.as_deref(), "location")?;
        Ok(SignedPart {
            name: required(self.name, "name")?,
            prefix,
            location: self.location,
        })
    }
}

/// One way to build a compound beacon: its parts, in order.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Constructor {
    pub(crate) parts: Vec<ConstructorPart>,
}

impl Constructor {
    /// A builder for a constructor.
    #[must_use]
    pub fn builder() -> ConstructorBuilder {
        ConstructorBuilder::default()
    }

    /// The parts, in order.
    #[must_use]
    pub fn parts(&self) -> &[ConstructorPart] {
        &self.parts
    }
}

/// A builder for [`Constructor`].
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct ConstructorBuilder {
    parts: Option<Vec<ConstructorPart>>,
}

impl ConstructorBuilder {
    /// Add a part. At least one is required, and at least one part must be required.
    #[must_use]
    pub fn parts(mut self, part: ConstructorPart) -> Self {
        self.parts.get_or_insert_with(Vec::new).push(part);
        self
    }

    /// Replace the parts. See [`Self::parts`].
    #[must_use]
    pub fn set_parts(mut self, parts: Option<Vec<ConstructorPart>>) -> Self {
        self.parts = parts;
        self
    }

    /// Build the constructor.
    ///
    /// # Errors
    ///
    /// A `Validation` error when there are no parts.
    pub fn build(self) -> Result<Constructor, Error> {
        let parts = required(self.parts, "parts")?;
        non_empty(Some(&parts), "parts")?;
        Ok(Constructor { parts })
    }
}

/// A part of a [`Constructor`]: the name of an encrypted or signed part.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ConstructorPart {
    pub(crate) name: String,
    pub(crate) required: bool,
}

impl ConstructorPart {
    /// A builder for a constructor part.
    #[must_use]
    pub fn builder() -> ConstructorPartBuilder {
        ConstructorPartBuilder::default()
    }

    /// A part the item must have for the constructor to be used.
    #[must_use]
    pub fn required(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            required: true,
        }
    }

    /// The name of the encrypted or signed part.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether the item must have the part for the constructor to be used.
    #[must_use]
    pub const fn is_required(&self) -> bool {
        self.required
    }
}

/// A builder for [`ConstructorPart`].
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct ConstructorPartBuilder {
    name: Option<String>,
    required: Option<bool>,
}

impl ConstructorPartBuilder {
    /// The name of the encrypted or signed part. Required.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// The part's name. See [`Self::name`].
    #[must_use]
    pub fn set_name(mut self, name: Option<String>) -> Self {
        self.name = name;
        self
    }

    /// Whether the item must have the part for the constructor to be used. Required.
    #[must_use]
    pub const fn required(mut self, required: bool) -> Self {
        self.required = Some(required);
        self
    }

    /// Whether the part is required. See [`Self::required`].
    #[must_use]
    pub const fn set_required(mut self, required: Option<bool>) -> Self {
        self.required = required;
        self
    }

    /// Build the constructor part.
    ///
    /// # Errors
    ///
    /// A `Validation` error when the name or the required flag is missing.
    pub fn build(self) -> Result<ConstructorPart, Error> {
        Ok(ConstructorPart {
            name: required(self.name, "name")?,
            required: required(self.required, "required")?,
        })
    }
}

/// A value computed from other values of the item, for a beacon to beacon.
/// It is never written to the item.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct VirtualField {
    pub(crate) name: String,
    pub(crate) parts: Vec<VirtualPart>,
}

impl VirtualField {
    /// A builder for a virtual field.
    #[must_use]
    pub fn builder() -> VirtualFieldBuilder {
        VirtualFieldBuilder::default()
    }

    /// The field's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The parts joined to make the field's value, in order.
    #[must_use]
    pub fn parts(&self) -> &[VirtualPart] {
        &self.parts
    }
}

/// A builder for [`VirtualField`].
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct VirtualFieldBuilder {
    name: Option<String>,
    parts: Option<Vec<VirtualPart>>,
}

impl VirtualFieldBuilder {
    /// The field's name. It must not be an attribute of the table. Required.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// The field's name. See [`Self::name`].
    #[must_use]
    pub fn set_name(mut self, name: Option<String>) -> Self {
        self.name = name;
        self
    }

    /// Add a part. At least one is required.
    #[must_use]
    pub fn parts(mut self, part: VirtualPart) -> Self {
        self.parts.get_or_insert_with(Vec::new).push(part);
        self
    }

    /// Replace the parts. See [`Self::parts`].
    #[must_use]
    pub fn set_parts(mut self, parts: Option<Vec<VirtualPart>>) -> Self {
        self.parts = parts;
        self
    }

    /// Build the virtual field.
    ///
    /// # Errors
    ///
    /// A `Validation` error when the name or the parts are missing, or there are no parts.
    pub fn build(self) -> Result<VirtualField, Error> {
        let parts = required(self.parts, "parts")?;
        non_empty(Some(&parts), "parts")?;
        Ok(VirtualField {
            name: required(self.name, "name")?,
            parts,
        })
    }
}

/// A part of a [`VirtualField`]: a value of the item, transformed.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct VirtualPart {
    pub(crate) location: String,
    pub(crate) transforms: Option<Vec<VirtualTransform>>,
}

impl VirtualPart {
    /// A builder for a virtual part.
    #[must_use]
    pub fn builder() -> VirtualPartBuilder {
        VirtualPartBuilder::default()
    }

    /// The DynamoDB document path of the value.
    #[must_use]
    pub fn location(&self) -> &str {
        &self.location
    }

    /// The transforms applied to the value, in order.
    #[must_use]
    pub fn transforms(&self) -> &[VirtualTransform] {
        self.transforms.as_deref().unwrap_or_default()
    }
}

/// A builder for [`VirtualPart`].
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct VirtualPartBuilder {
    location: Option<String>,
    transforms: Option<Vec<VirtualTransform>>,
}

impl VirtualPartBuilder {
    /// The DynamoDB document path of a signed value, for example `"a.b[2]"`. Required.
    #[must_use]
    pub fn location(mut self, location: impl Into<String>) -> Self {
        self.location = Some(location.into());
        self
    }

    /// The location. See [`Self::location`].
    #[must_use]
    pub fn set_location(mut self, location: Option<String>) -> Self {
        self.location = location;
        self
    }

    /// Add a transform, applied after the ones before it.
    #[must_use]
    pub fn transforms(mut self, transform: VirtualTransform) -> Self {
        self.transforms.get_or_insert_with(Vec::new).push(transform);
        self
    }

    /// Replace the transforms. See [`Self::transforms`].
    #[must_use]
    pub fn set_transforms(mut self, transforms: Option<Vec<VirtualTransform>>) -> Self {
        self.transforms = transforms;
        self
    }

    /// Build the virtual part.
    ///
    /// # Errors
    ///
    /// A `Validation` error when the location is missing or empty, or the transforms are empty.
    pub fn build(self) -> Result<VirtualPart, Error> {
        let location = required(self.location, "location")?;
        non_empty_str(Some(&location), "location")?;
        non_empty(self.transforms.as_ref(), "transforms")?;
        Ok(VirtualPart {
            location,
            transforms: self.transforms,
        })
    }
}

/// A change to a [`VirtualPart`]'s value, which is treated as a string.
///
/// A position counts from 0; a negative position counts back from the end.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum VirtualTransform {
    /// Change ASCII letters to upper case.
    Upper(Upper),
    /// Change ASCII letters to lower case.
    Lower(Lower),
    /// Append a literal string.
    Insert(Insert),
    /// Keep the front of the value.
    Prefix(GetPrefix),
    /// Keep the end of the value.
    Suffix(GetSuffix),
    /// Keep a range of characters.
    Substring(GetSubstring),
    /// Split the value and keep one segment.
    Segment(GetSegment),
    /// Split the value and keep a range of segments.
    Segments(GetSegments),
}

impl VirtualTransform {
    /// An [`Upper`](Self::Upper) transform.
    #[must_use]
    pub fn upper() -> Self {
        Self::Upper(Upper::new())
    }

    /// A [`Lower`](Self::Lower) transform.
    #[must_use]
    pub fn lower() -> Self {
        Self::Lower(Lower::new())
    }

    /// An [`Insert`](Self::Insert) transform appending `literal`.
    #[must_use]
    pub fn insert(literal: impl Into<String>) -> Self {
        Self::Insert(Insert {
            literal: literal.into(),
        })
    }

    /// A [`Prefix`](Self::Prefix) transform. See [`GetPrefixBuilder::length`].
    #[must_use]
    pub const fn prefix(length: i32) -> Self {
        Self::Prefix(GetPrefix { length })
    }

    /// A [`Suffix`](Self::Suffix) transform. See [`GetSuffixBuilder::length`].
    #[must_use]
    pub const fn suffix(length: i32) -> Self {
        Self::Suffix(GetSuffix { length })
    }

    /// A [`Substring`](Self::Substring) transform keeping positions `low` up to, not including, `high`.
    #[must_use]
    pub const fn substring(low: i32, high: i32) -> Self {
        Self::Substring(GetSubstring { low, high })
    }

    /// A [`Segment`](Self::Segment) transform: split on `split`, keep segment `index`.
    #[must_use]
    pub const fn segment(split: char, index: i32) -> Self {
        Self::Segment(GetSegment { split, index })
    }

    /// A [`Segments`](Self::Segments) transform: split on `split`,
    /// keep segments `low` up to, not including, `high`.
    #[must_use]
    pub const fn segments(split: char, low: i32, high: i32) -> Self {
        Self::Segments(GetSegments { split, low, high })
    }
}

/// The [`VirtualTransform::Upper`] transform.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct Upper {}

impl Upper {
    /// The upper-case transform.
    #[must_use]
    pub const fn new() -> Self {
        Self {}
    }
}

/// The [`VirtualTransform::Lower`] transform.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct Lower {}

impl Lower {
    /// The lower-case transform.
    #[must_use]
    pub const fn new() -> Self {
        Self {}
    }
}

/// The [`VirtualTransform::Insert`] transform.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Insert {
    pub(crate) literal: String,
}

impl Insert {
    /// A builder for the insert transform.
    #[must_use]
    pub fn builder() -> InsertBuilder {
        InsertBuilder::default()
    }

    /// The string appended.
    #[must_use]
    pub fn literal(&self) -> &str {
        &self.literal
    }
}

/// A builder for [`Insert`].
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct InsertBuilder {
    literal: Option<String>,
}

impl InsertBuilder {
    /// The string appended. Required.
    #[must_use]
    pub fn literal(mut self, literal: impl Into<String>) -> Self {
        self.literal = Some(literal.into());
        self
    }

    /// The string appended. See [`Self::literal`].
    #[must_use]
    pub fn set_literal(mut self, literal: Option<String>) -> Self {
        self.literal = literal;
        self
    }

    /// Build the transform.
    ///
    /// # Errors
    ///
    /// A `Validation` error when the literal is missing.
    pub fn build(self) -> Result<Insert, Error> {
        Ok(Insert {
            literal: required(self.literal, "literal")?,
        })
    }
}

/// The [`VirtualTransform::Prefix`] transform.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct GetPrefix {
    pub(crate) length: i32,
}

impl GetPrefix {
    /// A builder for the prefix transform.
    #[must_use]
    pub fn builder() -> GetPrefixBuilder {
        GetPrefixBuilder::default()
    }

    /// The characters kept, or dropped from the end when negative.
    #[must_use]
    pub const fn length(&self) -> i32 {
        self.length
    }
}

/// A builder for [`GetPrefix`].
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct GetPrefixBuilder {
    length: Option<i32>,
}

impl GetPrefixBuilder {
    /// How many characters to keep from the front. Required.
    /// When negative, how many to drop from the end: `-1` keeps all but the last.
    #[must_use]
    pub const fn length(mut self, length: i32) -> Self {
        self.length = Some(length);
        self
    }

    /// The length. See [`Self::length`].
    #[must_use]
    pub const fn set_length(mut self, length: Option<i32>) -> Self {
        self.length = length;
        self
    }

    /// Build the transform.
    ///
    /// # Errors
    ///
    /// A `Validation` error when the length is missing.
    pub fn build(self) -> Result<GetPrefix, Error> {
        Ok(GetPrefix {
            length: required(self.length, "length")?,
        })
    }
}

/// The [`VirtualTransform::Suffix`] transform.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct GetSuffix {
    pub(crate) length: i32,
}

impl GetSuffix {
    /// A builder for the suffix transform.
    #[must_use]
    pub fn builder() -> GetSuffixBuilder {
        GetSuffixBuilder::default()
    }

    /// The characters kept, or dropped from the front when negative.
    #[must_use]
    pub const fn length(&self) -> i32 {
        self.length
    }
}

/// A builder for [`GetSuffix`].
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct GetSuffixBuilder {
    length: Option<i32>,
}

impl GetSuffixBuilder {
    /// How many characters to keep from the end. Required.
    /// When negative, how many to drop from the front: `-1` keeps all but the first.
    #[must_use]
    pub const fn length(mut self, length: i32) -> Self {
        self.length = Some(length);
        self
    }

    /// The length. See [`Self::length`].
    #[must_use]
    pub const fn set_length(mut self, length: Option<i32>) -> Self {
        self.length = length;
        self
    }

    /// Build the transform.
    ///
    /// # Errors
    ///
    /// A `Validation` error when the length is missing.
    pub fn build(self) -> Result<GetSuffix, Error> {
        Ok(GetSuffix {
            length: required(self.length, "length")?,
        })
    }
}

/// The [`VirtualTransform::Substring`] transform.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct GetSubstring {
    pub(crate) low: i32,
    pub(crate) high: i32,
}

impl GetSubstring {
    /// A builder for the substring transform.
    #[must_use]
    pub fn builder() -> GetSubstringBuilder {
        GetSubstringBuilder::default()
    }

    /// The first position kept.
    #[must_use]
    pub const fn low(&self) -> i32 {
        self.low
    }

    /// The position after the last one kept.
    #[must_use]
    pub const fn high(&self) -> i32 {
        self.high
    }
}

/// A builder for [`GetSubstring`].
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct GetSubstringBuilder {
    low: Option<i32>,
    high: Option<i32>,
}

impl GetSubstringBuilder {
    /// The first position kept. Required.
    #[must_use]
    pub const fn low(mut self, low: i32) -> Self {
        self.low = Some(low);
        self
    }

    /// The first position. See [`Self::low`].
    #[must_use]
    pub const fn set_low(mut self, low: Option<i32>) -> Self {
        self.low = low;
        self
    }

    /// The position after the last one kept. Required.
    #[must_use]
    pub const fn high(mut self, high: i32) -> Self {
        self.high = Some(high);
        self
    }

    /// The end position. See [`Self::high`].
    #[must_use]
    pub const fn set_high(mut self, high: Option<i32>) -> Self {
        self.high = high;
        self
    }

    /// Build the transform.
    ///
    /// # Errors
    ///
    /// A `Validation` error when a position is missing.
    pub fn build(self) -> Result<GetSubstring, Error> {
        Ok(GetSubstring {
            low: required(self.low, "low")?,
            high: required(self.high, "high")?,
        })
    }
}

/// The [`VirtualTransform::Segment`] transform.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct GetSegment {
    pub(crate) split: char,
    pub(crate) index: i32,
}

impl GetSegment {
    /// A builder for the segment transform.
    #[must_use]
    pub fn builder() -> GetSegmentBuilder {
        GetSegmentBuilder::default()
    }

    /// The character the value is split on.
    #[must_use]
    pub const fn split(&self) -> char {
        self.split
    }

    /// The position of the segment kept.
    #[must_use]
    pub const fn index(&self) -> i32 {
        self.index
    }
}

/// A builder for [`GetSegment`].
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct GetSegmentBuilder {
    split: Option<String>,
    index: Option<i32>,
}

impl GetSegmentBuilder {
    /// The one character the value is split on. Required.
    #[must_use]
    pub fn split(mut self, split: impl Into<String>) -> Self {
        self.split = Some(split.into());
        self
    }

    /// The split character. See [`Self::split`].
    #[must_use]
    pub fn set_split(mut self, split: Option<String>) -> Self {
        self.split = split;
        self
    }

    /// The position of the segment kept: 0 is before the first split, -1 after the last. Required.
    #[must_use]
    pub const fn index(mut self, index: i32) -> Self {
        self.index = Some(index);
        self
    }

    /// The segment's position. See [`Self::index`].
    #[must_use]
    pub const fn set_index(mut self, index: Option<i32>) -> Self {
        self.index = index;
        self
    }

    /// Build the transform.
    ///
    /// # Errors
    ///
    /// A `Validation` error when the split or the index is missing,
    /// or the split is not exactly one character.
    pub fn build(self) -> Result<GetSegment, Error> {
        Ok(GetSegment {
            split: one_char(&required(self.split, "split")?, "split")?,
            index: required(self.index, "index")?,
        })
    }
}

/// The [`VirtualTransform::Segments`] transform.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct GetSegments {
    pub(crate) split: char,
    pub(crate) low: i32,
    pub(crate) high: i32,
}

impl GetSegments {
    /// A builder for the segments transform.
    #[must_use]
    pub fn builder() -> GetSegmentsBuilder {
        GetSegmentsBuilder::default()
    }

    /// The character the value is split on.
    #[must_use]
    pub const fn split(&self) -> char {
        self.split
    }

    /// The position of the first segment kept.
    #[must_use]
    pub const fn low(&self) -> i32 {
        self.low
    }

    /// The position after the last segment kept.
    #[must_use]
    pub const fn high(&self) -> i32 {
        self.high
    }
}

/// A builder for [`GetSegments`].
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct GetSegmentsBuilder {
    split: Option<String>,
    low: Option<i32>,
    high: Option<i32>,
}

impl GetSegmentsBuilder {
    /// The one character the value is split on. Required.
    #[must_use]
    pub fn split(mut self, split: impl Into<String>) -> Self {
        self.split = Some(split.into());
        self
    }

    /// The split character. See [`Self::split`].
    #[must_use]
    pub fn set_split(mut self, split: Option<String>) -> Self {
        self.split = split;
        self
    }

    /// The position of the first segment kept. Required.
    #[must_use]
    pub const fn low(mut self, low: i32) -> Self {
        self.low = Some(low);
        self
    }

    /// The first position. See [`Self::low`].
    #[must_use]
    pub const fn set_low(mut self, low: Option<i32>) -> Self {
        self.low = low;
        self
    }

    /// The position after the last segment kept. Required.
    #[must_use]
    pub const fn high(mut self, high: i32) -> Self {
        self.high = Some(high);
        self
    }

    /// The end position. See [`Self::high`].
    #[must_use]
    pub const fn set_high(mut self, high: Option<i32>) -> Self {
        self.high = high;
        self
    }

    /// Build the transform.
    ///
    /// # Errors
    ///
    /// A `Validation` error when the split or a position is missing,
    /// or the split is not exactly one character.
    pub fn build(self) -> Result<GetSegments, Error> {
        Ok(GetSegments {
            split: one_char(&required(self.split, "split")?, "split")?,
            low: required(self.low, "low")?,
            high: required(self.high, "high")?,
        })
    }
}

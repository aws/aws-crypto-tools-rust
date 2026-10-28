// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The searchable-encryption (beacon) configuration: the wire shapes of the
//! TestServer model's `SearchConfig`, and their conversion to `aws_db_esdk::search`.

use std::collections::HashMap;
use std::time::Duration;

use aws_db_esdk::search;
use serde::Deserialize;

use crate::error::ServerError;
use crate::keyring::key_store_for;

#[derive(Debug, Deserialize)]
pub struct SearchConfig {
    pub versions: Vec<BeaconVersion>,
    #[serde(rename = "writeVersion", default)]
    pub write_version: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct BeaconVersion {
    pub version: i32,
    #[serde(rename = "keyStore")]
    pub key_store: BeaconKeyStore,
    #[serde(rename = "keySource")]
    pub key_source: BeaconKeySource,
    #[serde(rename = "standardBeacons", default)]
    pub standard_beacons: Option<Vec<StandardBeacon>>,
    #[serde(rename = "compoundBeacons", default)]
    pub compound_beacons: Option<Vec<CompoundBeacon>>,
    #[serde(rename = "virtualFields", default)]
    pub virtual_fields: Option<Vec<VirtualField>>,
    #[serde(rename = "encryptedParts", default)]
    pub encrypted_parts: Option<Vec<EncryptedPart>>,
    #[serde(rename = "signedParts", default)]
    pub signed_parts: Option<Vec<SignedPart>>,
    #[serde(rename = "maximumNumberOfPartitions", default)]
    pub maximum_number_of_partitions: Option<i32>,
    #[serde(rename = "defaultNumberOfPartitions", default)]
    pub default_number_of_partitions: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct BeaconKeyStore {
    #[serde(rename = "ddbTableName")]
    pub ddb_table_name: String,
    #[serde(rename = "logicalKeyStoreName")]
    pub logical_key_store_name: String,
    #[serde(rename = "kmsKeyArn")]
    pub kms_key_arn: String,
}

/// The key source union: only the single key store is modeled; any other member is refused.
#[derive(Debug, Deserialize)]
pub struct BeaconKeySource {
    #[serde(default)]
    pub single: Option<SingleKeyStore>,
    #[serde(flatten)]
    pub other: HashMap<String, ciborium::Value>,
}

#[derive(Debug, Deserialize)]
pub struct SingleKeyStore {
    #[serde(rename = "keyId")]
    pub key_id: String,
    #[serde(rename = "cacheTtlSeconds")]
    pub cache_ttl_seconds: i32,
}

#[derive(Debug, Deserialize)]
pub struct StandardBeacon {
    pub name: String,
    pub length: i32,
    #[serde(default)]
    pub loc: Option<String>,
    #[serde(rename = "numberOfPartitions", default)]
    pub number_of_partitions: Option<i32>,
    #[serde(default)]
    pub style: Option<BeaconStyle>,
}

/// An empty structure member, such as `PartOnly` or `Upper`.
#[derive(Debug, Deserialize)]
pub struct Empty {}

#[derive(Debug, Deserialize)]
pub struct Other {
    pub other: String,
}

#[derive(Debug, Deserialize)]
pub struct BeaconStyle {
    #[serde(rename = "partOnly", default)]
    pub part_only: Option<Empty>,
    #[serde(default)]
    pub shared: Option<Other>,
    #[serde(rename = "asSet", default)]
    pub as_set: Option<Empty>,
    #[serde(rename = "sharedSet", default)]
    pub shared_set: Option<Other>,
}

#[derive(Debug, Deserialize)]
pub struct CompoundBeacon {
    pub name: String,
    pub split: String,
    #[serde(default)]
    pub constructors: Option<Vec<Constructor>>,
    #[serde(default)]
    pub encrypted: Option<Vec<EncryptedPart>>,
    #[serde(default)]
    pub signed: Option<Vec<SignedPart>>,
}

#[derive(Debug, Deserialize)]
pub struct Constructor {
    pub parts: Vec<ConstructorPart>,
}

#[derive(Debug, Deserialize)]
pub struct ConstructorPart {
    pub name: String,
    pub required: bool,
}

#[derive(Debug, Deserialize)]
pub struct EncryptedPart {
    pub name: String,
    pub prefix: String,
}

#[derive(Debug, Deserialize)]
pub struct SignedPart {
    pub name: String,
    pub prefix: String,
    #[serde(default)]
    pub loc: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct VirtualField {
    pub name: String,
    pub parts: Vec<VirtualPart>,
}

#[derive(Debug, Deserialize)]
pub struct VirtualPart {
    pub loc: String,
    #[serde(default)]
    pub trans: Option<Vec<VirtualTransform>>,
}

#[derive(Debug, Deserialize)]
pub struct Literal {
    pub literal: String,
}

#[derive(Debug, Deserialize)]
pub struct Length {
    pub length: i32,
}

#[derive(Debug, Deserialize)]
pub struct Range {
    pub low: i32,
    pub high: i32,
}

#[derive(Debug, Deserialize)]
pub struct Segment {
    pub split: String,
    pub index: i32,
}

#[derive(Debug, Deserialize)]
pub struct Segments {
    pub split: String,
    pub low: i32,
    pub high: i32,
}

/// The virtual-transform union (exactly one member set).
#[derive(Debug, Deserialize)]
pub struct VirtualTransform {
    #[serde(default)]
    pub upper: Option<Empty>,
    #[serde(default)]
    pub lower: Option<Empty>,
    #[serde(default)]
    pub insert: Option<Literal>,
    #[serde(default)]
    pub prefix: Option<Length>,
    #[serde(default)]
    pub suffix: Option<Length>,
    #[serde(default)]
    pub substring: Option<Range>,
    #[serde(default)]
    pub segment: Option<Segment>,
    #[serde(default)]
    pub segments: Option<Segments>,
}

/// An integer member converted to the library's type, or a library-style error.
fn int<T: TryFrom<i32>>(value: i32, field: &str) -> Result<T, ServerError> {
    T::try_from(value).map_err(|_| ServerError::client(format!("{field} is out of range: {value}")))
}

fn opt_int<T: TryFrom<i32>>(value: Option<i32>, field: &str) -> Result<Option<T>, ServerError> {
    value.map(|v| int(v, field)).transpose()
}

/// Convert each element of an optional list.
fn list<W, T>(
    items: Option<Vec<W>>,
    f: impl Fn(W) -> Result<T, ServerError>,
) -> Result<Option<Vec<T>>, ServerError> {
    items.map(|v| v.into_iter().map(f).collect()).transpose()
}

/// The library's search configuration for the wire's `config`.
pub async fn search_config(config: SearchConfig) -> Result<search::SearchConfig, ServerError> {
    let mut versions = Vec::with_capacity(config.versions.len());
    for v in config.versions {
        versions.push(beacon_version(v).await?);
    }
    Ok(search::SearchConfig::builder()
        .set_versions(Some(versions))
        .write_version(int(config.write_version.unwrap_or(1), "writeVersion")?)
        .build()?)
}

async fn beacon_version(v: BeaconVersion) -> Result<search::BeaconVersion, ServerError> {
    let key_store = key_store_for(
        &v.key_store.ddb_table_name,
        &v.key_store.logical_key_store_name,
        &v.key_store.kms_key_arn,
    )
    .await?;
    Ok(search::BeaconVersion::builder()
        .version(int(v.version, "version")?)
        .key_store(key_store)
        .key_source(key_source(v.key_source)?)
        .set_standard_beacons(list(v.standard_beacons, standard_beacon)?)
        .set_compound_beacons(list(v.compound_beacons, compound_beacon)?)
        .set_virtual_fields(list(v.virtual_fields, virtual_field)?)
        .set_encrypted_parts(list(v.encrypted_parts, encrypted_part)?)
        .set_signed_parts(list(v.signed_parts, signed_part)?)
        .set_maximum_number_of_partitions(opt_int(
            v.maximum_number_of_partitions,
            "maximumNumberOfPartitions",
        )?)
        .set_default_number_of_partitions(opt_int(
            v.default_number_of_partitions,
            "defaultNumberOfPartitions",
        )?)
        .build()?)
}

fn key_source(source: BeaconKeySource) -> Result<search::BeaconKeySource, ServerError> {
    match (source.single, source.other.is_empty()) {
        (Some(single), true) => {
            let ttl: u64 = int(single.cache_ttl_seconds, "cacheTtlSeconds")?;
            Ok(search::BeaconKeySource::Single(
                search::SingleKeyStore::builder()
                    .key_id(single.key_id)
                    .cache_ttl(Duration::from_secs(ttl))
                    .build()?,
            ))
        }
        _ => Err(ServerError::generic(
            "BeaconKeySource must set exactly one supported member (single)",
        )),
    }
}

fn standard_beacon(b: StandardBeacon) -> Result<search::StandardBeacon, ServerError> {
    let style = b.style.map(beacon_style).transpose()?;
    Ok(search::StandardBeacon::builder()
        .name(b.name)
        .bits(int(b.length, "length")?)
        .set_location(b.loc)
        .set_style(style)
        .set_number_of_partitions(opt_int(b.number_of_partitions, "numberOfPartitions")?)
        .build()?)
}

fn beacon_style(s: BeaconStyle) -> Result<search::BeaconStyle, ServerError> {
    match (s.part_only, s.shared, s.as_set, s.shared_set) {
        (Some(_), None, None, None) => Ok(search::BeaconStyle::part_only()),
        (None, Some(o), None, None) => Ok(search::BeaconStyle::shared(o.other)),
        (None, None, Some(_), None) => Ok(search::BeaconStyle::as_set()),
        (None, None, None, Some(o)) => Ok(search::BeaconStyle::shared_set(o.other)),
        _ => Err(ServerError::generic(
            "BeaconStyle must set exactly one member",
        )),
    }
}

fn compound_beacon(b: CompoundBeacon) -> Result<search::CompoundBeacon, ServerError> {
    Ok(search::CompoundBeacon::builder()
        .name(b.name)
        .split(b.split)
        .set_constructors(list(b.constructors, constructor)?)
        .set_encrypted(list(b.encrypted, encrypted_part)?)
        .set_signed(list(b.signed, signed_part)?)
        .build()?)
}

fn constructor(c: Constructor) -> Result<search::Constructor, ServerError> {
    let parts = c
        .parts
        .into_iter()
        .map(|p| {
            search::ConstructorPart::builder()
                .name(p.name)
                .required(p.required)
                .build()
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(search::Constructor::builder()
        .set_parts(Some(parts))
        .build()?)
}

fn encrypted_part(p: EncryptedPart) -> Result<search::EncryptedPart, ServerError> {
    Ok(search::EncryptedPart::builder()
        .name(p.name)
        .prefix(p.prefix)
        .build()?)
}

fn signed_part(p: SignedPart) -> Result<search::SignedPart, ServerError> {
    Ok(search::SignedPart::builder()
        .name(p.name)
        .prefix(p.prefix)
        .set_location(p.loc)
        .build()?)
}

fn virtual_field(f: VirtualField) -> Result<search::VirtualField, ServerError> {
    let parts = f
        .parts
        .into_iter()
        .map(virtual_part)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(search::VirtualField::builder()
        .name(f.name)
        .set_parts(Some(parts))
        .build()?)
}

fn virtual_part(p: VirtualPart) -> Result<search::VirtualPart, ServerError> {
    Ok(search::VirtualPart::builder()
        .location(p.loc)
        .set_transforms(list(p.trans, virtual_transform)?)
        .build()?)
}

fn virtual_transform(t: VirtualTransform) -> Result<search::VirtualTransform, ServerError> {
    use search::VirtualTransform as T;
    let set = [
        t.upper.is_some(),
        t.lower.is_some(),
        t.insert.is_some(),
        t.prefix.is_some(),
        t.suffix.is_some(),
        t.substring.is_some(),
        t.segment.is_some(),
        t.segments.is_some(),
    ];
    if set.iter().filter(|s| **s).count() != 1 {
        return Err(ServerError::generic(
            "VirtualTransform must set exactly one member",
        ));
    }
    Ok(if t.upper.is_some() {
        T::upper()
    } else if t.lower.is_some() {
        T::lower()
    } else if let Some(i) = t.insert {
        T::insert(i.literal)
    } else if let Some(p) = t.prefix {
        T::prefix(p.length)
    } else if let Some(s) = t.suffix {
        T::suffix(s.length)
    } else if let Some(r) = t.substring {
        T::substring(r.low, r.high)
    } else if let Some(s) = t.segment {
        T::Segment(
            search::GetSegment::builder()
                .split(s.split)
                .index(s.index)
                .build()?,
        )
    } else if let Some(s) = t.segments {
        T::Segments(
            search::GetSegments::builder()
                .split(s.split)
                .low(s.low)
                .high(s.high)
                .build()?,
        )
    } else {
        unreachable!("exactly one member is set")
    })
}

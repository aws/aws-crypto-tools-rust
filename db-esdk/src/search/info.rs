// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The checked, internal form of a search configuration.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use aws_crypto_mpl::aws_sdk_dynamodb::types::AttributeValue;

use crate::ddb::Item;
use crate::error::Error;
use crate::search::beacon::{MaybeKeyId, MaybeKeyMap};
use crate::search::config::VirtualTransform;
use crate::search::key_source::KeySource;
use crate::search::partition::SharedPartitionSelector;
use crate::search::term_loc::TermLoc;

/// The prefix of the attribute holding a beacon's value.
pub(crate) const BEACON_PREFIX: &str = "aws_dbe_b_";

/// The checked search configuration of a table.
#[derive(Debug)]
pub(crate) struct SearchInfo {
    /// The beacon version items are written and read with.
    pub(crate) version: BeaconVersionInfo,
}

/// A checked beacon version.
#[derive(Debug)]
pub(crate) struct BeaconVersionInfo {
    pub(crate) key_source: KeySource,
    /// Every beacon, standard and compound, by name.
    pub(crate) beacons: BTreeMap<String, Beacon>,
    pub(crate) virtual_fields: BTreeMap<String, VirtField>,
    /// The names of the standard beacons, in order: one HMAC key each.
    pub(crate) standard_names: Vec<String>,
    /// The attributes that are `ENCRYPT_AND_SIGN`.
    pub(crate) encrypted_fields: BTreeSet<String>,
    /// The most partitions any beacon is divided across.
    pub(crate) max_partitions: u8,
    /// What picks the partition an item is written in.
    pub(crate) partition_selector: SharedPartitionSelector,
}

impl BeaconVersionInfo {
    /// The compound beacons whose parts are all signed: their values are written in plaintext.
    pub(crate) fn signed_beacon_names(&self) -> Vec<String> {
        self.beacons
            .iter()
            .filter(|(_, b)| !b.is_encrypted())
            .map(|(n, _)| n.clone())
            .collect()
    }

    /// The beacon HMAC keys for `key_id`.
    pub(crate) async fn get_key_map(&self, key_id: &MaybeKeyId) -> Result<MaybeKeyMap, Error> {
        //= spec/searchable-encryption/search-config.md#beacon-keys
        //# Beacon keys MUST be obtained from the configured [Beacon Key Source](#beacon-key-source).
        self.key_source
            .get_key_map(&self.standard_names, key_id)
            .await
    }

    /// The value of every beacon of type `kind` that `item` has, by beacon attribute name.
    ///
    /// A part-only beacon is never written.
    fn generate_beacons(
        &self,
        item: &Item,
        keys: &MaybeKeyMap,
        kind: BeaconKind,
        partition: u8,
    ) -> Result<Item, Error> {
        let mut out = Item::new();
        for beacon in self.beacons.values() {
            let of_kind = match kind {
                BeaconKind::Any => true,
                BeaconKind::Signed => !beacon.is_encrypted(),
                BeaconKind::Encrypted => beacon.is_encrypted(),
            };

            //= spec/searchable-encryption/beacons.md#partonly-initialization
            //# The Standard Beacon MUST NOT be stored in the item for a PartOnly beacon.
            if !of_kind || beacon.is_part_only() {
                continue;
            }
            if let Some(value) = beacon.attr_hash(item, &self.virtual_fields, keys, partition)? {
                out.insert(beacon.beacon_name().to_owned(), value);
            }
        }
        Ok(out)
    }

    /// Every beacon's plaintext value: what a re-filter compares on a decrypted item.
    pub(crate) fn generate_plain_beacons(&self, item: &Item, partition: u8) -> Result<Item, Error> {
        self.generate_beacons(item, &MaybeKeyMap::DontUseKeys, BeaconKind::Any, partition)
    }

    /// The values of the beacons whose parts are all signed, written in plaintext.
    pub(crate) fn generate_signed_beacons(
        &self,
        item: &Item,
        partition: u8,
    ) -> Result<Item, Error> {
        self.generate_beacons(
            item,
            &MaybeKeyMap::DontUseKeys,
            BeaconKind::Signed,
            partition,
        )
    }

    /// The value of every virtual field `item` has, by field name.
    pub(crate) fn virtual_field_values(
        &self,
        item: &Item,
    ) -> Result<HashMap<String, String>, Error> {
        let mut out = HashMap::new();
        for (name, field) in &self.virtual_fields {
            if let Some(value) = field.value(item)? {
                out.insert(name.clone(), value);
            }
        }
        Ok(out)
    }

    /// The plaintext value of every compound beacon `item` has, by beacon name.
    pub(crate) fn compound_beacon_values(
        &self,
        item: &Item,
        partition: u8,
    ) -> Result<HashMap<String, String>, Error> {
        let mut out = HashMap::new();
        for (name, beacon) in &self.beacons {
            if !matches!(beacon, Beacon::Compound(_)) {
                continue;
            }
            if let Some(AttributeValue::S(value)) = beacon.attr_hash(
                item,
                &self.virtual_fields,
                &MaybeKeyMap::DontUseKeys,
                partition,
            )? {
                out.insert(name.clone(), value);
            }
        }
        Ok(out)
    }

    /// The values of the beacons on encrypted fields, under the beacon key `key_id` selects.
    pub(crate) async fn generate_encrypted_beacons(
        &self,
        item: &Item,
        key_id: &MaybeKeyId,
        partition: u8,
    ) -> Result<Item, Error> {
        //= spec/searchable-encryption/search-config.md#get-beacon-key-after-encrypt
        //# The `beacon key id`, [Key Store Cache](#key-store-cache), and a `KeyStore`
        //# MUST be passed to [Get Beacon Key Materials](#get-beacon-key-materials)
        //# and the result returned for Get beacon key after encrypt.
        let keys = self.get_key_map(key_id).await?;
        self.generate_beacons(item, &keys, BeaconKind::Encrypted, partition)
    }
}

/// Which beacons to generate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BeaconKind {
    Any,
    Signed,
    Encrypted,
}

/// A checked beacon.
#[derive(Clone, Debug)]
pub(crate) enum Beacon {
    Standard(StandardInfo),
    Compound(CompoundInfo),
}

impl Beacon {
    /// Whether any value of the beacon is encrypted, so its value is an HMAC.
    pub(crate) const fn is_encrypted(&self) -> bool {
        match self {
            Self::Standard(_) => true,
            Self::Compound(c) => c.num_signed < c.parts.len(),
        }
    }

    /// Whether this is a part-only standard beacon.
    pub(crate) const fn is_part_only(&self) -> bool {
        matches!(self, Self::Standard(s) if s.part_only)
    }
}

/// A checked standard beacon.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StandardInfo {
    pub(crate) name: String,
    /// The attribute the value is written to: `aws_dbe_b_<name>`.
    pub(crate) beacon_name: String,
    /// The number of bits of the value.
    pub(crate) length: u8,
    pub(crate) loc: TermLoc,
    pub(crate) part_only: bool,
    pub(crate) as_set: bool,
    /// The beacon whose key this beacon uses.
    pub(crate) share: Option<String>,
    pub(crate) number_of_partitions: u8,
}

/// A part of a compound beacon.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum BeaconPart {
    Encrypted {
        prefix: String,
        beacon: StandardInfo,
    },
    Signed {
        prefix: String,
        name: String,
        loc: TermLoc,
    },
}

impl BeaconPart {
    pub(crate) fn name(&self) -> &str {
        match self {
            Self::Encrypted { beacon, .. } => &beacon.name,
            Self::Signed { name, .. } => name,
        }
    }

    pub(crate) fn prefix(&self) -> &str {
        match self {
            Self::Encrypted { prefix, .. } | Self::Signed { prefix, .. } => prefix,
        }
    }
}

/// A part of a constructor: an index into its beacon's parts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ConstructorPartInfo {
    pub(crate) part: usize,
    pub(crate) required: bool,
}

/// A checked compound beacon.
#[derive(Clone, Debug)]
pub(crate) struct CompoundInfo {
    pub(crate) name: String,
    /// The attribute the value is written to: `aws_dbe_b_<name>`, or `<name>` when fully signed.
    pub(crate) beacon_name: String,
    pub(crate) split: char,
    /// The signed parts, then the encrypted parts.
    pub(crate) parts: Vec<BeaconPart>,
    pub(crate) num_signed: usize,
    pub(crate) constructors: Vec<Vec<ConstructorPartInfo>>,
}

impl CompoundInfo {
    /// Whether one of the parts holds standard beacon `name`.
    pub(crate) fn has_beacon(&self, name: &str) -> bool {
        self.parts.iter().any(|p| p.name() == name)
    }
}

/// A checked virtual field.
#[derive(Clone, Debug)]
pub(crate) struct VirtField {
    pub(crate) parts: Vec<VirtPart>,
}

impl VirtField {
    /// Whether `exam` holds for the location of any part.
    pub(crate) fn examine(&self, exam: impl Fn(&TermLoc) -> bool) -> bool {
        self.parts.iter().any(|p| exam(&p.loc))
    }

    /// The set of the parts' locations.
    pub(crate) fn locs(&self) -> BTreeSet<&TermLoc> {
        self.parts.iter().map(|p| &p.loc).collect()
    }
}

/// A checked virtual part.
#[derive(Clone, Debug)]
pub(crate) struct VirtPart {
    pub(crate) loc: TermLoc,
    pub(crate) transforms: Vec<VirtualTransform>,
}

#[cfg(test)]
#[path = "info_tests.rs"]
mod tests;

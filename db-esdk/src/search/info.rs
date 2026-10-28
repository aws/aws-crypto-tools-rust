// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The checked, internal form of a search configuration.

use std::collections::{BTreeMap, BTreeSet};

use crate::search::config::VirtualTransform;
use crate::search::key_source::KeySource;
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
#[expect(dead_code, reason = "beacon values are computed in a later layer")]
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
}

/// A checked beacon.
#[derive(Clone, Debug)]
pub(crate) enum Beacon {
    Standard(StandardInfo),
    Compound(CompoundInfo),
}

impl Beacon {
    /// Whether any value of the beacon is encrypted, so its value is an HMAC.
    pub(crate) fn is_encrypted(&self) -> bool {
        match self {
            Self::Standard(_) => true,
            Self::Compound(c) => c.num_signed < c.parts.len(),
        }
    }

    /// Whether this is a part-only standard beacon.
    pub(crate) fn is_part_only(&self) -> bool {
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
#[expect(dead_code, reason = "beacon values are computed in a later layer")]
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
#[expect(
    dead_code,
    reason = "virtual field values are computed in a later layer"
)]
pub(crate) struct VirtPart {
    pub(crate) loc: TermLoc,
    pub(crate) transforms: Vec<VirtualTransform>,
}

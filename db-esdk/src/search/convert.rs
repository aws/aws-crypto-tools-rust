// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Check a table's search configuration and convert it to its internal form.
//!
//! Every check runs when the [`Client`](crate::Client) is built, before any item is written.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::error::{Error, val_err};
use crate::search::config::{
    BeaconKeySource, BeaconStyle, BeaconVersion, CompoundBeacon, Constructor, EncryptedPart,
    SignedPart, StandardBeacon, VirtualField,
};
use crate::search::info::{
    BEACON_PREFIX, Beacon, BeaconPart, BeaconVersionInfo, CompoundInfo, ConstructorPartInfo,
    SearchInfo, StandardInfo, VirtField, VirtPart,
};
use crate::search::key_source::{KeyLocation, KeySource};
use crate::search::partition::{RandomPartitionSelector, SharedPartitionSelector};
use crate::search::term_loc::TermLoc;
use crate::structured::util::RESERVED_PREFIX;
use crate::table_config::{MAX_ATTRIBUTE_NAME_LEN, TableConfig};
use crate::types::CryptoAction;

/// The default cache size of a single key store, which only ever caches one key.
const SINGLE_KEY_CACHE_CAPACITY: usize = 1;
/// The default cache size of a multi key store.
const MULTI_KEY_CACHE_CAPACITY: usize = 1000;
/// One more than the most partitions a beacon version may have.
const MAX_PARTITION_COUNT: u8 = 255;

/// The parts of a table configuration the checks read.
struct Outer<'a> {
    actions: &'a HashMap<String, CryptoAction>,
    allowed_unsigned_attributes: &'a [String],
    allowed_unsigned_attribute_prefix: Option<&'a str>,
}

impl Outer<'_> {
    fn action(&self, loc: &TermLoc) -> Option<CryptoAction> {
        self.actions.get(loc.attribute_name()).copied()
    }

    /// Whether the location is signed.
    fn is_signed(&self, loc: &TermLoc) -> bool {
        self.action(loc)
            .is_some_and(|a| a != CryptoAction::DoNothing)
    }

    /// Whether the location is signed but not encrypted.
    fn is_sign_only(&self, loc: &TermLoc) -> bool {
        matches!(
            self.action(loc),
            Some(CryptoAction::SignOnly | CryptoAction::SignAndIncludeInEncryptionContext)
        )
    }

    /// Whether the location is encrypted.
    fn is_encrypted(&self, loc: &TermLoc) -> bool {
        self.action(loc) == Some(CryptoAction::EncryptAndSign)
    }

    /// Whether the location is encrypted, or is a virtual field with an encrypted part.
    fn is_encrypted_v(&self, virtual_fields: &BTreeMap<String, VirtField>, loc: &TermLoc) -> bool {
        self.is_encrypted(loc)
            || virtual_fields
                .get(loc.attribute_name())
                .is_some_and(|vf| vf.examine(|t| self.is_encrypted(t)))
    }

    fn is_allowed_unsigned(&self, name: &str) -> bool {
        self.allowed_unsigned_attributes.iter().any(|a| a == name)
    }

    fn has_unsigned_prefix(&self, name: &str) -> bool {
        self.allowed_unsigned_attribute_prefix
            .is_some_and(|p| name.starts_with(p))
    }

    /// Reject `name` as a beacon when an attribute or the reserved prefix already claims it.
    fn beacon_name_allowed(
        &self,
        name: &str,
        context: &str,
        is_signed_beacon: bool,
    ) -> Result<(), Error> {
        let action = self.actions.get(name);
        if action.is_some_and(|a| *a != CryptoAction::EncryptAndSign) {
            Err(val_err(format!(
                "{name} not allowed as a {context} because it is already an unencrypted attribute."
            )))
        } else if is_signed_beacon && action.is_some() {
            Err(val_err(format!(
                "{name} not allowed as a {context} because a fully signed beacon cannot have the same name as an existing attribute."
            )))
        } else if self.is_allowed_unsigned(name) {
            Err(val_err(format!(
                "{name} not allowed as a {context} because it is already an allowed unauthenticated attribute."
            )))
        } else if self.has_unsigned_prefix(name) {
            Err(val_err(format!(
                "{name} not allowed as a {context} because it begins with the allowed unauthenticated prefix."
            )))
        } else if name.starts_with(RESERVED_PREFIX) {
            Err(val_err(format!(
                "{name} not allowed as a {context} because it begins with the reserved prefix."
            )))
        } else {
            Ok(())
        }
    }

    /// Reject `name` as a virtual field when an attribute or the reserved prefix already claims it.
    fn virtual_field_name_allowed(&self, name: &str) -> Result<(), Error> {
        if self.actions.contains_key(name) {
            Err(val_err(format!(
                "{name} not allowed as a Virtual Field because it is already a configured attribute."
            )))
        } else if self.is_allowed_unsigned(name) {
            Err(val_err(format!(
                "{name} not allowed as a Virtual Field because it is already an allowed unauthenticated attribute."
            )))
        } else if self.has_unsigned_prefix(name) {
            Err(val_err(format!(
                "{name} not allowed as a Virtual Field because it begins with the allowed unauthenticated prefix."
            )))
        } else if name.starts_with(RESERVED_PREFIX) {
            Err(val_err(format!(
                "{name} not allowed as a Virtual Field because it begins with the reserved prefix."
            )))
        } else {
            Ok(())
        }
    }

    /// Whether `name` is an attribute of the table: it has an action or is unsigned.
    fn is_configured(&self, name: &str) -> bool {
        self.actions.contains_key(name)
            || self.is_allowed_unsigned(name)
            || self.has_unsigned_prefix(name)
    }
}

/// Whether `name` is a valid DynamoDB attribute name.
fn is_valid_attribute_name(name: &str) -> bool {
    (1..=MAX_ATTRIBUTE_NAME_LEN).contains(&name.encode_utf16().count())
}

/// Check the search configuration of `table`, if it has one, and convert it.
pub(crate) fn convert(table: &TableConfig) -> Result<Option<SearchInfo>, Error> {
    let Some(search) = &table.search else {
        return Ok(None);
    };
    if search.write_version != 1 {
        return Err(val_err("write_version must be 1"));
    }
    let [version] = search.versions.as_slice() else {
        return Err(val_err(
            "the search config must have exactly one beacon version",
        ));
    };
    let outer = Outer {
        actions: &table.attribute_actions_on_encrypt,
        allowed_unsigned_attributes: table.allowed_unsigned_attributes(),
        allowed_unsigned_attribute_prefix: table.allowed_unsigned_attribute_prefix(),
    };
    let version = convert_version(&outer, version)?;

    // Fully signed compound beacons are written in plaintext, as SIGN_ONLY attributes.
    let signed = version.signed_beacon_names();
    let bad: Vec<&str> = signed
        .iter()
        .map(String::as_str)
        .filter(|s| outer.is_configured(s))
        .collect();
    if !bad.is_empty() {
        return Err(val_err(format!(
            "Signed beacons cannot be configured with CryptoActions or as unauthenticated : {}",
            bad.join(", ")
        )));
    }
    if !signed.iter().all(|s| is_valid_attribute_name(s)) {
        return Err(val_err(
            "a signed beacon's name is not a valid attribute name",
        ));
    }
    Ok(Some(SearchInfo { version }))
}

/// Check and convert one beacon version.
fn convert_version(outer: &Outer<'_>, config: &BeaconVersion) -> Result<BeaconVersionInfo, Error> {
    if config.version != 1 {
        return Err(val_err("the beacon version's version must be 1"));
    }
    if config.standard_beacons.is_empty() {
        return Err(val_err("At least one standard beacon must be configured."));
    }
    let key_source = make_key_source(outer, config)?;

    let max_partitions = config.maximum_number_of_partitions.unwrap_or(1);
    if max_partitions == MAX_PARTITION_COUNT {
        return Err(val_err(format!(
            "Invalid maximumNumberOfPartitions specified, {max_partitions}, must be 0 < maximumNumberOfPartitions <= 255."
        )));
    }
    let default_partitions = match config.default_number_of_partitions {
        None => max_partitions,
        Some(d) if max_partitions <= d => {
            return Err(val_err(format!(
                "Invalid defaultNumberOfPartitions specified, {d}, must be 0 < defaultNumberOfPartitions < maximumNumberOfPartitions."
            )));
        }
        Some(d) => d,
    };

    let virtual_fields =
        add_virtual_fields(outer, config.virtual_fields.as_deref().unwrap_or_default())?;
    let std = add_standard_beacons(
        outer,
        &config.standard_beacons,
        &virtual_fields,
        max_partitions,
        default_partitions,
    )?;

    let global_signed = get_signed_parts(
        outer,
        config.signed_parts.as_deref().unwrap_or_default(),
        "Global Parts List",
    )?;
    let global_encrypted = match &config.encrypted_parts {
        Some(parts) => get_encrypted_parts(parts, &std, "Global Parts List")?,
        None => PartSet::default(),
    };

    let beacons = match &config.compound_beacons {
        Some(compound) => {
            add_compound_beacons(outer, compound, std, &global_signed, &global_encrypted)?
        }
        None => std,
    };
    check_beacons(&beacons)?;

    if let KeyLocation::Multi { key_field_name, .. } = &key_source.location {
        if beacons.contains_key(key_field_name) {
            return Err(val_err(format!(
                "A beacon key field name of {key_field_name} was configured, but there's also a beacon of that name."
            )));
        }
        if virtual_fields.contains_key(key_field_name) {
            return Err(val_err(format!(
                "A beacon key field name of {key_field_name} was configured, but there's also a virtual field of that name."
            )));
        }
    }

    let standard_names = beacons
        .iter()
        .filter(|(_, b)| matches!(b, Beacon::Standard(_)))
        .map(|(n, _)| n.clone())
        .collect();
    let encrypted_fields = outer
        .actions
        .iter()
        .filter(|(_, a)| **a == CryptoAction::EncryptAndSign)
        .map(|(n, _)| n.clone())
        .collect();
    Ok(BeaconVersionInfo {
        key_source,
        beacons,
        virtual_fields,
        standard_names,
        encrypted_fields,
        max_partitions,
        partition_selector: config
            .partition_selector
            .clone()
            .unwrap_or_else(|| SharedPartitionSelector::new(RandomPartitionSelector)),
    })
}

/// The beacon key source of `config`.
fn make_key_source(outer: &Outer<'_>, config: &BeaconVersion) -> Result<KeySource, Error> {
    match &config.key_source {
        BeaconKeySource::Multi(multi) => {
            let delete_key = should_delete_key_field(outer, &multi.key_field_name)?;
            KeySource::new(
                config.key_store.clone(),
                KeyLocation::Multi {
                    key_field_name: multi.key_field_name.clone(),
                    delete_key,
                },
                multi.cache.clone(),
                MULTI_KEY_CACHE_CAPACITY,
                multi.cache_ttl,
                multi.partition_id.as_deref(),
            )
        }
        BeaconKeySource::Single(single) => KeySource::new(
            config.key_store.clone(),
            KeyLocation::Single {
                key_id: single.key_id.clone(),
            },
            single.cache.clone(),
            SINGLE_KEY_CACHE_CAPACITY,
            single.cache_ttl,
            single.partition_id.as_deref(),
        ),
    }
}

/// Whether the beacon key field is removed from an item before it is written.
fn should_delete_key_field(outer: &Outer<'_>, name: &str) -> Result<bool, Error> {
    match outer.actions.get(name) {
        None | Some(CryptoAction::DoNothing) => Ok(true),
        Some(CryptoAction::EncryptAndSign) => Err(val_err(format!(
            "Beacon key field name {name} is configured as ENCRYPT_AND_SIGN which is not allowed."
        ))),
        Some(_) => Ok(false),
    }
}

/// The virtual field whose set of locations is `locs`, if any; the first by name.
fn find_virtual_field_with_locs<'a>(
    fields: &'a BTreeMap<String, VirtField>,
    locs: &BTreeSet<&TermLoc>,
) -> Option<&'a str> {
    fields
        .iter()
        .find(|(_, f)| f.locs() == *locs)
        .map(|(n, _)| n.as_str())
}

/// Check and convert the virtual fields.
fn add_virtual_fields(
    outer: &Outer<'_>,
    fields: &[VirtualField],
) -> Result<BTreeMap<String, VirtField>, Error> {
    let mut converted = BTreeMap::new();
    for vf in fields {
        if converted.contains_key(&vf.name) {
            return Err(val_err(format!(
                "Duplicate VirtualField name : {}",
                vf.name
            )));
        }
        outer.virtual_field_name_allowed(&vf.name)?;
        let parts = vf
            .parts
            .iter()
            .map(|p| {
                Ok(VirtPart {
                    loc: TermLoc::parse(&p.location)?,
                    transforms: p.transforms.clone().unwrap_or_default(),
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let field = VirtField { parts };
        if field.examine(|t| !outer.is_signed(t)) {
            return Err(val_err(format!(
                "VirtualField {} must be defined on signed fields.",
                vf.name
            )));
        }
        if let Some(bad) = find_virtual_field_with_locs(&converted, &field.locs()) {
            return Err(val_err(format!(
                "Virtual field {} is defined on the same locations as {bad}.",
                vf.name
            )));
        }
        converted.insert(vf.name.clone(), field);
    }
    Ok(converted)
}

/// The standard beacon on location `loc`, if any; the first by name.
fn find_beacon_with_loc<'a>(
    beacons: &'a BTreeMap<String, Beacon>,
    loc: &TermLoc,
) -> Option<&'a str> {
    beacons
        .iter()
        .find(|(_, b)| matches!(b, Beacon::Standard(s) if s.loc == *loc))
        .map(|(n, _)| n.as_str())
}

/// The partitions of a beacon: its own count, or the default.
fn partition_count(
    count: Option<u8>,
    name: &str,
    max_partitions: u8,
    default_partitions: u8,
) -> Result<u8, Error> {
    match count {
        None | Some(0) => Ok(default_partitions),
        Some(c) if c < max_partitions => Ok(c),
        //= spec/searchable-encryption/beacons.md#standard-beacon-initialization
        //# Initialization MUST fail if [number of partitions](#beacon-constraint) is specified, and is greater than or equal to
        //# the maximum number of partitions specified in the [beacon version](search-config.md#beacon-version-initialization).
        Some(c) => Err(val_err(format!(
            "Constrained numberOfPartitions for  {name} is {c} but it must be less than the maximumNumberOfPartitions {max_partitions}"
        ))),
    }
}

/// Check and convert the standard beacons.
fn add_standard_beacons(
    outer: &Outer<'_>,
    beacons: &[StandardBeacon],
    virtual_fields: &BTreeMap<String, VirtField>,
    max_partitions: u8,
    default_partitions: u8,
) -> Result<BTreeMap<String, Beacon>, Error> {
    let mut converted = BTreeMap::new();
    for b in beacons {
        if converted.contains_key(&b.name) {
            return Err(val_err(format!(
                "Duplicate StandardBeacon name : {}",
                b.name
            )));
        }
        outer.beacon_name_allowed(&b.name, "StandardBeacon", false)?;

        //= spec/searchable-encryption/beacons.md#standard-beacon-initialization
        //# If no [terminal location](virtual.md#terminal-location) is provided,
        //# the `name` MUST be used as the [terminal location](virtual.md#terminal-location).
        let loc_string = b.location.as_deref().unwrap_or(&b.name);
        let (part_only, as_set, share) = match &b.style {
            None => (false, false, None),
            Some(BeaconStyle::PartOnly(_)) => (true, false, None),
            Some(BeaconStyle::Shared(s)) => (false, false, Some(s.other.clone())),
            Some(BeaconStyle::AsSet(_)) => (false, true, None),
            //= spec/searchable-encryption/beacons.md#sharedset-initialization
            //= reason=the tuple is (part_only, as_set, share): as_set as for AsSet, share as for Shared
            //# A SharedSet Beacon MUST behave both as [Shared](#shared-initialization) and [AsSet](#asset-initialization).
            Some(BeaconStyle::SharedSet(s)) => (false, true, Some(s.other.clone())),
        };
        let number_of_partitions = partition_count(
            b.number_of_partitions,
            &b.name,
            max_partitions,
            default_partitions,
        )?;
        let loc = TermLoc::parse(loc_string)?;
        let beacon_name = format!("{BEACON_PREFIX}{}", b.name);
        if !is_valid_attribute_name(&beacon_name) {
            return Err(val_err(format!(
                "{beacon_name} is not a valid attribute name."
            )));
        }
        if !outer.is_encrypted_v(virtual_fields, &loc) {
            return Err(val_err(format!(
                "StandardBeacon {} not defined on an encrypted field.",
                b.name
            )));
        }
        if let Some(bad) = find_beacon_with_loc(&converted, &loc) {
            //= spec/searchable-encryption/beacons.md#standard-beacon-initialization
            //# Initialization MUST fail if two standard beacons are configured with the same location.
            return Err(val_err(format!(
                "Beacon {} is defined on location {loc}, but beacon {bad} is already defined on that location.",
                b.name
            )));
        }
        if let Some(bad) = find_virtual_field_with_locs(virtual_fields, &BTreeSet::from([&loc])) {
            return Err(val_err(format!(
                "Beacon {} is defined on location {loc}, but virtual field {bad} is already defined on that single location.",
                b.name
            )));
        }
        converted.insert(
            b.name.clone(),
            Beacon::Standard(StandardInfo {
                name: b.name.clone(),
                beacon_name,
                length: b.bits,
                loc,
                part_only,
                as_set,
                share,
                number_of_partitions,
            }),
        );
    }
    Ok(converted)
}

/// A list of compound beacon parts with distinct names and prefixes.
#[derive(Clone, Debug, Default)]
struct PartSet {
    parts: Vec<BeaconPart>,
    names: BTreeSet<String>,
    prefixes: BTreeSet<String>,
}

impl PartSet {
    /// Add `part`, rejecting a name or prefix already in `context`.
    fn add(&mut self, part: BeaconPart, context: &str) -> Result<(), Error> {
        if self.names.contains(part.name()) {
            return Err(val_err(format!(
                "Duplicate part name {} in {context}.",
                part.name()
            )));
        }
        if self.prefixes.contains(part.prefix()) {
            return Err(val_err(format!(
                "Duplicate prefix {} in {context}.",
                part.prefix()
            )));
        }
        self.names.insert(part.name().to_owned());
        self.prefixes.insert(part.prefix().to_owned());
        self.parts.push(part);
        Ok(())
    }

    /// Both sets, rejecting a name or a prefix in both.
    fn combine(&self, other: &Self, name: &str, other_name: &str) -> Result<Self, Error> {
        let names: Vec<&str> = self
            .names
            .intersection(&other.names)
            .map(String::as_str)
            .collect();
        if !names.is_empty() {
            return Err(val_err(format!(
                "Duplicate part name(s) {} between {name} and {other_name}.",
                names.join(", ")
            )));
        }
        let prefixes: Vec<&str> = self
            .prefixes
            .intersection(&other.prefixes)
            .map(String::as_str)
            .collect();
        if !prefixes.is_empty() {
            return Err(val_err(format!(
                "Duplicate prefix(es) {} between {name} and {other_name}.",
                prefixes.join(", ")
            )));
        }
        let mut out = self.clone();
        out.parts.extend(other.parts.iter().cloned());
        out.names.extend(other.names.iter().cloned());
        out.prefixes.extend(other.prefixes.iter().cloned());
        Ok(out)
    }
}

/// Check and convert signed parts, which must be signed but not encrypted.
fn get_signed_parts(
    outer: &Outer<'_>,
    parts: &[SignedPart],
    context: &str,
) -> Result<PartSet, Error> {
    let mut set = PartSet::default();
    for p in parts {
        //= spec/searchable-encryption/beacons.md#signed-part-initialization
        //# If no [terminal location](virtual.md#terminal-location) is provided,
        //# the `name` MUST be used as the [terminal location](virtual.md#terminal-location).
        let loc_string = p.location.as_deref().unwrap_or(&p.name);
        let loc = TermLoc::parse(loc_string)?;
        if !outer.is_sign_only(&loc) {
            //= spec/searchable-encryption/beacons.md#initialization-failure
            //# Initialization MUST fail if any [signed-part](#signed-part-initialization) contains
            //# anything but SIGN_ONLY fields.
            return Err(val_err(format!(
                "Signed Part {} is built from {loc_string} which is not SIGN_ONLY.",
                p.name
            )));
        }
        set.add(
            BeaconPart::Signed {
                prefix: p.prefix.clone(),
                name: p.name.clone(),
                loc,
            },
            context,
        )?;
    }
    Ok(set)
}

/// Check and convert encrypted parts, each naming a standard beacon that is not `AsSet`.
fn get_encrypted_parts(
    parts: &[EncryptedPart],
    beacons: &BTreeMap<String, Beacon>,
    context: &str,
) -> Result<PartSet, Error> {
    let mut set = PartSet::default();
    for p in parts {
        match beacons.get(&p.name) {
            Some(Beacon::Standard(s)) if s.as_set => {
                //= spec/searchable-encryption/beacons.md#asset-initialization
                //# - initialization MUST fail if any compound beacon has an AsSet beacon as a part.
                return Err(val_err(format!(
                    "{context} uses {} which is an AsSet beacon, and therefore cannot be used in a Compound Beacon.",
                    p.name
                )));
            }
            Some(Beacon::Standard(s)) => set.add(
                BeaconPart::Encrypted {
                    prefix: p.prefix.clone(),
                    beacon: s.clone(),
                },
                context,
            )?,
            _ => {
                //= spec/searchable-encryption/beacons.md#compound-beacon
                //# The name MUST be the name of a configured standard beacon.
                return Err(val_err(format!(
                    "{context} refers to standard beacon {} which is not configured.",
                    p.name
                )));
            }
        }
    }
    Ok(set)
}

/// The global parts of the `signed` kind that the constructors name.
fn get_global_parts(
    constructors: &[Constructor],
    globals: &PartSet,
    signed: bool,
) -> Result<PartSet, Error> {
    let mut set = PartSet::default();
    for part in constructors.iter().flat_map(|c| &c.parts) {
        let found = globals
            .parts
            .iter()
            .find(|g| matches!(g, BeaconPart::Signed { .. }) == signed && g.name() == part.name);
        if let Some(g) = found {
            set.add(g.clone(), "Global Parts List")?;
        }
    }
    Ok(set)
}

/// Reject a local part whose name or prefix is a global part's.
fn check_local_parts<'a>(
    parts: impl Iterator<Item = (&'a str, &'a str)>,
    globals: &PartSet,
    name: &str,
    kind: &str,
) -> Result<(), Error> {
    for (part, prefix) in parts {
        if globals.names.contains(part) {
            return Err(val_err(format!(
                "Compound beacon {name} defines {kind} part {part} which is already defined as a global part."
            )));
        }
        if globals.prefixes.contains(prefix) {
            return Err(val_err(format!(
                "Compound beacon {name} defines {kind} part {part} with prefix {prefix} which is already defined as the prefix of a global part."
            )));
        }
    }
    Ok(())
}

/// Check and convert the constructors, or make the default one: every part, all required.
fn add_constructors(
    constructors: Option<&[Constructor]>,
    name: &str,
    parts: &[BeaconPart],
) -> Result<Vec<Vec<ConstructorPartInfo>>, Error> {
    //= spec/searchable-encryption/beacons.md#default-construction
    //# - If no constructors are configured, a default constructor MUST be generated.
    let Some(constructors) = constructors else {
        return Ok(vec![
            //= spec/searchable-encryption/beacons.md#default-construction
            //= reason=create_compound_beacon passes parts as signed.parts, then parts.extend(encrypted.parts)
            //# - This default constructor MUST be all of the signed parts,
            //# followed by all the encrypted parts, all parts being required.
            (0..parts.len())
                .map(|part| ConstructorPartInfo {
                    part,
                    required: true,
                })
                .collect(),
        ]);
    };
    let mut converted: Vec<Vec<ConstructorPartInfo>> = Vec::with_capacity(constructors.len());
    for c in constructors {
        if c.parts.is_empty() {
            return Err(val_err("Every constructor must have at least one part."));
        }
        if !c.parts.iter().any(|p| p.required) {
            //= spec/searchable-encryption/beacons.md#initialization-failure
            //# Initialization MUST fail if any [constructor](#constructor-initialization) is configured without at least one
            //# required part.
            return Err(val_err(format!(
                "A Constructor for beacon {name} lacks any required parts"
            )));
        }
        let made =
            c.parts
                .iter()
                .map(|cp| {
                    //= spec/searchable-encryption/beacons.md#constructor-part-initialization
                    //# This name MUST match the name of one of the [encrypted](#encrypted-part-initialization) or [signed](#signed-part-initialization) parts.
                    //
                    //= spec/searchable-encryption/beacons.md#initialization-failure
                    //# Initialization MUST fail if any [constructor](#constructor-initialization) is configured with a field name
                    //# that is not a defined [part](#part).
                    let part = parts.iter().position(|p| p.name() == cp.name).ok_or_else(|| {
                    val_err(format!(
                        "Constructor refers to part name {} but there is no part by that name.",
                        cp.name
                    ))
                })?;
                    Ok(ConstructorPartInfo {
                        part,
                        required: cp.required,
                    })
                })
                .collect::<Result<Vec<_>, Error>>()?;
        let required = required_parts(&made);
        if converted.iter().any(|c| required_parts(c) == required) {
            //= spec/searchable-encryption/beacons.md#initialization-failure
            //# Initialization MUST fail if two [constructors](#constructor-initialization) are configured
            //# with the same set of required parts.
            let names: Vec<&str> = made
                .iter()
                .filter(|p| p.required)
                .map(|p| parts[p.part].name())
                .collect();
            return Err(val_err(format!(
                "Multiple constructors for {name} have the same set of required parts : {}",
                names.join(", ")
            )));
        }
        converted.push(made);
    }
    Ok(converted)
}

/// The set of a constructor's required parts.
fn required_parts(constructor: &[ConstructorPartInfo]) -> BTreeSet<usize> {
    constructor
        .iter()
        .filter(|p| p.required)
        .map(|p| p.part)
        .collect()
}

/// Whether one of two prefixes begins with the other.
fn prefixes_overlap(x: &str, y: &str) -> bool {
    x.starts_with(y) || y.starts_with(x)
}

/// Reject parts where one prefix begins with another.
fn check_prefixes(name: &str, parts: &[BeaconPart]) -> Result<(), Error> {
    for (i, a) in parts.iter().enumerate() {
        for (j, b) in parts.iter().enumerate() {
            if i != j && prefixes_overlap(a.prefix(), b.prefix()) {
                //= spec/searchable-encryption/beacons.md#initialization-failure
                //# Initialization MUST fail if any `prefix` in any [part](#part) is a prefix of
                //# the `prefix` of any other [part](#part).
                return Err(val_err(format!(
                    "Compound beacon {name} defines part {} with prefix {} which is incompatible with part {} which has a prefix of {}.",
                    a.name(),
                    a.prefix(),
                    b.name(),
                    b.prefix()
                )));
            }
        }
    }
    Ok(())
}

/// Check and convert one compound beacon.
fn create_compound_beacon(
    outer: &Outer<'_>,
    beacon: &CompoundBeacon,
    converted: &BTreeMap<String, Beacon>,
    global_signed: &PartSet,
    global_encrypted: &PartSet,
) -> Result<CompoundInfo, Error> {
    let name = beacon.name.as_str();
    let signed_parts = beacon.signed.as_deref().unwrap_or_default();
    let encrypted_parts = beacon.encrypted.as_deref().unwrap_or_default();
    let constructors = beacon.constructors.as_deref().unwrap_or_default();

    let globals = global_signed.combine(
        global_encrypted,
        "Global Signed Parts List",
        "Global Encrypted Parts List",
    )?;
    check_local_parts(
        signed_parts
            .iter()
            .map(|p| (p.name.as_str(), p.prefix.as_str())),
        &globals,
        name,
        "signed",
    )?;
    check_local_parts(
        encrypted_parts
            .iter()
            .map(|p| (p.name.as_str(), p.prefix.as_str())),
        &globals,
        name,
        "encrypted",
    )?;
    let signed = get_signed_parts(outer, signed_parts, name)?.combine(
        &get_global_parts(constructors, global_signed, true)?,
        name,
        "Global Parts List",
    )?;
    let encrypted = get_encrypted_parts(
        encrypted_parts,
        converted,
        &format!("Compound beacon {name}"),
    )?
    .combine(
        &get_global_parts(constructors, global_encrypted, false)?,
        name,
        "Global Parts List",
    )?;

    if converted.contains_key(name) {
        return Err(val_err(format!("two compound beacons are named {name}")));
    }
    if beacon.constructors.as_ref().is_some_and(Vec::is_empty) {
        return Err(val_err(format!(
            "For beacon {name} an empty constructor list was supplied."
        )));
    }
    if beacon.constructors.is_none() && signed_parts.is_empty() && encrypted_parts.is_empty() {
        //= spec/searchable-encryption/beacons.md#default-construction
        //# - Initialization MUST fail if no constructors are configured, and no local parts are configured.
        return Err(val_err(format!(
            "Compound beacon {name} defines no constructors, and also no local parts. Cannot make a default constructor from global parts."
        )));
    }

    let num_signed = signed.parts.len();
    let is_signed_beacon = encrypted.parts.is_empty();
    let mut parts = signed.parts;
    parts.extend(encrypted.parts);

    //= spec/searchable-encryption/beacons.md#signed-beacons
    //# Initialization MUST fail if `NAME` is explicitly configured with an
    //# [attribute actions](../dynamodb-encryption-client/ddb-item-encryptor.md#attribute-actions) or
    //# [unauthenticated attributes](../dynamodb-encryption-client/ddb-item-encryptor.md#unauthenticated-attributes),
    //# or begins with the [unauthenticated attribute prefix](../dynamodb-encryption-client/ddb-item-encryptor.md#unauthenticated-attribute-prefix).
    outer.beacon_name_allowed(name, "CompoundBeacon", is_signed_beacon)?;
    if parts.is_empty() {
        return Err(val_err(format!(
            "For beacon {name} no parts were supplied."
        )));
    }
    let constructors = add_constructors(beacon.constructors.as_deref(), name, &parts)?;

    let beacon_name = if is_signed_beacon {
        //= spec/searchable-encryption/beacons.md#signed-beacons
        //# The beacon value MUST be stored as `NAME`, rather than the usual `aws_dbe_b_NAME`.
        name.to_owned()
    } else {
        format!("{BEACON_PREFIX}{name}")
    };
    if !is_valid_attribute_name(&beacon_name) {
        return Err(val_err(format!(
            "{beacon_name} is not a valid attribute name."
        )));
    }
    check_prefixes(name, &parts)?;
    Ok(CompoundInfo {
        name: name.to_owned(),
        beacon_name,
        split: beacon.split,
        parts,
        num_signed,
        constructors,
    })
}

/// Check and convert the compound beacons, adding them to `converted`.
fn add_compound_beacons(
    outer: &Outer<'_>,
    beacons: &[CompoundBeacon],
    mut converted: BTreeMap<String, Beacon>,
    global_signed: &PartSet,
    global_encrypted: &PartSet,
) -> Result<BTreeMap<String, Beacon>, Error> {
    for b in beacons {
        let beacon = create_compound_beacon(outer, b, &converted, global_signed, global_encrypted)?;
        converted.insert(b.name.clone(), Beacon::Compound(beacon));
    }
    Ok(converted)
}

/// Check a shared beacon: `share` is a standard beacon, not itself shared, of the same length.
fn check_share(
    beacons: &BTreeMap<String, Beacon>,
    name: &str,
    length: u8,
    share: &str,
) -> Result<(), Error> {
    match beacons.get(share) {
        Some(Beacon::Standard(target)) => match &target.share {
            Some(_) if name == share => Err(val_err(format!("Beacon {name} is shared to itself."))),
            Some(next) => Err(val_err(format!(
                "Beacon {name} is shared to {share} which is in turn shared to {next}. Share chains are not allowed."
            ))),
            None if target.length == length => Ok(()),
            //= spec/searchable-encryption/beacons.md#shared-initialization
            //# This beacon's [length](#beacon-length) MUST be equal to the `other` beacon's [length](#beacon-length).
            None => Err(val_err(format!(
                "Beacon {name} is shared to {share} but {name} has length {length} and {share} has length {}.",
                target.length
            ))),
        },
        //= spec/searchable-encryption/beacons.md#shared-initialization
        //# This name MUST be the name of a previously defined Standard Beacon.
        Some(Beacon::Compound(_)) => Err(val_err(format!(
            "Beacon {name} is shared to {share} but {share} is a compound beacon."
        ))),
        None => Err(val_err(format!(
            "Beacon {name} is shared to {share} which is not defined."
        ))),
    }
}

/// Check every beacon: each part-only beacon is in a compound beacon, and each share is valid.
fn check_beacons(beacons: &BTreeMap<String, Beacon>) -> Result<(), Error> {
    for (name, b) in beacons {
        if b.is_part_only()
            && !beacons
                .values()
                .any(|c| matches!(c, Beacon::Compound(c) if c.has_beacon(name)))
        {
            //= spec/searchable-encryption/beacons.md#partonly-initialization
            //# Initialization MUST fail if the configuration does not use a PartOnly in a [compound beacon](#compound-beacon).
            return Err(val_err(format!(
                "PartOnly beacon {name} MUST be used in a compound beacon."
            )));
        }
        if let Beacon::Standard(s) = b
            && let Some(share) = &s.share
        {
            check_share(beacons, name, s.length, share)?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "convert_tests.rs"]
mod tests;

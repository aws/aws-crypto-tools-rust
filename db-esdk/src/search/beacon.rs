// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Beacon values: the truncated HMAC written next to an item, and the value a query compares to it.

use std::collections::{BTreeMap, HashMap};

use aws_crypto_mpl::aws_sdk_dynamodb::types::AttributeValue;
use aws_mpl_primitives::{DigestAlg, hmac};

use crate::ddb::top_level_attr_to_bytes;
use crate::error::{Error, val_err};
use crate::search::info::{Beacon, BeaconPart, CompoundInfo, ConstructorPartInfo, StandardInfo};
use crate::search::virt::{VirtualFieldMap, virt_to_attr, virt_to_bytes, virt_to_string};

/// Each standard beacon's HMAC key, by beacon name.
pub(crate) type HmacKeyMap = BTreeMap<String, Vec<u8>>;

/// The beacon keys an operation has.
#[derive(Debug)]
pub(crate) enum MaybeKeyMap {
    /// Compute no HMAC: beacon values are the plaintext they are computed from.
    DontUseKeys,
    /// A key is needed, but the query names no beacon key id.
    ShouldHaveKeys,
    Keys(HmacKeyMap),
}

/// The beacon key id an operation uses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum MaybeKeyId {
    /// The key source has a single key: no key id is supplied.
    DontUse,
    /// The key source has many keys, but the query names none.
    ShouldHave,
    Id(String),
}

/// The name DynamoDB gives the type of `v`.
pub(crate) const fn attr_type_to_str(v: &AttributeValue) -> &'static str {
    match v {
        AttributeValue::S(_) => "S",
        AttributeValue::N(_) => "N",
        AttributeValue::B(_) => "B",
        AttributeValue::Ss(_) => "SS",
        AttributeValue::Ns(_) => "NS",
        AttributeValue::Bs(_) => "BS",
        AttributeValue::M(_) => "M",
        AttributeValue::L(_) => "L",
        AttributeValue::Null(_) => "NULL",
        AttributeValue::Bool(_) => "BOOL",
        _ => "UNKNOWN",
    }
}

/// The bytes a partition number appends to a beacon's input: none for partition 0.
fn partition_bytes(partition: u8) -> Vec<u8> {
    if partition == 0 {
        Vec::new()
    } else {
        vec![partition]
    }
}

/// The hex digit of `x`, which is less than 16.
fn hex_char(x: u8) -> char {
    char::from_digit(u32::from(x), 16).unwrap_or('0')
}

/// The rightmost `bits` bits of the 8-byte `bytes`, as lowercase hex.
fn bytes_to_hex(bytes: &[u8; 8], bits: u8) -> String {
    let num_bytes = usize::from(bits.div_ceil(8));
    let num_chars = usize::from(bits.div_ceil(4));
    let top_bits = match bits % 4 {
        0 => 4,
        x => x,
    };
    let truncate = |nibble: u8| nibble % (1 << top_bits);
    let bytes = &bytes[8 - num_bytes..];
    let mut out = String::with_capacity(num_chars);
    if num_chars == 2 * num_bytes {
        out.push(hex_char(truncate(bytes[0] / 16)));
        out.push(hex_char(bytes[0] % 16));
    } else {
        out.push(hex_char(truncate(bytes[0] % 16)));
    }
    for b in &bytes[1..] {
        out.push(hex_char(b / 16));
        out.push(hex_char(b % 16));
    }
    out
}

/// The basic hash: the first 8 bytes of the HMAC-SHA-384 of `val` under `key`,
/// truncated to the rightmost `length` bits, as hex.
fn basic_hash(val: &[u8], key: &[u8], length: u8) -> Result<String, Error> {
    let mut out = [0u8; 48];
    hmac(DigestAlg::Sha384, key, val, &mut out)?;
    let mut first = [0u8; 8];
    first.copy_from_slice(&out[..8]);
    Ok(bytes_to_hex(&first, length))
}

impl StandardInfo {
    /// The beacon whose HMAC key this beacon uses: the shared beacon, or itself.
    pub(crate) fn key_name(&self) -> &str {
        self.share.as_deref().unwrap_or(&self.name)
    }

    /// The bytes of `partition`, constrained to this beacon's partitions.
    fn constrained_partition(&self, partition: u8) -> Vec<u8> {
        if self.number_of_partitions == 0 || partition == 0 {
            partition_bytes(partition)
        } else {
            partition_bytes(partition % self.number_of_partitions)
        }
    }

    /// The beacon value of `val` under `key` in `partition`.
    fn hash(&self, val: &[u8], key: &[u8], partition: u8) -> Result<String, Error> {
        let mut data = val.to_vec();
        data.extend_from_slice(&self.constrained_partition(partition));
        basic_hash(&data, key, self.length)
    }

    /// The beacon value of the UTF-8 bytes of `val`.
    pub(crate) fn hash_str(
        &self,
        val: &str,
        keys: &HmacKeyMap,
        partition: u8,
    ) -> Result<String, Error> {
        let key = keys
            .get(self.key_name())
            .ok_or_else(|| val_err(format!("Internal Error, no key for {}", self.key_name())))?;
        self.hash(val.as_bytes(), key, partition)
    }

    /// The beacon value of each element of a set, without duplicates, as a string set.
    fn value_to_set(
        &self,
        value: &AttributeValue,
        key: &[u8],
        partition: u8,
    ) -> Result<AttributeValue, Error> {
        let elements: Vec<AttributeValue> = match value {
            AttributeValue::Ss(s) => s.iter().cloned().map(AttributeValue::S).collect(),
            AttributeValue::Ns(n) => n.iter().cloned().map(AttributeValue::N).collect(),
            AttributeValue::Bs(b) => b.iter().cloned().map(AttributeValue::B).collect(),
            other => {
                return Err(val_err(format!(
                    "Beacon {} has style AsSet, but attribute has type {}.",
                    self.name,
                    attr_type_to_str(other)
                )));
            }
        };
        let mut converted: Vec<String> = Vec::with_capacity(elements.len());
        for e in &elements {
            let bytes = top_level_attr_to_bytes(e).map_err(val_err)?;
            let h = self.hash(&bytes, key, partition)?;
            if !converted.contains(&h) {
                converted.push(h);
            }
        }
        Ok(AttributeValue::Ss(converted))
    }

    /// The beacon value of `item`; `None` when the item lacks the beacon's field.
    fn get_hash(
        &self,
        item: &HashMap<String, AttributeValue>,
        vf: &VirtualFieldMap,
        key: &[u8],
        partition: u8,
    ) -> Result<Option<AttributeValue>, Error> {
        if self.as_set {
            match self.loc.term_to_attr(item, None) {
                None => Ok(None),
                Some(v) => Ok(Some(self.value_to_set(&v, key, partition)?)),
            }
        } else {
            match virt_to_bytes(&self.loc, item, vf)? {
                None => Ok(None),
                Some(bytes) => Ok(Some(AttributeValue::S(self.hash(&bytes, key, partition)?))),
            }
        }
    }

    /// The plaintext value the beacon is computed from.
    fn get_naked(
        &self,
        item: &HashMap<String, AttributeValue>,
        vf: &VirtualFieldMap,
    ) -> Result<Option<AttributeValue>, Error> {
        virt_to_attr(&self.loc, item, vf)
    }

    /// The beacon value a query compares in place of `value`.
    fn get_beacon_value(
        &self,
        value: &AttributeValue,
        key: &[u8],
        for_contains: bool,
        partition: u8,
    ) -> Result<AttributeValue, Error> {
        let is_scalar = matches!(
            value,
            AttributeValue::S(_) | AttributeValue::N(_) | AttributeValue::B(_)
        );
        let is_set = matches!(
            value,
            AttributeValue::Ss(_) | AttributeValue::Ns(_) | AttributeValue::Bs(_)
        );
        if (self.as_set && !is_scalar) || (for_contains && is_set) {
            self.value_to_set(value, key, partition)
        } else {
            let bytes = top_level_attr_to_bytes(value).map_err(val_err)?;
            Ok(AttributeValue::S(self.hash(&bytes, key, partition)?))
        }
    }
}

impl BeaconPart {
    /// The string value of the part's field in `item`.
    fn get_string(
        &self,
        item: &HashMap<String, AttributeValue>,
        vf: &VirtualFieldMap,
    ) -> Result<Option<String>, Error> {
        match self {
            Self::Encrypted { beacon, .. } => virt_to_string(&beacon.loc, item, vf),
            Self::Signed { loc, .. } => virt_to_string(loc, item, vf),
        }
    }
}

/// Least common multiple of two partition counts, capped at `max`.
pub(crate) fn lcm_partition(a: u8, b: u8, max: u8) -> u8 {
    if a == 1 || b == max || a == b {
        b.min(max)
    } else if b == 1 || a == max {
        a.min(max)
    } else {
        let (x, y) = (u32::from(a), u32::from(b));
        let mut g = (x, y);
        while g.1 != 0 {
            g = (g.1, g.0 % g.1);
        }
        let lcm = x / g.0 * y;
        if lcm < u32::from(max) {
            u8::try_from(lcm).unwrap_or(max)
        } else {
            max
        }
    }
}

/// The least common multiple of `values`, capped at `max`.
pub(crate) fn lcm_seq(values: impl IntoIterator<Item = u8>, max: u8) -> u8 {
    let mut result = 1;
    for partitions in values {
        if partitions == 1 || partitions == result {
            continue;
        }
        result = lcm_partition(result, partitions, max);
    }
    result
}

impl CompoundInfo {
    /// The index of the first part whose prefix `value` starts with.
    fn part_from_prefix(&self, value: &str) -> Result<usize, Error> {
        self.parts
            .iter()
            .position(|p| value.starts_with(p.prefix()))
            .ok_or_else(|| {
                val_err(format!(
                    "Value {value} for beacon {} does not match the prefix of any configured part.",
                    self.name
                ))
            })
    }

    /// `pieces` without its leading signed pieces.
    fn skip_signed_pieces<'a>(&self, pieces: &'a [&'a str]) -> Result<&'a [&'a str], Error> {
        let mut rest = pieces;
        while let Some(first) = rest.first() {
            if matches!(
                self.parts[self.part_from_prefix(first)?],
                BeaconPart::Encrypted { .. }
            ) {
                break;
            }
            rest = &rest[1..];
        }
        Ok(rest)
    }

    /// Whether a `<`-style comparison on these pieces can be answered with beacons:
    /// after any signed pieces, at most one piece, which is only a prefix.
    pub(crate) fn is_less_than_comparable(&self, pieces: &[&str]) -> Result<bool, Error> {
        let rest = self.skip_signed_pieces(pieces)?;
        match rest {
            [] => Ok(true),
            [one] => Ok(self.parts[self.part_from_prefix(one)?].prefix() == *one),
            _ => Ok(false),
        }
    }

    /// The beacon value of part `part` with value `data`.
    fn part_value_calc(
        &self,
        data: &str,
        keys: &MaybeKeyMap,
        part: &BeaconPart,
        partition: u8,
    ) -> Result<String, Error> {
        if data.contains(self.split) {
            return Err(val_err(format!(
                "Value '{data}' for beacon part {} contains the split character '{}'.",
                part.name(),
                self.split
            )));
        }
        match part {
            BeaconPart::Encrypted { prefix, beacon } => {
                let MaybeKeyMap::Keys(keys) = keys else {
                    return Err(val_err(format!(
                        "Need KeyId for beacon {} but no KeyId found in query.",
                        beacon.name
                    )));
                };
                Ok(format!(
                    "{prefix}{}",
                    beacon.hash_str(data, keys, partition)?
                ))
            }
            BeaconPart::Signed { prefix, .. } => Ok(format!("{prefix}{data}")),
        }
    }

    fn find_and_calc_part(
        &self,
        value: &str,
        keys: &MaybeKeyMap,
        partition: u8,
    ) -> Result<String, Error> {
        let part = &self.parts[self.part_from_prefix(value)?];
        self.part_value_calc(&value[part.prefix().len()..], keys, part, partition)
    }

    fn just_prefix(&self, value: &str) -> Result<bool, Error> {
        Ok(self.parts[self.part_from_prefix(value)?].prefix() == value)
    }

    /// Whether constructor `con` can build the parts `in_parts`, in order.
    fn can_construct(con: &[ConstructorPartInfo], in_parts: &[usize], matched: bool) -> bool {
        match (con.split_first(), in_parts.split_first()) {
            (_, None) => true,
            (None, Some(_)) => false,
            (Some((c, con_rest)), Some((p, parts_rest))) => {
                if c.part == *p {
                    Self::can_construct(con_rest, parts_rest, true)
                } else if !c.required || !matched {
                    Self::can_construct(con_rest, in_parts, matched)
                } else {
                    false
                }
            }
        }
    }

    fn constructors_to_string(&self) -> String {
        self.constructors
            .iter()
            .map(|c| {
                c.iter()
                    .map(|p| {
                        let prefix = self.parts[p.part].prefix();
                        if p.required {
                            prefix.to_owned()
                        } else {
                            format!("[{prefix}]")
                        }
                    })
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Reject parts that no constructor builds in this order.
    fn validate_part_order(&self, in_parts: &[usize], orig: &str) -> Result<(), Error> {
        if self
            .constructors
            .iter()
            .any(|c| Self::can_construct(c, in_parts, false))
        {
            return Ok(());
        }
        let parsed: String = in_parts.iter().map(|p| self.parts[*p].prefix()).collect();
        Err(val_err(format!(
            "Compound Beacon value '{orig}' cannot be constructed from any available constructor for {} value parsed as {parsed} available constructors are {}.",
            self.name,
            self.constructors_to_string()
        )))
    }

    /// The parts `value` is made of, checked against the constructors.
    fn parts_of_value(&self, value: &AttributeValue) -> Result<(Vec<String>, Vec<usize>), Error> {
        let AttributeValue::S(s) = value else {
            return Err(val_err(format!(
                "CompoundBeacon {} can only be queried as a string, not as {}",
                self.name,
                attr_type_to_str(value)
            )));
        };
        let pieces: Vec<String> = s.split(self.split).map(str::to_owned).collect();
        let used = pieces
            .iter()
            .map(|p| self.part_from_prefix(p))
            .collect::<Result<Vec<_>, _>>()?;
        self.validate_part_order(&used, s)?;
        Ok((pieces, used))
    }

    /// The beacon value a query compares in place of `value`.
    fn get_beacon_value(
        &self,
        value: &AttributeValue,
        keys: &MaybeKeyMap,
        for_equality: bool,
        partition: u8,
    ) -> Result<AttributeValue, Error> {
        let (pieces, _) = self.parts_of_value(value)?;
        let beacon_parts = pieces
            .iter()
            .map(|p| self.find_and_calc_part(p, keys, partition))
            .collect::<Result<Vec<_>, _>>()?;
        let last = pieces.last().map_or("", String::as_str);
        let split = self.split.to_string();
        if !for_equality && self.just_prefix(last)? {
            let mut joined = beacon_parts[..beacon_parts.len() - 1].to_vec();
            joined.push(last.to_owned());
            Ok(AttributeValue::S(joined.join(&split)))
        } else {
            Ok(AttributeValue::S(beacon_parts.join(&split)))
        }
    }

    /// How many queries a query on `value` takes: the partitions its encrypted parts span.
    fn num_queries(&self, global_max: u8, value: &str) -> u8 {
        match self.parts_of_value(&AttributeValue::S(value.to_owned())) {
            Err(_) => 1,
            Ok((_, used)) => lcm_seq(
                used.iter().filter_map(|p| match &self.parts[*p] {
                    BeaconPart::Encrypted { beacon, .. } => Some(beacon.number_of_partitions),
                    BeaconPart::Signed { .. } => None,
                }),
                global_max,
            ),
        }
    }

    /// The value constructor `con` builds from `item`; `None` when a required part is missing.
    fn try_constructor(
        &self,
        con: &[ConstructorPartInfo],
        item: &HashMap<String, AttributeValue>,
        vf: &VirtualFieldMap,
        keys: &MaybeKeyMap,
        partition: u8,
    ) -> Result<Option<String>, Error> {
        let mut acc = String::new();
        for cp in con {
            let part = &self.parts[cp.part];
            match part.get_string(item, vf)? {
                Some(value) => {
                    if value.contains(self.split) {
                        return Err(val_err(format!(
                            "Part {} for beacon {} has value '{value}' which contains the split character {}'.",
                            part.name(),
                            self.name,
                            self.split
                        )));
                    }
                    let val = if matches!(keys, MaybeKeyMap::DontUseKeys) {
                        format!("{}{value}", part.prefix())
                    } else {
                        self.part_value_calc(&value, keys, part, partition)?
                    };
                    if !acc.is_empty() {
                        acc.push(self.split);
                    }
                    acc.push_str(&val);
                }
                None if cp.required => return Ok(None),
                None => {}
            }
        }
        if acc.is_empty() {
            return Err(val_err("Internal Error : Empty beacon created."));
        }
        Ok(Some(acc))
    }

    /// The value of the first constructor that can build one from `item`.
    fn try_constructors(
        &self,
        item: &HashMap<String, AttributeValue>,
        vf: &VirtualFieldMap,
        keys: &MaybeKeyMap,
        partition: u8,
    ) -> Result<Option<String>, Error> {
        for con in &self.constructors {
            if let Some(v) = self.try_constructor(con, item, vf, keys, partition)? {
                return Ok(Some(v));
            }
        }
        Ok(None)
    }
}

impl Beacon {
    /// The beacon's name.
    pub(crate) fn name(&self) -> &str {
        match self {
            Self::Standard(s) => &s.name,
            Self::Compound(c) => &c.name,
        }
    }

    /// The attribute the beacon's value is written to.
    pub(crate) fn beacon_name(&self) -> &str {
        match self {
            Self::Standard(s) => &s.beacon_name,
            Self::Compound(c) => &c.beacon_name,
        }
    }

    /// How many queries a query on `value` takes, at most `global_max`.
    pub(crate) fn num_queries(&self, global_max: u8, value: &str) -> u8 {
        match self {
            Self::Standard(s) => s.number_of_partitions.min(global_max),
            Self::Compound(c) => c.num_queries(global_max, value),
        }
    }

    /// The beacon value of `item` under `keys`, which are not `DontUseKeys`.
    fn hash(
        &self,
        item: &HashMap<String, AttributeValue>,
        vf: &VirtualFieldMap,
        keys: &MaybeKeyMap,
        partition: u8,
    ) -> Result<Option<AttributeValue>, Error> {
        match self {
            Self::Standard(s) => {
                let MaybeKeyMap::Keys(keys) = keys else {
                    return Err(val_err(format!(
                        "Need key for beacon {} but no keyId found in query.",
                        s.key_name()
                    )));
                };
                let key = keys.get(s.key_name()).ok_or_else(|| {
                    val_err(format!(
                        "Internal error. Beacon {} has no key!",
                        s.key_name()
                    ))
                })?;
                s.get_hash(item, vf, key, partition)
            }
            Self::Compound(c) => Ok(c
                .try_constructors(item, vf, keys, partition)?
                .map(AttributeValue::S)),
        }
    }

    /// The plaintext value of the beacon in `item`.
    fn naked(
        &self,
        item: &HashMap<String, AttributeValue>,
        vf: &VirtualFieldMap,
        partition: u8,
    ) -> Result<Option<AttributeValue>, Error> {
        match self {
            Self::Standard(s) => s.get_naked(item, vf),
            Self::Compound(c) => Ok(c
                .try_constructors(item, vf, &MaybeKeyMap::DontUseKeys, partition)?
                .map(AttributeValue::S)),
        }
    }

    /// The beacon value of `item`; the plaintext value with `DontUseKeys`.
    pub(crate) fn attr_hash(
        &self,
        item: &HashMap<String, AttributeValue>,
        vf: &VirtualFieldMap,
        keys: &MaybeKeyMap,
        partition: u8,
    ) -> Result<Option<AttributeValue>, Error> {
        if matches!(keys, MaybeKeyMap::DontUseKeys) {
            self.naked(item, vf, partition)
        } else {
            self.hash(item, vf, keys, partition)
        }
    }

    /// The value a query compares in place of `value`; `value` itself with `DontUseKeys`.
    pub(crate) fn get_beacon_value(
        &self,
        value: &AttributeValue,
        keys: &MaybeKeyMap,
        for_equality: bool,
        for_contains: bool,
        partition: u8,
    ) -> Result<AttributeValue, Error> {
        match (self, keys) {
            (_, MaybeKeyMap::DontUseKeys) => Ok(value.clone()),
            (Self::Standard(s), MaybeKeyMap::ShouldHaveKeys) => Err(val_err(format!(
                "Need KeyId because of beacon {} but no KeyId found in query",
                s.key_name()
            ))),
            (Self::Standard(s), MaybeKeyMap::Keys(keys)) => {
                let key = keys.get(s.key_name()).ok_or_else(|| {
                    val_err(format!(
                        "Internal error. Beacon {} has no key.",
                        s.key_name()
                    ))
                })?;
                s.get_beacon_value(value, key, for_contains, partition)
            }
            (Self::Compound(c), keys) => c.get_beacon_value(value, keys, for_equality, partition),
        }
    }
}

#[cfg(test)]
#[path = "beacon_tests.rs"]
mod tests;

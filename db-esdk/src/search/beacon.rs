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
        //= spec/searchable-encryption/beacons.md#beacon-partition-encoding
        //# If this number is zero, then the input sequence of bytes MUST be returned unchanged.
        Vec::new()
    } else {
        //= spec/searchable-encryption/beacons.md#beacon-partition-encoding
        //# Otherwise, a single byte with a value equal to this calculated partition number, MUST be appended to the input sequence of bytes.
        vec![partition]
    }
}

/// The hex digit of `x`, which is less than 16.
fn hex_char(x: u8) -> char {
    char::from_digit(u32::from(x), 16).unwrap_or('0')
}

/// The rightmost `bits` bits of the 8-byte `bytes`, as lowercase hex.
fn bytes_to_hex(bytes: [u8; 8], bits: u8) -> String {
    let num_bytes = usize::from(bits.div_ceil(8));

    //= spec/searchable-encryption/beacons.md#basichash
    //# - the length of the returned string MUST be (`beacon length`/4) rounded up.
    let num_chars = usize::from(bits.div_ceil(4));
    let top_bits = match bits % 4 {
        0 => 4,
        x => x,
    };
    let truncate = |nibble: u8| nibble % (1 << top_bits);
    let bytes = &bytes[8 - num_bytes..];
    let mut out = String::with_capacity(num_chars);

    //= spec/searchable-encryption/beacons.md#basichash
    //# - basicHash MUST produce a non-empty string as output.
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
//= spec/searchable-encryption/beacons.md#basichash
//= type=implication
//# - basicHash MUST take an [hmac key](./search-config.md#hmac-key-generation), a [beacon length](#beacon-length) and a sequence of bytes as input.
fn basic_hash(val: &[u8], key: &[u8], length: u8) -> Result<String, Error> {
    let mut out = [0u8; 48];

    //= spec/searchable-encryption/beacons.md#basichash
    //# - basicHash MUST calculate the [HmacSha384](https://www.ietf.org/rfc/rfc2104.txt)
    //# of the input bytes and the [hmac key](./search-config.md#hmac-key-generation), and keep the first 8 bytes.
    hmac(DigestAlg::Sha384, key, val, &mut out)?;
    let mut first = [0u8; 8];
    first.copy_from_slice(&out[..8]);

    //= spec/searchable-encryption/beacons.md#basichash
    //# - basicHash MUST return the rightmost [beacon length](#beacon-length) bits of these 8 bytes as a hexadecimal string.
    Ok(bytes_to_hex(first, length))
}

impl StandardInfo {
    /// The beacon whose HMAC key this beacon uses: the shared beacon, or itself.
    pub(crate) fn key_name(&self) -> &str {
        //= spec/searchable-encryption/beacons.md#shared-initialization
        //# This beacon MUST calculate its [value](#beacon-value) as if it were the `other` beacon.
        self.share.as_deref().unwrap_or(&self.name)
    }

    /// The bytes of `partition`, constrained to this beacon's partitions.
    fn constrained_partition(&self, partition: u8) -> Vec<u8> {
        if self.number_of_partitions == 0 || partition == 0 {
            partition_bytes(partition)
        } else {
            //= spec/searchable-encryption/beacons.md#beacon-constraint
            //# If an item is being written or queried as partition `X`, but the [standard beacon](#standard-beacon-initialization) is constrained to only `N` partitions,
            //# then the partition used to [encode](#beacon-partition-encoding) the beacon MUST be `X % N`, where `%` is the modulo or remainder operation.
            partition_bytes(partition % self.number_of_partitions)
        }
    }

    /// The beacon value of `val` under `key` in `partition`.
    //= spec/searchable-encryption/beacons.md#getpart-for-a-standard-beacon
    //= type=implication
    //# - getPart MUST take an [hmac key](./search-config.md#hmac-key-generation), a sequence of bytes as input, and produce a string.
    fn hash(&self, val: &[u8], key: &[u8], partition: u8) -> Result<String, Error> {
        let mut data = val.to_vec();

        //= spec/searchable-encryption/beacons.md#value-for-a-non-set-standard-beacon
        //# - The serialized form MUST be augmented as per [beacon partition encoding](#beacon-partition-encoding).
        data.extend_from_slice(&self.constrained_partition(partition));

        //= spec/searchable-encryption/beacons.md#value-for-a-non-set-standard-beacon
        //# - This operation MUST return the [basicHash](#basichash) of the resulting bytes and the configured [beacon length](#beacon-length).
        //
        //= spec/searchable-encryption/beacons.md#getpart-for-a-standard-beacon
        //# - getPart MUST return the [basicHash](#basichash) of the input and the configured [beacon length](#beacon-length).
        basic_hash(&data, key, self.length)
    }

    /// The beacon value of the UTF-8 bytes of `val`.
    //= spec/searchable-encryption/beacons.md#string-hash
    //= type=implication
    //# - string hash MUST take a string and some [key materials](./search-config.md#get-beacon-key-materials)
    //# as input, and produce a string as output.
    pub(crate) fn hash_str(
        &self,
        val: &str,
        keys: &HmacKeyMap,
        partition: u8,
    ) -> Result<String, Error> {
        //= spec/searchable-encryption/beacons.md#string-hash
        //# - string hash MUST return the [basic hash](#basichash) of the UTF8 representation
        //# of the input string, the HMAC key from the [key materials](./search-config.md#get-beacon-key-materials)
        //# associated with this beacon, and the beacon length associated with this beacon.
        let key = keys
            .get(self.key_name())
            .ok_or_else(|| val_err(format!("no HMAC key for beacon {}", self.key_name())))?;
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
                //= spec/searchable-encryption/beacons.md#asset-initialization
                //# - Writing an item MUST fail if the item contains this beacon's attribute,
                //# and that attribute is not of type Set.
                return Err(val_err(format!(
                    "Beacon {} has style AsSet, but attribute has type {}.",
                    self.name,
                    attr_type_to_str(other)
                )));
            }
        };
        let mut converted: Vec<String> = Vec::with_capacity(elements.len());
        for e in &elements {
            //= spec/searchable-encryption/beacons.md#value-for-a-set-standard-beacon
            //# - This operation MUST convert the value of each item in the set to
            //# a sequence of bytes, as per [attribute serialization](../dynamodb-encryption-client/ddb-attribute-serialization.md).
            let bytes = top_level_attr_to_bytes(e).map_err(val_err)?;

            //= spec/searchable-encryption/beacons.md#value-for-a-set-standard-beacon
            //# - This operation MUST return a set containing the [basicHash](#basichash) of the resulting bytes and the configured [beacon length](#beacon-length).
            let h = self.hash(&bytes, key, partition)?;

            //= spec/searchable-encryption/beacons.md#value-for-a-set-standard-beacon
            //# - The resulting set MUST NOT contain duplicates.
            if !converted.contains(&h) {
                converted.push(h);
            }
        }

        //= spec/searchable-encryption/beacons.md#value-for-a-set-standard-beacon
        //# - The returned
        //# [AttributeValue](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_AttributeValue.html)
        //# MUST be type "SS" StringSet.
        Ok(AttributeValue::Ss(converted))
    }

    /// The beacon value of `item`; `None` when the item lacks the beacon's field.
    //= spec/searchable-encryption/beacons.md#value-for-a-standard-beacon
    //= type=implication
    //# - This operation MUST take an [hmac key](./search-config.md#hmac-key-generation), a record as input, and produce an optional [AttributeValue](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_AttributeValue.html).
    fn get_hash(
        &self,
        item: &HashMap<String, AttributeValue>,
        vf: &VirtualFieldMap,
        key: &[u8],
        partition: u8,
    ) -> Result<Option<AttributeValue>, Error> {
        //= spec/searchable-encryption/beacons.md#value-for-a-standard-beacon
        //# - If this beacon is marked AsSet then this operation MUST return the
        //# [set value](#value-for-a-set-standard-beacon),
        //# otherwise it MUST return the [non-set value](#value-for-a-non-set-standard-beacon)
        if self.as_set {
            match self.loc.term_to_attr(item, None) {
                None => Ok(None),
                //= spec/searchable-encryption/beacons.md#asset-initialization
                //# - The Standard Beacon MUST be stored in the item as a Set,
                //# comprised of the [beacon values](#beacon-value) of all the elements in the original Set.
                Some(v) => Ok(Some(self.value_to_set(&v, key, partition)?)),
            }
        } else {
            //= spec/searchable-encryption/beacons.md#value-for-a-non-set-standard-beacon
            //# - This operation MUST convert the attribute value of the associated field to
            //# a sequence of bytes, as per [attribute serialization](../dynamodb-encryption-client/ddb-attribute-serialization.md).
            match virt_to_bytes(&self.loc, item, vf)? {
                //= spec/searchable-encryption/beacons.md#value-for-a-standard-beacon
                //# - This operation MUST return no value if the associated field does not exist in the record
                None => Ok(None),
                //= spec/searchable-encryption/beacons.md#value-for-a-non-set-standard-beacon
                //# - The returned
                //# [AttributeValue](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_AttributeValue.html)
                //# MUST be type "S" String.
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

/// Greatest common divisor of two partition counts.
const fn gcd(mut a: u8, mut b: u8) -> u8 {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}

/// Least common multiple of two partition counts, capped at `max`.
pub(crate) fn lcm_partition(a: u8, b: u8, max: u8) -> u8 {
    if a == 1 || b == max || a == b {
        b.min(max)
    } else if b == 1 || a == max {
        a.min(max)
    } else {
        let lcm = u32::from(a) / u32::from(gcd(a, b)) * u32::from(b);
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
            //= spec/searchable-encryption/beacons.md#getpart-for-a-compound-beacon
            //# - For each piece, a [part](#part) MUST be identified
            //# by matching the prefix of a [part](#part)
            //# to the beginning of the piece.
            .position(|p| value.starts_with(p.prefix()))
            //= spec/searchable-encryption/beacons.md#getpart-for-a-compound-beacon
            //# - If no such part exists, this operation MUST fail.
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
    //= spec/searchable-encryption/beacons.md#part-value-calculation
    //= type=implication
    //# Part Value Calculation MUST take some [key materials](./search-config.md#get-beacon-key-materials),
    //# a string (the value for which the beacon is being calculated)
    //# and a [Part](#part) as input, and return a string as output.
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
                    // An encrypted part needs a key, as `Beacon::get_beacon_value` checks for
                    // standard beacons (search-config.md#get-beacon-key-for-query).
                    return Err(val_err(format!(
                        "Need KeyId for beacon {} but no KeyId found in query.",
                        beacon.name
                    )));
                };

                //= spec/searchable-encryption/beacons.md#part-value-calculation
                //# If the part is a [encrypted part](#encrypted-part-initialization),
                //# the part value MUST be the concatenation of the part's prefix
                //# and the [string hash](#string-hash) of the input string.
                Ok(format!(
                    "{prefix}{}",
                    beacon.hash_str(data, keys, partition)?
                ))
            }

            //= spec/searchable-encryption/beacons.md#part-value-calculation
            //# If the part is a [signed part](#signed-part-initialization),
            //# the part value MUST be the concatenation of the part's prefix and the input string.
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

        //= spec/searchable-encryption/beacons.md#getpart-for-a-compound-beacon
        //# - The [Part Value](#part-value-calculation) MUST be calculated for each piece,
        //# using the prefix and length from the discovered part.
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
            //= spec/searchable-encryption/beacons.md#getpart-for-a-compound-beacon
            //# - getPart MUST take a string as input and produce a string.
            return Err(val_err(format!(
                "CompoundBeacon {} can only be queried as a string, not as {}",
                self.name,
                attr_type_to_str(value)
            )));
        };

        //= spec/searchable-encryption/beacons.md#getpart-for-a-compound-beacon
        //# - The string MUST be split on the `split character` into pieces.
        let pieces: Vec<String> = s.split(self.split).map(str::to_owned).collect();
        let used = pieces
            .iter()
            .map(|p| self.part_from_prefix(p))
            .collect::<Result<Vec<_>, _>>()?;
        self.validate_part_order(&used, s)?;
        Ok((pieces, used))
    }

    /// The beacon value a query compares in place of `value`.
    //= spec/searchable-encryption/beacons.md#getpart-for-a-compound-beacon
    //= type=implication
    //= reason=every piece must start with a part's prefix, and part builders reject empty prefixes
    //# - The returned string MUST NOT be empty.
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
            //= spec/searchable-encryption/beacons.md#getpart-for-a-compound-beacon
            //# - The value returned MUST be these part values, joined with the `split character`.
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
                        //= spec/searchable-encryption/beacons.md#value-for-a-compound-beacon
                        //# - This operation MUST fail if any plaintext value used in the construction contains the split character.
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

                    //= spec/searchable-encryption/beacons.md#value-for-a-compound-beacon
                    //# - For that constructor, hash MUST join the [part value](#part-value) for each part
                    //# on the `split character`,
                    //# excluding parts that are not required and with a source field that is not available.
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
            //= spec/searchable-encryption/beacons.md#value-for-a-compound-beacon
            //# - If a string is returned, it MUST NOT be empty.
            return Err(val_err("the compound beacon has no parts in this item"));
        }
        Ok(Some(acc))
    }

    /// The value of the first constructor that can build one from `item`.
    //= spec/searchable-encryption/beacons.md#value-for-a-compound-beacon
    //= type=implication
    //# - This operation MUST take a record as input, and produce an optional string.
    fn try_constructors(
        &self,
        item: &HashMap<String, AttributeValue>,
        vf: &VirtualFieldMap,
        keys: &MaybeKeyMap,
        partition: u8,
    ) -> Result<Option<String>, Error> {
        //= spec/searchable-encryption/beacons.md#value-for-a-compound-beacon
        //# - This operation MUST iterate through all constructors, in order, using the first that succeeds.
        for con in &self.constructors {
            if let Some(v) = self.try_constructor(con, item, vf, keys, partition)? {
                return Ok(Some(v));
            }
        }

        //= spec/searchable-encryption/beacons.md#value-for-a-compound-beacon
        //# - If no constructor succeeds, this operation MUST return no value.
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
            //= spec/searchable-encryption/search-config.md#get-beacon-key-for-query
            //# A query MUST fail if this flag is present, and any part of the query
            //# requires a key; that is, needs to compute a standard beacon.
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

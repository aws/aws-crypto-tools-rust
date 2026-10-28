// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Virtual field values: the parts of an item a virtual field joins, each transformed.
//!
//! Strings are measured and cut in UTF-16 code units, as in the other implementations,
//! so every implementation computes the same value for the same item.

use std::collections::{BTreeMap, HashMap};

use aws_crypto_mpl::aws_sdk_dynamodb::types::AttributeValue;

use crate::error::Error;
use crate::search::config::VirtualTransform;
use crate::search::info::{VirtField, VirtPart};
use crate::search::term_loc::TermLoc;

/// The virtual fields of a beacon version, by name.
pub(crate) type VirtualFieldMap = BTreeMap<String, VirtField>;

impl VirtField {
    /// The value of this virtual field in `item`; `None` when a part is missing.
    pub(crate) fn value(
        &self,
        item: &HashMap<String, AttributeValue>,
    ) -> Result<Option<String>, Error> {
        let mut acc = String::new();
        for part in &self.parts {
            //= spec/searchable-encryption/virtual.md#virtual-part-initialization
            //= reason=a missing location yields None; as in Dafny, N/BOOL/NULL are stringified and B/sets/lists/maps are errors
            //# Evaluation MUST return no value if the location does not exist,
            //# or is not a plain string value.
            let Some(value) = part.loc.term_to_string(item)? else {
                return Ok(None);
            };

            //= spec/searchable-encryption/virtual.md#virtual-field-initialization
            //# The evaluation of a Virtual Field MUST be the concatenation of all of its parts,
            //# in the order they are configured.
            acc.push_str(&part.transform(value));
        }
        Ok(Some(acc))
    }
}

impl VirtPart {
    /// `s` after each of the part's transforms, in order.
    fn transform(&self, s: String) -> String {
        //= spec/searchable-encryption/virtual.md#virtual-part-initialization
        //# The evaluation of a Virtual Part MUST be the value of its location,
        //# which is then transformed by each Virtual Transform,
        //# in the order they are configured.
        self.transforms.iter().fold(s, |s, t| do_transform(t, &s))
    }
}

/// The virtual field `loc` names, when `loc` is a whole attribute that is a virtual field.
fn virtual_field<'a>(loc: &TermLoc, vf: &'a VirtualFieldMap) -> Option<&'a VirtField> {
    if loc.is_whole_attribute() {
        vf.get(loc.attribute_name())
    } else {
        None
    }
}

/// The value at `loc` in `item`, where `loc` may name a virtual field.
pub(crate) fn virt_to_attr(
    loc: &TermLoc,
    item: &HashMap<String, AttributeValue>,
    vf: &VirtualFieldMap,
) -> Result<Option<AttributeValue>, Error> {
    match virtual_field(loc, vf) {
        Some(field) => Ok(field.value(item)?.map(AttributeValue::S)),
        None => Ok(loc.term_to_attr(item, None)),
    }
}

/// The serialized value at `loc` in `item`, where `loc` may name a virtual field.
pub(crate) fn virt_to_bytes(
    loc: &TermLoc,
    item: &HashMap<String, AttributeValue>,
    vf: &VirtualFieldMap,
) -> Result<Option<Vec<u8>>, Error> {
    match virtual_field(loc, vf) {
        Some(field) => Ok(field.value(item)?.map(String::into_bytes)),
        None => loc.term_to_bytes(item),
    }
}

/// The string value at `loc` in `item`, where `loc` may name a virtual field.
pub(crate) fn virt_to_string(
    loc: &TermLoc,
    item: &HashMap<String, AttributeValue>,
    vf: &VirtualFieldMap,
) -> Result<Option<String>, Error> {
    match virtual_field(loc, vf) {
        Some(field) => field.value(item),
        None => loc.term_to_string(item),
    }
}

fn utf16(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

fn from_utf16(s: &[u16]) -> String {
    String::from_utf16_lossy(s)
}

/// `n` clamped to `0..=limit`, as a length.
fn min_len(n: i64, limit: usize) -> usize {
    usize::try_from(n).map_or(limit, |n| n.min(limit))
}

/// The first `length` code units of `s`; when negative, all but the last `-length`.
fn get_prefix(s: &str, length: i32) -> String {
    let s = utf16(s);
    let length = i64::from(length);
    let end = if length >= 0 {
        //= spec/searchable-encryption/virtual.md#getprefix-transform-initialization
        //# If length is non-negative, the GetPrefix transform MUST return the first `length` characters of the input.
        //
        //= spec/searchable-encryption/virtual.md#getprefix-transform-initialization
        //# If length is non-negative, and length exceeds the length of the string, the input string MUST be returned.
        min_len(length, s.len())
    } else {
        //= spec/searchable-encryption/virtual.md#getprefix-transform-initialization
        //# If length is negative, then the GetPrefix transform MUST return
        //# all but the last `-length` character of the input.
        //
        //= spec/searchable-encryption/virtual.md#getprefix-transform-initialization
        //# If length is negative and -length exceeds the length on the input,
        //# the empty string MUST be returned.
        s.len() - min_len(-length, s.len())
    };
    from_utf16(&s[..end])
}

/// The last `length` code units of `s`; when negative, all but the first `-length`.
fn get_suffix(s: &str, length: i32) -> String {
    let s = utf16(s);
    let length = i64::from(length);
    let start = if length >= 0 {
        //= spec/searchable-encryption/virtual.md#getsuffix-transform-initialization
        //# If length is non-negative, the GetSuffix transform MUST return the last `length` characters of the input.
        //
        //= spec/searchable-encryption/virtual.md#getsuffix-transform-initialization
        //# If length is non-negative, and length exceeds the length of the string, the input string MUST be returned.
        s.len() - min_len(length, s.len())
    } else {
        //= spec/searchable-encryption/virtual.md#getsuffix-transform-initialization
        //# If length is negative, then the GetSuffix transform MUST return
        //# all but the first `-length` character of the input.
        //
        //= spec/searchable-encryption/virtual.md#getsuffix-transform-initialization
        //# If length is negative and -length exceeds the length on the input,
        //# the empty string MUST be returned.
        min_len(-length, s.len())
    };
    from_utf16(&s[start..])
}

/// Position `pos` within `limit` items: a negative position counts from the end.
fn get_pos(pos: i32, limit: usize) -> usize {
    if limit == 0 {
        return 0;
    }
    let pos = i64::from(pos);
    let limit_i = i64::try_from(limit).unwrap_or(i64::MAX);
    if pos >= 0 {
        //= spec/searchable-encryption/virtual.md#position-definition
        //# If the position provided is positive, it MUST be the zero-based index from the start of the list.
        min_len(pos, limit - 1)
    } else if limit_i + pos < 0 {
        0
    } else {
        //= spec/searchable-encryption/virtual.md#position-definition
        //# If the position provided is negative, it's absolute value MUST be the
        //# one-based index from the end of the list, that is, -1 refers to the last item in the list.
        usize::try_from(limit_i + pos).unwrap_or(0)
    }
}

fn get_substring(s: &str, low: i32, high: i32) -> String {
    let s = utf16(s);
    let lo = get_pos(low, s.len());
    let hi = get_pos(high, s.len());
    if lo < hi {
        //= spec/searchable-encryption/virtual.md#getsubstring-transform-initialization
        //# The GetSubstring transform MUST return the range of characters
        //# from low (inclusive) to high (exclusive)
        from_utf16(&s[lo..hi])
    } else {
        String::new()
    }
}

/// `s` split on `split`.
fn split_parts(s: &str, split: char) -> Vec<&str> {
    s.split(split).collect()
}

fn get_segment(s: &str, split: char, index: i32) -> String {
    let parts = split_parts(s, split);
    let len = i64::try_from(parts.len()).unwrap_or(i64::MAX);
    let index_i = i64::from(index);
    if index_i >= len || -index_i > len {
        //= spec/searchable-encryption/virtual.md#getsegment-transform-initialization
        //# If index is greater than the number of items in the list, an empty string MUST be returned.
        String::new()
    } else {
        //= spec/searchable-encryption/virtual.md#getsegment-transform-initialization
        //# The GetSegment transform MUST split the input string on the given character,
        //# and return the item in the resulting list the corresponds to the given position.
        parts[get_pos(index, parts.len())].to_owned()
    }
}

fn get_segments(s: &str, split: char, low: i32, high: i32) -> String {
    //= spec/searchable-encryption/virtual.md#getsegments-transform-initialization
    //# The GetSegments transform MUST split the input string on the `split` character.
    let parts = split_parts(s, split);
    let lo = get_pos(low, parts.len());
    let hi = get_pos(high, parts.len());
    if lo < hi {
        //= spec/searchable-encryption/virtual.md#getsegments-transform-initialization
        //# GetSegments MUST return the range of parts from low (inclusive) to high (exclusive),
        //# joined on the `split` character.
        parts[lo..hi].join(&split.to_string())
    } else {
        //= spec/searchable-encryption/virtual.md#getsegments-transform-initialization
        //# If high is less than or equal to low, an empty string MUST be returned.
        String::new()
    }
}

fn do_transform(t: &VirtualTransform, s: &str) -> String {
    match t {
        //= spec/searchable-encryption/virtual.md#upper-transform-initialization
        //# The Upper transform MUST convert all ascii lowercase characters into their uppercase equivalents.
        VirtualTransform::Upper(_) => s.to_ascii_uppercase(),

        //= spec/searchable-encryption/virtual.md#lower-transform-initialization
        //# The Lower transform MUST convert all ascii uppercase characters into their lowercase equivalents.
        VirtualTransform::Lower(_) => s.to_ascii_lowercase(),

        //= spec/searchable-encryption/virtual.md#insert-transform-initialization
        //# The Insert transform MUST append this string to its input
        VirtualTransform::Insert(ins) => format!("{s}{}", ins.literal),
        VirtualTransform::Prefix(p) => get_prefix(s, p.length),
        VirtualTransform::Suffix(p) => get_suffix(s, p.length),
        VirtualTransform::Substring(p) => get_substring(s, p.low, p.high),
        VirtualTransform::Segment(p) => get_segment(s, p.split, p.index),
        VirtualTransform::Segments(p) => get_segments(s, p.split, p.low, p.high),
    }
}

#[cfg(test)]
#[path = "virt_tests.rs"]
mod tests;

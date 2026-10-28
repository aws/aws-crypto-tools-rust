// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! DynamoDB attribute values as structured-encryption terminals, and back.

pub(crate) mod filter_expr;
pub(crate) mod float_compare;
pub(crate) mod number;
pub(crate) mod update_expr;

use std::collections::{BTreeSet, HashMap};

use aws_crypto_mpl::aws_sdk_dynamodb::primitives::Blob;
use aws_crypto_mpl::aws_sdk_dynamodb::types::AttributeValue;

use crate::structured::util::{
    BINARY, BINARY_SET, BOOLEAN, LIST, MAP, NULL, NUMBER, NUMBER_SET, RESERVED_PREFIX, STRING,
    STRING_SET, Terminal, TypeId, utf16_cmp, utf16_len,
};
use crate::types::CryptoAction;
pub(crate) use number::normalize_number;

/// A DynamoDB item.
pub(crate) type Item = HashMap<String, AttributeValue>;

/// How deeply lists and maps may nest.
const MAX_STRUCTURE_DEPTH: u64 = 32;
const LENGTH_LEN: usize = 4;
const PREFIX_LEN: usize = 6;
const MAX_ATTR_NAME_LEN: usize = 65_535;

/// The type id of `a`.
fn type_id(a: &AttributeValue) -> Result<TypeId, String> {
    //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#type-id
    //# Type ID indicates what type a DynamoDB Attribute Value MUST
    //# be serialized and deserialized as.
    Ok(match a {
        AttributeValue::S(_) => STRING,
        AttributeValue::N(_) => NUMBER,
        AttributeValue::B(_) => BINARY,
        AttributeValue::Ss(_) => STRING_SET,
        AttributeValue::Ns(_) => NUMBER_SET,
        AttributeValue::Bs(_) => BINARY_SET,
        AttributeValue::M(_) => MAP,
        AttributeValue::L(_) => LIST,
        AttributeValue::Null(_) => NULL,
        AttributeValue::Bool(_) => BOOLEAN,
        _ => return Err("Unsupported AttributeValue type".to_owned()),
    })
}

fn u32_be(len: usize) -> Result<[u8; 4], String> {
    u32::try_from(len)
        .map(u32::to_be_bytes)
        .map_err(|_| "Length was too big".to_owned())
}

fn has_duplicates<T: Ord>(items: impl IntoIterator<Item = T>) -> bool {
    let mut seen = BTreeSet::new();
    !items.into_iter().all(|x| seen.insert(x))
}

/// Append the Set Count and Set Entries of the already sorted, duplicate-free `sorted`.
fn write_set_entries<T: AsRef<[u8]>>(sorted: &[T], out: &mut Vec<u8>) -> Result<(), String> {
    //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#set
    //# A Set MUST be serialized as:
    //
    //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#set-count
    //# Set Count MUST be a big-endian unsigned integer
    //# equal to the number of serialized entries in
    //# [Set Entries](#set-entries).
    out.extend_from_slice(&u32_be(sorted.len())?);

    //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#set-count
    //# Set Count MAY be `0`,
    //# in which case [Set Entries](#set-entries) is a zero-length byte string.
    for entry in sorted {
        let entry = entry.as_ref();

        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#set-entries
        //# Each of these entries MUST be serialized as:
        //
        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#set-entry-length
        //# Set Entry Length MUST be a big-endian unsigned integer
        //# equal to the length of [Set Entry Value](#set-entry-value).
        out.extend_from_slice(&u32_be(entry.len())?);
        out.extend_from_slice(entry);
    }
    Ok(())
}

fn string_set_to_bytes(ss: &[String], out: &mut Vec<u8>) -> Result<(), String> {
    if has_duplicates(ss) {
        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#set-entries
        //# String Sets MUST NOT contain duplicate entries.
        return Err("String Set had duplicate values".to_owned());
    }
    let mut sorted = ss.to_vec();

    //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#set-entries
    //# Entries in a String Set MUST be ordered in ascending [UTF-16 binary order](./string-ordering.md#utf-16-binary-order).
    sorted.sort_by(|a, b| utf16_cmp(a, b));
    write_set_entries(&sorted, out)
}

fn number_set_to_bytes(ns: &[String], out: &mut Vec<u8>) -> Result<(), String> {
    if has_duplicates(ns) {
        return Err("Number Set had duplicate values".to_owned());
    }
    let mut norm = ns
        .iter()
        .map(|n| normalize_number(n))
        .collect::<Result<Vec<_>, _>>()?;
    if has_duplicates(&norm) {
        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#set-entries
        //# Number Sets MUST NOT contain duplicate entries.
        return Err("Number Set had duplicate values after normalization.".to_owned());
    }

    //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#set-entries
    //# Entries in a Number Set MUST be ordered in ascending [UTF-16 binary order](./string-ordering.md#utf-16-binary-order).
    //
    //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#set-entries
    //# This ordering MUST be applied after normalization of the number value.
    norm.sort_by(|a, b| utf16_cmp(a, b));
    write_set_entries(&norm, out)
}

fn binary_set_to_bytes(bs: &[Blob], out: &mut Vec<u8>) -> Result<(), String> {
    if has_duplicates(bs.iter().map(Blob::as_ref)) {
        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#set-entries
        //# Binary Sets MUST NOT contain duplicate entries.
        return Err("Binary Set had duplicate values".to_owned());
    }
    let mut sorted: Vec<&[u8]> = bs.iter().map(Blob::as_ref).collect();

    //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#set-entries
    //# Entries in a Binary Set MUST be ordered lexicographically by their underlying bytes in ascending order.
    sorted.sort_unstable();
    write_set_entries(&sorted, out)
}

fn map_to_bytes(
    m: &HashMap<String, AttributeValue>,
    depth: u64,
    out: &mut Vec<u8>,
) -> Result<(), String> {
    let mut keys: Vec<&String> = m.keys().collect();

    //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#key-value-pair-entries
    //# Entries in a serialized Map MUST be ordered by key value,
    //# ordered in ascending [UTF-16 binary order](./string-ordering.md#utf-16-binary-order).
    keys.sort_by(|a, b| utf16_cmp(a, b));

    // Key Value Pair Count

    //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#map-attribute
    //# Map MUST be serialized as:
    //
    //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#key-value-pair-count
    //# Key Value Pair Count MUST be a big-endian unsigned integer
    //# equal to the number of serialized key-value pairs in
    //# [Key Value Pair Entries](#key-value-pair-entries).
    out.extend_from_slice(&u32_be(keys.len())?);

    // Key Value Pair Entries

    //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#key-value-pair-count
    //# Key Value Pair Count MAY be `0`,
    //# in which case [Key Value Pair Entries](#key-value-pair-entries) is an empty bytestring.
    for k in keys {
        // A bad value is reported before a bad name.
        let name_ok = !k.is_empty() && k.len() <= MAX_ATTR_NAME_LEN;
        if name_ok {
            //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#key-value-pair-entries
            //# Each key-value pair MUST be serialized as:
            //
            //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#key-type
            //# Key Type MUST be the [Type ID](#type-id) for Strings.
            out.extend_from_slice(&STRING);
            // Key Length
            out.extend_from_slice(&u32_be(k.len())?);

            //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#map-key
            //# Map Key MUST be a [String Value](#string).
            out.extend_from_slice(k.as_bytes());
        }

        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#map-value
        //# Map Value MUST be a [Value](#value).
        //
        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#map-value
        //# A Map MAY hold any DynamoDB Attribute Value data type,
        //# and MAY hold values of different types.
        write_attr(&m[k], true, depth + 1, out)?;
        if !name_ok {
            //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#key-length
            //# Key Length MUST be a non-zero big-endian unsigned integer
            //# equal to the length of [Map Key](#map-key).
            return Err("Attribute name must be between 1 and 65535 UTF-8 bytes".to_owned());
        }
    }
    Ok(())
}

fn list_to_bytes(l: &[AttributeValue], depth: u64, out: &mut Vec<u8>) -> Result<(), String> {
    // List Count

    //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#list
    //# List MUST be serialized as:
    //
    //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#list-count
    //# List Count MUST be a big-endian unsigned integer
    //# equal to the number of serialized list entries in
    //# [List Entries](#list-entries).
    out.extend_from_slice(&u32_be(l.len())?);

    // List Entries

    //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#list-count
    //# List Count MAY be `0`,
    //# in which case [List Entries](#list-entries) is an empty byte string.
    //
    //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#list-entries
    //# The order of these serialized list entries MUST match
    //# the order of the entries in the original list.
    for v in l {
        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#list-entries
        //# Each list entry in the sequence MUST be serialized as:
        //
        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#list-entry-value
        //# A List MAY hold any DynamoDB Attribute Value data type,
        //# and MAY hold values of different types.
        write_attr(v, true, depth + 1, out)?;
    }
    Ok(())
}

/// Append the serialized value of `a` to `out`; with `prefix`, preceded by its type id and length.
fn write_attr(
    a: &AttributeValue,
    prefix: bool,
    depth: u64,
    out: &mut Vec<u8>,
) -> Result<(), String> {
    if depth > MAX_STRUCTURE_DEPTH {
        return Err(format!(
            "Depth of attribute structure to serialize exceeds limit of {MAX_STRUCTURE_DEPTH}"
        ));
    }
    // The type id and a length placeholder, filled in once the value is written.
    let len_at = if prefix {
        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#value-type
        //# Value Type MUST be the [Type ID](#type-id) of the type of [Map Value](#map-value).
        //
        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#list-entry-type
        //# List Entry Type MUST be the [Type ID](#type-id) of the type of [List Entry Value](#list-entry-value).
        out.extend_from_slice(&type_id(a)?);
        out.extend_from_slice(&[0; LENGTH_LEN]);
        Some(out.len())
    } else {
        None
    };
    match a {
        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#string
        //# String MUST be serialized as UTF-8 encoded bytes.
        AttributeValue::S(s) => out.extend_from_slice(s.as_bytes()),

        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#number
        //# This value MUST be normalized in the same way as DynamoDB normalizes numbers.
        //
        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#number
        //# This normalized value MUST then be serialized as UTF-8 encoded bytes.
        AttributeValue::N(n) => out.extend_from_slice(normalize_number(n)?.as_bytes()),

        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#binary
        //# Binary MUST be serialized with the identity function;
        //# or more plainly, Binary Attribute Values are used as is.
        AttributeValue::B(b) => out.extend_from_slice(b.as_ref()),
        AttributeValue::Ss(ss) => string_set_to_bytes(ss, out)?,
        AttributeValue::Ns(ns) => number_set_to_bytes(ns, out)?,
        AttributeValue::Bs(bs) => binary_set_to_bytes(bs, out)?,
        AttributeValue::M(m) => map_to_bytes(m, depth, out)?,
        AttributeValue::L(l) => list_to_bytes(l, depth, out)?,

        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#null
        //# Null MUST be serialized as a zero-length byte string.
        AttributeValue::Null(_) => {}

        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#boolean
        //# Boolean MUST be serialized as:
        AttributeValue::Bool(b) => out.push(u8::from(*b)),
        _ => return Err("Unsupported AttributeValue type".to_owned()),
    }
    if let Some(body) = len_at {
        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#value-length
        //# Value Length MUST be a big-endian unsigned integer
        //# equal to the length of [Map Value](#map-value).
        //
        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#list-entry-length
        //# List Entry Length MUST be a big-endian unsigned integer
        //# equal to the length of [List Entry Value](#list-entry-value).
        let len = u32_be(out.len() - body)?;
        out[body - LENGTH_LEN..body].copy_from_slice(&len);
    }
    Ok(())
}

/// The serialized value of `a`; with `prefix`, preceded by its type id and length.
fn attr_to_bytes(a: &AttributeValue, prefix: bool, depth: u64) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    write_attr(a, prefix, depth, &mut out)?;
    Ok(out)
}

/// The serialized value of a top-level attribute, without its type id.
pub(crate) fn top_level_attr_to_bytes(a: &AttributeValue) -> Result<Vec<u8>, String> {
    attr_to_bytes(a, false, 1)
}

/// `a` as a terminal.
pub(crate) fn attr_to_terminal(a: &AttributeValue) -> Result<Terminal, String> {
    //= spec/dynamodb-encryption-client/ddb-item-conversion.md#convert-ddb-item-to-structured-data
    //# - The [Terminal Type ID](../structured-encryption/structures.md#terminal-type-id) for each attribute MUST
    //# be the [Type ID](./ddb-attribute-serialization.md#type-id) of the [serialization](./ddb-attribute-serialization.md) of this Attribute Value.
    let type_id = type_id(a)?;

    //= spec/dynamodb-encryption-client/ddb-item-conversion.md#convert-ddb-item-to-structured-data
    //# - The [Terminal Value](../structured-encryption/structures.md#terminal-value) for each attribute MUST
    //# be the [Value](./ddb-attribute-serialization.md#type-id) of the [serialization](./ddb-attribute-serialization.md) of this Attribute Value.
    let value = attr_to_bytes(a, false, 1)?;
    Ok(Terminal::new(type_id, value))
}

/// A value read from serialized bytes, and how many bytes it took.
struct Read {
    val: AttributeValue,
    len: usize,
}

fn read_u32(x: &[u8], pos: usize) -> Result<usize, String> {
    let bytes: [u8; LENGTH_LEN] = x
        .get(pos..pos + LENGTH_LEN)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| "Length of 4-byte integer was less than 4".to_owned())?;
    let n = u32::from_be_bytes(bytes);
    usize::try_from(n).map_err(|_| "Length was too big".to_owned())
}

fn utf8(bytes: &[u8]) -> Result<String, String> {
    String::from_utf8(bytes.to_vec()).map_err(|_| "Invalid UTF-8".to_owned())
}

/// The kind of set being read, which names it in error messages.
#[derive(Clone, Copy)]
enum SetKind {
    String,
    Number,
    Binary,
}

impl SetKind {
    const fn name(self) -> &'static str {
        match self {
            Self::String => "String",
            Self::Number => "Number",
            Self::Binary => "Binary",
        }
    }
}

/// Read `count` Set Entries from `data`: the entry values and how many bytes they took.
fn read_set_entries(
    data: &[u8],
    count: usize,
    kind: SetKind,
) -> Result<(Vec<&[u8]>, usize), String> {
    let mut out = Vec::new();
    let mut pos = 0usize;

    //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#set-count
    //# Set Count MAY be `0`,
    //# in which case [Set Entries](#set-entries) is a zero-length byte string.
    for _ in 0..count {
        if data.len() - pos < LENGTH_LEN {
            // Number sets report "String Set" here, as the Dafny implementation does.
            let set = match kind {
                SetKind::Binary => "Binary",
                SetKind::String | SetKind::Number => "String",
            };
            return Err(format!("Out of bytes reading {set} Set"));
        }

        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#set-entries
        //# Each of these entries MUST be serialized as:
        //
        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#set-entry-length
        //# Set Entry Length MUST be a big-endian unsigned integer
        //# equal to the length of [Set Entry Value](#set-entry-value).
        let len = read_u32(data, pos)?;
        pos += LENGTH_LEN;
        if data.len() - pos < len {
            return Err(format!(
                "{} Set Structured Data has too few bytes",
                kind.name()
            ));
        }
        out.push(&data[pos..pos + len]);
        pos += len;
    }
    Ok((out, pos))
}

/// Read `count` Set Entries from `data` as strings.
fn read_strings(data: &[u8], count: usize, kind: SetKind) -> Result<(Vec<String>, usize), String> {
    let (entries, n) = read_set_entries(data, count, kind)?;
    let strings = entries.into_iter().map(utf8).collect::<Result<_, _>>()?;
    Ok((strings, n))
}

/// Read the `len`-byte value of type `type_id` at `pos` in `value`.
fn bytes_to_attr(
    value: &[u8],
    type_id: TypeId,
    len: usize,
    depth: u64,
    pos: usize,
) -> Result<Read, String> {
    if depth > MAX_STRUCTURE_DEPTH {
        return Err(format!(
            "Depth of attribute structure to deserialize exceeds limit of {MAX_STRUCTURE_DEPTH}"
        ));
    }
    if value.len().saturating_sub(pos) < len || pos > value.len() {
        return Err("Structured Data has too few bytes".to_owned());
    }
    let body = &value[pos..pos + len];
    let read = |val, len| Read { val, len };

    //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#type-id
    //# Type ID indicates what type a DynamoDB Attribute Value MUST
    //# be serialized and deserialized as.
    match type_id {
        NULL => {
            if len != 0 {
                //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#null
                //# Null MUST be serialized as a zero-length byte string.
                return Err("NULL type did not have length zero".to_owned());
            }
            Ok(read(AttributeValue::Null(true), 0))
        }

        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#string
        //# String MUST be serialized as UTF-8 encoded bytes.
        STRING => Ok(read(AttributeValue::S(utf8(body)?), len)),

        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#number
        //# This normalized value MUST then be serialized as UTF-8 encoded bytes.
        NUMBER => Ok(read(AttributeValue::N(utf8(body)?), len)),

        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#binary
        //# Binary MUST be serialized with the identity function;
        //# or more plainly, Binary Attribute Values are used as is.
        BINARY => Ok(read(AttributeValue::B(Blob::new(body)), len)),

        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#boolean
        //# Boolean MUST be serialized as:
        BOOLEAN => match body {
            [0] => Ok(read(AttributeValue::Bool(false), 1)),
            [1] => Ok(read(AttributeValue::Bool(true), 1)),
            [_] => Err("Boolean Structured Data had inappropriate value".to_owned()),
            _ => Err("Boolean Structured Data has more than one byte".to_owned()),
        },
        STRING_SET | NUMBER_SET | BINARY_SET => {
            let rest = &value[pos..];
            if rest.len() < LENGTH_LEN {
                return Err("Set Structured Data has less than LENGTH_LEN bytes".to_owned());
            }

            //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#set
            //# A Set MUST be serialized as:
            //
            //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#set-count
            //# Set Count MUST be a big-endian unsigned integer
            //# equal to the number of serialized entries in
            //# [Set Entries](#set-entries).
            let count = read_u32(rest, 0)?;
            let items = &rest[LENGTH_LEN..];
            match type_id {
                STRING_SET => {
                    let (ss, n) = read_strings(items, count, SetKind::String)?;
                    if has_duplicates(&ss) {
                        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#set-entries
                        //# String Sets MUST NOT contain duplicate entries.
                        //
                        //= spec/dynamodb-encryption-client/ddb-item-conversion.md#duplicates
                        //# - Conversion from a Structured Data String Set MUST fail if it has duplicate values
                        return Err("String set values must not have duplicates".to_owned());
                    }
                    Ok(read(AttributeValue::Ss(ss), LENGTH_LEN + n))
                }
                NUMBER_SET => {
                    let (ns, n) = read_strings(items, count, SetKind::Number)?;
                    if has_duplicates(&ns) {
                        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#set-entries
                        //# Number Sets MUST NOT contain duplicate entries.
                        //
                        //= spec/dynamodb-encryption-client/ddb-item-conversion.md#duplicates
                        //# - Conversion from a Structured Data Number Set MUST fail if it has duplicate values
                        return Err("Number set values must not have duplicates".to_owned());
                    }
                    Ok(read(AttributeValue::Ns(ns), LENGTH_LEN + n))
                }
                _ => {
                    let (entries, n) = read_set_entries(items, count, SetKind::Binary)?;
                    if has_duplicates(&entries) {
                        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#set-entries
                        //# Binary Sets MUST NOT contain duplicate entries.
                        //
                        //= spec/dynamodb-encryption-client/ddb-item-conversion.md#duplicates
                        //# - Conversion from a Structured Data Binary Set MUST fail if it has duplicate values
                        return Err("Binary set values must not have duplicates".to_owned());
                    }
                    let bs = entries.into_iter().map(Blob::new).collect();
                    Ok(read(AttributeValue::Bs(bs), LENGTH_LEN + n))
                }
            }
        }
        MAP => read_map(value, pos, depth),
        LIST => read_list(value, pos, depth),

        //= spec/structured-encryption/structures.md#terminal-type-id
        //= reason=BINARY is the only 0xFF-prefixed id matched above; the reserved ones land here
        //# Any other value prefixed by 0xFF is reserved and MUST NOT be used.
        _ => Err("Unsupported TerminalTypeId".to_owned()),
    }
}

/// Read the Map at `pos` in `value`.
fn read_map(value: &[u8], pos: usize, depth: u64) -> Result<Read, String> {
    if value.len() < pos + LENGTH_LEN {
        return Err("List Structured Data has less than 4 bytes".to_owned());
    }

    // Key Value Pair Count

    //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#map-attribute
    //# Map MUST be serialized as:
    //
    //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#key-value-pair-count
    //# Key Value Pair Count MUST be a big-endian unsigned integer
    //# equal to the number of serialized key-value pairs in
    //# [Key Value Pair Entries](#key-value-pair-entries).
    let count = read_u32(value, pos)?;
    let mut p = pos + LENGTH_LEN;
    // Every entry takes at least PREFIX_LEN bytes, which bounds the capacity.
    let mut m = HashMap::with_capacity(count.min((value.len() - p) / PREFIX_LEN));

    // Key Value Pair Entries

    //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#key-value-pair-count
    //# Key Value Pair Count MAY be `0`,
    //# in which case [Key Value Pair Entries](#key-value-pair-entries) is an empty bytestring.
    for _ in 0..count {
        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#key-value-pair-entries
        //# Each key-value pair MUST be serialized as:
        if value.len() - p < PREFIX_LEN {
            return Err("Out of bytes reading Map Key".to_owned());
        }
        if value[p..p + 2] != STRING {
            //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#key-type
            //# Key Type MUST be the [Type ID](#type-id) for Strings.
            return Err("Key of Map is not String".to_owned());
        }
        p += 2;
        // Key Length
        let klen = read_u32(value, p)?;
        p += LENGTH_LEN;
        if klen > value.len() - p {
            return Err("Key of Map of Structured Data has too few bytes".to_owned());
        }
        if klen == 0 || klen > MAX_ATTR_NAME_LEN {
            //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#key-length
            //# Key Length MUST be a non-zero big-endian unsigned integer
            //# equal to the length of [Map Key](#map-key).
            return Err("Attribute name must be between 1 and 65535 UTF-8 bytes".to_owned());
        }

        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#map-key
        //# Map Key MUST be a [String Value](#string).
        let key = utf8(&value[p..p + klen])?;
        p += klen;
        if value.len() - p < 2 {
            return Err("Out of bytes reading Map Value".to_owned());
        }

        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#value-type
        //# Value Type MUST be the [Type ID](#type-id) of the type of [Map Value](#map-value).
        let vtype = [value[p], value[p + 1]];
        p += 2;

        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#value-length
        //# Value Length MUST be a big-endian unsigned integer
        //# equal to the length of [Map Value](#map-value).
        let vlen = read_u32(value, p)?;
        p += LENGTH_LEN;

        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#map-value
        //# Map Value MUST be a [Value](#value).
        //
        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#map-value
        //# A Map MAY hold any DynamoDB Attribute Value data type,
        //# and MAY hold values of different types.
        let nval = bytes_to_attr(value, vtype, vlen, depth + 1, p)?;
        p += nval.len;
        if m.contains_key(&key) {
            //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#key-value-pair-entries
            //# This sequence MUST NOT contain duplicate [Map Keys](#map-key).
            //
            //= spec/dynamodb-encryption-client/ddb-item-conversion.md#duplicates
            //# - Conversion from a Structured Data Map MUST fail if it has duplicate keys
            return Err("Duplicate key in map.".to_owned());
        }
        m.insert(key, nval.val);
    }
    Ok(Read {
        val: AttributeValue::M(m),
        len: p - pos,
    })
}

/// Read the List at `pos` in `value`.
fn read_list(value: &[u8], pos: usize, depth: u64) -> Result<Read, String> {
    if value.len() < pos + LENGTH_LEN {
        return Err("List Structured Data has less than 4 bytes".to_owned());
    }

    // List Count

    //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#list
    //# List MUST be serialized as:
    //
    //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#list-count
    //# List Count MUST be a big-endian unsigned integer
    //# equal to the number of serialized list entries in
    //# [List Entries](#list-entries).
    let count = read_u32(value, pos)?;
    let mut p = pos + LENGTH_LEN;
    let mut l = Vec::with_capacity(count.min((value.len() - p) / PREFIX_LEN));

    // List Entries

    //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#list-count
    //# List Count MAY be `0`,
    //# in which case [List Entries](#list-entries) is an empty byte string.
    for _ in 0..count {
        if value.len() - p < PREFIX_LEN {
            return Err("Out of bytes reading Type of List element".to_owned());
        }

        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#list-entries
        //# Each list entry in the sequence MUST be serialized as:
        //
        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#list-entry-type
        //# List Entry Type MUST be the [Type ID](#type-id) of the type of [List Entry Value](#list-entry-value).
        let etype = [value[p], value[p + 1]];

        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#list-entry-length
        //# List Entry Length MUST be a big-endian unsigned integer
        //# equal to the length of [List Entry Value](#list-entry-value).
        let elen = read_u32(value, p + 2)?;
        let np = p + PREFIX_LEN;
        if value.len() - np < elen {
            return Err("Out of bytes reading Content of List element".to_owned());
        }

        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#list-entry-value
        //# A List MAY hold any DynamoDB Attribute Value data type,
        //# and MAY hold values of different types.
        let nval = bytes_to_attr(value, etype, elen, depth + 1, np)?;
        p = np + nval.len;

        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#list-entries
        //# The order of these serialized list entries MUST match
        //# the order of the entries in the original list.
        l.push(nval.val);
    }
    Ok(Read {
        val: AttributeValue::L(l),
        len: p - pos,
    })
}

/// The attribute value a terminal holds.
pub(crate) fn terminal_to_attr(t: &Terminal) -> Result<AttributeValue, String> {
    //= spec/structured-encryption/structures.md#terminal-value
    //# If these bytes are to be deserialized, these bytes MUST be interpreted as the type indicated in this Terminal Data's [Terminal Type ID](#terminal-type-id).D
    //
    //= spec/dynamodb-encryption-client/ddb-item-conversion.md#convert-structured-data-to-ddb-item
    //# - Each Attribute MUST be deserializable
    //# according to [the serialization scheme](./ddb-attribute-serialization.md#value).
    let read = bytes_to_attr(&t.value, t.type_id, t.value.len(), 1, 0)?;
    if read.len != t.value.len() {
        return Err("Mismatch between length of encoded data and length of data".to_owned());
    }
    Ok(read.val)
}

/// The terminals of the item's attributes, leaving out attributes configured `DO_NOTHING`
/// (unless reserved).
pub(crate) fn item_to_structured(
    item: &Item,
    actions: &HashMap<String, CryptoAction>,
) -> Result<HashMap<String, Terminal>, String> {
    let mut out = HashMap::with_capacity(item.len());
    let mut errors = BTreeSet::new();
    for (k, v) in item {
        let skip =
            actions.get(k) == Some(&CryptoAction::DoNothing) && !k.starts_with(RESERVED_PREFIX);
        if skip {
            continue;
        }
        match attr_to_terminal(v) {
            Ok(t) => {
                //= spec/dynamodb-encryption-client/ddb-item-conversion.md#convert-ddb-item-to-structured-data
                //= reason=one terminal per attribute; non-reserved DO_NOTHING attributes are left out, as they are never signed
                //# - MUST contain a [Structured Data Terminal](../structured-encryption/structures.md#structured-data-terminal)
                //# for each attribute on the DynamoDB Item, and no others.
                //
                //= spec/dynamodb-encryption-client/ddb-item-conversion.md#convert-ddb-item-to-structured-data
                //# - The Structured Data Terminal MUST be located at the top level of the Structured Data,
                //# string indexed by the Attribute Name.
                out.insert(k.clone(), t);
            }
            Err(e) => {
                errors.insert(e);
            }
        }
    }
    if errors.is_empty() {
        Ok(out)
    } else {
        Err(errors.into_iter().collect::<Vec<_>>().join("\n"))
    }
}

/// Reject any Structured Data key that is not a valid DynamoDB attribute name.
fn check_attribute_names(s: &HashMap<String, Terminal>) -> Result<(), String> {
    let mut bad: Vec<&str> = s
        .keys()
        .filter(|k| utf16_len(k) > MAX_ATTR_NAME_LEN)
        .map(String::as_str)
        .collect();
    if bad.is_empty() {
        return Ok(());
    }
    bad.sort_by(|a, b| utf16_cmp(a, b));

    //= spec/dynamodb-encryption-client/ddb-item-conversion.md#convert-structured-data-to-ddb-item
    //# - MUST NOT have any `Key` strings that are invalid DynamoDB AttributeNames, that is, with more than 65535 characters.
    Err(format!("Not valid attribute names : {}", bad.join(",")))
}

/// The encrypted item: each encrypted attribute replaced, plus the header and footer.
pub(crate) fn structured_to_item_encrypt(
    s: &HashMap<String, Terminal>,
    orig: &Item,
    actions: &HashMap<String, CryptoAction>,
) -> Result<Item, String> {
    check_attribute_names(s)?;
    let mut out = HashMap::with_capacity(s.len());
    for (k, v) in orig {
        if k.starts_with(RESERVED_PREFIX) {
            continue;
        }
        if let (Some(t), Some(CryptoAction::EncryptAndSign)) = (s.get(k), actions.get(k)) {
            out.insert(k.clone(), terminal_to_attr(t)?);
        } else {
            out.insert(k.clone(), v.clone());
        }
    }

    //= spec/dynamodb-encryption-client/ddb-item-conversion.md#convert-structured-data-to-ddb-item
    //= reason=every terminal becomes an attribute; the only others are the DO_NOTHING ones item_to_structured left out
    //# - MUST contain an Attribute for every [Structured Data Terminal](../structured-encryption/structures.md#structured-data-terminal)
    //# on the Structured Data, and no other Attributes.
    for (k, t) in s {
        if !orig.contains_key(k) {
            out.insert(k.clone(), terminal_to_attr(t)?);
        }
    }
    Ok(out)
}

/// The decrypted item: each encrypted attribute replaced, the header and footer dropped.
pub(crate) fn structured_to_item_decrypt(
    s: &HashMap<String, Terminal>,
    orig: &Item,
    actions: &HashMap<String, CryptoAction>,
) -> Result<Item, String> {
    check_attribute_names(s)?;
    let mut out = HashMap::with_capacity(orig.len());
    for (k, v) in orig {
        if k.starts_with(RESERVED_PREFIX) {
            continue;
        }
        if let (Some(t), Some(CryptoAction::EncryptAndSign)) = (s.get(k), actions.get(k)) {
            out.insert(k.clone(), terminal_to_attr(t)?);
        } else {
            out.insert(k.clone(), v.clone());
        }
    }
    Ok(out)
}

// Vectors ported from DynamoDbEncryption/test/DynamoToStruct.dfy.
#[cfg(test)]
mod tests {
    use super::*;

    const K: u8 = b'k';
    const E: u8 = b'e';
    const Y: u8 = b'y';
    const A: u8 = b'A';
    const B: u8 = b'B';
    const C: u8 = b'C';
    const D: u8 = b'D';

    // "&", "\u{10002}" and "\u{FF61}" sort differently in UTF-8 and UTF-16.
    const AMP: &str = "&";
    const LINEAR_B: &str = "\u{10002}";
    const HALFWIDTH_STOP: &str = "\u{FF61}";

    fn s(x: &str) -> AttributeValue {
        AttributeValue::S(x.to_owned())
    }
    fn n(x: &str) -> AttributeValue {
        AttributeValue::N(x.to_owned())
    }
    fn b(x: &[u8]) -> AttributeValue {
        AttributeValue::B(Blob::new(x))
    }
    fn ss(x: &[&str]) -> AttributeValue {
        AttributeValue::Ss(x.iter().map(|v| (*v).to_owned()).collect())
    }
    fn ns(x: &[&str]) -> AttributeValue {
        AttributeValue::Ns(x.iter().map(|v| (*v).to_owned()).collect())
    }
    fn bs(x: &[&[u8]]) -> AttributeValue {
        AttributeValue::Bs(x.iter().map(|v| Blob::new(*v)).collect())
    }
    fn m(x: &[(&str, AttributeValue)]) -> AttributeValue {
        AttributeValue::M(
            x.iter()
                .map(|(k, v)| ((*k).to_owned(), v.clone()))
                .collect(),
        )
    }
    fn null() -> AttributeValue {
        AttributeValue::Null(true)
    }

    fn decode(type_id: TypeId, value: &[u8]) -> Result<AttributeValue, String> {
        terminal_to_attr(&Terminal::new(type_id, value.to_vec()))
    }

    /// `attr` encodes to exactly `(type_id, value)` and decodes back to `decoded`.
    #[track_caller]
    fn check_encode(
        attr: &AttributeValue,
        type_id: TypeId,
        value: &[u8],
        decoded: &AttributeValue,
    ) {
        let t = attr_to_terminal(attr).unwrap();
        assert_eq!(t, Terminal::new(type_id, value.to_vec()));
        assert_eq!(&terminal_to_attr(&t).unwrap(), decoded);
    }

    #[test]
    fn zero_bytes() {
        // Empty values: only Null, String, Number and Binary may be zero bytes long; Boolean
        // needs its one byte and Sets, Maps and Lists need their 4-byte count.
        assert_eq!(decode(NULL, &[]), Ok(null()));
        assert_eq!(decode(STRING, &[]), Ok(s("")));
        assert_eq!(decode(NUMBER, &[]), Ok(n("")));
        assert_eq!(decode(BINARY, &[]), Ok(b(&[])));
        assert_eq!(
            decode(BOOLEAN, &[]).unwrap_err(),
            "Boolean Structured Data has more than one byte"
        );
        for t in [STRING_SET, NUMBER_SET, BINARY_SET] {
            assert_eq!(
                decode(t, &[]).unwrap_err(),
                "Set Structured Data has less than LENGTH_LEN bytes"
            );
        }
        for t in [MAP, LIST] {
            assert_eq!(
                decode(t, &[]).unwrap_err(),
                "List Structured Data has less than 4 bytes"
            );
        }
    }

    #[test]
    fn bad_type() {
        assert_eq!(
            decode(LIST, &[0, 0, 0, 1, 0, 0, 0, 0, 0, 0]),
            Ok(AttributeValue::L(vec![null()]))
        );
        assert_eq!(
            decode(LIST, &[0, 0, 0, 1, 3, 1, 0, 0, 0, 0]).unwrap_err(),
            "Unsupported TerminalTypeId"
        );

        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#type-id
        //= type=test
        //# Type ID indicates what type a DynamoDB Attribute Value MUST
        //# be serialized and deserialized as.
        assert_eq!(
            decode([9, 9], &[]).unwrap_err(),
            "Unsupported TerminalTypeId"
        );
    }

    #[test]
    fn bad_length_list() {
        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#list-entry-length
        //= type=test
        //# List Entry Length MUST be a big-endian unsigned integer
        //# equal to the length of [List Entry Value](#list-entry-value).
        assert_eq!(
            decode(LIST, &[0, 0, 0, 1, 0, 3, 0, 0, 0, 2, 1]).unwrap_err(),
            "Out of bytes reading Content of List element"
        );
        assert_eq!(
            decode(LIST, &[0, 0, 0, 1, 0xff, 0xff, 0, 0, 0, 2, 1, 2]),
            Ok(AttributeValue::L(vec![b(&[1, 2])]))
        );
        assert_eq!(
            decode(LIST, &[0, 0, 0, 1, 0, 3, 0, 0, 0, 2, 1, 2, 3]).unwrap_err(),
            "Unsupported TerminalTypeId"
        );
        assert_eq!(
            decode(LIST, &[0, 0, 0, 1, 0xff, 0xff, 0, 0, 0, 2, 1, 2, 3]).unwrap_err(),
            "Mismatch between length of encoded data and length of data"
        );
    }

    #[test]
    fn bad_length_map() {
        let key = [0, 1, 0, 0, 0, 4, K, E, Y, A];
        let with = |tail: &[u8]| [&[0, 0, 0, 1][..], &key, tail].concat();

        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#value-length
        //= type=test
        //# Value Length MUST be a big-endian unsigned integer
        //# equal to the length of [Map Value](#map-value).
        assert_eq!(
            decode(MAP, &with(&[0xff, 0xff, 0, 0, 0, 5, 1, 2, 3, 4])).unwrap_err(),
            "Structured Data has too few bytes"
        );
        assert_eq!(
            decode(MAP, &with(&[0xff, 0xff, 0, 0, 0, 5, 1, 2, 3, 4, 5])),
            Ok(m(&[("keyA", b(&[1, 2, 3, 4, 5]))]))
        );
        assert_eq!(
            decode(MAP, &with(&[0, 3, 0, 0, 0, 5, 1, 2, 3, 4, 5, 6])).unwrap_err(),
            "Unsupported TerminalTypeId"
        );
        assert_eq!(
            decode(MAP, &with(&[0xff, 0xff, 0, 0, 0, 5, 1, 2, 3, 4, 5, 6])).unwrap_err(),
            "Mismatch between length of encoded data and length of data"
        );
    }

    #[test]
    fn bad_dup_keys() {
        // Key Type, Key Length, Map Key "key<last>", Value Type, Value Length, then Map Value.
        let entry = |last: u8| {
            [
                0, 1, 0, 0, 0, 4, K, E, Y, last, 0xff, 0xff, 0, 0, 0, 5, 1, 2, 3, 4, 5,
            ]
        };
        let two = |a: u8, bb: u8| [&[0, 0, 0, 2][..], &entry(a), &entry(bb)].concat();
        assert_eq!(
            decode(MAP, &two(A, B)),
            Ok(m(&[
                ("keyA", b(&[1, 2, 3, 4, 5])),
                ("keyB", b(&[1, 2, 3, 4, 5]))
            ]))
        );

        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#key-value-pair-entries
        //= type=test
        //# This sequence MUST NOT contain duplicate [Map Keys](#map-key).
        //
        //= spec/dynamodb-encryption-client/ddb-item-conversion.md#duplicates
        //= type=test
        //# - Conversion from a Structured Data Map MUST fail if it has duplicate keys
        assert_eq!(
            decode(MAP, &two(A, A)).unwrap_err(),
            "Duplicate key in map."
        );

        let distinct = [
            &[0, 0, 0, 2][..],         // Set Count
            &[0, 0, 0, 3, 49, 50, 51], // Set Entry Length, Set Entry Value "123"
            &[0, 0, 0, 3, 52, 53, 54], // Set Entry Length, Set Entry Value "456"
        ]
        .concat();
        let dup = [
            &[0, 0, 0, 2][..],         // Set Count
            &[0, 0, 0, 3, 49, 50, 51], // Set Entry Length, Set Entry Value "123"
            &[0, 0, 0, 3, 49, 50, 51], // Set Entry Length, Set Entry Value "123"
        ]
        .concat();
        assert_eq!(decode(BINARY_SET, &distinct), Ok(bs(&[b"123", b"456"])));

        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#set-entries
        //= type=test
        //# Binary Sets MUST NOT contain duplicate entries.
        //
        //= spec/dynamodb-encryption-client/ddb-item-conversion.md#duplicates
        //= type=test
        //# - Conversion from a Structured Data Binary Set MUST fail if it has duplicate values
        assert_eq!(
            decode(BINARY_SET, &dup).unwrap_err(),
            "Binary set values must not have duplicates"
        );
        assert_eq!(decode(NUMBER_SET, &distinct), Ok(ns(&["123", "456"])));

        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#set-entries
        //= type=test
        //# Number Sets MUST NOT contain duplicate entries.
        //
        //= spec/dynamodb-encryption-client/ddb-item-conversion.md#duplicates
        //= type=test
        //# - Conversion from a Structured Data Number Set MUST fail if it has duplicate values
        assert_eq!(
            decode(NUMBER_SET, &dup).unwrap_err(),
            "Number set values must not have duplicates"
        );
        assert_eq!(decode(STRING_SET, &distinct), Ok(ss(&["123", "456"])));

        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#set-entries
        //= type=test
        //# String Sets MUST NOT contain duplicate entries.
        //
        //= spec/dynamodb-encryption-client/ddb-item-conversion.md#duplicates
        //= type=test
        //# - Conversion from a Structured Data String Set MUST fail if it has duplicate values
        assert_eq!(
            decode(STRING_SET, &dup).unwrap_err(),
            "String set values must not have duplicates"
        );
    }

    #[test]
    fn type_ids() {
        for (attr, type_id) in [
            (null(), [0x00, 0x00]),
            (s("a"), [0x00, 0x01]),
            (n("1"), [0x00, 0x02]),
            (b(&[1]), [0xFF, 0xFF]),
            (AttributeValue::Bool(true), [0x00, 0x04]),
            (ss(&["a"]), [0x01, 0x01]),
            (ns(&["1"]), [0x01, 0x02]),
            (bs(&[&[1]]), [0x01, 0xFF]),
            (m(&[("a", null())]), [0x02, 0x00]),
            (AttributeValue::L(vec![null()]), [0x03, 0x00]),
        ] {
            let t = attr_to_terminal(&attr).unwrap();

            //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#type-id
            //= type=test
            //# Type ID indicates what type a DynamoDB Attribute Value MUST
            //# be serialized and deserialized as.
            assert_eq!((t.type_id, terminal_to_attr(&t).unwrap()), (type_id, attr));
        }
    }

    #[test]
    fn encode_scalars_and_sets() {
        check_encode(&s("abc"), STRING, &[97, 98, 99], &s("abc"));

        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#string
        //= type=test
        //# String MUST be serialized as UTF-8 encoded bytes.
        check_encode(&s("\u{e9}"), STRING, &[0xC3, 0xA9], &s("\u{e9}"));

        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#number
        //= type=test
        //# This normalized value MUST then be serialized as UTF-8 encoded bytes.
        check_encode(&n("123"), NUMBER, &[49, 50, 51], &n("123"));

        let number_set = ns(&["123", "45"]);
        let number_set_bytes = [
            &[0, 0, 0, 2][..],         // Set Count
            &[0, 0, 0, 3, 49, 50, 51], // Set Entry Length, Set Entry Value "123"
            &[0, 0, 0, 2, 52, 53],     // Set Entry Length, Set Entry Value "45"
        ]
        .concat();
        check_encode(&number_set, NUMBER_SET, &number_set_bytes, &number_set);

        let string_set = ss(&["abc", "de"]);
        let string_set_bytes = [
            &[0, 0, 0, 2][..],         // Set Count
            &[0, 0, 0, 3, 97, 98, 99], // Set Entry Length, Set Entry Value
            &[0, 0, 0, 2, 100, 101],   // Set Entry Length, Set Entry Value
        ]
        .concat();

        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#set
        //= type=test
        //# A Set MUST be serialized as:
        //
        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#set-count
        //= type=test
        //# Set Count MUST be a big-endian unsigned integer
        //# equal to the number of serialized entries in
        //# [Set Entries](#set-entries).
        //
        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#set-entries
        //= type=test
        //# Each of these entries MUST be serialized as:
        //
        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#set-entry-length
        //= type=test
        //# Set Entry Length MUST be a big-endian unsigned integer
        //# equal to the length of [Set Entry Value](#set-entry-value).
        check_encode(&string_set, STRING_SET, &string_set_bytes, &string_set);

        let binary_set = bs(&[&[1, 2, 3], &[4, 5]]);
        let binary_set_bytes = [
            &[0, 0, 0, 2][..],      // Set Count
            &[0, 0, 0, 3, 1, 2, 3], // Set Entry Length, Set Entry Value [1, 2, 3]
            &[0, 0, 0, 2, 4, 5],    // Set Entry Length, Set Entry Value [4, 5]
        ]
        .concat();
        check_encode(&binary_set, BINARY_SET, &binary_set_bytes, &binary_set);

        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#binary
        //= type=test
        //# Binary MUST be serialized with the identity function;
        //# or more plainly, Binary Attribute Values are used as is.
        check_encode(
            &b(&[1, 2, 3, 4, 5]),
            BINARY,
            &[1, 2, 3, 4, 5],
            &b(&[1, 2, 3, 4, 5]),
        );

        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#null
        //= type=test
        //# Null MUST be serialized as a zero-length byte string.
        check_encode(&null(), NULL, &[], &null());

        let (f, t) = (AttributeValue::Bool(false), AttributeValue::Bool(true));

        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#boolean
        //= type=test
        //# Boolean MUST be serialized as:
        check_encode(&f, BOOLEAN, &[0x00], &f);
        check_encode(&t, BOOLEAN, &[0x01], &t);
    }

    #[test]
    fn empty_collections() {
        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#set-count
        //= type=test
        //# Set Count MAY be `0`,
        //# in which case [Set Entries](#set-entries) is a zero-length byte string.
        check_encode(&ss(&[]), STRING_SET, &[0, 0, 0, 0], &ss(&[]));

        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#key-value-pair-count
        //= type=test
        //# Key Value Pair Count MAY be `0`,
        //# in which case [Key Value Pair Entries](#key-value-pair-entries) is an empty bytestring.
        check_encode(&m(&[]), MAP, &[0, 0, 0, 0], &m(&[]));

        let empty_list = AttributeValue::L(vec![]);

        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#list-count
        //= type=test
        //# List Count MAY be `0`,
        //# in which case [List Entries](#list-entries) is an empty byte string.
        check_encode(&empty_list, LIST, &[0, 0, 0, 0], &empty_list);
    }

    #[test]
    fn encode_list_and_map() {
        let binary = b(&[1, 2, 3, 4, 5]);
        let boolean = AttributeValue::Bool(false);
        let list = AttributeValue::L(vec![binary.clone(), null(), boolean.clone()]);
        // Each entry is its List Entry Type, List Entry Length, then List Entry Value.
        let list_bytes = [
            &[0, 0, 0, 3][..],                        // List Count
            &[0xff, 0xff, 0, 0, 0, 5, 1, 2, 3, 4, 5], // binary
            &[0, 0, 0, 0, 0, 0],                      // null
            &[0, 4, 0, 0, 0, 1, 0],                   // boolean
        ]
        .concat();

        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#list
        //= type=test
        //# List MUST be serialized as:
        //
        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#list-count
        //= type=test
        //# List Count MUST be a big-endian unsigned integer
        //# equal to the number of serialized list entries in
        //# [List Entries](#list-entries).
        //
        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#list-entries
        //= type=test
        //# Each list entry in the sequence MUST be serialized as:
        //
        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#list-entries
        //= type=test
        //# The order of these serialized list entries MUST match
        //# the order of the entries in the original list.
        //
        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#list-entry-type
        //= type=test
        //# List Entry Type MUST be the [Type ID](#type-id) of the type of [List Entry Value](#list-entry-value).
        //
        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#list-entry-length
        //= type=test
        //# List Entry Length MUST be a big-endian unsigned integer
        //# equal to the length of [List Entry Value](#list-entry-value).
        //
        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#list-entry-value
        //= type=test
        //# A List MAY hold any DynamoDB Attribute Value data type,
        //# and MAY hold values of different types.
        check_encode(&list, LIST, &list_bytes, &list);

        let map = m(&[
            ("keyA", binary),
            ("keyB", null()),
            ("keyC", boolean),
            ("keyD", list),
        ]);
        // Each entry is its Key Type, Key Length, Map Key, Value Type, Value Length, then Map Value.
        let map_bytes = [
            &[0, 0, 0, 4][..], // Key Value Pair Count
            &[
                0, 1, 0, 0, 0, 4, K, E, Y, A, 0xff, 0xff, 0, 0, 0, 5, 1, 2, 3, 4, 5,
            ],
            &[0, 1, 0, 0, 0, 4, K, E, Y, B, 0, 0, 0, 0, 0, 0],
            &[0, 1, 0, 0, 0, 4, K, E, Y, C, 0, 4, 0, 0, 0, 1, 0],
            &[0, 1, 0, 0, 0, 4, K, E, Y, D, 3, 0, 0, 0, 0, 28],
            &list_bytes,
        ]
        .concat();

        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#map-attribute
        //= type=test
        //# Map MUST be serialized as:
        //
        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#key-value-pair-count
        //= type=test
        //# Key Value Pair Count MUST be a big-endian unsigned integer
        //# equal to the number of serialized key-value pairs in
        //# [Key Value Pair Entries](#key-value-pair-entries).
        //
        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#key-value-pair-entries
        //= type=test
        //# Each key-value pair MUST be serialized as:
        //
        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#key-type
        //= type=test
        //# Key Type MUST be the [Type ID](#type-id) for Strings.
        //
        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#value-type
        //= type=test
        //# Value Type MUST be the [Type ID](#type-id) of the type of [Map Value](#map-value).
        //
        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#value-length
        //= type=test
        //# Value Length MUST be a big-endian unsigned integer
        //# equal to the length of [Map Value](#map-value).
        //
        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#map-value
        //= type=test
        //# Map Value MUST be a [Value](#value).
        //
        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#map-value
        //= type=test
        //# A Map MAY hold any DynamoDB Attribute Value data type,
        //# and MAY hold values of different types.
        check_encode(&map, MAP, &map_bytes, &map);
    }

    #[test]
    fn numbers_are_normalized() {
        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#number
        //= type=test
        //# This value MUST be normalized in the same way as DynamoDB normalizes numbers.
        check_encode(&n("000123.000"), NUMBER, &[49, 50, 51], &n("123"));
        assert_eq!(top_level_attr_to_bytes(&n("000123.000")).unwrap(), b"123");
        check_encode(
            &ns(&["001.00"]),
            NUMBER_SET,
            &[0, 0, 0, 1, 0, 0, 0, 1, 49],
            &ns(&["1"]),
        );
        check_encode(
            &AttributeValue::L(vec![n("001.00")]),
            LIST,
            &[0, 0, 0, 1, 0, 2, 0, 0, 0, 1, 49],
            &AttributeValue::L(vec![n("1")]),
        );
        check_encode(
            &m(&[("keyA", n("001.00"))]),
            MAP,
            &[
                0, 0, 0, 1, 0, 1, 0, 0, 0, 4, K, E, Y, A, 0, 2, 0, 0, 0, 1, 49,
            ],
            &m(&[("keyA", n("1"))]),
        );
    }

    const SORTED_NS: [u8; 20] = [
        0, 0, 0, 3, // Set Count
        0, 0, 0, 1, 49, // Set Entry Length, Set Entry Value "1"
        0, 0, 0, 2, 49, 48, // Set Entry Length, Set Entry Value "10"
        0, 0, 0, 1, 50, // Set Entry Length, Set Entry Value "2"
    ];
    // UTF-8 bytes, in UTF-16 order: "&", "\u{10002}", "\u{FF61}".
    const SORTED_SS: [u8; 24] = [
        0, 0, 0, 3, 0, 0, 0, 1, 0x26, 0, 0, 0, 4, 0xF0, 0x90, 0x80, 0x82, 0, 0, 0, 3, 0xEF, 0xBD,
        0xA1,
    ];
    const SORTED_BS: [u8; 20] = [
        0, 0, 0, 3, // Set Count
        0, 0, 0, 1, 1, // Set Entry Length, Set Entry Value [1]
        0, 0, 0, 2, 1, 0, // Set Entry Length, Set Entry Value [1, 0]
        0, 0, 0, 1, 2, // Set Entry Length, Set Entry Value [2]
    ];

    #[test]
    fn sets_are_sorted() {
        let sorted_ns = ns(&["1", "10", "2"]);

        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#set-entries
        //= type=test
        //# Entries in a Number Set MUST be ordered in ascending [UTF-16 binary order](./string-ordering.md#utf-16-binary-order).
        check_encode(&ns(&["1", "2", "10"]), NUMBER_SET, &SORTED_NS, &sorted_ns);

        // "02" sorts before "1" unless it is normalized to "2" first.

        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#set-entries
        //= type=test
        //# This ordering MUST be applied after normalization of the number value.
        check_encode(&ns(&["1", "02", "10"]), NUMBER_SET, &SORTED_NS, &sorted_ns);

        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#set-entries
        //= type=test
        //# Entries in a String Set MUST be ordered in ascending [UTF-16 binary order](./string-ordering.md#utf-16-binary-order).
        check_encode(
            &ss(&[AMP, HALFWIDTH_STOP, LINEAR_B]),
            STRING_SET,
            &SORTED_SS,
            &ss(&[AMP, LINEAR_B, HALFWIDTH_STOP]),
        );

        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#set-entries
        //= type=test
        //# Entries in a Binary Set MUST be ordered lexicographically by their underlying bytes in ascending order.
        check_encode(
            &bs(&[&[1], &[2], &[1, 0]]),
            BINARY_SET,
            &SORTED_BS,
            &bs(&[&[1], &[1, 0], &[2]]),
        );
    }

    #[test]
    fn sets_in_list_are_sorted() {
        let list = AttributeValue::L(vec![
            ns(&["2", "1", "10"]),
            ss(&[AMP, HALFWIDTH_STOP, LINEAR_B]),
            bs(&[&[1, 0], &[1], &[2]]),
        ]);
        let bytes = [
            &[0, 0, 0, 3, 1, 2, 0, 0, 0, 20][..],
            &SORTED_NS,
            &[1, 1, 0, 0, 0, 24],
            &SORTED_SS,
            &[1, 0xFF, 0, 0, 0, 20],
            &SORTED_BS,
        ]
        .concat();
        let sorted = AttributeValue::L(vec![
            ns(&["1", "10", "2"]),
            ss(&[AMP, LINEAR_B, HALFWIDTH_STOP]),
            bs(&[&[1], &[1, 0], &[2]]),
        ]);
        check_encode(&list, LIST, &bytes, &sorted);
    }

    #[test]
    fn sets_in_map_are_sorted() {
        let map = m(&[
            ("keyA", ss(&[AMP, HALFWIDTH_STOP, LINEAR_B])),
            ("keyB", ns(&["2", "1", "10"])),
            ("keyC", bs(&[&[1, 0], &[1], &[2]])),
        ]);
        let bytes = [
            &[0, 0, 0, 3, 0, 1, 0, 0, 0, 4, K, E, Y, A, 1, 1, 0, 0, 0, 24][..],
            &SORTED_SS,
            &[0, 1, 0, 0, 0, 4, K, E, Y, B, 1, 2, 0, 0, 0, 20],
            &SORTED_NS,
            &[0, 1, 0, 0, 0, 4, K, E, Y, C, 1, 0xFF, 0, 0, 0, 20],
            &SORTED_BS,
        ]
        .concat();
        let sorted = m(&[
            ("keyA", ss(&[AMP, LINEAR_B, HALFWIDTH_STOP])),
            ("keyB", ns(&["1", "10", "2"])),
            ("keyC", bs(&[&[1], &[1, 0], &[2]])),
        ]);
        check_encode(&map, MAP, &bytes, &sorted);
    }

    #[test]
    fn map_keys_are_sorted_by_utf16() {
        let map = m(&[(AMP, null()), (HALFWIDTH_STOP, null()), (LINEAR_B, null())]);
        // Each entry is its Key Type, Key Length, Map Key, then a Null's Value Type and Value Length.
        let bytes = [
            &[0, 0, 0, 3][..],                           // Key Value Pair Count
            &[0, 1, 0, 0, 0, 1, 0x26, 0, 0, 0, 0, 0, 0], // "&"
            &[0, 1, 0, 0, 0, 4, 0xF0, 0x90, 0x80, 0x82, 0, 0, 0, 0, 0, 0], // "\u{10002}"
            &[0, 1, 0, 0, 0, 3, 0xEF, 0xBD, 0xA1, 0, 0, 0, 0, 0, 0], // "\u{FF61}"
        ]
        .concat();

        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#key-value-pair-entries
        //= type=test
        //# Entries in a serialized Map MUST be ordered by key value,
        //# ordered in ascending [UTF-16 binary order](./string-ordering.md#utf-16-binary-order).
        //
        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#map-key
        //= type=test
        //# Map Key MUST be a [String Value](#string).
        check_encode(&map, MAP, &bytes, &map);
    }

    fn round_trip(item: &Item) -> Item {
        item_to_structured(item, &HashMap::new())
            .unwrap()
            .iter()
            .map(|(k, t)| (k.clone(), terminal_to_attr(t).unwrap()))
            .collect()
    }

    #[test]
    fn item_round_trip() {
        // Set and number values are pre-normalized and pre-sorted.
        let val1 = s("astring");
        let val2 = n("12345");
        let val3 = b(&[1, 2, 3, 4, 5]);
        let val4 = AttributeValue::Bool(true);
        let val5 = null();
        let val6 = bs(&[&[1, 2, 3, 4, 5], &[2, 3, 4, 5, 6], &[3, 4, 5, 6, 7]]);
        let val7 = ss(&["ab", "cdef", "ghijk"]);
        let val8 = ns(&["0", "1", "234.567"]);
        let val9 = AttributeValue::L(vec![
            AttributeValue::L(vec![val8.clone(), val7.clone(), val6.clone()]),
            AttributeValue::L(vec![val5.clone(), val4.clone(), val3.clone()]),
            AttributeValue::L(vec![val2.clone(), val1.clone()]),
        ]);
        let fields = [
            ("key1", val1),
            ("key2", val2),
            ("key3", val3),
            ("key4", val4),
            ("key5", val5),
            ("key6", val6),
            ("key7", val7),
            ("key8", val8),
            ("key9", val9),
        ];
        let mut item: Item = fields
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect();
        item.insert("key10".to_owned(), m(&fields));
        assert_eq!(round_trip(&item), item);
    }

    /// "hello" nested in `levels` alternating maps and lists.
    fn nested(levels: u64) -> AttributeValue {
        (0..levels).fold(s("hello"), |v, i| {
            if i % 2 == 0 {
                m(&[("key", v)])
            } else {
                AttributeValue::L(vec![v])
            }
        })
    }

    #[test]
    fn max_depth() {
        let item: Item = [("key1".to_owned(), nested(MAX_STRUCTURE_DEPTH - 1))].into();
        assert_eq!(round_trip(&item), item);
    }

    #[test]
    fn too_deep() {
        let item: Item = [("key1".to_owned(), nested(MAX_STRUCTURE_DEPTH))].into();
        assert_eq!(
            item_to_structured(&item, &HashMap::new()).unwrap_err(),
            "Depth of attribute structure to serialize exceeds limit of 32"
        );
    }

    /// The bytes of "hello" nested in `levels` lists, as the encoder would write them.
    fn nested_list_bytes(levels: u64) -> Vec<u8> {
        let (mut type_id, mut value) = (STRING, b"hello".to_vec());
        for _ in 0..levels {
            let mut list = vec![0, 0, 0, 1];
            list.extend_from_slice(&type_id);
            list.extend_from_slice(&u32_be(value.len()).unwrap());
            list.extend_from_slice(&value);
            (type_id, value) = (LIST, list);
        }
        value
    }

    #[test]
    fn too_deep_to_decode() {
        let ok = (0..MAX_STRUCTURE_DEPTH - 1).fold(s("hello"), |v, _| AttributeValue::L(vec![v]));
        assert_eq!(
            decode(LIST, &nested_list_bytes(MAX_STRUCTURE_DEPTH - 1)),
            Ok(ok)
        );
        assert_eq!(
            decode(LIST, &nested_list_bytes(MAX_STRUCTURE_DEPTH)).unwrap_err(),
            "Depth of attribute structure to deserialize exceeds limit of 32"
        );
    }

    #[test]
    fn attribute_name_length_is_bytes() {
        // 40000 two-byte characters are 80000 UTF-8 bytes, over the 65535-byte limit.
        let long_key = "\u{e9}".repeat(40_000);
        let err = attr_to_terminal(&m(&[(&long_key, AttributeValue::Bool(true))])).unwrap_err();
        assert_eq!(
            err,
            "Attribute name must be between 1 and 65535 UTF-8 bytes"
        );
        let err = attr_to_terminal(&m(&[("", null())])).unwrap_err();
        assert_eq!(
            err,
            "Attribute name must be between 1 and 65535 UTF-8 bytes"
        );
        let max_key = "A".repeat(MAX_ATTR_NAME_LEN);
        let map = m(&[(&max_key, null())]);

        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#key-length
        //= type=test
        //# Key Length MUST be a non-zero big-endian unsigned integer
        //# equal to the length of [Map Key](#map-key).
        check_encode(
            &map,
            MAP,
            &[
                &[0, 0, 0, 1, 0, 1, 0, 0, 0xff, 0xff][..],
                max_key.as_bytes(),
                &[0, 0, 0, 0, 0, 0],
            ]
            .concat(),
            &map,
        );
    }

    #[test]
    fn decode_attribute_name_too_long() {
        // A key length of 65536 with that many key bytes present, so the length check fails.
        let map_bytes = [
            &[0, 0, 0, 1, 0, 1, 0, 1, 0, 0][..],
            &vec![0x41; 65_536],
            &[0, 1, 0, 0, 0, 0],
        ]
        .concat();
        assert_eq!(
            decode(MAP, &map_bytes).unwrap_err(),
            "Attribute name must be between 1 and 65535 UTF-8 bytes"
        );

        // A key length of 0.

        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#key-length
        //= type=test
        //# Key Length MUST be a non-zero big-endian unsigned integer
        //# equal to the length of [Map Key](#map-key).
        assert_eq!(
            decode(MAP, &[0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap_err(),
            "Attribute name must be between 1 and 65535 UTF-8 bytes"
        );
    }

    #[test]
    fn encode_rejects_duplicate_set_values() {
        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#set-entries
        //= type=test
        //# String Sets MUST NOT contain duplicate entries.
        assert_eq!(
            attr_to_terminal(&ss(&["a", "a"])).unwrap_err(),
            "String Set had duplicate values"
        );
        assert_eq!(
            attr_to_terminal(&ns(&["1", "1"])).unwrap_err(),
            "Number Set had duplicate values"
        );

        // "1" and "01" are distinct strings but the same normalized number.

        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#set-entries
        //= type=test
        //# Number Sets MUST NOT contain duplicate entries.
        assert_eq!(
            attr_to_terminal(&ns(&["1", "01"])).unwrap_err(),
            "Number Set had duplicate values after normalization."
        );

        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#set-entries
        //= type=test
        //# Binary Sets MUST NOT contain duplicate entries.
        assert_eq!(
            attr_to_terminal(&bs(&[&[1], &[1]])).unwrap_err(),
            "Binary Set had duplicate values"
        );
        assert_eq!(
            attr_to_terminal(&ns(&["1", "x"])).unwrap_err(),
            "Number needs digits either before or after the decimal point. when parsing 'x'."
        );
        assert_eq!(
            attr_to_terminal(&n("")).unwrap_err(),
            "An empty string is not a valid number. when parsing ''."
        );
    }

    #[test]
    fn decode_rejects_malformed_terminals() {
        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#null
        //= type=test
        //# Null MUST be serialized as a zero-length byte string.
        assert_eq!(
            decode(NULL, &[1]).unwrap_err(),
            "NULL type did not have length zero"
        );

        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#string
        //= type=test
        //# String MUST be serialized as UTF-8 encoded bytes.
        assert_eq!(decode(STRING, &[0xff]).unwrap_err(), "Invalid UTF-8");

        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#boolean
        //= type=test
        //# Boolean MUST be serialized as:
        assert_eq!(
            decode(BOOLEAN, &[2]).unwrap_err(),
            "Boolean Structured Data had inappropriate value"
        );

        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#key-type
        //= type=test
        //# Key Type MUST be the [Type ID](#type-id) for Strings.
        assert_eq!(
            decode(MAP, &[0, 0, 0, 1, 0, 2, 0, 0, 0, 1, 0x61]).unwrap_err(),
            "Key of Map is not String"
        );

        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#map-key
        //= type=test
        //# Map Key MUST be a [String Value](#string).
        assert_eq!(
            decode(MAP, &[0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0xff, 0, 0, 0, 0, 0, 0]).unwrap_err(),
            "Invalid UTF-8"
        );

        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#number
        //= type=test
        //# This normalized value MUST then be serialized as UTF-8 encoded bytes.
        assert_eq!(decode(NUMBER, &[0xff]).unwrap_err(), "Invalid UTF-8");

        // A Map Count of 1 with no bytes left for the pair's Key Type and Key Length.

        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#key-value-pair-entries
        //= type=test
        //# Each key-value pair MUST be serialized as:
        assert_eq!(
            decode(MAP, &[0, 0, 0, 1]).unwrap_err(),
            "Out of bytes reading Map Key"
        );

        // A Set Entry Length of 2 with only 1 byte of Set Entry Value.

        //= spec/dynamodb-encryption-client/ddb-attribute-serialization.md#set-entry-length
        //= type=test
        //# Set Entry Length MUST be a big-endian unsigned integer
        //# equal to the length of [Set Entry Value](#set-entry-value).
        assert_eq!(
            decode(BINARY_SET, &[0, 0, 0, 1, 0, 0, 0, 2, 1]).unwrap_err(),
            "Binary Set Structured Data has too few bytes"
        );

        // Truncated or length-mismatched Boolean, Set, Map and List values: every field their
        // layouts declare must be present, and no bytes may be left over.
        for (type_id, value, msg) in [
            (
                BOOLEAN,
                &[0, 1][..],
                "Boolean Structured Data has more than one byte",
            ),
            (STRING_SET, &[0, 0, 0, 1], "Out of bytes reading String Set"),
            (NUMBER_SET, &[0, 0, 0, 1], "Out of bytes reading String Set"),
            (
                STRING_SET,
                &[0, 0, 0, 1, 0, 0, 0, 2, 0x61],
                "String Set Structured Data has too few bytes",
            ),
            (STRING_SET, &[0, 0, 0, 1, 0, 0, 0, 1, 0xff], "Invalid UTF-8"),
            (
                NUMBER_SET,
                &[0, 0, 0, 1, 0, 0, 0, 2, 0x31],
                "Number Set Structured Data has too few bytes",
            ),
            (
                BINARY_SET,
                &[0, 0, 0, 1, 0, 0],
                "Out of bytes reading Binary Set",
            ),
            (
                STRING_SET,
                &[0, 0, 0, 0, 7],
                "Mismatch between length of encoded data and length of data",
            ),
            (
                MAP,
                &[0, 0, 0, 1, 0, 1, 0, 0, 0, 9, 0x61],
                "Key of Map of Structured Data has too few bytes",
            ),
            (
                MAP,
                &[0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0x61, 0],
                "Out of bytes reading Map Value",
            ),
            (
                MAP,
                &[0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0x61, 0, 0, 0, 0],
                "Length of 4-byte integer was less than 4",
            ),
            (
                LIST,
                &[0, 0, 0, 1, 0, 0],
                "Out of bytes reading Type of List element",
            ),
        ] {
            assert_eq!(
                decode(type_id, value).unwrap_err(),
                msg,
                "{type_id:?} {value:?}"
            );
        }
    }

    fn actions(x: &[(&str, CryptoAction)]) -> HashMap<String, CryptoAction> {
        x.iter().map(|(k, v)| ((*k).to_owned(), *v)).collect()
    }
    fn item(x: &[(&str, AttributeValue)]) -> Item {
        x.iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect()
    }

    #[test]
    fn item_to_structured_skips_do_nothing_unless_reserved() {
        let it = item(&[
            ("a", s("x")),
            ("b", n("1")),
            ("aws_dbe_x", s("r")),
            ("c", n("02")),
            ("bad", n("not a number")),
        ]);
        let acts = actions(&[
            ("a", CryptoAction::EncryptAndSign),
            ("b", CryptoAction::DoNothing),
            ("aws_dbe_x", CryptoAction::DoNothing),
            ("bad", CryptoAction::DoNothing),
        ]);
        let expected: HashMap<String, Terminal> = [
            ("a".to_owned(), Terminal::new(STRING, b"x".to_vec())),
            ("aws_dbe_x".to_owned(), Terminal::new(STRING, b"r".to_vec())),
            ("c".to_owned(), Terminal::new(NUMBER, b"2".to_vec())),
        ]
        .into();
        assert_eq!(item_to_structured(&it, &acts).unwrap(), expected);
    }

    #[test]
    fn item_to_structured_reports_every_error() {
        let it = item(&[
            ("x", n("1a1")),
            ("y", ss(&["a", "a"])),
            ("z", ss(&["b", "b"])),
        ]);
        assert_eq!(
            item_to_structured(&it, &HashMap::new()).unwrap_err(),
            "Invalid Character in number at 'a1'. when parsing '1a1'.\nString Set had duplicate values"
        );
    }

    #[test]
    fn structured_to_item_encrypt_replaces_encrypted_and_adds_new() {
        let orig = item(&[
            ("a", s("plain")),
            ("b", n("1")),
            ("c", s("dn")),
            ("aws_dbe_old", s("x")),
        ]);
        let acts = actions(&[
            ("a", CryptoAction::EncryptAndSign),
            ("b", CryptoAction::SignOnly),
            ("c", CryptoAction::DoNothing),
        ]);
        let mut st: HashMap<String, Terminal> = [
            ("a".to_owned(), Terminal::new(BINARY, vec![9, 9])),
            ("b".to_owned(), Terminal::new(NUMBER, b"5".to_vec())),
            ("aws_dbe_head".to_owned(), Terminal::new(BINARY, vec![1])),
            ("aws_dbe_foot".to_owned(), Terminal::new(BINARY, vec![2])),
        ]
        .into();

        //= spec/dynamodb-encryption-client/ddb-item-conversion.md#convert-structured-data-to-ddb-item
        //= type=test
        //= reason=head and foot terminals appear, a is converted, and only DO_NOTHING c is extra
        //# - MUST contain an Attribute for every [Structured Data Terminal](../structured-encryption/structures.md#structured-data-terminal)
        //# on the Structured Data, and no other Attributes.
        assert_eq!(
            structured_to_item_encrypt(&st, &orig, &acts).unwrap(),
            item(&[
                ("a", b(&[9, 9])),
                ("b", n("1")),
                ("c", s("dn")),
                ("aws_dbe_head", b(&[1])),
                ("aws_dbe_foot", b(&[2])),
            ])
        );

        st.insert("aws_dbe_foot".to_owned(), Terminal::new(NULL, vec![1]));
        assert_eq!(
            structured_to_item_encrypt(&st, &orig, &acts).unwrap_err(),
            "NULL type did not have length zero"
        );
        st.insert("aws_dbe_foot".to_owned(), Terminal::new(BINARY, vec![2]));
        st.insert("a".to_owned(), Terminal::new(BOOLEAN, vec![7]));

        //= spec/dynamodb-encryption-client/ddb-item-conversion.md#convert-structured-data-to-ddb-item
        //= type=test
        //# - Each Attribute MUST be deserializable
        //# according to [the serialization scheme](./ddb-attribute-serialization.md#value).
        assert_eq!(
            structured_to_item_encrypt(&st, &orig, &acts).unwrap_err(),
            "Boolean Structured Data had inappropriate value"
        );
    }

    #[test]
    fn structured_to_item_decrypt_replaces_encrypted_and_drops_reserved() {
        let orig = item(&[("a", b(&[9, 9])), ("b", n("1")), ("aws_dbe_head", b(&[1]))]);
        let acts = actions(&[
            ("a", CryptoAction::EncryptAndSign),
            ("b", CryptoAction::SignOnly),
        ]);
        let mut st: HashMap<String, Terminal> = [
            ("a".to_owned(), Terminal::new(STRING, b"plain".to_vec())),
            ("b".to_owned(), Terminal::new(NUMBER, b"5".to_vec())),
            ("extra".to_owned(), Terminal::new(STRING, b"x".to_vec())),
        ]
        .into();
        assert_eq!(
            structured_to_item_decrypt(&st, &orig, &acts).unwrap(),
            item(&[("a", s("plain")), ("b", n("1"))])
        );

        st.insert("a".to_owned(), Terminal::new(STRING, vec![0xff]));
        assert_eq!(
            structured_to_item_decrypt(&st, &orig, &acts).unwrap_err(),
            "Invalid UTF-8"
        );
    }

    #[test]
    fn item_to_structured_has_one_top_level_terminal_per_attribute() {
        let it = item(&[
            ("str", s("abc")),
            ("num", n("02")),
            ("strs", ss(&["b", "a"])),
            ("map", m(&[("k", n("1"))])),
            ("bool", AttributeValue::Bool(true)),
        ]);
        let out = item_to_structured(&it, &HashMap::new()).unwrap();

        //= spec/dynamodb-encryption-client/ddb-item-conversion.md#convert-ddb-item-to-structured-data
        //= type=test
        //# - MUST contain a [Structured Data Terminal](../structured-encryption/structures.md#structured-data-terminal)
        //# for each attribute on the DynamoDB Item, and no others.
        assert_eq!(
            out.keys().collect::<BTreeSet<_>>(),
            it.keys().collect::<BTreeSet<_>>()
        );

        //= spec/dynamodb-encryption-client/ddb-item-conversion.md#convert-ddb-item-to-structured-data
        //= type=test
        //# - The [Terminal Type ID](../structured-encryption/structures.md#terminal-type-id) for each attribute MUST
        //# be the [Type ID](./ddb-attribute-serialization.md#type-id) of the [serialization](./ddb-attribute-serialization.md) of this Attribute Value.
        for (k, expected) in [
            ("str", STRING),
            ("num", NUMBER),
            ("strs", STRING_SET),
            ("map", MAP),
            ("bool", BOOLEAN),
        ] {
            assert_eq!(out[k].type_id, expected, "{k}");
        }

        //= spec/dynamodb-encryption-client/ddb-item-conversion.md#convert-ddb-item-to-structured-data
        //= type=test
        //# - The [Terminal Value](../structured-encryption/structures.md#terminal-value) for each attribute MUST
        //# be the [Value](./ddb-attribute-serialization.md#type-id) of the [serialization](./ddb-attribute-serialization.md) of this Attribute Value.
        for (k, v) in &it {
            assert_eq!(out[k].value, top_level_attr_to_bytes(v).unwrap(), "{k}");
        }
        // The serialization normalizes "02" to "2", so the value is not the input string.
        assert_eq!(out["num"].value, b"2");

        //= spec/dynamodb-encryption-client/ddb-item-conversion.md#convert-ddb-item-to-structured-data
        //= type=test
        //# - The Structured Data Terminal MUST be located at the top level of the Structured Data,
        //# string indexed by the Attribute Name.
        assert_eq!(
            out.get("str"),
            Some(&Terminal::new(STRING, b"abc".to_vec()))
        );
    }

    #[test]
    fn structured_to_item_rejects_attribute_names_over_65535_chars() {
        let long = "a".repeat(MAX_ATTR_NAME_LEN + 1);
        let too_long: HashMap<String, Terminal> =
            [(long.clone(), Terminal::new(STRING, b"x".to_vec()))].into();
        let expected = format!("Not valid attribute names : {long}");

        //= spec/dynamodb-encryption-client/ddb-item-conversion.md#convert-structured-data-to-ddb-item
        //= type=test
        //# - MUST NOT have any `Key` strings that are invalid DynamoDB AttributeNames, that is, with more than 65535 characters.
        assert_eq!(
            structured_to_item_encrypt(&too_long, &HashMap::new(), &HashMap::new()).unwrap_err(),
            expected
        );
        let orig = item(&[(long.as_str(), s("x"))]);
        assert_eq!(
            structured_to_item_decrypt(&too_long, &orig, &HashMap::new()).unwrap_err(),
            expected
        );

        // At the limit, and counted in UTF-16 code units: 40000 U+00E9 is 80000 UTF-8 bytes.
        for name in ["a".repeat(MAX_ATTR_NAME_LEN), "\u{e9}".repeat(40_000)] {
            let st: HashMap<String, Terminal> =
                [(name.clone(), Terminal::new(STRING, b"x".to_vec()))].into();
            let it = item(&[(name.as_str(), s("x"))]);
            assert_eq!(
                structured_to_item_encrypt(&st, &HashMap::new(), &HashMap::new()).unwrap(),
                it
            );
            assert_eq!(
                structured_to_item_decrypt(&st, &it, &HashMap::new()).unwrap(),
                it
            );
        }
    }

    #[test]
    fn utf16_binary_order() {
        use std::cmp::Ordering::{Greater, Less};

        let mut v = [
            "\u{1F0A1}",
            "&",
            "\u{FF61}",
            "\u{10437}",
            "\u{0409}",
            "\u{10002}",
            "\u{1740}",
        ];
        v.sort_by(|a, b| utf16_cmp(a, b));

        //= spec/dynamodb-encryption-client/string-ordering.md#utf-16-binary-order
        //= type=test
        //# When ordering strings,
        //# these strings MUST be compared according to their UTF-16 encoding,
        //# lexicographically per [UTF-16 code unit](#utf-16-code-unit).
        assert_eq!(
            v,
            [
                "&",
                "\u{0409}",
                "\u{1740}",
                "\u{10002}",
                "\u{10437}",
                "\u{1F0A1}",
                "\u{FF61}",
            ]
        );
        assert_eq!(utf16_cmp("ab", "abc"), Less);

        // Code point order puts U+FF61 first; its UTF-16 0xFF61 is above the high surrogate 0xD800.
        assert_eq!("\u{FF61}".cmp("\u{10002}"), Less);

        //= spec/dynamodb-encryption-client/string-ordering.md#utf-16-binary-order
        //= type=test
        //# UTF-16 code units for [high or low surrogates](#surrogates) MUST be compared individually,
        //# and the [Unicode scalar value](#unicode-scalar-value) represented by a surrogate pair
        //# MUST NOT be compared.
        assert_eq!(utf16_cmp("\u{FF61}", "\u{10002}"), Greater);

        //= spec/dynamodb-encryption-client/string-ordering.md#utf-16-binary-order
        //= type=test
        //# Specifically, the range of characters with Unicode code point U+E000 to U+0xFFFF
        //# (code points representable by 16 bits, but after the surrogate range)
        //# MUST be considered "greater than" any character with a Unicode code point of U+10000 to U+10FFFF.
        for (bmp, supplementary) in [
            ("\u{E000}", "\u{10000}"),
            ("\u{E000}", "\u{10FFFF}"),
            ("\u{FFFF}", "\u{10000}"),
            ("\u{FFFF}", "\u{10FFFF}"),
        ] {
            assert_eq!(utf16_cmp(bmp, supplementary), Greater);
        }
    }
}

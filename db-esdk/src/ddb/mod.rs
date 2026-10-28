// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! DynamoDB attribute values as structured-encryption terminals, and back.

pub(crate) mod filter_expr;
mod number;
pub(crate) mod update_expr;

use std::collections::{BTreeSet, HashMap};

use aws_crypto_mpl::aws_sdk_dynamodb::primitives::Blob;
use aws_crypto_mpl::aws_sdk_dynamodb::types::AttributeValue;

use crate::structured::util::{
    BINARY, BINARY_SET, BOOLEAN, LIST, MAP, NULL, NUMBER, NUMBER_SET, RESERVED_PREFIX, STRING,
    STRING_SET, Terminal, TypeId, utf16_cmp,
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

fn collect_strings(sorted: &[String]) -> Result<Vec<u8>, String> {
    let mut out = u32_be(sorted.len())?.to_vec();
    for s in sorted {
        out.extend_from_slice(&u32_be(s.len())?);
        out.extend_from_slice(s.as_bytes());
    }
    Ok(out)
}

fn string_set_to_bytes(ss: &[String]) -> Result<Vec<u8>, String> {
    if has_duplicates(ss) {
        return Err("String Set had duplicate values".to_owned());
    }
    let mut sorted = ss.to_vec();
    sorted.sort_by(|a, b| utf16_cmp(a, b));
    collect_strings(&sorted)
}

fn number_set_to_bytes(ns: &[String]) -> Result<Vec<u8>, String> {
    if has_duplicates(ns) {
        return Err("Number Set had duplicate values".to_owned());
    }
    let mut norm = ns
        .iter()
        .map(|n| normalize_number(n))
        .collect::<Result<Vec<_>, _>>()?;
    if has_duplicates(&norm) {
        return Err("Number Set had duplicate values after normalization.".to_owned());
    }
    norm.sort_by(|a, b| utf16_cmp(a, b));
    collect_strings(&norm)
}

fn binary_set_to_bytes(bs: &[Blob]) -> Result<Vec<u8>, String> {
    if has_duplicates(bs.iter().map(Blob::as_ref)) {
        return Err("Binary Set had duplicate values".to_owned());
    }
    let mut sorted: Vec<&[u8]> = bs.iter().map(Blob::as_ref).collect();
    sorted.sort_unstable();
    let mut out = u32_be(sorted.len())?.to_vec();
    for b in sorted {
        out.extend_from_slice(&u32_be(b.len())?);
        out.extend_from_slice(b);
    }
    Ok(out)
}

fn serialize_map_item(key: &str, value: &[u8]) -> Result<Vec<u8>, String> {
    if key.is_empty() || key.len() > MAX_ATTR_NAME_LEN {
        return Err("Attribute name must be between 1 and 65535 UTF-8 bytes".to_owned());
    }
    let mut out = STRING.to_vec();
    out.extend_from_slice(&u32_be(key.len())?);
    out.extend_from_slice(key.as_bytes());
    out.extend_from_slice(value);
    Ok(out)
}

fn map_to_bytes(m: &HashMap<String, AttributeValue>, depth: u64) -> Result<Vec<u8>, String> {
    let mut keys: Vec<&String> = m.keys().collect();
    keys.sort_by(|a, b| utf16_cmp(a, b));
    let mut out = u32_be(keys.len())?.to_vec();
    for k in keys {
        let val = attr_to_bytes(&m[k], true, depth + 1)?;
        out.extend_from_slice(&serialize_map_item(k, &val)?);
    }
    Ok(out)
}

fn list_to_bytes(l: &[AttributeValue], depth: u64) -> Result<Vec<u8>, String> {
    let mut out = u32_be(l.len())?.to_vec();
    for v in l {
        out.extend_from_slice(&attr_to_bytes(v, true, depth + 1)?);
    }
    Ok(out)
}

/// The serialized value of `a`; with `prefix`, preceded by its type id and length.
fn attr_to_bytes(a: &AttributeValue, prefix: bool, depth: u64) -> Result<Vec<u8>, String> {
    if depth > MAX_STRUCTURE_DEPTH {
        return Err(format!(
            "Depth of attribute structure to serialize exceeds limit of {MAX_STRUCTURE_DEPTH}"
        ));
    }
    let base = match a {
        AttributeValue::S(s) => s.as_bytes().to_vec(),
        AttributeValue::N(n) => normalize_number(n)?.into_bytes(),
        AttributeValue::B(b) => b.as_ref().to_vec(),
        AttributeValue::Ss(ss) => string_set_to_bytes(ss)?,
        AttributeValue::Ns(ns) => number_set_to_bytes(ns)?,
        AttributeValue::Bs(bs) => binary_set_to_bytes(bs)?,
        AttributeValue::M(m) => map_to_bytes(m, depth)?,
        AttributeValue::L(l) => list_to_bytes(l, depth)?,
        AttributeValue::Null(_) => Vec::new(),
        AttributeValue::Bool(b) => vec![u8::from(*b)],
        _ => return Err("Unsupported AttributeValue type".to_owned()),
    };
    if prefix {
        let mut out = type_id(a)?.to_vec();
        out.extend_from_slice(&u32_be(base.len())?);
        out.extend_from_slice(&base);
        Ok(out)
    } else {
        Ok(base)
    }
}

/// `a` as a terminal.
pub(crate) fn attr_to_terminal(a: &AttributeValue) -> Result<Terminal, String> {
    Ok(Terminal::new(type_id(a)?, attr_to_bytes(a, false, 1)?))
}

/// A value read from serialized bytes, and how many bytes it took.
struct Read {
    val: AttributeValue,
    len: usize,
}

fn read_u32(x: &[u8], pos: usize) -> Result<usize, String> {
    let bytes = x
        .get(pos..pos + LENGTH_LEN)
        .ok_or_else(|| "Length of 4-byte integer was less than 4".to_owned())?;
    let n = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    usize::try_from(n).map_err(|_| "Length was too big".to_owned())
}

fn utf8(bytes: &[u8]) -> Result<String, String> {
    String::from_utf8(bytes.to_vec()).map_err(|_| "Invalid UTF-8".to_owned())
}

/// Read `count` length-prefixed strings from `data`.
fn read_strings(data: &[u8], count: usize, kind: &str) -> Result<(Vec<String>, usize), String> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    for _ in 0..count {
        if data.len() - pos < LENGTH_LEN {
            return Err("Out of bytes reading String Set".to_owned());
        }
        let len = read_u32(data, pos)?;
        pos += LENGTH_LEN;
        if data.len() - pos < len {
            return Err(format!("{kind} Set Structured Data has too few bytes"));
        }
        out.push(utf8(&data[pos..pos + len])?);
        pos += len;
    }
    Ok((out, pos))
}

fn bytes_to_attr(
    value: &[u8],
    type_id: TypeId,
    total: Option<usize>,
    depth: u64,
    pos: usize,
) -> Result<Read, String> {
    if depth > MAX_STRUCTURE_DEPTH {
        return Err(format!(
            "Depth of attribute structure to deserialize exceeds limit of {MAX_STRUCTURE_DEPTH}"
        ));
    }
    let (len, pos, length_bytes) = match total {
        None => (read_u32(value, pos)?, pos + LENGTH_LEN, LENGTH_LEN),
        Some(t) => (t, pos, 0),
    };
    if value.len().saturating_sub(pos) < len || pos > value.len() {
        return Err("Structured Data has too few bytes".to_owned());
    }
    let body = &value[pos..pos + len];
    let read = |val, n| Read {
        val,
        len: n + length_bytes,
    };
    match type_id {
        NULL => {
            if len != 0 {
                return Err("NULL type did not have length zero".to_owned());
            }
            Ok(read(AttributeValue::Null(true), 0))
        }
        STRING => Ok(read(AttributeValue::S(utf8(body)?), len)),
        NUMBER => Ok(read(AttributeValue::N(utf8(body)?), len)),
        BINARY => Ok(read(AttributeValue::B(Blob::new(body)), len)),
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
            let count = read_u32(rest, 0)?;
            let items = &rest[LENGTH_LEN..];
            match type_id {
                STRING_SET => {
                    let (ss, n) = read_strings(items, count, "String")?;
                    if has_duplicates(&ss) {
                        return Err("String set values must not have duplicates".to_owned());
                    }
                    Ok(read(AttributeValue::Ss(ss), LENGTH_LEN + n))
                }
                NUMBER_SET => {
                    let (ns, n) = read_strings(items, count, "Number")?;
                    if has_duplicates(&ns) {
                        return Err("Number set values must not have duplicates".to_owned());
                    }
                    Ok(read(AttributeValue::Ns(ns), LENGTH_LEN + n))
                }
                _ => {
                    let mut bs: Vec<Blob> = Vec::new();
                    let mut p = 0usize;
                    for _ in 0..count {
                        if items.len() - p < LENGTH_LEN {
                            return Err("Out of bytes reading Binary Set".to_owned());
                        }
                        let l = read_u32(items, p)?;
                        p += LENGTH_LEN;
                        if items.len() - p < l {
                            return Err("Binary Set Structured Data has too few bytes".to_owned());
                        }
                        bs.push(Blob::new(&items[p..p + l]));
                        p += l;
                    }
                    if has_duplicates(bs.iter().map(Blob::as_ref)) {
                        return Err("Binary set values must not have duplicates".to_owned());
                    }
                    Ok(read(AttributeValue::Bs(bs), LENGTH_LEN + p))
                }
            }
        }
        MAP => {
            if value.len() < pos + LENGTH_LEN {
                return Err("List Structured Data has less than 4 bytes".to_owned());
            }
            let count = read_u32(value, pos)?;
            let mut p = pos + LENGTH_LEN;
            let mut m = HashMap::new();
            for _ in 0..count {
                if value.len() - p < PREFIX_LEN {
                    return Err("Out of bytes reading Map Key".to_owned());
                }
                if value[p..p + 2] != STRING {
                    return Err("Key of Map is not String".to_owned());
                }
                p += 2;
                let klen = read_u32(value, p)?;
                p += LENGTH_LEN;
                if klen > value.len() - p {
                    return Err("Key of Map of Structured Data has too few bytes".to_owned());
                }
                if klen == 0 || klen > MAX_ATTR_NAME_LEN {
                    return Err("Attribute name must be between 1 and 65535 UTF-8 bytes".to_owned());
                }
                let key = utf8(&value[p..p + klen])?;
                p += klen;
                if value.len() - p < 2 {
                    return Err("Out of bytes reading Map Value".to_owned());
                }
                let vtype = [value[p], value[p + 1]];
                p += 2;
                let nval = bytes_to_attr(value, vtype, None, depth + 1, p)?;
                p += nval.len;
                if m.contains_key(&key) {
                    return Err("Duplicate key in map.".to_owned());
                }
                m.insert(key, nval.val);
            }
            Ok(Read {
                val: AttributeValue::M(m),
                len: p - pos + length_bytes,
            })
        }
        LIST => {
            if value.len() < pos + LENGTH_LEN {
                return Err("List Structured Data has less than 4 bytes".to_owned());
            }
            let count = read_u32(value, pos)?;
            let mut p = pos + LENGTH_LEN;
            let mut l = Vec::new();
            for _ in 0..count {
                if value.len() - p < PREFIX_LEN {
                    return Err("Out of bytes reading Type of List element".to_owned());
                }
                let etype = [value[p], value[p + 1]];
                let elen = read_u32(value, p + 2)?;
                let np = p + PREFIX_LEN;
                if value.len() - np < elen {
                    return Err("Out of bytes reading Content of List element".to_owned());
                }
                let nval = bytes_to_attr(value, etype, Some(elen), depth + 1, np)?;
                p = np + nval.len;
                l.push(nval.val);
            }
            Ok(Read {
                val: AttributeValue::L(l),
                len: p - pos + length_bytes,
            })
        }
        _ => Err("Unsupported TerminalTypeId".to_owned()),
    }
}

/// The attribute value a terminal holds.
pub(crate) fn terminal_to_attr(t: &Terminal) -> Result<AttributeValue, String> {
    let read = bytes_to_attr(&t.value, t.type_id, Some(t.value.len()), 1, 0)?;
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

/// The encrypted item: each encrypted attribute replaced, plus the header and footer.
pub(crate) fn structured_to_item_encrypt(
    s: &HashMap<String, Terminal>,
    orig: &Item,
    actions: &HashMap<String, CryptoAction>,
) -> Result<Item, String> {
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

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

fn collect_strings(sorted: &[String], out: &mut Vec<u8>) -> Result<(), String> {
    out.extend_from_slice(&u32_be(sorted.len())?);
    for s in sorted {
        out.extend_from_slice(&u32_be(s.len())?);
        out.extend_from_slice(s.as_bytes());
    }
    Ok(())
}

fn string_set_to_bytes(ss: &[String], out: &mut Vec<u8>) -> Result<(), String> {
    if has_duplicates(ss) {
        return Err("String Set had duplicate values".to_owned());
    }
    let mut sorted = ss.to_vec();
    sorted.sort_by(|a, b| utf16_cmp(a, b));
    collect_strings(&sorted, out)
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
        return Err("Number Set had duplicate values after normalization.".to_owned());
    }
    norm.sort_by(|a, b| utf16_cmp(a, b));
    collect_strings(&norm, out)
}

fn binary_set_to_bytes(bs: &[Blob], out: &mut Vec<u8>) -> Result<(), String> {
    if has_duplicates(bs.iter().map(Blob::as_ref)) {
        return Err("Binary Set had duplicate values".to_owned());
    }
    let mut sorted: Vec<&[u8]> = bs.iter().map(Blob::as_ref).collect();
    sorted.sort_unstable();
    out.extend_from_slice(&u32_be(sorted.len())?);
    for b in sorted {
        out.extend_from_slice(&u32_be(b.len())?);
        out.extend_from_slice(b);
    }
    Ok(())
}

fn map_to_bytes(
    m: &HashMap<String, AttributeValue>,
    depth: u64,
    out: &mut Vec<u8>,
) -> Result<(), String> {
    let mut keys: Vec<&String> = m.keys().collect();
    keys.sort_by(|a, b| utf16_cmp(a, b));
    out.extend_from_slice(&u32_be(keys.len())?);
    for k in keys {
        // A bad value is reported before a bad name.
        let name_ok = !k.is_empty() && k.len() <= MAX_ATTR_NAME_LEN;
        if name_ok {
            out.extend_from_slice(&STRING);
            out.extend_from_slice(&u32_be(k.len())?);
            out.extend_from_slice(k.as_bytes());
        }
        write_attr(&m[k], true, depth + 1, out)?;
        if !name_ok {
            return Err("Attribute name must be between 1 and 65535 UTF-8 bytes".to_owned());
        }
    }
    Ok(())
}

fn list_to_bytes(l: &[AttributeValue], depth: u64, out: &mut Vec<u8>) -> Result<(), String> {
    out.extend_from_slice(&u32_be(l.len())?);
    for v in l {
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
        out.extend_from_slice(&type_id(a)?);
        out.extend_from_slice(&[0; LENGTH_LEN]);
        Some(out.len())
    } else {
        None
    };
    match a {
        AttributeValue::S(s) => out.extend_from_slice(s.as_bytes()),
        AttributeValue::N(n) => out.extend_from_slice(normalize_number(n)?.as_bytes()),
        AttributeValue::B(b) => out.extend_from_slice(b.as_ref()),
        AttributeValue::Ss(ss) => string_set_to_bytes(ss, out)?,
        AttributeValue::Ns(ns) => number_set_to_bytes(ns, out)?,
        AttributeValue::Bs(bs) => binary_set_to_bytes(bs, out)?,
        AttributeValue::M(m) => map_to_bytes(m, depth, out)?,
        AttributeValue::L(l) => list_to_bytes(l, depth, out)?,
        AttributeValue::Null(_) => {}
        AttributeValue::Bool(b) => out.push(u8::from(*b)),
        _ => return Err("Unsupported AttributeValue type".to_owned()),
    }
    if let Some(body) = len_at {
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
    Ok(Terminal::new(type_id(a)?, attr_to_bytes(a, false, 1)?))
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
            // Every entry takes at least PREFIX_LEN bytes, which bounds the capacity.
            let mut m = HashMap::with_capacity(count.min((value.len() - p) / PREFIX_LEN));
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
            let mut l = Vec::with_capacity(count.min((value.len() - p) / PREFIX_LEN));
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

        //= spec/structured-encryption/structures.md#terminal-type-id
        //= reason=BINARY is the only 0xFF-prefixed id matched above; the reserved ones land here
        //# Any other value prefixed by 0xFF is reserved and MUST NOT be used.
        _ => Err("Unsupported TerminalTypeId".to_owned()),
    }
}

/// The attribute value a terminal holds.
pub(crate) fn terminal_to_attr(t: &Terminal) -> Result<AttributeValue, String> {
    //= spec/structured-encryption/structures.md#terminal-value
    //# If these bytes are to be deserialized, these bytes MUST be interpreted as the type indicated in this Terminal Data's [Terminal Type ID](#terminal-type-id).D
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
        assert_eq!(
            decode([9, 9], &[]).unwrap_err(),
            "Unsupported TerminalTypeId"
        );
    }

    #[test]
    fn bad_length_list() {
        assert_eq!(
            decode(LIST, &[0, 0, 0, 1, 0, 3, 0, 0, 0, 2, 1]).unwrap_err(),
            "Out of bytes reading Content of List element"
        );
        assert_eq!(
            decode(LIST, &[0, 0, 0, 1, 0xff, 0xff, 0, 0, 0, 2, 1, 2]),
            Ok(AttributeValue::L(vec![b(&[1, 2])]))
        );
        assert!(decode(LIST, &[0, 0, 0, 1, 0, 3, 0, 0, 0, 2, 1, 2, 3]).is_err());
        assert_eq!(
            decode(LIST, &[0, 0, 0, 1, 0xff, 0xff, 0, 0, 0, 2, 1, 2, 3]).unwrap_err(),
            "Mismatch between length of encoded data and length of data"
        );
    }

    #[test]
    fn bad_length_map() {
        let key = [0, 1, 0, 0, 0, 4, K, E, Y, A];
        let with = |tail: &[u8]| [&[0, 0, 0, 1][..], &key, tail].concat();
        assert_eq!(
            decode(MAP, &with(&[0, 3, 0, 0, 0, 5, 1, 2, 3, 4])).unwrap_err(),
            "Structured Data has too few bytes"
        );
        assert_eq!(
            decode(MAP, &with(&[0xff, 0xff, 0, 0, 0, 5, 1, 2, 3, 4, 5])),
            Ok(m(&[("keyA", b(&[1, 2, 3, 4, 5]))]))
        );
        assert!(decode(MAP, &with(&[0, 3, 0, 0, 0, 5, 1, 2, 3, 4, 5, 6])).is_err());
        assert_eq!(
            decode(MAP, &with(&[0xff, 0xff, 0, 0, 0, 5, 1, 2, 3, 4, 5, 6])).unwrap_err(),
            "Mismatch between length of encoded data and length of data"
        );
    }

    #[test]
    fn bad_dup_keys() {
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
        assert_eq!(
            decode(MAP, &two(A, A)).unwrap_err(),
            "Duplicate key in map."
        );

        let distinct = [0, 0, 0, 2, 0, 0, 0, 3, 49, 50, 51, 0, 0, 0, 3, 52, 53, 54];
        let dup = [0, 0, 0, 2, 0, 0, 0, 3, 49, 50, 51, 0, 0, 0, 3, 49, 50, 51];
        assert_eq!(decode(BINARY_SET, &distinct), Ok(bs(&[b"123", b"456"])));
        assert_eq!(
            decode(BINARY_SET, &dup).unwrap_err(),
            "Binary set values must not have duplicates"
        );
        assert_eq!(decode(NUMBER_SET, &distinct), Ok(ns(&["123", "456"])));
        assert_eq!(
            decode(NUMBER_SET, &dup).unwrap_err(),
            "Number set values must not have duplicates"
        );
        assert_eq!(decode(STRING_SET, &distinct), Ok(ss(&["123", "456"])));
        assert_eq!(
            decode(STRING_SET, &dup).unwrap_err(),
            "String set values must not have duplicates"
        );
    }

    #[test]
    fn encode_scalars_and_sets() {
        for (attr, type_id, value) in [
            (s("abc"), STRING, &[97, 98, 99][..]),
            (n("123"), NUMBER, &[49, 50, 51]),
            (
                ns(&["123", "45"]),
                NUMBER_SET,
                &[0, 0, 0, 2, 0, 0, 0, 3, 49, 50, 51, 0, 0, 0, 2, 52, 53],
            ),
            (
                ss(&["abc", "de"]),
                STRING_SET,
                &[0, 0, 0, 2, 0, 0, 0, 3, 97, 98, 99, 0, 0, 0, 2, 100, 101],
            ),
            (
                bs(&[&[1, 2, 3], &[4, 5]]),
                BINARY_SET,
                &[0, 0, 0, 2, 0, 0, 0, 3, 1, 2, 3, 0, 0, 0, 2, 4, 5],
            ),
            (b(&[1, 2, 3, 4, 5]), BINARY, &[1, 2, 3, 4, 5]),
            (null(), NULL, &[]),
            (AttributeValue::Bool(false), BOOLEAN, &[0]),
            (AttributeValue::Bool(true), BOOLEAN, &[1]),
        ] {
            check_encode(&attr, type_id, value, &attr);
        }
    }

    #[test]
    fn encode_list_and_map() {
        let binary = b(&[1, 2, 3, 4, 5]);
        let boolean = AttributeValue::Bool(false);
        let list = AttributeValue::L(vec![binary.clone(), null(), boolean.clone()]);
        let list_bytes = [
            0, 0, 0, 3, 0xff, 0xff, 0, 0, 0, 5, 1, 2, 3, 4, 5, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 1,
            0,
        ];
        check_encode(&list, LIST, &list_bytes, &list);

        let map = m(&[
            ("keyA", binary),
            ("keyB", null()),
            ("keyC", boolean),
            ("keyD", list),
        ]);
        let map_bytes = [
            &[0, 0, 0, 4][..],
            &[
                0, 1, 0, 0, 0, 4, K, E, Y, A, 0xff, 0xff, 0, 0, 0, 5, 1, 2, 3, 4, 5,
            ],
            &[0, 1, 0, 0, 0, 4, K, E, Y, B, 0, 0, 0, 0, 0, 0],
            &[0, 1, 0, 0, 0, 4, K, E, Y, C, 0, 4, 0, 0, 0, 1, 0],
            &[0, 1, 0, 0, 0, 4, K, E, Y, D, 3, 0, 0, 0, 0, 28],
            &list_bytes,
        ]
        .concat();
        check_encode(&map, MAP, &map_bytes, &map);
    }

    #[test]
    fn numbers_are_normalized() {
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
        0, 0, 0, 3, 0, 0, 0, 1, 49, 0, 0, 0, 2, 49, 48, 0, 0, 0, 1, 50,
    ];
    // UTF-8 bytes, in UTF-16 order: "&", "\u{10002}", "\u{FF61}".
    const SORTED_SS: [u8; 24] = [
        0, 0, 0, 3, 0, 0, 0, 1, 0x26, 0, 0, 0, 4, 0xF0, 0x90, 0x80, 0x82, 0, 0, 0, 3, 0xEF, 0xBD,
        0xA1,
    ];
    const SORTED_BS: [u8; 20] = [0, 0, 0, 3, 0, 0, 0, 1, 1, 0, 0, 0, 2, 1, 0, 0, 0, 0, 1, 2];

    #[test]
    fn sets_are_sorted() {
        let sorted_ns = ns(&["1", "10", "2"]);
        check_encode(&ns(&["1", "2", "10"]), NUMBER_SET, &SORTED_NS, &sorted_ns);
        // Ordering applies after normalization.
        check_encode(&ns(&["1", "02", "10"]), NUMBER_SET, &SORTED_NS, &sorted_ns);
        check_encode(
            &ss(&[AMP, HALFWIDTH_STOP, LINEAR_B]),
            STRING_SET,
            &SORTED_SS,
            &ss(&[AMP, LINEAR_B, HALFWIDTH_STOP]),
        );
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
        let bytes = [
            0, 0, 0, 3, 0, 1, 0, 0, 0, 1, 0x26, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 4, 0xF0, 0x90,
            0x80, 0x82, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 3, 0xEF, 0xBD, 0xA1, 0, 0, 0, 0, 0, 0,
        ];
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
        assert_eq!(
            decode(MAP, &[0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap_err(),
            "Attribute name must be between 1 and 65535 UTF-8 bytes"
        );
    }

    #[test]
    fn encode_rejects_duplicate_set_values() {
        for (attr, msg) in [
            (ss(&["a", "a"]), "String Set had duplicate values"),
            (ns(&["1", "1"]), "Number Set had duplicate values"),
            (
                ns(&["1", "01"]),
                "Number Set had duplicate values after normalization.",
            ),
            (bs(&[&[1], &[1]]), "Binary Set had duplicate values"),
        ] {
            assert_eq!(attr_to_terminal(&attr).unwrap_err(), msg);
        }
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
        for (type_id, value, msg) in [
            (NULL, &[1][..], "NULL type did not have length zero"),
            (STRING, &[0xff], "Invalid UTF-8"),
            (NUMBER, &[0xff], "Invalid UTF-8"),
            (
                BOOLEAN,
                &[2],
                "Boolean Structured Data had inappropriate value",
            ),
            (
                BOOLEAN,
                &[0, 1],
                "Boolean Structured Data has more than one byte",
            ),
            (STRING_SET, &[0, 0, 0, 1], "Out of bytes reading String Set"),
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
                BINARY_SET,
                &[0, 0, 0, 1, 0, 0, 0, 2, 1],
                "Binary Set Structured Data has too few bytes",
            ),
            (
                STRING_SET,
                &[0, 0, 0, 0, 7],
                "Mismatch between length of encoded data and length of data",
            ),
            (MAP, &[0, 0, 0, 1], "Out of bytes reading Map Key"),
            (
                MAP,
                &[0, 0, 0, 1, 0, 2, 0, 0, 0, 1, 0x61],
                "Key of Map is not String",
            ),
            (
                MAP,
                &[0, 0, 0, 1, 0, 1, 0, 0, 0, 9, 0x61],
                "Key of Map of Structured Data has too few bytes",
            ),
            (
                MAP,
                &[0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0xff, 0, 0, 0, 0, 0, 0],
                "Invalid UTF-8",
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
}

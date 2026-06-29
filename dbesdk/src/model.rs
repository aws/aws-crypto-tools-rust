// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The DynamoDB item / attribute-value model and its canonical binary
//! serialization.
//!
//! [`AttributeValue`] mirrors the TestServer model's `AttributeValue` union
//! (which itself mirrors the subset of DynamoDB attribute types the conformance
//! suite exercises). An [`Item`] is a map of attribute name to value.
//!
//! [`AttributeValue::to_canonical_bytes`] / [`AttributeValue::from_canonical_bytes`]
//! provide a deterministic, reversible binary encoding. It is used two ways:
//!   * as the plaintext fed to AES-GCM for an `ENCRYPT_AND_SIGN` attribute (so a
//!     decrypted attribute reconstructs the exact original value), and
//!   * as the per-attribute contribution to the signed canonical form.

use std::collections::BTreeMap;

use crate::error::{DbEsdkError, Result};

/// A DynamoDB item: attribute name -> attribute value.
///
/// A `BTreeMap` is used so iteration is deterministically ordered by attribute
/// name, which the canonical signed form relies on.
pub type Item = BTreeMap<String, AttributeValue>;

/// A DynamoDB attribute value — the subset of types the conformance suite
/// exercises (mirrors the Smithy model `AttributeValue` union).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttributeValue {
    /// String (`S`).
    S(String),
    /// Number, carried as its DynamoDB string form (`N`).
    N(String),
    /// Binary (`B`).
    B(Vec<u8>),
    /// Boolean (`BOOL`).
    Bool(bool),
    /// Null (`NULL`); the bool is always `true` when present, per DynamoDB.
    Null(bool),
    /// String set (`SS`).
    Ss(Vec<String>),
    /// Number set (`NS`), numbers carried as strings.
    Ns(Vec<String>),
    /// Binary set (`BS`).
    Bs(Vec<Vec<u8>>),
    /// Nested map (`M`).
    M(Item),
    /// List (`L`).
    L(Vec<AttributeValue>),
}

// Type tags for the canonical binary encoding. Stable on-the-wire constants.
const TAG_S: u8 = 0x01;
const TAG_N: u8 = 0x02;
const TAG_B: u8 = 0x03;
const TAG_BOOL: u8 = 0x04;
const TAG_NULL: u8 = 0x05;
const TAG_SS: u8 = 0x06;
const TAG_NS: u8 = 0x07;
const TAG_BS: u8 = 0x08;
const TAG_M: u8 = 0x09;
const TAG_L: u8 = 0x0A;

impl AttributeValue {
    /// Serialize this value to its deterministic, reversible canonical bytes.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write_canonical(&mut out);
        out
    }

    /// Parse a value previously produced by [`Self::to_canonical_bytes`].
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        let value = read_value(&mut cursor)?;
        if !cursor.is_empty() {
            return Err(DbEsdkError::crypto(
                "trailing bytes after decoding a canonical attribute value",
            ));
        }
        Ok(value)
    }

    fn write_canonical(&self, out: &mut Vec<u8>) {
        match self {
            Self::S(s) => {
                out.push(TAG_S);
                write_bytes(out, s.as_bytes());
            }
            Self::N(n) => {
                out.push(TAG_N);
                write_bytes(out, n.as_bytes());
            }
            Self::B(b) => {
                out.push(TAG_B);
                write_bytes(out, b);
            }
            Self::Bool(v) => {
                out.push(TAG_BOOL);
                out.push(u8::from(*v));
            }
            Self::Null(v) => {
                out.push(TAG_NULL);
                out.push(u8::from(*v));
            }
            Self::Ss(set) => {
                out.push(TAG_SS);
                write_str_seq(out, set);
            }
            Self::Ns(set) => {
                out.push(TAG_NS);
                write_str_seq(out, set);
            }
            Self::Bs(set) => {
                out.push(TAG_BS);
                write_u32(out, set.len());
                for b in set {
                    write_bytes(out, b);
                }
            }
            Self::M(map) => {
                out.push(TAG_M);
                write_u32(out, map.len());
                // BTreeMap iterates in sorted key order: deterministic.
                for (name, value) in map {
                    write_bytes(out, name.as_bytes());
                    value.write_canonical(out);
                }
            }
            Self::L(list) => {
                out.push(TAG_L);
                write_u32(out, list.len());
                for value in list {
                    value.write_canonical(out);
                }
            }
        }
    }
}

fn write_u32(out: &mut Vec<u8>, value: usize) {
    // Lengths in this model are tiny; a usize that does not fit u32 is a bug.
    let v = u32::try_from(value).expect("canonical length exceeds u32");
    out.extend_from_slice(&v.to_be_bytes());
}

fn write_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    write_u32(out, bytes.len());
    out.extend_from_slice(bytes);
}

fn write_str_seq(out: &mut Vec<u8>, seq: &[String]) {
    write_u32(out, seq.len());
    for s in seq {
        write_bytes(out, s.as_bytes());
    }
}

/// A minimal big-endian byte cursor for decoding canonical bytes.
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| DbEsdkError::crypto("canonical attribute value truncated"))?;
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn take_u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn take_u32(&mut self) -> Result<usize> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize)
    }

    fn take_len_prefixed(&mut self) -> Result<&'a [u8]> {
        let len = self.take_u32()?;
        self.take(len)
    }

    fn take_string(&mut self) -> Result<String> {
        let bytes = self.take_len_prefixed()?;
        String::from_utf8(bytes.to_vec())
            .map_err(|_| DbEsdkError::crypto("canonical string was not valid UTF-8"))
    }
}

fn read_value(cursor: &mut Cursor<'_>) -> Result<AttributeValue> {
    let tag = cursor.take_u8()?;
    match tag {
        TAG_S => Ok(AttributeValue::S(cursor.take_string()?)),
        TAG_N => Ok(AttributeValue::N(cursor.take_string()?)),
        TAG_B => Ok(AttributeValue::B(cursor.take_len_prefixed()?.to_vec())),
        TAG_BOOL => Ok(AttributeValue::Bool(cursor.take_u8()? != 0)),
        TAG_NULL => Ok(AttributeValue::Null(cursor.take_u8()? != 0)),
        TAG_SS => Ok(AttributeValue::Ss(read_str_seq(cursor)?)),
        TAG_NS => Ok(AttributeValue::Ns(read_str_seq(cursor)?)),
        TAG_BS => {
            let count = cursor.take_u32()?;
            let mut set = Vec::with_capacity(count);
            for _ in 0..count {
                set.push(cursor.take_len_prefixed()?.to_vec());
            }
            Ok(AttributeValue::Bs(set))
        }
        TAG_M => {
            let count = cursor.take_u32()?;
            let mut map = Item::new();
            for _ in 0..count {
                let name = cursor.take_string()?;
                let value = read_value(cursor)?;
                map.insert(name, value);
            }
            Ok(AttributeValue::M(map))
        }
        TAG_L => {
            let count = cursor.take_u32()?;
            let mut list = Vec::with_capacity(count);
            for _ in 0..count {
                list.push(read_value(cursor)?);
            }
            Ok(AttributeValue::L(list))
        }
        other => Err(DbEsdkError::crypto(format!(
            "unknown canonical attribute-value tag 0x{other:02x}"
        ))),
    }
}

fn read_str_seq(cursor: &mut Cursor<'_>) -> Result<Vec<String>> {
    let count = cursor.take_u32()?;
    let mut seq = Vec::with_capacity(count);
    for _ in 0..count {
        seq.push(cursor.take_string()?);
    }
    Ok(seq)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(value: AttributeValue) {
        let bytes = value.to_canonical_bytes();
        let parsed = AttributeValue::from_canonical_bytes(&bytes).expect("must decode");
        assert_eq!(value, parsed);
    }

    #[test]
    fn canonical_round_trips_every_scalar_variant() {
        round_trip(AttributeValue::S("top-secret-value".to_string()));
        round_trip(AttributeValue::N("42".to_string()));
        round_trip(AttributeValue::B(b"binary-blob".to_vec()));
        round_trip(AttributeValue::Bool(true));
        round_trip(AttributeValue::Bool(false));
        round_trip(AttributeValue::Null(true));
    }

    #[test]
    fn canonical_round_trips_sets_and_collections() {
        round_trip(AttributeValue::Ss(vec!["a".into(), "b".into()]));
        round_trip(AttributeValue::Ns(vec!["1".into(), "2".into()]));
        round_trip(AttributeValue::Bs(vec![b"x".to_vec(), b"yy".to_vec()]));
        round_trip(AttributeValue::L(vec![
            AttributeValue::S("s".into()),
            AttributeValue::N("7".into()),
            AttributeValue::Bool(false),
        ]));
        let mut m = Item::new();
        m.insert("inner".into(), AttributeValue::S("v".into()));
        m.insert("flag".into(), AttributeValue::Bool(true));
        round_trip(AttributeValue::M(m));
    }

    #[test]
    fn map_encoding_is_order_independent() {
        let mut a = Item::new();
        a.insert("z".into(), AttributeValue::S("1".into()));
        a.insert("a".into(), AttributeValue::S("2".into()));
        let mut b = Item::new();
        b.insert("a".into(), AttributeValue::S("2".into()));
        b.insert("z".into(), AttributeValue::S("1".into()));
        assert_eq!(
            AttributeValue::M(a).to_canonical_bytes(),
            AttributeValue::M(b).to_canonical_bytes()
        );
    }

    #[test]
    fn from_canonical_rejects_trailing_and_truncated_input() {
        let mut bytes = AttributeValue::S("x".into()).to_canonical_bytes();
        bytes.push(0xFF);
        assert!(AttributeValue::from_canonical_bytes(&bytes).is_err());

        let short = AttributeValue::B(b"abcd".to_vec()).to_canonical_bytes();
        assert!(AttributeValue::from_canonical_bytes(&short[..short.len() - 1]).is_err());
    }
}

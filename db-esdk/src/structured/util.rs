// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The type ids, terminals, and paths of structured encryption.

use crate::types::CryptoAction;

/// Prefix of every attribute name this library reserves.
pub(crate) const RESERVED_PREFIX: &str = "aws_dbe_";
/// The attribute that holds the header.
//= spec/structured-encryption/encrypt-path-structure.md#header-field
//# The Header Field name MUST be `aws_dbe_head`
pub(crate) const HEADER_FIELD: &str = "aws_dbe_head";
/// The attribute that holds the footer.
//= spec/structured-encryption/encrypt-path-structure.md#footer-field
//# The Footer Field name MUST be `aws_dbe_foot`
pub(crate) const FOOTER_FIELD: &str = "aws_dbe_foot";

/// Prefix of every encryption context key this library reserves.
pub(crate) const RESERVED_CRYPTO_CONTEXT_PREFIX: &str = "aws-crypto-";
/// Prefix of the encryption context entry of a `SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT` attribute.
pub(crate) const ATTR_PREFIX: &str = "aws-crypto-attr.";
/// The encryption context key whose value says how each attribute entry is encoded.
pub(crate) const LEGEND: &str = "aws-crypto-legend";

/// The two-byte type id of a terminal value.
pub(crate) type TypeId = [u8; 2];

pub(crate) const NULL: TypeId = [0x00, 0x00];
pub(crate) const STRING: TypeId = [0x00, 0x01];
pub(crate) const NUMBER: TypeId = [0x00, 0x02];
pub(crate) const BOOLEAN: TypeId = [0x00, 0x04];

//= spec/structured-encryption/structures.md#terminal-type-id
//# If [Terminal Value](#terminal-value) is to be interpreted as raw bytes,
//# the Terminal Type ID MUST be 0xFFFF.
pub(crate) const BINARY: TypeId = [0xFF, 0xFF];
pub(crate) const STRING_SET: TypeId = [0x01, 0x01];
pub(crate) const NUMBER_SET: TypeId = [0x01, 0x02];
pub(crate) const BINARY_SET: TypeId = [0x01, 0xFF];
pub(crate) const MAP: TypeId = [0x02, 0x00];
pub(crate) const LIST: TypeId = [0x03, 0x00];

/// The type id of an encrypted terminal, and of the header and footer.
pub(crate) const BYTES_TYPE_ID: TypeId = BINARY;

/// A serialized value and its type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Terminal {
    pub(crate) type_id: TypeId,
    pub(crate) value: Vec<u8>,
}

impl Terminal {
    pub(crate) const fn new(type_id: TypeId, value: Vec<u8>) -> Self {
        Self { type_id, value }
    }

    /// The type id followed by the value, base64-encoded, as stored in an encryption context.
    pub(crate) fn encode(&self) -> String {
        use base64::Engine as _;
        let mut bytes = Vec::with_capacity(2 + self.value.len());
        bytes.extend_from_slice(&self.type_id);
        bytes.extend_from_slice(&self.value);

        //= spec/dynamodb-encryption-client/encrypt-item.md#base-context-value-version-1
        //# The value MUST be the UTF8 Encoding of the
        //# [Base 64 encoded](https://www.rfc-editor.org/rfc/rfc4648),
        //# of the concatenation of the bytes `typeID + serializedValue`
        //# where `typeId` is the attribute's [type ID](./ddb-attribute-serialization.md#type-id)
        //# and `serializedValue` is the attribute's value serialized according to
        //# [Attribute Value Serialization](./ddb-attribute-serialization.md#attribute-value-serialization).
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }
}

/// A location in a structure: the names of the nested structure members, outermost first.
//= spec/structured-encryption/structures.md#overview
//= type=implication
//= reason=internally a path is bare member names; every path segment property still holds
//# While these structures will usually be represented as objects, lower level languages MAY represent
//# these fields in a less strictly defined way as long as all field properties are still upheld.
pub(crate) type Path = Vec<String>;

/// Whether a field of an item being decrypted is covered by the signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuthAction {
    Sign,
    DoNotSign,
}

/// A field and the action to take on it when encrypting.
#[derive(Clone, Debug)]
pub(crate) struct CryptoField {
    pub(crate) key: Path,
    pub(crate) data: Terminal,
    pub(crate) action: CryptoAction,
}

/// A field of an item being decrypted and whether it is signed.
#[derive(Clone, Debug)]
pub(crate) struct AuthField {
    pub(crate) key: Path,
    pub(crate) data: Terminal,
    pub(crate) action: AuthAction,
}

/// A field with its canonical path.
#[derive(Clone, Debug)]
pub(crate) struct CanonItem {
    pub(crate) canon: Vec<u8>,
    pub(crate) key: Path,
    pub(crate) data: Terminal,
    pub(crate) action: CryptoAction,
}

/// The number of UTF-16 code units in `s`.
/// The reference implementation measures string lengths in these units.
pub(crate) fn utf16_len(s: &str) -> usize {
    s.encode_utf16().count()
}

/// Compare strings by UTF-16 code units.
/// The reference implementation sorts strings in this order.
pub(crate) fn utf16_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    //= spec/dynamodb-encryption-client/string-ordering.md#utf-16-binary-order
    //# When ordering strings,
    //# these strings MUST be compared according to their UTF-16 encoding,
    //# lexicographically per [UTF-16 code unit](#utf-16-code-unit).
    //
    //= spec/dynamodb-encryption-client/string-ordering.md#utf-16-binary-order
    //# UTF-16 code units for [high or low surrogates](#surrogates) MUST be compared individually,
    //# and the [Unicode scalar value](#unicode-scalar-value) represented by a surrogate pair
    //# MUST NOT be compared.
    //
    //= spec/dynamodb-encryption-client/string-ordering.md#utf-16-binary-order
    //# Specifically, the range of characters with Unicode code point U+E000 to U+0xFFFF
    //# (code points representable by 16 bits, but after the surrogate range)
    //# MUST be considered "greater than" any character with a Unicode code point of U+10000 to U+10FFFF.
    a.encode_utf16().cmp(b.encode_utf16())
}

/// The canonical path of `path` in `table`:
/// the table name, the path depth, then each member's tag, length, and name.
pub(crate) fn canon_path(table: &str, path: &[String]) -> Vec<u8> {
    //= spec/structured-encryption/header.md#canonical-path
    //= type=exception
    //= reason=paths are member-only (a list segment cannot be expressed), matching the reference
    //# For Structured Data in Structured Data Lists, this MUST be a 0x23 byte (# in UTF-8),
    //# followed by the numerical index.
    const MAP_TAG: u8 = b'$';
    let mut out =
        Vec::with_capacity(table.len() + 8 + path.iter().map(|s| s.len() + 9).sum::<usize>());

    //= spec/structured-encryption/header.md#canonical-path
    //# The canonical path MUST start with the UTF8 encoded table name.
    out.extend_from_slice(table.as_bytes());

    //= spec/structured-encryption/header.md#canonical-path
    //# This MUST be followed by the depth of the Terminal within Structured Data.
    out.extend_from_slice(&u64_len(path.len()).to_be_bytes());

    //= spec/structured-encryption/header.md#canonical-path
    //# This MUST be followed by the encoding for each Structured Data in the path, including the Terminal itself.
    for segment in path {
        //= spec/structured-encryption/header.md#canonical-path
        //= reason=key length counts UTF-16 code units, as the reference does
        //# For Structured Data in Structured Data Maps, this MUST be a 0x24 byte ($ in UTF-8),
        //# followed by the length of the key, followed by the key as a UTF8 string.
        out.push(MAP_TAG);
        out.extend_from_slice(&u64_len(utf16_len(segment)).to_be_bytes());
        out.extend_from_slice(segment.as_bytes());
    }
    out
}

/// `path` as a dotted string, for messages and encryption context keys.
pub(crate) fn path_to_string(path: &[String]) -> String {
    path.join(".")
}

/// A length as `u64`; every in-memory length fits.
pub(crate) fn u64_len(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

/// The legend byte of a signed action.
pub(crate) const ENCRYPT_AND_SIGN_LEGEND: u8 = 0x65;
pub(crate) const SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT_LEGEND: u8 = 0x63;
pub(crate) const SIGN_ONLY_LEGEND: u8 = 0x73;

/// Whether `action` puts the field in the signature.
pub(crate) const fn is_auth_attr(action: CryptoAction) -> bool {
    !matches!(action, CryptoAction::DoNothing)
}

#[cfg(test)]
#[path = "util_tests.rs"]
mod tests;

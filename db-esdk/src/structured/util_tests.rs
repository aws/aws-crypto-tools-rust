// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::cmp::Ordering;

use super::*;

fn path(segments: &[&str]) -> Path {
    segments.iter().map(|s| (*s).to_owned()).collect()
}

// Paths.dfy TestSpecExamples.
#[test]
fn canon_path_spec_example() {
    let mut expected = b"example_table".to_vec();
    expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]);
    expected.push(b'$');
    expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 4]);
    expected.extend_from_slice(b"name");

    //= spec/structured-encryption/header.md#canonical-path
    //= type=test
    //# The canonical path MUST start with the UTF8 encoded table name.
    //
    //= spec/structured-encryption/header.md#canonical-path
    //= type=test
    //# For Structured Data in Structured Data Maps, this MUST be a 0x24 byte ($ in UTF-8),
    //# followed by the length of the key, followed by the key as a UTF8 string.
    assert_eq!(canon_path("example_table", &path(&["name"])), expected);
}

#[test]
fn canon_path_nested_segments_in_order() {
    let mut expected = b"t".to_vec();
    expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 2]);
    expected.push(b'$');
    expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]);
    expected.extend_from_slice(b"a");
    expected.push(b'$');
    expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 2]);
    expected.extend_from_slice(b"bc");

    //= spec/structured-encryption/header.md#canonical-path
    //= type=test
    //# This MUST be followed by the depth of the Terminal within Structured Data.
    //
    //= spec/structured-encryption/header.md#canonical-path
    //= type=test
    //# This MUST be followed by the encoding for each Structured Data in the path, including the Terminal itself.
    assert_eq!(canon_path("t", &path(&["a", "bc"])), expected);
}

// The segment length counts UTF-16 code units, as the reference does, while the
// name itself is written as UTF-8.
#[test]
fn canon_path_length_counts_utf16_units() {
    let grin = "\u{1F600}";
    let mut expected = b"t".to_vec();
    expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]);
    expected.push(b'$');
    expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 2]);
    expected.extend_from_slice(&[0xF0, 0x9F, 0x98, 0x80]);
    assert_eq!(canon_path("t", &path(&[grin])), expected);
}

#[test]
fn utf16_len_counts_code_units() {
    assert_eq!(utf16_len(""), 0);
    assert_eq!(utf16_len("abc"), 3);
    assert_eq!(utf16_len("\u{00E9}"), 1);
    assert_eq!(utf16_len("\u{1F600}"), 2);
}

// U+FFFF sorts before U+1F600 by UTF-8 bytes, but after it by UTF-16 code units
// (0xFFFF > 0xD83D), and the reference sorts by UTF-16.
#[test]
fn utf16_cmp_differs_from_byte_order() {
    let bmp_max = "\u{FFFF}";
    let astral = "\u{1F600}";
    assert_eq!(bmp_max.as_bytes().cmp(astral.as_bytes()), Ordering::Less);
    assert_eq!(utf16_cmp(bmp_max, astral), Ordering::Greater);
    assert_eq!(utf16_cmp("a", "b"), Ordering::Less);
    assert_eq!(utf16_cmp("ab", "ab"), Ordering::Equal);
}

#[test]
fn terminal_encode_is_base64_of_type_id_and_value() {
    assert_eq!(Terminal::new(STRING, b"abc".to_vec()).encode(), "AAFhYmM=");
    assert_eq!(Terminal::new(NULL, Vec::new()).encode(), "AAA=");
}

#[test]
fn path_to_string_joins_with_dots() {
    assert_eq!(path_to_string(&path(&["a", "b", "c"])), "a.b.c");
    assert_eq!(path_to_string(&path(&["only"])), "only");
}

#[test]
fn only_do_nothing_is_unauthenticated() {
    assert!(is_auth_attr(CryptoAction::EncryptAndSign));
    assert!(is_auth_attr(CryptoAction::SignOnly));
    assert!(is_auth_attr(
        CryptoAction::SignAndIncludeInEncryptionContext
    ));
    assert!(!is_auth_attr(CryptoAction::DoNothing));
}

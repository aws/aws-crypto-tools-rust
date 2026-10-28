// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests ported from the reference implementation's `Virtual.dfy`.

use super::*;
use crate::search::test_fixtures::{item, n, s};

const MIXED: &str = "aBcD\u{f1}\u{d1}eF";

fn t(transform: &VirtualTransform, input: &str) -> String {
    do_transform(transform, input)
}

#[test]
fn upper() {
    let u = VirtualTransform::upper();
    assert_eq!(t(&u, ""), "");

    // Only ASCII letters change case.
    //= spec/searchable-encryption/virtual.md#upper-transform-initialization
    //= type=test
    //# The Upper transform MUST convert all ascii lowercase characters into their uppercase equivalents.
    assert_eq!(t(&u, MIXED), "ABCD\u{f1}\u{d1}EF");
}

#[test]
fn lower() {
    let l = VirtualTransform::lower();
    assert_eq!(t(&l, ""), "");

    //= spec/searchable-encryption/virtual.md#lower-transform-initialization
    //= type=test
    //# The Lower transform MUST convert all ascii uppercase characters into their lowercase equivalents.
    assert_eq!(t(&l, MIXED), "abcd\u{f1}\u{d1}ef");
}

#[test]
fn insert() {
    let i = VirtualTransform::insert("_foo");
    assert_eq!(t(&i, ""), "_foo");

    //= spec/searchable-encryption/virtual.md#insert-transform-initialization
    //= type=test
    //# The Insert transform MUST append this string to its input
    assert_eq!(t(&i, MIXED), "aBcD\u{f1}\u{d1}eF_foo");
}

#[test]
fn prefix() {
    let (p0, p3, pn3) = (
        VirtualTransform::prefix(0),
        VirtualTransform::prefix(3),
        VirtualTransform::prefix(-3),
    );
    for input in ["", "a", "abc"] {
        assert_eq!(t(&p0, input), "");

        //= spec/searchable-encryption/virtual.md#getprefix-transform-initialization
        //= type=test
        //# If length is non-negative, and length exceeds the length of the string, the input string MUST be returned.
        assert_eq!(t(&p3, input), input);

        //= spec/searchable-encryption/virtual.md#getprefix-transform-initialization
        //= type=test
        //# If length is negative and -length exceeds the length on the input,
        //# the empty string MUST be returned.
        assert_eq!(t(&pn3, input), "");
    }
    assert_eq!(t(&p0, MIXED), "");

    //= spec/searchable-encryption/virtual.md#getprefix-transform-initialization
    //= type=test
    //# If length is non-negative, the GetPrefix transform MUST return the first `length` characters of the input.
    assert_eq!(t(&p3, MIXED), "aBc");

    //= spec/searchable-encryption/virtual.md#getprefix-transform-initialization
    //= type=test
    //# If length is negative, then the GetPrefix transform MUST return
    //# all but the last `-length` character of the input.
    assert_eq!(t(&pn3, MIXED), "aBcD\u{f1}");
}

#[test]
fn suffix() {
    let (p0, p3, pn3) = (
        VirtualTransform::suffix(0),
        VirtualTransform::suffix(3),
        VirtualTransform::suffix(-3),
    );
    for input in ["", "a", "abc"] {
        assert_eq!(t(&p0, input), "");

        //= spec/searchable-encryption/virtual.md#getsuffix-transform-initialization
        //= type=test
        //# If length is non-negative, and length exceeds the length of the string, the input string MUST be returned.
        assert_eq!(t(&p3, input), input);

        //= spec/searchable-encryption/virtual.md#getsuffix-transform-initialization
        //= type=test
        //# If length is negative and -length exceeds the length on the input,
        //# the empty string MUST be returned.
        assert_eq!(t(&pn3, input), "");
    }
    assert_eq!(t(&p0, MIXED), "");

    //= spec/searchable-encryption/virtual.md#getsuffix-transform-initialization
    //= type=test
    //# If length is non-negative, the GetSuffix transform MUST return the last `length` characters of the input.
    assert_eq!(t(&p3, MIXED), "\u{d1}eF");

    //= spec/searchable-encryption/virtual.md#getsuffix-transform-initialization
    //= type=test
    //# If length is negative, then the GetSuffix transform MUST return
    //# all but the first `-length` character of the input.
    assert_eq!(t(&pn3, MIXED), "D\u{f1}\u{d1}eF");
}

#[test]
fn lengths_count_utf16_code_units() {
    // U+1F600 is two UTF-16 code units.
    let face = "\u{1F600}abc";
    assert_eq!(t(&VirtualTransform::prefix(2), face), "\u{1F600}");
    assert_eq!(t(&VirtualTransform::suffix(-2), face), "abc");
    assert_eq!(t(&VirtualTransform::substring(2, 4), face), "ab");
}

#[test]
fn substring() {
    let cases = [
        ((2, 4), "cd"),
        ((2, -2), "cd"),
        ((-4, 4), "cd"),
        ((-4, -2), "cd"),
    ];
    for ((low, high), want) in cases {
        //= spec/searchable-encryption/virtual.md#getsubstring-transform-initialization
        //= type=test
        //# The GetSubstring transform MUST return the range of characters
        //# from low (inclusive) to high (exclusive)
        assert_eq!(
            t(&VirtualTransform::substring(low, high), "abcdef"),
            want,
            "{low}..{high}"
        );
    }
    // Positions are clamped into the string: past the end is the last character.
    assert_eq!(
        t(&VirtualTransform::substring(-100, 100), "abcdef"),
        "abcde"
    );
    // High at or below low is empty.
    for (low, high) in [(4, 2), (0, 0)] {
        assert_eq!(
            t(&VirtualTransform::substring(low, high), "abcdef"),
            "",
            "{low}..{high}"
        );
    }
    assert_eq!(t(&VirtualTransform::substring(0, 3), ""), "");
}

/// Ported from `GetPosTest` in the reference implementation's `Virtual.dfy`.
#[test]
fn positions() {
    let from_start = [(0, 0), (1, 1), (2, 2), (3, 3), (4, 4)];
    for (pos, want) in from_start {
        //= spec/searchable-encryption/virtual.md#position-definition
        //= type=test
        //# If the position provided is positive, it MUST be the zero-based index from the start of the list.
        assert_eq!(get_pos(pos, 5), want, "{pos}");
    }
    let from_end = [(-1, 4), (-2, 3), (-3, 2), (-4, 1), (-5, 0)];
    for (pos, want) in from_end {
        //= spec/searchable-encryption/virtual.md#position-definition
        //= type=test
        //# If the position provided is negative, it's absolute value MUST be the
        //# one-based index from the end of the list, that is, -1 refers to the last item in the list.
        assert_eq!(get_pos(pos, 5), want, "{pos}");
    }
    // Positions past either end are clamped into the list.
    assert_eq!(get_pos(5, 5), 4);
    assert_eq!(get_pos(-6, 5), 0);
    assert_eq!(get_pos(3, 0), 0);
}

#[test]
fn segment() {
    let input = "1.23.456.7890";
    let in_range = [
        (0, "1"),
        (1, "23"),
        (2, "456"),
        (3, "7890"),
        (-1, "7890"),
        (-2, "456"),
        (-3, "23"),
        (-4, "1"),
    ];
    for (index, want) in in_range {
        //= spec/searchable-encryption/virtual.md#getsegment-transform-initialization
        //= type=test
        //# The GetSegment transform MUST split the input string on the given character,
        //# and return the item in the resulting list the corresponds to the given position.
        assert_eq!(
            t(&VirtualTransform::segment('.', index), input),
            want,
            "{index}"
        );
    }
    // There are four segments, so index 4 is the first one past the end.
    for index in [4, 5] {
        //= spec/searchable-encryption/virtual.md#getsegment-transform-initialization
        //= type=test
        //# If index is greater than the number of items in the list, an empty string MUST be returned.
        assert_eq!(
            t(&VirtualTransform::segment('.', index), input),
            "",
            "{index}"
        );
    }
    // Past the end from the back is also empty.
    for index in [-5, -6] {
        assert_eq!(
            t(&VirtualTransform::segment('.', index), input),
            "",
            "{index}"
        );
    }
    // Without the split character, the whole string is the only segment.
    assert_eq!(t(&VirtualTransform::segment('.', 0), "abc"), "abc");
}

#[test]
fn segments() {
    let input = "1.23.456.7890";
    let non_empty = [
        ((1, 2), "23"),
        ((1, 3), "23.456"),
        ((-3, 2), "23"),
        ((0, -1), "1.23.456"),
    ];
    for ((low, high), want) in non_empty {
        //= spec/searchable-encryption/virtual.md#getsegments-transform-initialization
        //= type=test
        //# The GetSegments transform MUST split the input string on the `split` character.
        //
        //= spec/searchable-encryption/virtual.md#getsegments-transform-initialization
        //= type=test
        //# GetSegments MUST return the range of parts from low (inclusive) to high (exclusive),
        //# joined on the `split` character.
        assert_eq!(
            t(&VirtualTransform::segments('.', low, high), input),
            want,
            "{low}..{high}"
        );
    }
    // High equal to low, then high below low.
    for (low, high) in [(0, 0), (3, 1)] {
        //= spec/searchable-encryption/virtual.md#getsegments-transform-initialization
        //= type=test
        //# If high is less than or equal to low, an empty string MUST be returned.
        assert_eq!(
            t(&VirtualTransform::segments('.', low, high), input),
            "",
            "{low}..{high}"
        );
    }
}

fn part(loc: &str, transforms: Vec<VirtualTransform>) -> VirtPart {
    VirtPart {
        loc: TermLoc::parse(loc).unwrap(),
        transforms,
    }
}

fn my_field() -> VirtField {
    VirtField {
        parts: vec![
            part("foo", vec![]),
            part("bar", vec![VirtualTransform::lower()]),
            part("baz[2].florn", vec![]),
        ],
    }
}

fn my_item() -> HashMap<String, AttributeValue> {
    let florn = AttributeValue::M([("florn".to_owned(), s("FlornString"))].into());
    item(&[
        ("foo", n("1.23")),
        ("bar", n("BarString")),
        (
            "baz",
            AttributeValue::L(vec![n("1.23"), n("BarString"), florn]),
        ),
    ])
}

#[test]
fn virtual_field() {
    //= spec/searchable-encryption/virtual.md#virtual-field-initialization
    //= type=test
    //# The evaluation of a Virtual Field MUST be the concatenation of all of its parts,
    //# in the order they are configured.
    assert_eq!(
        my_field().value(&my_item()).unwrap().as_deref(),
        Some("1.23barstringFlornString")
    );
}

#[test]
fn transforms_apply_in_order() {
    let field = VirtField {
        parts: vec![part(
            "foo",
            vec![VirtualTransform::insert("Ab"), VirtualTransform::upper()],
        )],
    };
    let it = item(&[("foo", s("x"))]);

    // Upper before insert would give "XAb".
    //= spec/searchable-encryption/virtual.md#virtual-part-initialization
    //= type=test
    //# The evaluation of a Virtual Part MUST be the value of its location,
    //# which is then transformed by each Virtual Transform,
    //# in the order they are configured.
    assert_eq!(field.value(&it).unwrap().as_deref(), Some("XAB"));
}

#[test]
fn virtual_field_missing_part_is_none() {
    let mut it = my_item();
    it.remove("bar");

    //= spec/searchable-encryption/virtual.md#virtual-part-initialization
    //= type=test
    //= reason=only the missing-location half is observable; non-string values stringify or raise Validation, as in Dafny
    //# Evaluation MUST return no value if the location does not exist,
    //# or is not a plain string value.
    assert_eq!(my_field().value(&it).unwrap(), None);
}

#[test]
fn virtual_field_part_that_is_not_a_string_fails() {
    // Adjacent guard for virtual.md#virtual-part-initialization ("no value ... not a plain string value"):
    // a string set raises a Validation error instead of no value, matching Dafny TermToString.
    let mut it = my_item();
    it.insert("bar".to_owned(), AttributeValue::Ss(vec!["a".to_owned()]));
    let err = my_field().value(&it).unwrap_err();
    assert!(matches!(err, Error::Validation(_)));
    assert_eq!(
        err.message(),
        "a beacon cannot be built from a string set; use a set beacon"
    );
}

#[test]
fn virt_lookups_read_virtual_fields_and_attributes() {
    let vf: VirtualFieldMap = [("myField".to_owned(), my_field())].into();
    let it = my_item();
    let field = TermLoc::attribute("myField");
    let want = "1.23barstringFlornString";
    assert_eq!(virt_to_attr(&field, &it, &vf).unwrap(), Some(s(want)));
    assert_eq!(
        virt_to_bytes(&field, &it, &vf).unwrap(),
        Some(want.as_bytes().to_vec())
    );
    assert_eq!(
        virt_to_string(&field, &it, &vf).unwrap().as_deref(),
        Some(want)
    );

    // A path into an attribute is never a virtual field.
    let nested = TermLoc::parse("baz[0]").unwrap();
    assert_eq!(virt_to_attr(&nested, &it, &vf).unwrap(), Some(n("1.23")));
    assert_eq!(
        virt_to_string(&nested, &it, &vf).unwrap().as_deref(),
        Some("1.23")
    );
    assert_eq!(
        virt_to_bytes(&TermLoc::attribute("foo"), &it, &vf).unwrap(),
        Some(b"1.23".to_vec())
    );
    let missing = TermLoc::attribute("nope");
    assert_eq!(virt_to_attr(&missing, &it, &vf).unwrap(), None);
    assert_eq!(virt_to_bytes(&missing, &it, &vf).unwrap(), None);
    assert_eq!(virt_to_string(&missing, &it, &vf).unwrap(), None);
}

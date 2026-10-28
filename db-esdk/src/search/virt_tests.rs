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
    assert_eq!(t(&u, MIXED), "ABCD\u{f1}\u{d1}EF");
}

#[test]
fn lower() {
    let l = VirtualTransform::lower();
    assert_eq!(t(&l, ""), "");
    assert_eq!(t(&l, MIXED), "abcd\u{f1}\u{d1}ef");
}

#[test]
fn insert() {
    let i = VirtualTransform::insert("_foo");
    assert_eq!(t(&i, ""), "_foo");
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
        assert_eq!(t(&p3, input), input);
        assert_eq!(t(&pn3, input), "");
    }
    assert_eq!(t(&p0, MIXED), "");
    assert_eq!(t(&p3, MIXED), "aBc");
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
        assert_eq!(t(&p3, input), input);
        assert_eq!(t(&pn3, input), "");
    }
    assert_eq!(t(&p0, MIXED), "");
    assert_eq!(t(&p3, MIXED), "\u{d1}eF");
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
        ((4, 2), ""),
        ((2, -2), "cd"),
        ((-4, 4), "cd"),
        ((-4, -2), "cd"),
        // Positions are clamped into the string: past the end is the last character.
        ((-100, 100), "abcde"),
        ((0, 0), ""),
    ];
    for ((low, high), want) in cases {
        assert_eq!(
            t(&VirtualTransform::substring(low, high), "abcdef"),
            want,
            "{low}..{high}"
        );
    }
    assert_eq!(t(&VirtualTransform::substring(0, 3), ""), "");
}

#[test]
fn segment() {
    let input = "1.23.456.7890";
    let cases = [
        (0, "1"),
        (1, "23"),
        (2, "456"),
        (3, "7890"),
        (4, ""),
        (5, ""),
        (-1, "7890"),
        (-2, "456"),
        (-3, "23"),
        (-4, "1"),
        (-5, ""),
        (-6, ""),
    ];
    for (index, want) in cases {
        assert_eq!(
            t(&VirtualTransform::segment('.', index), input),
            want,
            "{index}"
        );
    }
    // Without the split character, the whole string is the only segment.
    assert_eq!(t(&VirtualTransform::segment('.', 0), "abc"), "abc");
}

#[test]
fn segments() {
    let input = "1.23.456.7890";
    let cases = [
        ((0, 0), ""),
        ((1, 2), "23"),
        ((1, 3), "23.456"),
        ((-3, 2), "23"),
        ((0, -1), "1.23.456"),
        ((3, 1), ""),
    ];
    for ((low, high), want) in cases {
        assert_eq!(
            t(&VirtualTransform::segments('.', low, high), input),
            want,
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
    assert_eq!(field.value(&it).unwrap().as_deref(), Some("XAB"));
}

#[test]
fn virtual_field_missing_part_is_none() {
    let mut it = my_item();
    it.remove("bar");
    assert_eq!(my_field().value(&it).unwrap(), None);
}

#[test]
fn virtual_field_part_that_is_not_a_string_fails() {
    let mut it = my_item();
    it.insert("bar".to_owned(), AttributeValue::Ss(vec!["a".to_owned()]));
    let err = my_field().value(&it).unwrap_err();
    assert!(matches!(err, Error::Validation(_)));
    assert_eq!(err.message(), "Can't convert String Set to string.");
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

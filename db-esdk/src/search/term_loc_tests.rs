// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use aws_smithy_types::Blob;

use super::*;
use crate::search::test_fixtures::{item, n, s};

fn parse(p: &str) -> TermLoc {
    TermLoc::parse(p).unwrap()
}

fn parse_err(p: &str) -> String {
    let err = TermLoc::parse(p).unwrap_err();
    assert!(matches!(err, Error::Validation(_)), "{err:?}");
    err.message().to_owned()
}

#[test]
fn parse_paths() {
    let loc = parse("a.b[12].c");
    assert_eq!(loc.attribute_name(), "a");
    assert!(!loc.is_whole_attribute());
    assert_eq!(
        loc.selectors,
        vec![
            Selector::Map("b".to_owned()),
            Selector::List(12),
            Selector::Map("c".to_owned()),
        ]
    );
    assert_eq!(loc.to_string(), "a.b[12].c");

    let whole = parse("abc");
    assert!(whole.is_whole_attribute());
    assert_eq!(whole, TermLoc::attribute("abc"));
    assert_eq!(whole.to_string(), "abc");

    assert_eq!(
        parse("x[0][1]").selectors,
        vec![Selector::List(0), Selector::List(1)]
    );
}

#[test]
fn parse_errors() {
    assert_eq!(
        parse_err(""),
        "a beacon or virtual field path must not be empty"
    );

    //= spec/searchable-encryption/virtual.md#segments
    //= type=test
    //# A Segment MUST be one of
    assert_eq!(
        parse_err("a[1"),
        "a list index in a path must be written as [N]"
    );
    assert_eq!(
        parse_err("a[1x]"),
        "a list index in a path has a character that is not a digit: x"
    );
    assert_eq!(
        parse_err("a[99999999999999999999]"),
        "a list index in a path is too big: 99999999999999999999"
    );
}

fn nested_item() -> HashMap<String, AttributeValue> {
    let inner = AttributeValue::M([("c".to_owned(), s("deep"))].into());
    item(&[
        (
            "a",
            AttributeValue::M(
                [
                    ("b".to_owned(), AttributeValue::L(vec![n("1"), inner])),
                    ("real".to_owned(), s("named")),
                ]
                .into(),
            ),
        ),
        ("flag", AttributeValue::Bool(false)),
        ("on", AttributeValue::Bool(true)),
        ("nul", AttributeValue::Null(true)),
        ("bin", AttributeValue::B(Blob::new(vec![1]))),
    ])
}

#[test]
fn term_to_attr_follows_selectors() {
    let it = nested_item();
    assert_eq!(parse("a.b[1].c").term_to_attr(&it, None), Some(s("deep")));
    assert_eq!(parse("a.b[0]").term_to_attr(&it, None), Some(n("1")));
    // Every wrong step yields no value.
    for bad in ["a.b[2]", "a.b.c", "a[0]", "a.nope", "a.b[0].x", "missing"] {
        assert_eq!(parse(bad).term_to_attr(&it, None), None, "{bad}");
    }
}

#[test]
fn map_keys_resolve_through_names() {
    let it = nested_item();
    let names: HashMap<String, String> = [("#r".to_owned(), "real".to_owned())].into();
    let loc = parse("a.#r");
    assert_eq!(loc.term_to_attr(&it, Some(&names)), Some(s("named")));
    assert_eq!(loc.term_to_attr(&it, None), None);
}

#[test]
fn get_terminal_errors() {
    let it = nested_item();
    let top = &it["a"];
    let err = |sel: Vec<Selector>, v: &AttributeValue| {
        get_terminal(v, &sel, None)
            .unwrap_err()
            .message()
            .to_owned()
    };
    assert_eq!(
        err(vec![Selector::List(0)], top),
        "the path uses a list index on a map"
    );
    let list = AttributeValue::L(vec![]);
    assert_eq!(
        err(vec![Selector::Map("x".to_owned())], &list),
        "the path uses a map key on a list"
    );
    assert_eq!(
        err(vec![Selector::List(0)], &list),
        "the path's list index is past the end of the list"
    );
    assert_eq!(
        err(vec![Selector::Map("zz".to_owned())], top),
        "the path\'s key zz is not in the map"
    );
    let kinds = [
        (s("x"), "string"),
        (n("1"), "number"),
        (AttributeValue::B(Blob::new(vec![])), "binary"),
        (AttributeValue::Ss(vec![]), "string set"),
        (AttributeValue::Ns(vec![]), "number set"),
        (AttributeValue::Bs(vec![]), "binary set"),
        (AttributeValue::Bool(true), "boolean"),
        (AttributeValue::Null(true), "null"),
    ];
    for (v, kind) in kinds {
        assert_eq!(
            err(vec![Selector::List(0)], &v),
            format!("Found {kind} with parts left over.")
        );
    }
}

#[test]
fn term_to_string() {
    let it = nested_item();
    let get = |p: &str| parse(p).term_to_string(&it);
    assert_eq!(get("a.b[1].c").unwrap().as_deref(), Some("deep"));
    assert_eq!(get("a.b[0]").unwrap().as_deref(), Some("1"));
    assert_eq!(get("flag").unwrap().as_deref(), Some("false"));
    assert_eq!(get("on").unwrap().as_deref(), Some("true"));
    assert_eq!(get("nul").unwrap().as_deref(), Some("null"));
    assert_eq!(get("missing").unwrap(), None);
    assert_eq!(
        get("bin").unwrap_err().message(),
        "a beacon cannot be built from a binary value"
    );
    assert_eq!(
        get("a.b").unwrap_err().message(),
        "a beacon cannot be built from a list"
    );
    assert_eq!(
        get("a").unwrap_err().message(),
        "a beacon cannot be built from a map"
    );
    for (v, msg) in [
        (
            AttributeValue::Ss(vec![]),
            "a beacon cannot be built from a string set; use a set beacon",
        ),
        (
            AttributeValue::Ns(vec![]),
            "a beacon cannot be built from a number set",
        ),
        (
            AttributeValue::Bs(vec![]),
            "a beacon cannot be built from a binary set",
        ),
    ] {
        assert_eq!(attr_value_to_string(&v).unwrap_err().message(), msg);
    }
}

#[test]
fn term_to_bytes() {
    let it = nested_item();
    assert_eq!(
        parse("a.b[1].c").term_to_bytes(&it).unwrap(),
        Some(b"deep".to_vec())
    );
    assert_eq!(parse("missing").term_to_bytes(&it).unwrap(), None);
}

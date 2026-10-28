// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests ported from DynamoDbEncryption/test/FilterExpr.dfy, for the parts of it that do not
//! need beacons. The beacon cases (`Beaconize`, `BeaconizeParsedExpr`) test `search::filter`.

use super::*;
use aws_crypto_mpl::aws_sdk_dynamodb::primitives::Blob;

type Item = HashMap<String, AttributeValue>;

fn ds(s: &str) -> AttributeValue {
    AttributeValue::S(s.to_owned())
}

fn dn(s: &str) -> AttributeValue {
    AttributeValue::N(s.to_owned())
}

fn db(b: &[u8]) -> AttributeValue {
    AttributeValue::B(Blob::new(b))
}

fn attr(s: &str) -> Token {
    Token::Attr(s.to_owned())
}

fn map<V: Clone>(pairs: &[(&str, V)]) -> HashMap<String, V> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), v.clone()))
        .collect()
}

fn names(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

/// `SimpleItem` from BeaconTestFixtures.dfy.
fn simple_item() -> Item {
    let year = dn("1984");
    map(&[
        ("std2", dn("1.23")),
        ("std4", ds("abc")),
        ("std6", AttributeValue::L(vec![ds("666")])),
        (
            "Date",
            AttributeValue::M(map(&[("Month", ds("May")), ("Year", year.clone())])),
        ),
        ("Year", year),
        ("Name", ds("MyName")),
        ("Title", ds("MyTitle")),
    ])
}

/// Whether `item` passes `expr`: the pipeline `FilterResults` runs for an expression
/// that names no beacon.
fn filter(
    expr: &str,
    item: &Item,
    names: Option<&HashMap<String, String>>,
    values: &Item,
) -> Result<bool, Error> {
    let rpn = convert_to_rpn(&convert_to_prefix(&parse_expr(expr)));
    eval_expr(&rpn, item, names, values)
}

/// Assert each `(expr, passes)` case against `item`.
fn check(
    item: &Item,
    names: Option<&HashMap<String, String>>,
    values: &Item,
    cases: &[(&str, bool)],
) {
    for (expr, expected) in cases {
        assert_eq!(
            filter(expr, item, names, values).unwrap(),
            *expected,
            "{expr}"
        );
    }
}

/// The validation error `expr` fails with.
fn filter_err(expr: &str, item: &Item, values: &Item) -> Error {
    let err = filter(expr, item, None, values).unwrap_err();
    assert!(matches!(err, Error::Validation(..)), "{expr}: {err:?}");
    err
}

#[test]
#[allow(clippy::many_single_char_names)] // a..f name the strings in their order
fn unicode_less() {
    // A..F are strictly increasing in code point order, though D, E and F are surrogate
    // pairs in UTF-16 and so sort below C there.
    let (a, b, c, d, e, f) = (
        "A",
        "\u{d000}",
        "\u{fe4c}",
        "\u{10001}",
        "\u{10002}",
        "\u{20002}",
    );
    let strs = [
        format!("{a}{b}{c}{d}"),
        format!("{b}{c}"),
        format!("{c}{d}"),
        format!("{d}{c}"),
        format!("{d}{c}{b}{a}"),
        format!("{e}{d}"),
        format!("{f}{d}"),
    ];
    for (i, x) in strs.iter().enumerate() {
        for (j, y) in strs.iter().enumerate() {
            let less = |p: &str, q: &str| apply_binary_comp(&Token::Lt, &ds(p), &ds(q)).unwrap();
            assert_eq!(i < j, less(x, y), "{i} < {j}");
            assert_eq!(i <= j, !less(y, x), "{i} <= {j}");
        }
    }
}

#[test]
fn low_level() {
    assert_eq!(parse_expr("and"), [Token::And]);
    assert_eq!(parse_expr("  AnD   "), [Token::And]);
    assert_eq!(
        parse_expr(" A  AnD  B "),
        [attr("A"), Token::And, attr("B")]
    );
    assert_eq!(
        parse_expr(" A_B  AnD  B_C "),
        [attr("A_B"), Token::And, attr("B_C")]
    );

    let input = [
        Token::Not,
        attr("A"),
        Token::In,
        Token::Open,
        attr("B"),
        Token::Comma,
        attr("C"),
        Token::Close,
        Token::Or,
    ];
    assert!(is_in(&input, 1));
    assert!(is_in(&input[1..], 0));
    assert!(!is_in(&input, 0));
    assert_eq!(
        convert_to_prefix(&input),
        [
            Token::Not,
            Token::In,
            Token::Open,
            attr("A"),
            Token::Comma,
            attr("B"),
            Token::Comma,
            attr("C"),
            Token::Close,
            Token::Or
        ]
    );

    let input = [
        Token::And,
        Token::Or,
        Token::Not,
        Token::And,
        Token::Or,
        Token::Not,
        Token::And,
        Token::Or,
        Token::Not,
    ];
    assert_eq!(convert_to_prefix(&input), input);

    let input = &[
        Token::Not,
        attr("A"),
        Token::In,
        Token::Open,
        attr("B"),
        Token::Comma,
        attr("C"),
        Token::Close,
    ];
    assert_eq!(
        convert_to_prefix(input),
        [
            Token::Not,
            Token::In,
            Token::Open,
            attr("A"),
            Token::Comma,
            attr("B"),
            Token::Comma,
            attr("C"),
            Token::Close
        ]
    );
}

#[test]
fn between_converts_to_prefix_and_rpn() {
    let parsed = parse_expr("size(A) BETWEEN :x AND B");
    let prefix = convert_to_prefix(&parsed);
    assert_eq!(
        parsed_expr_to_string(&prefix),
        "BETWEEN ( size ( A ) , :x , B )"
    );
    assert_eq!(
        convert_to_rpn(&prefix),
        [
            attr("A"),
            Token::Size,
            Token::Value(":x".to_owned()),
            attr("B"),
            Token::Between
        ]
    );
    // An incomplete BETWEEN is left as written.
    let parsed = parse_expr("A BETWEEN :x OR B = C");
    assert_eq!(convert_to_prefix(&parsed), parsed);
}

#[test]
fn rpn_respects_precedence() {
    let rpn = convert_to_rpn(&convert_to_prefix(&parse_expr(
        "NOT A = :a OR B < :b AND C <> :c",
    )));
    assert_eq!(
        parsed_expr_to_string(&rpn),
        "A :a = NOT B :b < C :c <> AND OR"
    );
}

#[test]
fn every_token_writes_back() {
    let parsed = parse_expr(
        "a = b <> c < d > e <= f >= g between in ( ) , not and or attribute_exists \
         attribute_not_exists attribute_type begins_with contains size :v #n x.y[2]",
    );
    assert_eq!(
        parsed_expr_to_string(&parsed),
        "a = b <> c < d > e <= f >= g BETWEEN IN ( ) , NOT AND OR attribute_exists \
         attribute_not_exists attribute_type begins_with contains size :v #n x.y[2]"
    );
}

#[test]
fn parse_stops_at_unknown_character() {
    assert_eq!(
        parse_expr("A = :b ! C"),
        [attr("A"), Token::Eq, Token::Value(":b".to_owned())]
    );
    assert_eq!(parse_expr(""), []);
}

#[test]
fn extract_attributes_cases() {
    type Case<'a> = (&'a str, Option<&'a HashMap<String, String>>, &'a [&'a str]);
    let attr_map = names(&[("#one", "two"), ("#three", "four")]);
    let m = Some(&attr_map);
    let none: &[&str] = &[];
    let cases: [Case<'_>; 21] = [
        ("", None, none),
        ("", m, none),
        ("A < :b", None, &["A"]),
        ("A <= :b", m, &["A"]),
        ("A < B", None, &["A", "B"]),
        ("A < B", m, &["A", "B"]),
        (":a >= B", None, &["B"]),
        (":a = B", m, &["B"]),
        ("#one <> B", m, &["two", "B"]),
        ("A < #three", m, &["A", "four"]),
        ("#one < #three", m, &["two", "four"]),
        ("A in :a, :b, :c", m, &["A"]),
        ("A between B and C", m, &["A", "B", "C"]),
        ("not begins_with(A, :b)", m, &["A"]),
        ("A < B or C <> D", m, &["A", "B", "C", "D"]),
        ("contains(A, :b)", m, &["A"]),
        ("begins_with(A, :b)", m, &["A"]),
        // These ignore the underlying value, so they can work on any attribute.
        ("attribute_exists(A)", m, none),
        ("attribute_not_exists(A)", m, none),
        ("size(A)", m, none),
        (
            "A < B or size(C) or D between E and F",
            m,
            &["A", "B", "D", "E", "F"],
        ),
    ];
    for (expr, names, expected) in cases {
        assert_eq!(extract_attributes(expr, names), expected, "{expr}");
    }
}

#[test]
fn all_attributes_includes_value_ignoring_functions() {
    let attr_map = names(&[("#one", "two")]);
    assert_eq!(
        all_attributes("attribute_exists(#one) AND size(B) > :x", Some(&attr_map)),
        ["two", "B"]
    );
}

#[test]
fn filter_compare() {
    let item = map(&[("one", ds("abc")), ("two", ds("cde")), ("three", ds("cde"))]);
    check(
        &item,
        None,
        &Item::new(),
        &[
            ("one < two", true),
            ("one > two", false),
            ("one <= two", true),
            ("one >= two", false),
            ("one <> two", true),
            ("one = two", false),
            ("three < two", false),
            ("three > two", false),
            ("three <= two", true),
            ("three >= two", true),
            ("three <> two", false),
            ("three = two", true),
        ],
    );
}

#[test]
fn filter_fail_numeric() {
    let item = map(&[("one", dn("800"))]);
    let values = map(&[(":two", dn("foo"))]);
    let err = filter_err("one < :two", &item, &values);
    assert_eq!(
        err.message(),
        "Number needs digits either before or after the decimal point. when parsing 'foo'."
    );
}

#[test]
fn filter_compare_numeric() {
    let item = map(&[("one", dn("800"))]);
    let values = map(&[(":two", dn("0800.000e0"))]);
    check(
        &item,
        None,
        &values,
        &[
            ("one < :two", false),
            ("one > :two", false),
            ("one <= :two", true),
            ("one >= :two", true),
            ("one <> :two", false),
            ("one = :two", true),
            (":two < one", false),
            (":two > one", false),
            (":two <= one", true),
            (":two >= one", true),
            (":two <> one", false),
            (":two = one", true),
        ],
    );
}

#[test]
fn filter_in() {
    let item = map(&[("one", ds("abc")), ("two", ds("cde")), ("three", ds("cde"))]);
    check(
        &item,
        None,
        &Item::new(),
        &[
            ("one in (two, three)", false),
            ("two in (one, three)", true),
            ("three in (two, one)", true),
            ("three in (one, one, one, one, two, one, one)", true),
            ("three in (one, one, one, one, one, one, one)", false),
        ],
    );
}

const BETWEEN_CASES: [(&str, bool); 5] = [
    ("one between two and three", false),
    ("two between one and three", true),
    ("two between three and one", false),
    ("two between two and three", true),
    ("two between one and two", true),
];

#[test]
fn filter_between_alpha() {
    let item = map(&[("one", ds("abc")), ("two", ds("bcd")), ("three", ds("cde"))]);
    check(&item, None, &Item::new(), &BETWEEN_CASES);
}

#[test]
fn filter_between_number() {
    // Ordered by value, not as strings: "185" < "52" < "9".
    let item = map(&[("one", dn("9")), ("two", dn("52")), ("three", dn("185"))]);
    check(&item, None, &Item::new(), &BETWEEN_CASES);
}

#[test]
fn filter_size() {
    let item = map(&[("one", dn("9")), ("two", dn("52")), ("three", dn("185"))]);
    let values = map(&[(":uno", dn("1")), (":dos", dn("2")), (":tres", dn("3"))]);
    check(
        &item,
        None,
        &values,
        &[
            ("size(one) = :uno", true),
            ("size(two) between :uno and :tres", true),
            ("size(three) > :dos", true),
            ("size(two) in (:uno, :dos)", true),
            ("size(two) in (:uno, :tres)", false),
        ],
    );
}

#[test]
fn filter_contains() {
    let item = map(&[
        ("one", dn("abcdef")),
        ("two", dn("a")),
        ("three", dn("f")),
        ("four", dn("cde")),
        ("five", dn("efg")),
    ]);
    check(
        &item,
        None,
        &Item::new(),
        &[
            ("contains(one, two)", true),
            ("contains(one, three)", true),
            ("contains(one, four)", true),
            ("contains(one, five)", false),
        ],
    );
}

#[test]
fn filter_begins() {
    let item = map(&[
        ("one", dn("abcdef")),
        ("two", dn("a")),
        ("three", dn("f")),
        ("four", dn("abcd")),
        ("five", dn("abcdf")),
    ]);
    check(
        &item,
        None,
        &Item::new(),
        &[
            ("begins_with(one, two)", true),
            ("begins_with(one, three)", false),
            ("begins_with(one, four)", true),
            ("begins_with(one, five)", false),
        ],
    );
}

#[test]
fn filter_complex() {
    let item = map(&[("one", dn("1")), ("two", dn("2")), ("three", dn("3"))]);
    let values = map(&[(":four", dn("4")), (":five", dn("5")), (":six", dn("6"))]);
    check(
        &item,
        None,
        &values,
        &[
            ("one < :four and two < :five", true),
            ("one < :four or two > :five", true),
            // Not in the reference: each side false.
            ("one > :four and two < :five", false),
            ("one > :four or two > :five", false),
        ],
    );
}

#[test]
fn filter_indirect_names() {
    let item = map(&[("one", ds("abc")), ("two", ds("cde")), ("three", ds("cde"))]);
    let values = map(&[(":uno", ds("ab")), (":dos", ds("bc"))]);
    let n = names(&[("#eine", "one"), ("#zwei", "two"), ("#drei", "three")]);
    check(
        &item,
        Some(&n),
        &values,
        &[
            ("one < two", true),
            ("one > two", false),
            ("#eine < #zwei", true),
            ("#eine > #zwei", false),
            ("#eine < :dos", true),
            ("#eine > :dos", false),
        ],
    );
}

#[test]
fn filter_indirect_names_with_loc() {
    let values = map(&[(":uno", ds("ab")), (":dos", dn("2"))]);
    let n = names(&[("#eine", "Date"), ("#zwei", "Month"), ("#drei", "Year")]);
    check(
        &simple_item(),
        Some(&n),
        &values,
        &[
            ("Date.Month < :uno", true),
            ("Date.Month > :uno", false),
            ("Date.#zwei < :uno", true),
            ("Date.#zwei > :uno", false),
        ],
    );
}

#[test]
fn filter_attr_ops() {
    let n = names(&[("#fecha", "Date")]);
    let values = map(&[(":m", ds("M")), (":s", ds("N"))]);
    check(
        &simple_item(),
        Some(&n),
        &values,
        &[
            ("attribute_exists(Date)", true),
            ("attribute_exists(Nope)", false),
            ("attribute_not_exists(Date)", false),
            ("attribute_not_exists(Nope)", true),
            ("attribute_type(Date, :m)", true),
            ("attribute_type(std2, :s)", true),
            ("not attribute_exists(Date)", false),
            ("not attribute_exists(Nope)", true),
            // Not in the reference: the wrong type, and a name placeholder.
            ("attribute_type(std2, :m)", false),
            ("attribute_exists(#fecha)", true),
        ],
    );
}

#[test]
fn filter_size_in() {
    let item = map(&[("one", dn("9")), ("two", dn("52")), ("three", dn("185"))]);
    let values = map(&[(":uno", dn("1")), (":dos", dn("2")), (":tres", dn("3"))]);
    check(
        &item,
        None,
        &values,
        &[
            ("size(one) in (:uno, :dos, :tres)", true),
            (":uno in (size(one), :dos, :tres)", true),
            (":uno in (:dos, :tres, size(one))", true),
            (":uno in (:dos, :tres)", false),
        ],
    );
}

#[test]
fn size_of_each_type() {
    let cases = [
        // UTF-16 code units, as DynamoDB counts them.
        (ds("a\u{10001}"), 3),
        (dn("-1.5"), 4),
        (db(&[1, 2, 3]), 3),
        (AttributeValue::Ss(vec!["a".into(), "b".into()]), 2),
        (AttributeValue::Ns(vec!["1".into()]), 1),
        (AttributeValue::Bs(vec![Blob::new([1]), Blob::new([2])]), 2),
        (AttributeValue::M(map(&[("k", ds("v"))])), 1),
        (AttributeValue::L(vec![ds("a"), ds("b"), ds("c")]), 3),
        (AttributeValue::Bool(true), 1),
    ];
    for (v, size) in cases {
        assert_eq!(get_size(&v), size, "{v:?}");
    }
}

#[test]
fn contains_each_type() {
    let ss = AttributeValue::Ss(vec!["x".into(), "yz".into()]);
    let ns = AttributeValue::Ns(vec!["1".into(), "2".into()]);
    let bs = AttributeValue::Bs(vec![Blob::new([1, 2])]);
    let list = AttributeValue::L(vec![ds("x"), dn("7")]);
    let cases = [
        (ds("abc"), ds(""), true),
        (ds("a\u{10001}b"), ds("\u{10001}b"), true),
        (db(&[1, 2, 3]), db(&[2, 3]), true),
        (db(&[1, 2, 3]), db(&[3, 2]), false),
        (ss.clone(), ds("yz"), true),
        // A set element must match whole.
        (ss, ds("y"), false),
        (ns.clone(), dn("2"), true),
        (ns, ds("2"), false),
        (bs.clone(), db(&[1, 2]), true),
        (bs, db(&[1]), false),
        (list.clone(), dn("7"), true),
        (list, ds("7"), false),
        (ds("abc"), dn("1"), false),
    ];
    for (haystack, needle, expected) in cases {
        assert_eq!(
            does_contain(&haystack, &needle),
            expected,
            "{haystack:?} {needle:?}"
        );
    }
}

#[test]
fn begins_with_each_type() {
    let list = AttributeValue::L(vec![ds("a"), ds("b"), ds("c")]);
    let cases = [
        (db(&[1, 2, 3]), db(&[1, 2]), true),
        (db(&[1, 2, 3]), db(&[2]), false),
        (list.clone(), ds("a"), true),
        (list.clone(), ds("b"), false),
        (
            list.clone(),
            AttributeValue::L(vec![ds("a"), ds("b")]),
            true,
        ),
        (list, AttributeValue::L(vec![ds("b")]), false),
        (AttributeValue::L(vec![]), ds("a"), false),
        (ds("abc"), db(b"a"), false),
    ];
    for (haystack, needle, expected) in cases {
        assert_eq!(
            begins_with(&haystack, &needle),
            expected,
            "{haystack:?} {needle:?}"
        );
    }
}

#[test]
fn compare_binary_and_mixed_types() {
    let item = map(&[("b", db(&[1, 2])), ("s", ds("abc"))]);
    let values = map(&[(":b", db(&[1, 3])), (":n", dn("1"))]);
    check(
        &item,
        None,
        &values,
        &[
            ("b < :b", true),
            ("b >= :b", false),
            ("b = :b", false),
            // A string and a number are never equal, and neither is <= the other.
            ("s = :n", false),
            ("s <= :n", false),
            ("s >= :n", false),
        ],
    );
}

#[test]
fn malformed_expressions_fail_validation() {
    let item = map(&[("one", ds("abc")), ("two", ds("abd"))]);
    let values = Item::new();
    let cases = [
        (
            "one < :missing",
            "the filter expression compares something that is not a value",
        ),
        (
            "not one",
            "the filter expression's NOT operand is not true or false",
        ),
        ("not", "the filter expression's NOT has no operand"),
        (
            "one",
            "the filter expression does not evaluate to true or false",
        ),
        (
            "one two",
            "the filter expression does not evaluate to true or false",
        ),
        (
            "one and two",
            "the filter expression has an AND or OR operand that is not true or false",
        ),
        (
            "and",
            "the filter expression has an operator with a missing operand",
        ),
        (
            "one between :missing and two",
            "the filter expression's BETWEEN operands must be values",
        ),
        (
            "begins_with(one, :missing)",
            "the filter expression's begins_with operands must be values",
        ),
        (
            "contains(one, :missing)",
            "the filter expression's contains operands must be values",
        ),
        (
            "size(:missing) = one",
            "the filter expression's size operand must be a value",
        ),
        (
            "attribute_exists()",
            "the filter expression has a function with missing arguments",
        ),
    ];
    for (expr, msg) in cases {
        assert_eq!(filter_err(expr, &item, &values).message(), msg, "{expr}");
    }
}

#[test]
fn stack_shape_errors() {
    let item = Item::new();
    let values = map(&[(":x", ds("x"))]);
    let t = Token::Value(":x".to_owned());
    // `:x = :x = :x`: the second `=` compares a boolean with a value.
    let rpn = [t.clone(), t.clone(), Token::Eq, t, Token::Eq];
    let err = eval_expr(&rpn, &item, None, &values).unwrap_err();
    assert!(matches!(err, Error::Validation(..)));
    assert_eq!(
        err.message(),
        "the filter expression compares something that is not a value"
    );
    let err = eval_expr(&[Token::Between], &item, None, &values).unwrap_err();
    assert_eq!(
        err.message(),
        "the filter expression has a function with missing arguments"
    );
    let err = eval_expr(&[Token::In], &item, None, &values).unwrap_err();
    assert_eq!(err.message(), "the filter expression's IN has no values");
}

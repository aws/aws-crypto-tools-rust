// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Compare two decimal strings as numbers, without converting them to floating point.

use std::cmp::Ordering;

/// The digits of `s` as an integer, skipping other characters.
/// Saturates at `i64::MAX`.
fn str_to_int_inner(s: &str) -> i64 {
    s.chars()
        .filter_map(|c| c.to_digit(10))
        .fold(0i64, |acc, d| {
            acc.saturating_mul(10).saturating_add(i64::from(d))
        })
}

fn skip_leading_space(s: &str) -> &str {
    s.trim_start_matches(|c: char| c <= ' ')
}

/// An exponent: its digits, negated when it starts with `-`.
fn str_to_int(s: &str) -> i64 {
    let tmp = skip_leading_space(s);
    if tmp.starts_with('-') {
        -str_to_int_inner(s)
    } else {
        str_to_int_inner(s)
    }
}

/// The mantissa and exponent of `x`.
fn split_exp(x: &str) -> (&str, i64) {
    match x.split_once('e').or_else(|| x.split_once('E')) {
        Some((m, e)) => (m, str_to_int(e)),
        None => (x, 0),
    }
}

/// The integer and fraction digits of a mantissa, without leading or trailing zeros.
fn split_dot(x: &str) -> (&str, &str) {
    match x.split_once('.') {
        Some((i, f)) => (i.trim_start_matches('0'), f.trim_end_matches('0')),
        None => (x.trim_start_matches('0'), ""),
    }
}

/// Compare two digit strings of the same length by value.
fn str_cmp(x: &str, y: &str) -> Ordering {
    x.cmp(y)
}

/// `x` padded with zeros to `len` characters.
fn append_zeros(x: &str, len: usize) -> String {
    format!("{x}{}", "0".repeat(len.saturating_sub(x.len())))
}

fn len_i64(s: &str) -> i64 {
    i64::try_from(s.len()).unwrap_or(i64::MAX)
}

/// Compare two non-negative numbers.
fn compare_float_inner(x: &str, y: &str) -> Ordering {
    let (x_mant, x_exp) = split_exp(x);
    let (y_mant, y_exp) = split_exp(y);
    let x_num = split_dot(x_mant);
    let y_num = split_dot(y_mant);
    let x_digits_full = format!("{}{}", x_num.0, x_num.1);
    let y_digits_full = format!("{}{}", y_num.0, y_num.1);
    let x_digits = x_digits_full.trim_start_matches('0');
    let y_digits = y_digits_full.trim_start_matches('0');
    let log_x = x_exp - len_i64(x_num.1) + len_i64(x_digits);
    let log_y = y_exp - len_i64(y_num.1) + len_i64(y_digits);
    match log_x.cmp(&log_y) {
        Ordering::Equal => {}
        other => return other,
    }
    match x_digits.len().cmp(&y_digits.len()) {
        Ordering::Less => str_cmp(&append_zeros(x_digits, y_digits.len()), y_digits),
        Ordering::Greater => str_cmp(x_digits, &append_zeros(y_digits, x_digits.len())),
        Ordering::Equal => str_cmp(x_digits, y_digits),
    }
}

/// Whether `x`, after a sign, is zero: only zeros and dots before any exponent.
fn is_zero(x: &str) -> bool {
    for c in x.chars() {
        match c {
            '0' | '.' => {}
            '1'..='9' => return false,
            _ => return true,
        }
    }
    true
}

/// `x` without leading space or `+`, with every form of zero as `0`.
fn clean_number(x: &str) -> &str {
    let x = skip_leading_space(x);
    let x = x.strip_prefix('+').unwrap_or(x);
    let zero = match x.strip_prefix('-') {
        Some(rest) => is_zero(rest),
        None => is_zero(x),
    };
    if zero { "0" } else { x }
}

/// Compare `x` and `y` as decimal numbers.
pub(crate) fn compare_float(x: &str, y: &str) -> Ordering {
    let x = clean_number(x);
    let y = clean_number(y);
    match (x.strip_prefix('-'), y.strip_prefix('-')) {
        (Some(xa), Some(ya)) => compare_float_inner(ya, xa),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => compare_float_inner(x, y),
    }
}

// Vectors ported from StandardLibrary/test/FloatCompare.dfy (MPL).
#[cfg(test)]
mod tests {
    use super::compare_float;
    use std::cmp::Ordering::{self, Equal, Greater, Less};

    const NEGATIVE_TWO: &[&str] = &[
        "-2",
        "-2.",
        "-2.0",
        "-2e0",
        "-2.e0",
        "-2.0e0",
        "-2.0e+0",
        "-2.0e-0",
        "-.2e1",
        "-0.2e1",
        "-0.2e+1",
        "-0.02e2",
        "-20e-1",
        "-20.e-1",
        "-200.0e-2",
    ];
    const NEGATIVE_ONE: &[&str] = &[
        "-1",
        "-1.",
        "-1.0",
        "-1e0",
        "-1.e0",
        "-1.0e0",
        "-1.0e+0",
        "-1.0e-0",
        "-.1e1",
        "-0.1e1",
        "-0.1e+1",
        "-0.01e2",
        "-10e-1",
        "-10.e-1",
        "-100.0e-2",
    ];
    const ZERO: &[&str] = &[
        "0", "+0", "-0", "0.", "+0.", "-0.", "00", "+00", "-00", "0.0", "+0.0", "-0.0", "00.00",
        "+00.00", "-00.00", ".0", "+.0", "-.0", "0e0", "+0e0", "+0e+0", "+0e-0", "-0e0", "-0e+0",
        "-0e-0", "0e-99", "+0e-99", "-0e-99", "0e99", "+0e99", "-0e99", "0e+99", "+0e+99",
        "-0e+99",
    ];
    const ONE: &[&str] = &[
        "1",
        "1.",
        "1.0",
        "1e0",
        "1.e0",
        "1.0e0",
        "1.0e+0",
        "1.0e-0",
        ".1e1",
        "0.1e1",
        "0.1e+1",
        "0.01e2",
        "10e-1",
        "10.e-1",
        "100.0e-2",
        "+1",
        "+1.",
        "+1.0",
        "+1e0",
        "+1.e0",
        "+1.0e0",
        "+1.0e+0",
        "+1.0e-0",
        "+.1e1",
        "+0.1e1",
        "+0.1e+1",
        "+0.01e2",
        "+10e-1",
        "+10.e-1",
        "+100.0e-2",
    ];
    const TWO: &[&str] = &[
        "2",
        "2.",
        "2.0",
        "2e0",
        "2.e0",
        "2.0e0",
        "2.0e+0",
        "2.0e-0",
        ".2e1",
        "0.2e1",
        "0.2e+1",
        "0.02e2",
        "20e-1",
        "20.e-1",
        "200.0e-2",
        "+2",
        "+2.",
        "+2.0",
        "+2e0",
        "+2.e0",
        "+2.0e0",
        "+2.0e+0",
        "+2.0e-0",
        "+.2e1",
        "+0.2e1",
        "+0.2e+1",
        "+0.02e2",
        "+20e-1",
        "+20.e-1",
        "+200.0e-2",
    ];

    /// Checks `x` against `y` in both directions.
    #[track_caller]
    fn check(x: &str, y: &str, expected: Ordering) {
        assert_eq!(compare_float(x, y), expected, "compare_float({x}, {y})");
        assert_eq!(
            compare_float(y, x),
            expected.reverse(),
            "compare_float({y}, {x})"
        );
    }

    #[test]
    fn one_two_zero_matrix() {
        // The groups ascend by value.
        // Every spelling equals the others in its group and exceeds every spelling in earlier groups.
        let groups = [NEGATIVE_TWO, NEGATIVE_ONE, ZERO, ONE, TWO];
        for (gi, group) in groups.iter().enumerate() {
            for (i, x) in group.iter().enumerate() {
                for y in &group[i..] {
                    check(y, x, Equal);
                }
                for higher in &groups[gi + 1..] {
                    for y in *higher {
                        check(y, x, Greater);
                    }
                }
            }
        }
    }

    #[test]
    fn simple() {
        check("1", "1", Equal);
        check("2", "1", Greater);
        check("1.1", "1.2", Less);
        check("1.2", "1.2", Equal);
        check("1.35", "1.357", Less);
        check("1.35e2", "13.5e1", Equal);
        check("1.351e2", "13.5e1", Greater);
        check("1.35e-1", "13.5e-2", Equal);
        check("1", "-2", Greater);
        check("1.2e7", "2.3e2", Greater);
        check("-1.2e7", "2.3e2", Less);
        check("1.2e7", "-2.3e2", Greater);
        check("-1.2e7", "-2.3e2", Less);
    }

    #[test]
    fn signs() {
        check("+1", "1", Equal);
        check("+1e+0", "1", Equal);
        check("+1e-0", "1", Equal);
        check("-1", "1", Less);
        check("-1", "+1", Less);
        check("1", "-1", Greater);
        check("+1", "-1", Greater);
        // Leading whitespace is skipped before the sign.
        check(" +1", "1", Equal);
        check("\t-1", "-1", Equal);
    }

    #[test]
    fn exponents() {
        for (x, y, ord) in [
            ("2e0", "2e0", Equal),
            ("1e0", "2e0", Less),
            ("3e0", "2e0", Greater),
            ("1e-5", "1e5", Less),
            ("1e5", "1e-5", Greater),
            ("1e5", "1e6", Less),
            ("1e5", "1e4", Greater),
            ("1e-5", "1e-4", Less),
            ("1e-5", "1e-6", Greater),
            ("-1e5", "-1e-5", Less),
            ("-1e-5", "-1e5", Greater),
            ("-1e5", "-1e4", Less),
            ("-1e5", "-1e6", Greater),
            ("-1e-5", "-1e-6", Less),
            ("-1e-5", "-1e-4", Greater),
            ("2", "2e0", Equal),
            ("1", "2e0", Less),
            ("3", "2e0", Greater),
            ("20", "2e1", Equal),
            ("19", "2e1", Less),
            ("21", "2e1", Greater),
            ("-20", "-2e1", Equal),
            ("-21", "-2e1", Less),
            ("-19", "-2e1", Greater),
            ("0.2", "2e-1", Equal),
            ("0.02", "2e-2", Equal),
            ("0.02", ".2e-1", Equal),
            (".1", "2e-1", Less),
            (".3", "2e-1", Greater),
            ("-0.2", "-2e-1", Equal),
            ("-0.02", "-2e-2", Equal),
            ("-0.02", "-.2e-1", Equal),
            ("-.3", "-2e-1", Less),
            ("-.1", "-2e-1", Greater),
        ] {
            check(x, y, ord);
        }
    }

    #[test]
    fn zeros() {
        for (x, y) in [
            ("-0", "0"),
            ("+0", "0"),
            ("00", "0"),
            ("0.0", "0"),
            ("0", "000"),
            ("0", ".000"),
            ("0.0", "000.00000"),
            ("0", "000.000e0"),
            ("0", "0e+0"),
            ("0", "0e-0"),
            ("0", "0e99"),
            ("0", "0e-99"),
            ("0e+99", "0e-99"),
            ("+0e+99", "-0e-99"),
            ("-0e+99", "-0e-99"),
            ("-0e+99", "+0e-99"),
            ("01", "1"),
            ("1", "001"),
            ("1.0", "001.00000"),
        ] {
            check(x, y, Equal);
        }
    }

    #[test]
    fn extreme_numbers() {
        let big = "123456700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        let neg_big = format!("-{big}");
        let tiny = "0.0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
        let neg_tiny = format!("-{tiny}");
        let max = "999999999999999999999999999999999999990000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        let neg_max = format!("-{max}");
        let cases: &[(&str, &str, Ordering)] = &[
            // numbers with high precision
            (
                "123456789.01234567890123456789012345678",
                "123456789.01234567890123456789012345678",
                Equal,
            ),
            (
                "1234567890123456789012345678901234567800000000000000000000000000000",
                "1234567890123456789012345678901234567800000000000000000000000000000",
                Equal,
            ),
            (
                ".000000000000000000000000012345678901234567890123456789012345678",
                "0.000000000000000000000000012345678901234567890123456789012345678",
                Equal,
            ),
            (
                "123456789.01234567890123456789012345676",
                "123456789.01234567890123456789012345678",
                Less,
            ),
            (
                "123456789.01234567890123456789012345675",
                "123456789.01234567890123456789012345676",
                Less,
            ),
            (
                "123456789.01234567890123456789012345679",
                "123456789.01234567890123456789012345678",
                Greater,
            ),
            (
                "123456789.01234567890123456789012345677",
                "123456789.01234567890123456789012345676",
                Greater,
            ),
            (
                "-123456789.01234567890123456789012345678",
                "123456789.01234567890123456789012345678",
                Less,
            ),
            (
                "123456789.01234567890123456789012345678",
                "-123456789.01234567890123456789012345678",
                Greater,
            ),
            // high and low exponents
            ("0000000000000000000000000012345.67e121", big, Equal),
            ("12345.67e121", big, Equal),
            (
                "0.00000001e133",
                "100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                Equal,
            ),
            ("0.00000001e-122", tiny, Equal),
            (
                "1234567e-136",
                "0.0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001234567",
                Equal,
            ),
            ("0000000000000000000000000012345.66e121", big, Less),
            ("0000000000000000000000000012345.68e121", big, Greater),
            ("12345.67e120", "12345.67e121", Less),
            ("12345.67e122", "12345.67e121", Greater),
            ("-12345.67e122", "-12345.67e121", Less),
            ("-12345.67e120", "-12345.67e121", Greater),
            ("12345.67e120", big, Less),
            ("12345.67e122", big, Greater),
            ("-12345.67e122", &neg_big, Less),
            ("-12345.67e120", &neg_big, Greater),
            ("0.00000001e-123", "0.00000001e-122", Less),
            ("0.00000001e-121", "0.00000001e-122", Greater),
            ("-0.00000001e-121", "-0.00000001e-122", Less),
            ("-0.00000001e-123", "-0.00000001e-122", Greater),
            ("0.00000001e-123", tiny, Less),
            ("0.00000001e-121", tiny, Greater),
            ("-0.00000001e-121", &neg_tiny, Less),
            ("-0.00000001e-123", &neg_tiny, Greater),
            // large positive numbers
            ("9.9999999999999999999999999999999999999E+125", max, Equal),
            (".99999999999999999999999999999999999999E+126", max, Equal),
            (max, max, Equal),
            ("9.9999999999999999999999999999999999999E+124", max, Less),
            ("9.9999999999999999999999999999999999999E+126", max, Greater),
            (
                "999999999999999999999999999999999999989999999999999999999999999999999999999999999999999999999999999999999999999999999999999999",
                max,
                Less,
            ),
            (
                "999999999999999999999999999999999999990000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
                max,
                Greater,
            ),
            // small positive numbers
            ("1E-130", tiny, Equal),
            ("10E-131", tiny, Equal),
            (tiny, tiny, Equal),
            ("1E-131", tiny, Less),
            ("1E-129", tiny, Greater),
            (
                "0.00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000009",
                tiny,
                Less,
            ),
            (
                "0.0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002",
                tiny,
                Greater,
            ),
            // large negative numbers
            (
                "-9.9999999999999999999999999999999999999E+125",
                &neg_max,
                Equal,
            ),
            (
                "-.99999999999999999999999999999999999999E+126",
                &neg_max,
                Equal,
            ),
            (&neg_max, &neg_max, Equal),
            (
                "-9.9999999999999999999999999999999999999E+126",
                &neg_max,
                Less,
            ),
            (
                "-9.9999999999999999999999999999999999999E+124",
                &neg_max,
                Greater,
            ),
            (
                "-999999999999999999999999999999999999990000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
                &neg_max,
                Less,
            ),
            (
                "-99999999999999999999999999999999999998999999999999999999999999999999999999999999999999999999999999999999999999999999999999999",
                &neg_max,
                Greater,
            ),
            // small negative numbers
            ("-1E-130", &neg_tiny, Equal),
            ("-10E-131", &neg_tiny, Equal),
            (&neg_tiny, &neg_tiny, Equal),
            ("-1E-129", &neg_tiny, Less),
            ("-1E-131", &neg_tiny, Greater),
            (
                "-0.0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002",
                &neg_tiny,
                Less,
            ),
            (
                "-0.00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000009",
                &neg_tiny,
                Greater,
            ),
        ];
        for (x, y, ord) in cases {
            check(x, y, *ord);
        }
    }

    // The results for non-numbers are undefined, but must be consistent.
    #[test]
    fn invalid_inputs_compare_as_zero() {
        check("a", "0", Equal);
        check("a", "b", Equal);
    }
}

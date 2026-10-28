// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! DynamoDB number normalization: the canonical form numbers are signed and encrypted in.

const MAX_PRECISION: usize = 38;
const MIN_EXPONENT: i128 = -129;
const MAX_EXPONENT: i128 = 126;

fn skip_leading_zeros(val: &str) -> &str {
    let b = val.as_bytes();
    let mut i = 0;
    while b.len() - i > 1 && b[i] == b'0' && b[i + 1] != b'.' {
        i += 1;
    }
    &val[i..]
}

fn skip_trailing_zeros(val: &str) -> &str {
    let mut v = val;
    while v.len() > 1 && v.ends_with('0') {
        if v.as_bytes()[v.len() - 2] == b'.' {
            return &v[..v.len() - 2];
        }
        v = &v[..v.len() - 1];
    }
    v
}

fn skip_all_trailing_zeros(val: &str) -> &str {
    val.trim_end_matches('0')
}

fn count_digits(s: &str) -> usize {
    s.bytes().take_while(u8::is_ascii_digit).count()
}

fn str_to_int_inner(s: &str) -> Result<i128, String> {
    let mut acc: i128 = 0;
    for (i, ch) in s.char_indices() {
        let Some(d) = ch.to_digit(10) else {
            let next = &s[i..i + ch.len_utf8()];
            return Err(format!(
                "The character '{next}' is not a valid decimal digit."
            ));
        };
        // Saturating keeps the magnitude checks failing as an unbounded integer would.
        acc = acc.saturating_mul(10).saturating_add(i128::from(d));
    }
    Ok(acc)
}

/// The integer `s` spells: decimal digits after an optional sign.
pub(crate) fn str_to_int(s: &str) -> Result<i128, String> {
    if s.is_empty() {
        return Err("An empty string is not a valid number.".to_owned());
    }
    if let Some(rest) = s.strip_prefix('-') {
        if rest.is_empty() {
            return Err("An empty string is not a valid number.".to_owned());
        }
        return Ok(-str_to_int_inner(rest)?);
    }
    if let Some(rest) = s.strip_prefix('+') {
        if rest.is_empty() {
            return Err("An empty string is not a valid number.".to_owned());
        }
        return str_to_int_inner(rest);
    }
    str_to_int_inner(s)
}

/// Split a number into its digits, the position of the decimal point, and the exponent.
fn parse_number(n: &str) -> Result<(String, usize, i128), String> {
    let pre_dot = count_digits(n);
    if n.len() == pre_dot {
        return Ok((n.to_owned(), n.len(), 0));
    }
    let rest = &n[pre_dot..];
    if let Some(after_dot) = rest.strip_prefix('.') {
        let post_dot = count_digits(after_dot);
        if pre_dot + post_dot == 0 {
            return Err("Number needs digits either before or after the decimal point.".to_owned());
        }
        let len = pre_dot + post_dot + 1;
        let digits = format!("{}{}", &n[..pre_dot], &n[pre_dot + 1..len]);
        if len == n.len() {
            return Ok((digits, pre_dot, 0));
        }
        let tail = &n[len..];
        if tail.starts_with(['e', 'E']) {
            let exp = str_to_int(&tail[1..])?;
            return Ok((digits, pre_dot, exp));
        }
        return Err(format!("Invalid Character in number at '{tail}'."));
    }
    if pre_dot == 0 {
        return Err("Number needs digits either before or after the decimal point.".to_owned());
    }
    if rest.starts_with(['e', 'E']) {
        let exp = str_to_int(&rest[1..])?;
        return Ok((n[..pre_dot].to_owned(), pre_dot, exp));
    }
    Err(format!("Invalid Character in number at '{rest}'."))
}

fn count_zeros(value: &str) -> usize {
    value.bytes().take_while(|b| *b == b'0').count()
}

fn normalize_value(mut value: &str, mut pos: usize) -> (&str, usize) {
    loop {
        if value.is_empty() {
            return (value, pos);
        }
        if value.starts_with('0') && pos > 0 {
            value = &value[1..];
            pos -= 1;
        } else if value.ends_with('0') && pos < value.len() {
            value = &value[..value.len() - 1];
        } else {
            return (value, pos);
        }
    }
}

fn to_i128(n: usize) -> i128 {
    i128::try_from(n).unwrap_or(i128::MAX)
}

fn normalize_positive(n: &str) -> Result<String, String> {
    let (digits, pos, exp) = parse_number(n)?;
    let (value, pos) = normalize_value(&digits, pos);
    let precision = skip_all_trailing_zeros(skip_leading_zeros(value));
    if precision.len() > MAX_PRECISION {
        return Err("Attempting to store more than 38 significant digits in a Number.".to_owned());
    }
    let new_pos = to_i128(pos).saturating_add(exp);
    if precision.is_empty() {
        return Ok("0".to_owned());
    }
    let len = to_i128(value.len());
    if new_pos <= 0 {
        if new_pos - to_i128(count_zeros(value)) < MIN_EXPONENT {
            return Err(
                "Attempting to store a number with magnitude smaller than supported range."
                    .to_owned(),
            );
        }
        let zeros = usize::try_from(-new_pos).unwrap_or(0);
        Ok(format!("0.{}{value}", "0".repeat(zeros)))
    } else if new_pos >= len {
        if new_pos - to_i128(count_zeros(value)) > MAX_EXPONENT {
            return Err(
                "Attempting to store a number with magnitude larger than supported range."
                    .to_owned(),
            );
        }
        let zeros = usize::try_from(new_pos - len).unwrap_or(0);
        Ok(format!("{value}{}", "0".repeat(zeros)))
    } else {
        let p = usize::try_from(new_pos).unwrap_or(0);
        Ok(format!("{}.{}", &value[..p], &value[p..]))
    }
}

fn trim_zeros_from_valid_number(n: &str) -> &str {
    let n = skip_leading_zeros(n);
    if n.contains('.') {
        skip_trailing_zeros(n)
    } else {
        n
    }
}

/// The canonical form of a DynamoDB number, or why `n` is not one.
pub(crate) fn normalize_number(n: &str) -> Result<String, String> {
    let inner = || -> Result<String, String> {
        if n.is_empty() {
            return Err("An empty string is not a valid number.".to_owned());
        }
        let (neg, body) = if let Some(rest) = n.strip_prefix('-') {
            (true, rest)
        } else if let Some(rest) = n.strip_prefix('+') {
            (false, rest)
        } else {
            (false, n)
        };
        if body.is_empty() {
            return Err("An empty string is not a valid number.".to_owned());
        }
        let normalized = normalize_positive(body)?;
        let trimmed = trim_zeros_from_valid_number(&normalized);
        if neg && trimmed != "0" {
            Ok(format!("-{trimmed}"))
        } else {
            Ok(trimmed.to_owned())
        }
    };
    inner().map_err(|e| format!("{e} when parsing '{n}'."))
}

// Vectors ported from DynamoDbEncryption/test/NormalizeNumber.dfy.
#[cfg(test)]
mod tests {
    use super::{normalize_number, str_to_int};

    #[track_caller]
    fn check_normal(input: &str, expected: &str) {
        assert_eq!(normalize_number(input).as_deref(), Ok(expected), "{input}");
    }

    #[track_caller]
    fn check_failure(input: &str) {
        let res = normalize_number(input);
        assert!(res.is_err(), "{input} normalized to {res:?}");
    }

    #[test]
    fn extremes() {
        // Only 38 digits of precision are allowed, check that 38 is ok and 39 fails
        check_normal(
            "123456789.01234567890123456789012345678",
            "123456789.01234567890123456789012345678",
        );
        check_failure("123456789.012345678901234567890123456789");
        check_normal(
            "1234567890123456789012345678901234567800000000000000000000000000000",
            "1234567890123456789012345678901234567800000000000000000000000000000",
        );
        check_failure("1234567890123456789012345678901234567890000000000000000000000000000");
        check_normal(
            ".000000000000000000000000012345678901234567890123456789012345678",
            "0.000000000000000000000000012345678901234567890123456789012345678",
        );
        check_failure(".0000000000000000000000000123456789012345678901234567890123456789");

        // Check vaguely around the highest and lowest allowed exponent
        check_normal(
            "0000000000000000000000000012345.67e121",
            "123456700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        );
        check_normal(
            "12345.67e121",
            "123456700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        );
        check_failure("12345.67e122");
        check_failure("00000000000000000000000000012345.67e122");
        check_normal(
            "0.00000001e133",
            "100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        );
        check_failure("0.00000001e134");
        check_normal(
            "0.00000001e-122",
            "0.0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
        );
        check_failure("0.00000001e-123");
        check_normal(
            "1234567e-136",
            "0.0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001234567",
        );
        check_failure("1234567e-137");

        // Bounds around highest positive number
        let max = "999999999999999999999999999999999999990000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        check_normal("9.9999999999999999999999999999999999999E+125", max);
        check_normal(".99999999999999999999999999999999999999E+126", max);
        check_normal(max, max);
        check_failure("1E+126");
        check_failure("10E+125");
        let ten_pow_125 = "100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        check_normal(ten_pow_125, ten_pow_125);
        check_failure(
            "1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        );
        check_failure("9.99999999999999999999999999999999999991E+125");
        check_failure(
            "999999999999999999999999999999999999990000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
        );

        // Bounds around smallest positive number
        let min = "0.0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
        check_normal("1E-130", min);
        check_normal("10E-131", min);
        check_normal(min, min);
        check_failure("9.9999999999999999999999999999999999999E-131");
        check_failure(".99999999999999999999999999999999999999E-130");
        check_failure(
            "0.000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000099999999999999999999999999999999999999",
        );

        // Bounds around the smallest negative number
        let neg_max = format!("-{max}");
        check_normal("-9.9999999999999999999999999999999999999E+125", &neg_max);
        check_normal("-.99999999999999999999999999999999999999E+126", &neg_max);
        check_normal(&neg_max, &neg_max);
        check_failure("-1E+126");
        check_failure("-10E+125");
        check_failure(
            "-1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        );
        check_failure(
            "-999999999999999999999999999999999999990000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
        );
        check_failure("-9.99999999999999999999999999999999999991E+125");

        // Bounds around the largest negative number
        let neg_min = format!("-{min}");
        check_normal("-1E-130", &neg_min);
        check_normal("-10E-131", &neg_min);
        check_normal(&neg_min, &neg_min);
        check_failure("-9.9999999999999999999999999999999999999E-131");
        check_failure("-.99999999999999999999999999999999999999E-130");
        check_failure(
            "-0.000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000099999999999999999999999999999999999999",
        );
    }

    #[test]
    fn failures() {
        for input in [
            "", ".", "+", "-", "e", "E", "1.2.3", "1.2e3e4", ".e4", "1.2e4.", "e99", "e-99",
            "1.2e--99", "1.2e+-99", "1.2e-+99", "--1.2", "++1.2", "+-1.2", "-+1.2", "1e", "1e-",
            "1e+", "1e1.1", "e0", "1a1", "1-1", "1+1", "1.-2", "1.+2",
        ] {
            check_failure(input);
        }
    }

    #[test]
    fn examples() {
        for zero in [
            "0", "000", ".000", "0.", "0.0", "000.000", ".0", "0e99", "0.e99", ".0e99", "0.0e99",
            "0e-99", ".0e-99", "0.0e-99", "0e0", "0.0e0", "0.e0", ".0e0", "0e-0", "0.0e-0",
            "0.e-0", ".0e-0", "0e999", "0e-999", "-0", "-000", "-.000", "-0.", "-0.0", "-000.000",
            "-.0", "-0e99", "-0.e99", "-.0e99", "-0.0e99", "-0e-99", "-.0e-99", "-0.0e-99", "-0e0",
            "-0.0e0", "-0.e0", "-.0e0", "-0e-0", "-0.0e-0", "-0.e-0", "-.0e-0", "+0", "+0e+0",
            "+0e0", "0e+0", "-0e+0",
        ] {
            check_normal(zero, "0");
        }
        for (input, expected) in [
            ("1.2e2", "120"),
            ("+1.2e2", "120"),
            ("+1.2e+2", "120"),
            ("1.2e+2", "120"),
            ("-1.2e2", "-120"),
            ("-1.2e+2", "-120"),
            ("+123.456", "123.456"),
            ("-123.456", "-123.456"),
            ("12.34", "12.34"),
            ("00012.34", "12.34"),
            ("12.34000", "12.34"),
            ("012.340", "12.34"),
            ("123.456", "123.456"),
            ("123.456e0", "123.456"),
            ("123.456e-0", "123.456"),
            ("123.456e1", "1234.56"),
            ("123.456e-1", "12.3456"),
            ("123.456e2", "12345.6"),
            ("123.456e-2", "1.23456"),
            ("123.456e3", "123456"),
            ("123.456e-3", "0.123456"),
            ("123.456e4", "1234560"),
            ("123.456e-4", "0.0123456"),
            ("123.456e5", "12345600"),
            ("123.456e-5", "0.00123456"),
            ("123", "123"),
            ("123e0", "123"),
            ("123e-0", "123"),
            ("123e1", "1230"),
            ("123e2", "12300"),
            ("123e3", "123000"),
            ("123e-1", "12.3"),
            ("123e-2", "1.23"),
            ("123e-3", "0.123"),
            ("123e-4", "0.0123"),
            (".123", "0.123"),
            (".123e0", "0.123"),
            (".123e-0", "0.123"),
            (".123e1", "1.23"),
            (".123e-1", "0.0123"),
            (".123e2", "12.3"),
            (".123e-2", "0.00123"),
            (".123e3", "123"),
            (".123e-3", "0.000123"),
            (".123e4", "1230"),
            ("123.", "123"),
            ("123.e0", "123"),
            ("123.e-0", "123"),
            ("123.e1", "1230"),
            ("123.e-1", "12.3"),
            ("123.e2", "12300"),
            ("123.e-2", "1.23"),
            ("123.e3", "123000"),
            ("123.e-3", "0.123"),
            ("0.123", "0.123"),
            ("0.123e0", "0.123"),
            ("0.123e-0", "0.123"),
            ("0.123e1", "1.23"),
            ("0.123e2", "12.3"),
            ("0.123e3", "123"),
            ("0.123e4", "1230"),
            ("0.123e-1", "0.0123"),
            ("0.123e-2", "0.00123"),
        ] {
            check_normal(input, expected);
        }
    }

    #[test]
    fn error_messages_name_the_input() {
        assert_eq!(
            normalize_number("").unwrap_err(),
            "An empty string is not a valid number. when parsing ''."
        );
        assert_eq!(
            normalize_number("1a1").unwrap_err(),
            "Invalid Character in number at 'a1'. when parsing '1a1'."
        );
        assert_eq!(
            normalize_number(".").unwrap_err(),
            "Number needs digits either before or after the decimal point. when parsing '.'."
        );
        assert_eq!(
            normalize_number("1e1.1").unwrap_err(),
            "The character '.' is not a valid decimal digit. when parsing '1e1.1'."
        );
        assert_eq!(
            normalize_number("1E+126").unwrap_err(),
            "Attempting to store a number with magnitude larger than supported range. when parsing '1E+126'."
        );
        assert_eq!(
            normalize_number("1E-131").unwrap_err(),
            "Attempting to store a number with magnitude smaller than supported range. when parsing '1E-131'."
        );
        assert_eq!(
            normalize_number("1234567890123456789012345678901234567891").unwrap_err(),
            "Attempting to store more than 38 significant digits in a Number. when parsing '1234567890123456789012345678901234567891'."
        );
    }

    #[test]
    fn exponent_beyond_i128_is_out_of_range() {
        // The exponent saturates rather than wrapping, so it still fails the range checks.
        let huge = "9".repeat(60);
        assert!(
            normalize_number(&format!("1e{huge}"))
                .unwrap_err()
                .starts_with("Attempting to store a number with magnitude larger")
        );
        assert!(
            normalize_number(&format!("1e-{huge}"))
                .unwrap_err()
                .starts_with("Attempting to store a number with magnitude smaller")
        );
        check_normal(&format!("0e{huge}"), "0");
    }

    #[test]
    fn str_to_int_parses_signed_decimals() {
        assert_eq!(str_to_int("0"), Ok(0));
        assert_eq!(str_to_int("123"), Ok(123));
        assert_eq!(str_to_int("+123"), Ok(123));
        assert_eq!(str_to_int("-123"), Ok(-123));
        assert_eq!(str_to_int("007"), Ok(7));
        for empty in ["", "-", "+"] {
            assert_eq!(
                str_to_int(empty),
                Err("An empty string is not a valid number.".to_owned())
            );
        }
        assert_eq!(
            str_to_int("12x"),
            Err("The character 'x' is not a valid decimal digit.".to_owned())
        );
        assert_eq!(
            str_to_int("-\u{e9}"),
            Err("The character '\u{e9}' is not a valid decimal digit.".to_owned())
        );
        assert_eq!(str_to_int(&"9".repeat(50)), Ok(i128::MAX));
    }
}

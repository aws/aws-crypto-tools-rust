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

fn str_to_int(s: &str) -> Result<i128, String> {
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

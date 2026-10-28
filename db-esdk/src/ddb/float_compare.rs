// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Compare two decimal strings as numbers, without converting them to floating point.

use std::cmp::Ordering;

/// The digits of `s` as an integer; other characters are skipped. Saturates when too big.
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

/// Compare digit strings of the same length, or a shorter string as smaller.
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

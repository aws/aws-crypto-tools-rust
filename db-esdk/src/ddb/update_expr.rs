// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The attributes a DynamoDB update expression names.

use std::collections::HashMap;

/// Words that look like attribute names in an update expression, but are not.
const IGNORED: [&str; 6] = [
    "SET",
    "REMOVE",
    "ADD",
    "DELETE",
    "list_append",
    "if_not_exists",
];

/// The root attribute of every attribute path in `expr`,
/// each `#name` resolved through `names` when it is there.
pub(crate) fn extract_attributes(
    expr: &str,
    names: Option<&HashMap<String, String>>,
) -> Vec<String> {
    let attrs = extract_attrs(expr);
    match names {
        None => attrs,
        Some(names) => attrs
            .into_iter()
            .map(|a| names.get(&a).cloned().unwrap_or(a))
            .collect(),
    }
}

/// The part of `s` before the first `ch`, or all of `s`.
fn chop_one(s: &str, ch: char) -> &str {
    s.split_once(ch).map_or(s, |(head, _)| head)
}

/// The root attribute of an attribute path.
fn chop(s: &str) -> &str {
    chop_one(chop_one(s, '.'), '[')
}

/// Every attribute path's root attribute named in `s`, in order.
fn extract_attrs(s: &str) -> Vec<String> {
    let chars: Vec<char> = s.chars().collect();
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < chars.len() {
        let (len, token) = find_token(&chars[pos..]);
        if len == 0 {
            break;
        }
        if let Some(token) = token
            && !IGNORED.contains(&token.as_str())
        {
            out.push(chop(&token).to_owned());
        }
        pos += len;
    }
    out
}

/// A character that starts a token that is not an attribute name.
const fn bad_start(ch: char) -> bool {
    ch == ':' || ch.is_ascii_digit()
}

/// A character that can start an attribute name.
const fn attr_start(ch: char) -> bool {
    ch.is_ascii_alphabetic() || ch == '#' || ch == '_'
}

/// A character that can be part of an attribute path.
const fn attr_char(ch: char) -> bool {
    attr_start(ch) || ch.is_ascii_digit() || matches!(ch, '[' | ']' | '.')
}

/// How many leading characters of `s` are attribute path characters.
fn attr_len(s: &[char]) -> usize {
    s.iter().take_while(|c| attr_char(**c)).count()
}

/// The next token of `s`: how many characters it takes, and the attribute path, if it is one.
fn find_token(s: &[char]) -> (usize, Option<String>) {
    let Some(&ch) = s.first() else {
        return (0, None);
    };
    if ch == '#' || attr_start(ch) {
        let len = attr_len(&s[1..]) + 1;
        (len, Some(s[..len].iter().collect()))
    } else if bad_start(ch) {
        (attr_len(&s[1..]) + 1, None)
    } else {
        (1, None)
    }
}

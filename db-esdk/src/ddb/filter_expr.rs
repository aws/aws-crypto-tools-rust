// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! DynamoDB condition and filter expressions: their tokens, and the attributes they read.

use std::collections::HashMap;

/// One token of a condition or filter expression.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Token {
    /// An attribute path, or a `#name` placeholder.
    Attr(String),
    /// A `:value` placeholder.
    Value,
    Eq,
    Ne,
    Lt,
    Gt,
    Le,
    Ge,
    Between,
    In,
    Open,
    Close,
    Comma,
    Not,
    And,
    Or,
    AttributeExists,
    AttributeNotExists,
    AttributeType,
    BeginsWith,
    Contains,
    Size,
}

/// The attributes `expr` reads the value of, each `#name` resolved through `names`.
///
/// The attribute of `attribute_exists`, `attribute_not_exists`, and `size` is left out:
/// those functions do not read the attribute's value.
pub(crate) fn extract_attributes(
    expr: &str,
    names: Option<&HashMap<String, String>>,
) -> Vec<String> {
    let mut out = Vec::new();
    // Counts down to the token a value-ignoring function applies to; negative when there is none.
    let mut tokens_until_skip: i64 = -1;
    for token in parse_expr(expr) {
        if is_special(&token) {
            tokens_until_skip = 1;
        } else if let Token::Attr(name) = token {
            if tokens_until_skip != 0 {
                out.push(attr_name(name, names));
            }
            tokens_until_skip = -1;
        } else {
            tokens_until_skip -= 1;
        }
    }
    out
}

/// Every attribute `expr` names, in order, each `#name` resolved through `names`.
pub(crate) fn all_attributes(expr: &str, names: Option<&HashMap<String, String>>) -> Vec<String> {
    parse_expr(expr)
        .into_iter()
        .filter_map(|t| match t {
            Token::Attr(name) => Some(attr_name(name, names)),
            _ => None,
        })
        .collect()
}

/// A function that ignores the value of the attribute it is given.
const fn is_special(t: &Token) -> bool {
    matches!(
        t,
        Token::AttributeExists | Token::AttributeNotExists | Token::Size
    )
}

/// `name`, or what `names` maps it to.
fn attr_name(name: String, names: Option<&HashMap<String, String>>) -> String {
    match names.and_then(|n| n.get(&name)) {
        Some(real) => real.clone(),
        None => name,
    }
}

/// The tokens of `s`, up to the first character no token starts with.
pub(crate) fn parse_expr(s: &str) -> Vec<Token> {
    let chars: Vec<char> = s.chars().collect();
    let mut out = Vec::new();
    let mut pos = 0;
    while let Some((len, token)) = find_index_token(&chars, pos) {
        out.push(token);
        pos += len;
    }
    out
}

/// Whether the characters of `s` at `pos` are `pre`, ignoring ASCII case. `pre` is lowercase.
fn prefix_lower(pre: &str, s: &[char], pos: usize) -> bool {
    let pre: Vec<char> = pre.chars().collect();
    s.len() >= pos + pre.len()
        && pre
            .iter()
            .zip(&s[pos..])
            .all(|(p, c)| *p == c.to_ascii_lowercase())
}

/// A character of a `:value` or `#name` placeholder.
const fn value_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

/// A character of an attribute path.
const fn attribute_char(ch: char) -> bool {
    value_char(ch) || matches!(ch, ':' | '[' | ']' | '.' | '#')
}

/// How many characters of `s` from `pos` satisfy `f`.
fn run_len(s: &[char], pos: usize, f: fn(char) -> bool) -> usize {
    s[pos..].iter().take_while(|c| f(**c)).count()
}

/// The next token at or after `pos`, and how many characters it takes from `pos`;
/// `None` when no token starts there.
fn find_index_token(s: &[char], pos: usize) -> Option<(usize, Token)> {
    let mut start = pos;
    while s.get(start) == Some(&' ') {
        start += 1;
    }
    let skipped = start - pos;
    let &ch = s.get(start)?;
    let next = s.get(start + 1).copied();
    let (len, token) = match ch {
        '(' => (1, Token::Open),
        ')' => (1, Token::Close),
        ',' => (1, Token::Comma),
        '=' => (1, Token::Eq),
        '<' => match next {
            Some('=') => (2, Token::Le),
            Some('>') => (2, Token::Ne),
            _ => (1, Token::Lt),
        },
        '>' => match next {
            Some('=') => (2, Token::Ge),
            _ => (1, Token::Gt),
        },
        _ => {
            const WORDS: [(&str, Token); 11] = [
                ("in", Token::In),
                ("between", Token::Between),
                ("and", Token::And),
                ("or", Token::Or),
                ("not", Token::Not),
                ("attribute_not_exists", Token::AttributeNotExists),
                ("attribute_type", Token::AttributeType),
                ("begins_with", Token::BeginsWith),
                ("attribute_exists", Token::AttributeExists),
                ("contains", Token::Contains),
                ("size", Token::Size),
            ];
            if let Some((word, token)) = WORDS.iter().find(|(w, _)| prefix_lower(w, s, start)) {
                (word.len(), token.clone())
            } else if ch == ':' {
                (run_len(s, start + 1, value_char) + 1, Token::Value)
            } else if ch == '#' {
                let len = run_len(s, start + 1, value_char) + 1;
                (len, Token::Attr(s[start..start + len].iter().collect()))
            } else {
                let len = run_len(s, start, attribute_char);
                if len == 0 {
                    return None;
                }
                (len, Token::Attr(s[start..start + len].iter().collect()))
            }
        }
    };
    Some((skipped + len, token))
}

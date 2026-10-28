// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! DynamoDB condition and filter expressions: their tokens, and the attributes they read.

use std::cmp::Ordering;
use std::collections::HashMap;

use aws_crypto_mpl::aws_sdk_dynamodb::types::AttributeValue;

use crate::ddb::float_compare;
use crate::ddb::number::normalize_number;
use crate::error::{Error, val_err};
use crate::search::beacon::attr_type_to_str;
use crate::search::term_loc::TermLoc;
use crate::structured::util::utf16_len;

/// One token of a condition or filter expression.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Token {
    /// An attribute path, or a `#name` placeholder.
    Attr(String),
    /// A `:value` placeholder.
    Value(String),
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
                let len = run_len(s, start + 1, value_char) + 1;
                (len, Token::Value(s[start..start + len].iter().collect()))
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

impl Token {
    /// The token as it is written in an expression.
    pub(crate) fn as_str(&self) -> &str {
        match self {
            Self::Attr(s) | Self::Value(s) => s,
            Self::Eq => "=",
            Self::Ne => "<>",
            Self::Lt => "<",
            Self::Gt => ">",
            Self::Le => "<=",
            Self::Ge => ">=",
            Self::Between => "BETWEEN",
            Self::In => "IN",
            Self::Open => "(",
            Self::Close => ")",
            Self::Comma => ",",
            Self::Not => "NOT",
            Self::And => "AND",
            Self::Or => "OR",
            Self::AttributeExists => "attribute_exists",
            Self::AttributeNotExists => "attribute_not_exists",
            Self::AttributeType => "attribute_type",
            Self::BeginsWith => "begins_with",
            Self::Contains => "contains",
            Self::Size => "size",
        }
    }

    /// A comparison operator.
    pub(crate) const fn is_comp(&self) -> bool {
        matches!(
            self,
            Self::Eq | Self::Ne | Self::Lt | Self::Gt | Self::Le | Self::Ge
        )
    }

    /// An attribute or a value.
    const fn is_var(&self) -> bool {
        matches!(self, Self::Attr(_) | Self::Value(_))
    }

    /// A function, or an operator evaluated like one.
    const fn is_function(&self) -> bool {
        matches!(
            self,
            Self::Between
                | Self::In
                | Self::AttributeExists
                | Self::AttributeNotExists
                | Self::AttributeType
                | Self::BeginsWith
                | Self::Contains
                | Self::Size
        )
    }

    const fn is_binary(&self) -> bool {
        self.is_comp() || matches!(self, Self::And | Self::Or)
    }

    const fn precedence(&self) -> u8 {
        match self {
            Self::Open | Self::Close | Self::Comma => 11,
            Self::Attr(_) | Self::Value(_) => 10,
            Self::Eq | Self::Ne | Self::Lt | Self::Gt | Self::Le | Self::Ge => 9,
            Self::In => 8,
            Self::Between => 7,
            Self::AttributeExists
            | Self::AttributeNotExists
            | Self::AttributeType
            | Self::BeginsWith
            | Self::Contains
            | Self::Size => 6,
            Self::Not => 5,
            Self::And => 4,
            Self::Or => 3,
        }
    }
}

/// The location an attribute token names: its parsed path, or the whole token as one attribute.
pub(crate) fn attr_loc(s: &str) -> TermLoc {
    TermLoc::parse(s).unwrap_or_else(|_| TermLoc::attribute(s))
}

/// `expr` written back as an expression, its tokens separated by spaces.
pub(crate) fn parsed_expr_to_string(expr: &[Token]) -> String {
    expr.iter().map(Token::as_str).collect::<Vec<_>>().join(" ")
}

/// How many tokens from `pos` make a value: 1 for an attribute or value, 4 for `size(x)`, else 0.
fn var_or_size(input: &[Token], pos: usize) -> usize {
    match input.get(pos) {
        None => 0,
        Some(t) if t.is_var() => 1,
        Some(Token::Size)
            if pos + 3 < input.len()
                && input[pos + 1] == Token::Open
                && input[pos + 2].is_var()
                && input[pos + 3] == Token::Close =>
        {
            4
        }
        Some(_) => 0,
    }
}

/// The lengths of the three operands, when the tokens from `pos` are `A BETWEEN X AND Y`.
fn is_between(input: &[Token], pos: usize) -> Option<(usize, usize, usize)> {
    let size = input.len();
    if size < pos + 5 {
        return None;
    }
    let p1 = var_or_size(input, pos);
    if p1 == 0 || pos + p1 + 1 >= size || input[pos + p1] != Token::Between {
        return None;
    }
    let p2 = var_or_size(input, pos + p1 + 1);
    if p2 == 0 || pos + p1 + p2 + 2 >= size || input[pos + p1 + p2 + 1] != Token::And {
        return None;
    }
    let p3 = var_or_size(input, pos + p1 + p2 + 2);
    (p3 != 0).then_some((p1, p2, p3))
}

/// Whether the tokens from `pos` start `A IN (`.
fn is_in(input: &[Token], pos: usize) -> bool {
    input.len() >= pos + 3
        && input[pos].is_var()
        && input[pos + 1] == Token::In
        && input[pos + 2] == Token::Open
}

/// `A IN (X, Y)` as `IN (A, X, Y)`, and `A BETWEEN X AND Y` as `BETWEEN (A, X, Y)`.
pub(crate) fn convert_to_prefix(input: &[Token]) -> Vec<Token> {
    let mut out = Vec::with_capacity(input.len());
    let mut pos = 0;
    while input.len() >= pos + 5 {
        if is_in(input, pos) {
            out.extend([
                input[pos + 1].clone(),
                input[pos + 2].clone(),
                input[pos].clone(),
                Token::Comma,
            ]);
            pos += 3;
        } else if let Some((b0, b1, b2)) = is_between(input, pos) {
            out.extend([Token::Between, Token::Open]);
            out.extend_from_slice(&input[pos..pos + b0]);
            out.push(Token::Comma);
            out.extend_from_slice(&input[pos + b0 + 1..pos + b0 + b1 + 1]);
            out.push(Token::Comma);
            out.extend_from_slice(&input[pos + b0 + b1 + 2..pos + b0 + b1 + b2 + 2]);
            out.push(Token::Close);
            pos += b0 + b1 + b2 + 2;
        } else {
            out.push(input[pos].clone());
            pos += 1;
        }
    }
    out.extend_from_slice(&input[pos..]);
    out
}

/// Infix tokens, after [`convert_to_prefix`], in reverse Polish order.
pub(crate) fn convert_to_rpn(input: &[Token]) -> Vec<Token> {
    let mut out = Vec::with_capacity(input.len());
    let mut stack: Vec<Token> = Vec::new();
    let mut pos = 0;
    while let Some(t) = input.get(pos) {
        match t {
            Token::Attr(_) | Token::Value(_) => {
                out.push(t.clone());
                pos += 1;
            }
            Token::Between
            | Token::In
            | Token::Not
            | Token::AttributeExists
            | Token::AttributeNotExists
            | Token::AttributeType
            | Token::BeginsWith
            | Token::Contains
            | Token::Size => {
                stack.push(t.clone());
                pos += 1;
            }
            Token::Comma => {
                if stack.last().is_some_and(|top| !top.is_function())
                    && let Some(top) = stack.pop()
                {
                    out.push(top);
                }
                pos += 1;
            }
            Token::Close => {
                match stack.pop() {
                    None | Some(Token::Open) => {}
                    Some(top) => out.push(top),
                }
                pos += 1;
            }
            Token::Eq
            | Token::Ne
            | Token::Lt
            | Token::Gt
            | Token::Le
            | Token::Ge
            | Token::And
            | Token::Or => match stack.last() {
                Some(top) if top.precedence() >= t.precedence() => {
                    if let Some(top) = stack.pop() {
                        out.push(top);
                    }
                }
                _ => {
                    stack.push(t.clone());
                    pos += 1;
                }
            },
            Token::Open => pos += 1,
        }
    }
    while let Some(top) = stack.pop() {
        out.push(top);
    }
    out
}

/// A value on the evaluation stack.
#[derive(Clone, Debug, PartialEq)]
enum StackValue {
    Bool(bool),
    Str(AttributeValue),
    DoesNotExist,
}

impl StackValue {
    /// The attribute value; `NULL` for a boolean or a missing attribute.
    fn get_str(&self) -> AttributeValue {
        match self {
            Self::Str(s) => s.clone(),
            Self::Bool(_) | Self::DoesNotExist => AttributeValue::Null(true),
        }
    }
}

fn eval_err(msg: &str) -> Error {
    val_err(msg)
}

/// The length DynamoDB's `size` function gives `v`.
fn get_size(v: &AttributeValue) -> usize {
    match v {
        AttributeValue::S(s) | AttributeValue::N(s) => utf16_len(s),
        AttributeValue::B(b) => b.as_ref().len(),
        AttributeValue::Ss(s) | AttributeValue::Ns(s) => s.len(),
        AttributeValue::Bs(s) => s.len(),
        AttributeValue::M(m) => m.len(),
        AttributeValue::L(l) => l.len(),
        _ => 1,
    }
}

fn contains_subslice<T: PartialEq>(haystack: &[T], needle: &[T]) -> bool {
    needle.is_empty() || haystack.windows(needle.len()).any(|w| w == needle)
}

/// Whether `haystack` contains `needle`: a substring, or a set or list element.
fn does_contain(haystack: &AttributeValue, needle: &AttributeValue) -> bool {
    match (haystack, needle) {
        (AttributeValue::S(h), AttributeValue::S(n))
        | (AttributeValue::N(h), AttributeValue::N(n)) => contains_subslice(&utf16(h), &utf16(n)),
        (AttributeValue::B(h), AttributeValue::B(n)) => contains_subslice(h.as_ref(), n.as_ref()),
        (AttributeValue::Ss(h), AttributeValue::S(n))
        | (AttributeValue::Ns(h), AttributeValue::N(n)) => h.contains(n),
        (AttributeValue::Bs(h), AttributeValue::B(n)) => h.contains(n),
        (AttributeValue::L(h), n) => h.contains(n),
        _ => false,
    }
}

/// Whether `haystack` begins with `needle`.
fn begins_with(haystack: &AttributeValue, needle: &AttributeValue) -> bool {
    match (haystack, needle) {
        (AttributeValue::S(h), AttributeValue::S(n))
        | (AttributeValue::N(h), AttributeValue::N(n)) => utf16(h).starts_with(&utf16(n)),
        (AttributeValue::B(h), AttributeValue::B(n)) => h.as_ref().starts_with(n.as_ref()),
        (AttributeValue::L(list), n) => match list.first() {
            None => false,
            Some(first) if first == n => true,
            Some(_) => matches!(n, AttributeValue::L(nl) if list.starts_with(nl)),
        },
        _ => false,
    }
}

fn utf16(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

/// Compare two DynamoDB numbers by value.
fn compare_float(x: &str, y: &str) -> Result<Ordering, Error> {
    let x = normalize_number(x).map_err(val_err)?;
    let y = normalize_number(y).map_err(val_err)?;
    Ok(float_compare::compare_float(&x, &y))
}

fn attribute_eq(a: &AttributeValue, b: &AttributeValue) -> Result<bool, Error> {
    match (a, b) {
        (AttributeValue::N(x), AttributeValue::N(y)) => Ok(compare_float(x, y)? == Ordering::Equal),
        _ => Ok(a == b),
    }
}

fn attribute_le(a: &AttributeValue, b: &AttributeValue) -> Result<bool, Error> {
    match (a, b) {
        (AttributeValue::N(x), AttributeValue::N(y)) => {
            Ok(compare_float(x, y)? != Ordering::Greater)
        }
        // Code point order, which is how DynamoDB orders strings.
        (AttributeValue::S(x), AttributeValue::S(y)) => Ok(x <= y),
        (AttributeValue::B(x), AttributeValue::B(y)) => Ok(x.as_ref() <= y.as_ref()),
        _ => Ok(false),
    }
}

fn apply_binary_comp(op: &Token, x: &AttributeValue, y: &AttributeValue) -> Result<bool, Error> {
    match op {
        Token::Eq => attribute_eq(x, y),
        Token::Ne => Ok(!attribute_eq(x, y)?),
        Token::Le => attribute_le(x, y),
        Token::Lt => Ok(!attribute_le(y, x)?),
        Token::Ge => attribute_le(y, x),
        Token::Gt => Ok(!attribute_le(x, y)?),
        _ => Err(eval_err("invalid op in apply_binary_bool")),
    }
}

fn apply_binary(op: &Token, x: &StackValue, y: &StackValue) -> Result<StackValue, Error> {
    if op.is_comp() {
        match (x, y) {
            (StackValue::Str(x), StackValue::Str(y)) => {
                Ok(StackValue::Bool(apply_binary_comp(op, x, y)?))
            }
            _ => Err(eval_err("wrong types for comparison")),
        }
    } else {
        match (x, y, op) {
            (StackValue::Bool(x), StackValue::Bool(y), Token::And) => {
                Ok(StackValue::Bool(*x && *y))
            }
            (StackValue::Bool(x), StackValue::Bool(y), Token::Or) => Ok(StackValue::Bool(*x || *y)),
            (StackValue::Bool(_), StackValue::Bool(_), _) => {
                Err(eval_err("invalid op in apply_binary_bool"))
            }
            _ => Err(eval_err("wrong types for boolean binary")),
        }
    }
}

/// How many values at the top of `stack` are attribute values.
fn strings_following(stack: &[StackValue]) -> usize {
    stack
        .iter()
        .rev()
        .take_while(|v| matches!(v, StackValue::Str(_)))
        .count()
}

/// How many stack values function `t` takes.
fn num_args(t: &Token, stack: &[StackValue]) -> usize {
    match t {
        Token::Between => 3,
        Token::In => strings_following(stack),
        Token::AttributeExists | Token::AttributeNotExists | Token::Size => 1,
        Token::AttributeType | Token::BeginsWith | Token::Contains => 2,
        _ => 0,
    }
}

/// The string form of a value, for `attribute_type`.
fn attr_to_str(v: &AttributeValue) -> &str {
    match v {
        AttributeValue::S(s) | AttributeValue::N(s) => s,
        _ => "",
    }
}

fn apply_function(t: &Token, stack: &[StackValue]) -> Result<StackValue, Error> {
    let n = stack.len();
    let top = |i: usize| &stack[n - i];
    match t {
        Token::Between => {
            if n < 3 {
                return Err(eval_err("No Stack for Between"));
            }
            match (top(3), top(2), top(1)) {
                (StackValue::Str(m), StackValue::Str(l), StackValue::Str(r)) => {
                    Ok(StackValue::Bool(attribute_le(l, m)? && attribute_le(m, r)?))
                }
                _ => Err(eval_err("Wrong Types for Between")),
            }
        }
        Token::In => {
            let num = strings_following(stack);
            if num == 0 {
                return Err(eval_err("In has no args"));
            }
            let target = stack[n - num].get_str();
            Ok(StackValue::Bool(
                stack[n - num + 1..].iter().any(|v| v.get_str() == target),
            ))
        }
        Token::AttributeExists => {
            if n < 1 {
                return Err(eval_err("No Stack for AttributeExists"));
            }
            Ok(StackValue::Bool(*top(1) != StackValue::DoesNotExist))
        }
        Token::AttributeNotExists => {
            if n < 1 {
                return Err(eval_err("No Stack for AttributeExists"));
            }
            Ok(StackValue::Bool(*top(1) == StackValue::DoesNotExist))
        }
        Token::AttributeType => {
            if n < 2 {
                return Err(eval_err("No Stack for AttributeType"));
            }
            Ok(StackValue::Bool(
                attr_type_to_str(&top(2).get_str()) == attr_to_str(&top(1).get_str()),
            ))
        }
        Token::BeginsWith => {
            if n < 2 {
                return Err(eval_err("No Stack for BeginsWith"));
            }
            match (top(2), top(1)) {
                (StackValue::Str(h), StackValue::Str(nd)) => {
                    Ok(StackValue::Bool(begins_with(h, nd)))
                }
                _ => Err(eval_err("Wrong Types for BeginsWith")),
            }
        }
        Token::Contains => {
            if n < 2 {
                return Err(eval_err("No Stack for contains"));
            }
            match (top(2), top(1)) {
                (StackValue::Str(h), StackValue::Str(nd)) => {
                    Ok(StackValue::Bool(does_contain(h, nd)))
                }
                _ => Err(eval_err("Wrong Types for contains")),
            }
        }
        Token::Size => {
            if n < 1 {
                return Err(eval_err("No Stack for Size"));
            }
            match top(1) {
                StackValue::Str(v) => {
                    Ok(StackValue::Str(AttributeValue::N(get_size(v).to_string())))
                }
                _ => Err(eval_err("Wrong Types for Size")),
            }
        }
        _ => Ok(StackValue::Bool(true)),
    }
}

/// The value of attribute token `name` in `item`.
fn stack_value_from_attr(
    name: &str,
    item: &HashMap<String, AttributeValue>,
    names: Option<&HashMap<String, String>>,
) -> StackValue {
    let found = match names.and_then(|n| n.get(name)) {
        Some(real) => item.get(real).cloned(),
        None => attr_loc(name).term_to_attr(item, names),
    };
    found.map_or(StackValue::DoesNotExist, StackValue::Str)
}

/// Evaluate `input`, in reverse Polish order, on `item`.
///
/// # Errors
///
/// A `Validation` error when the expression is malformed,
/// or compares a value that is not a valid number as a number.
pub(crate) fn eval_expr(
    input: &[Token],
    item: &HashMap<String, AttributeValue>,
    names: Option<&HashMap<String, String>>,
    values: &HashMap<String, AttributeValue>,
) -> Result<bool, Error> {
    let mut stack: Vec<StackValue> = Vec::new();
    for t in input {
        match t {
            Token::Value(s) => stack.push(
                values
                    .get(s)
                    .cloned()
                    .map_or(StackValue::DoesNotExist, StackValue::Str),
            ),
            Token::Attr(s) => stack.push(stack_value_from_attr(s, item, names)),
            Token::Not => match stack.pop() {
                None => return Err(eval_err("Empty stack for unary op")),
                Some(StackValue::Bool(b)) => stack.push(StackValue::Bool(!b)),
                Some(_) => return Err(eval_err("wrong type for Not")),
            },
            t if t.is_binary() => {
                if stack.len() < 2 {
                    return Err(eval_err("Empty stack for binary op"));
                }
                let y = stack.pop().unwrap_or(StackValue::DoesNotExist);
                let x = stack.pop().unwrap_or(StackValue::DoesNotExist);
                stack.push(apply_binary(t, &x, &y)?);
            }
            t if t.is_function() => {
                let num = num_args(t, &stack);
                if stack.len() < num {
                    return Err(eval_err("Empty stack for function call"));
                }
                let val = apply_function(t, &stack)?;
                stack.truncate(stack.len() - num);
                stack.push(val);
            }
            _ => return Ok(true),
        }
    }
    match stack.as_slice() {
        [StackValue::Bool(b)] => Ok(*b),
        _ => Err(eval_err("ended with bad stack")),
    }
}

#[cfg(test)]
#[path = "filter_expr_tests.rs"]
mod tests;

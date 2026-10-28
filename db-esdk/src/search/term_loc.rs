// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Terminal locations: the parsed form of a DynamoDB document path such as `a.b[2]`.

use std::fmt;

use crate::error::{Error, val_err};

/// One step into a nested value.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum Selector {
    /// An index into a list.
    List(u64),
    /// A key into a map.
    Map(String),
}

/// A path to a value: an attribute name, then zero or more selectors.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct TermLoc {
    attribute: String,
    selectors: Vec<Selector>,
}

impl TermLoc {
    /// The location of the whole attribute `name`.
    pub(crate) fn attribute(name: &str) -> Self {
        Self {
            attribute: name.to_owned(),
            selectors: Vec::new(),
        }
    }

    /// Parse a path: `name`, followed by `.key` and `[index]` segments.
    pub(crate) fn parse(s: &str) -> Result<Self, Error> {
        if s.is_empty() {
            return Err(val_err("Path specification must not be empty."));
        }
        let Some(pos) = find_start_of_next(s) else {
            return Ok(Self::attribute(s));
        };
        Ok(Self {
            attribute: s[..pos].to_owned(),
            selectors: selectors(&s[pos..])?,
        })
    }

    /// The top-level attribute the path starts in.
    pub(crate) fn attribute_name(&self) -> &str {
        &self.attribute
    }
}

impl fmt::Display for TermLoc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.attribute)?;
        for s in &self.selectors {
            match s {
                Selector::Map(k) => write!(f, ".{k}")?,
                Selector::List(i) => write!(f, "[{i}]")?,
            }
        }
        Ok(())
    }
}

/// The byte position of the first `.` or `[` in `s`.
fn find_start_of_next(s: &str) -> Option<usize> {
    s.find(['.', '['])
}

/// Parse `s`, which starts with `.` or `[`, into selectors.
fn selectors(mut s: &str) -> Result<Vec<Selector>, Error> {
    let mut out = Vec::new();
    loop {
        // Skip the leading `.` or `[` when looking for the next segment.
        let next = find_start_of_next(&s[1..]).map(|p| p + 1);
        let end = next.unwrap_or(s.len());
        out.push(selector(&s[..end])?);
        match next {
            None => return Ok(out),
            Some(n) => s = &s[n..],
        }
    }
}

/// Parse one segment: `.key` or `[index]`.
fn selector(s: &str) -> Result<Selector, Error> {
    if let Some(key) = s.strip_prefix('.') {
        return Ok(Selector::Map(key.to_owned()));
    }
    let inner = s
        .strip_prefix('[')
        .and_then(|r| r.strip_suffix(']'))
        .ok_or_else(|| val_err("List index must end with ]"))?;
    number(inner).map(Selector::List)
}

/// Parse an unsigned decimal list index.
fn number(s: &str) -> Result<u64, Error> {
    let mut acc: u64 = 0;
    for c in s.chars() {
        let Some(d) = c.to_digit(10) else {
            return Err(val_err(format!("Unexpected character in number : {c}")));
        };
        if acc >= 0x0fff_ffff_ffff_ffff {
            return Err(val_err(format!("Number is too big for list index : {s}")));
        }
        acc = acc * 10 + u64::from(d);
    }
    Ok(acc)
}

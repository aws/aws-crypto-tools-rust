// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Terminal locations: the parsed form of a DynamoDB document path such as `a.b[2]`.

use std::collections::HashMap;
use std::fmt;

use aws_crypto_mpl::aws_sdk_dynamodb::types::AttributeValue;

use crate::ddb::top_level_attr_to_bytes;
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

    /// Whether the path is a whole top-level attribute, with no selectors.
    pub(crate) fn is_whole_attribute(&self) -> bool {
        self.selectors.is_empty()
    }

    /// The value at this path in `item`, if there is one.
    ///
    /// A map key that is not in the map is looked up again through `names`.
    pub(crate) fn term_to_attr(
        &self,
        item: &HashMap<String, AttributeValue>,
        names: Option<&HashMap<String, String>>,
    ) -> Option<AttributeValue> {
        let top = item.get(&self.attribute)?;
        get_terminal(top, &self.selectors, names).ok().cloned()
    }

    /// The string form of the value at this path in `item`, if there is one.
    pub(crate) fn term_to_string(
        &self,
        item: &HashMap<String, AttributeValue>,
    ) -> Result<Option<String>, Error> {
        self.term_to_attr(item, None)
            .map(|v| attr_value_to_string(&v))
            .transpose()
    }

    /// The serialized value at this path in `item`, if there is one.
    pub(crate) fn term_to_bytes(
        &self,
        item: &HashMap<String, AttributeValue>,
    ) -> Result<Option<Vec<u8>>, Error> {
        self.term_to_attr(item, None)
            .map(|v| top_level_attr_to_bytes(&v).map_err(val_err))
            .transpose()
    }
}

/// The value `parts` select inside `v`.
fn get_terminal<'a>(
    v: &'a AttributeValue,
    parts: &[Selector],
    names: Option<&HashMap<String, String>>,
) -> Result<&'a AttributeValue, Error> {
    let Some((first, rest)) = parts.split_first() else {
        return Ok(v);
    };
    match v {
        AttributeValue::L(l) => {
            let Selector::List(pos) = first else {
                return Err(val_err("Tried to access list with key"));
            };
            let next = usize::try_from(*pos)
                .ok()
                .and_then(|p| l.get(p))
                .ok_or_else(|| val_err("Tried to access beyond the end of the list"))?;
            get_terminal(next, rest, names)
        }
        AttributeValue::M(m) => {
            let Selector::Map(key) = first else {
                return Err(val_err("Tried to access map with index"));
            };
            let next = match m.get(key) {
                Some(n) => n,
                None => names
                    .and_then(|n| n.get(key))
                    .and_then(|real| m.get(real))
                    .ok_or_else(|| {
                        val_err(format!("Tried to access {key} which is not in the map."))
                    })?,
            };
            get_terminal(next, rest, names)
        }
        other => Err(val_err(format!(
            "Found {} with parts left over.",
            match other {
                AttributeValue::S(_) => "string",
                AttributeValue::N(_) => "number",
                AttributeValue::B(_) => "binary",
                AttributeValue::Ss(_) => "string set",
                AttributeValue::Ns(_) => "number set",
                AttributeValue::Bs(_) => "binary set",
                AttributeValue::Bool(_) => "boolean",
                _ => "null",
            }
        ))),
    }
}

/// The string form of a terminal value.
fn attr_value_to_string(v: &AttributeValue) -> Result<String, Error> {
    match v {
        AttributeValue::S(s) | AttributeValue::N(s) => Ok(s.clone()),
        AttributeValue::Bool(b) => Ok(if *b { "true" } else { "false" }.to_owned()),
        AttributeValue::Null(_) => Ok("null".to_owned()),
        AttributeValue::B(_) => Err(val_err("Can't convert Binary to string")),
        AttributeValue::Ss(_) => Err(val_err("Can't convert String Set to string.")),
        AttributeValue::Ns(_) => Err(val_err("Can't convert Number Set to string.")),
        AttributeValue::Bs(_) => Err(val_err("Can't convert Binary Set to string.")),
        AttributeValue::L(_) => Err(val_err("Can't convert List to string.")),
        _ => Err(val_err("Can't convert Map to string.")),
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

#[cfg(test)]
#[path = "term_loc_tests.rs"]
mod tests;

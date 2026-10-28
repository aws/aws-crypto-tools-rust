// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The JSON the DynamoDB wire protocol needs: enough to read the SDK's requests
//! and write the fake's responses.

use std::collections::BTreeMap;
use std::fmt::{self, Write as _};

/// A JSON value. Objects are sorted, so equal values serialize identically.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Json {
    Null,
    Bool(bool),
    /// A number, kept as its text.
    Num(String),
    Str(String),
    Arr(Vec<Json>),
    Obj(BTreeMap<String, Json>),
}

impl Json {
    pub fn get(&self, key: &str) -> Option<&Self> {
        match self {
            Self::Obj(m) => m.get(key),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_obj(&self) -> Option<&BTreeMap<String, Self>> {
        match self {
            Self::Obj(m) => Some(m),
            _ => None,
        }
    }

    pub fn as_arr(&self) -> Option<&[Self]> {
        match self {
            Self::Arr(a) => Some(a),
            _ => None,
        }
    }

    pub fn obj<const N: usize>(entries: [(&str, Self); N]) -> Self {
        Self::Obj(
            entries
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v))
                .collect(),
        )
    }
}

impl fmt::Display for Json {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => f.write_str("null"),
            Self::Bool(b) => write!(f, "{b}"),
            Self::Num(n) => f.write_str(n),
            Self::Str(s) => write_str(f, s),
            Self::Arr(a) => {
                f.write_char('[')?;
                for (i, v) in a.iter().enumerate() {
                    if i > 0 {
                        f.write_char(',')?;
                    }
                    write!(f, "{v}")?;
                }
                f.write_char(']')
            }
            Self::Obj(m) => {
                f.write_char('{')?;
                for (i, (k, v)) in m.iter().enumerate() {
                    if i > 0 {
                        f.write_char(',')?;
                    }
                    write_str(f, k)?;
                    write!(f, ":{v}")?;
                }
                f.write_char('}')
            }
        }
    }
}

fn write_str(f: &mut fmt::Formatter<'_>, s: &str) -> fmt::Result {
    f.write_char('"')?;
    for c in s.chars() {
        match c {
            '"' => f.write_str("\\\"")?,
            '\\' => f.write_str("\\\\")?,
            '\n' => f.write_str("\\n")?,
            '\r' => f.write_str("\\r")?,
            '\t' => f.write_str("\\t")?,
            c if u32::from(c) < 0x20 => write!(f, "\\u{:04x}", u32::from(c))?,
            c => f.write_char(c)?,
        }
    }
    f.write_char('"')
}

/// Parse `text`, which must be exactly one JSON value.
pub fn parse(text: &str) -> Result<Json, String> {
    let mut p = Parser {
        chars: text.chars().collect(),
        pos: 0,
    };
    let value = p.value()?;
    p.skip_ws();
    if p.pos == p.chars.len() {
        Ok(value)
    } else {
        Err(format!("trailing data at {}", p.pos))
    }
}

struct Parser {
    chars: Vec<char>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn next(&mut self) -> Result<char, String> {
        let c = self.peek().ok_or("unexpected end of JSON")?;
        self.pos += 1;
        Ok(c)
    }

    fn skip_ws(&mut self) {
        while self.peek().is_some_and(char::is_whitespace) {
            self.pos += 1;
        }
    }

    fn expect(&mut self, want: char) -> Result<(), String> {
        let got = self.next()?;
        if got == want {
            Ok(())
        } else {
            Err(format!(
                "expected {want:?}, got {got:?} at {}",
                self.pos - 1
            ))
        }
    }

    fn literal(&mut self, word: &str, value: Json) -> Result<Json, String> {
        for want in word.chars() {
            self.expect(want)?;
        }
        Ok(value)
    }

    fn value(&mut self) -> Result<Json, String> {
        self.skip_ws();
        match self.peek().ok_or("unexpected end of JSON")? {
            '{' => self.object(),
            '[' => self.array(),
            '"' => self.string().map(Json::Str),
            't' => self.literal("true", Json::Bool(true)),
            'f' => self.literal("false", Json::Bool(false)),
            'n' => self.literal("null", Json::Null),
            _ => self.number(),
        }
    }

    fn object(&mut self) -> Result<Json, String> {
        self.expect('{')?;
        let mut map = BTreeMap::new();
        self.skip_ws();
        if self.peek() == Some('}') {
            self.pos += 1;
            return Ok(Json::Obj(map));
        }
        loop {
            self.skip_ws();
            let key = self.string()?;
            self.skip_ws();
            self.expect(':')?;
            map.insert(key, self.value()?);
            self.skip_ws();
            match self.next()? {
                ',' => {}
                '}' => return Ok(Json::Obj(map)),
                c => return Err(format!("expected ',' or '}}', got {c:?}")),
            }
        }
    }

    fn array(&mut self) -> Result<Json, String> {
        self.expect('[')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(']') {
            self.pos += 1;
            return Ok(Json::Arr(items));
        }
        loop {
            items.push(self.value()?);
            self.skip_ws();
            match self.next()? {
                ',' => {}
                ']' => return Ok(Json::Arr(items)),
                c => return Err(format!("expected ',' or ']', got {c:?}")),
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let mut n = 0;
        for _ in 0..4 {
            let d = self.next()?.to_digit(16).ok_or("bad \\u escape")?;
            n = n * 16 + d;
        }
        Ok(n)
    }

    fn string(&mut self) -> Result<String, String> {
        self.expect('"')?;
        let mut out = String::new();
        loop {
            match self.next()? {
                '"' => return Ok(out),
                '\\' => match self.next()? {
                    '"' => out.push('"'),
                    '\\' => out.push('\\'),
                    '/' => out.push('/'),
                    'b' => out.push('\u{8}'),
                    'f' => out.push('\u{c}'),
                    'n' => out.push('\n'),
                    'r' => out.push('\r'),
                    't' => out.push('\t'),
                    'u' => {
                        let hi = self.hex4()?;
                        let code = if (0xD800..0xDC00).contains(&hi) {
                            self.expect('\\')?;
                            self.expect('u')?;
                            let lo = self.hex4()?;
                            0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                        } else {
                            hi
                        };
                        out.push(char::from_u32(code).ok_or("bad \\u escape")?);
                    }
                    c => return Err(format!("bad escape \\{c}")),
                },
                c => out.push(c),
            }
        }
    }

    fn number(&mut self) -> Result<Json, String> {
        let start = self.pos;
        while self
            .peek()
            .is_some_and(|c| c.is_ascii_digit() || matches!(c, '-' | '+' | '.' | 'e' | 'E'))
        {
            self.pos += 1;
        }
        if start == self.pos {
            return Err(format!("unexpected character at {start}"));
        }
        Ok(Json::Num(self.chars[start..self.pos].iter().collect()))
    }
}

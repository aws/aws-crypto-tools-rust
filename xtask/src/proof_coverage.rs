// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Says, for each line of a Rust source file, how much Verus checks it.
//!
//! Verus checks only code inside `verus! { ... }` blocks, so this reads the
//! source and does not run Verus. Each line of a function gets one kind:
//!
//! - `proven`: an exec fn inside `verus!` with `requires` or `ensures`. Verus
//!   proves the fn meets its stated rules and cannot panic.
//! - `no_panic`: an exec fn inside `verus!` with no `requires` or `ensures`.
//!   Verus proves only that it cannot panic or overflow.
//! - `ghost`: a `spec fn` or `proof fn`. It states or proves rules and is not
//!   compiled into the library.
//! - `trusted`: a `#[verifier::external_body]` fn or an
//!   `assume_specification`. Verus assumes its rules without checking them.
//! - `unverified`: an exec fn outside `verus!`. Verus does not check it.
//!
//! Lines inside `verus!` that are not in a function (types, constants) are
//! `verus_item`. Other lines, comments, blank lines and `#[cfg(test)]`
//! modules get no kind.

use serde::Serialize;

/// The line kinds, in the order the dashboard lists them.
pub const KINDS: [&str; 6] = [
    "proven",
    "no_panic",
    "ghost",
    "trusted",
    "verus_item",
    "unverified",
];

#[derive(Debug, Serialize)]
pub struct FileCoverage {
    pub path: String,
    pub lines: usize,
    /// Lines of each kind, keyed as in [`KINDS`].
    pub counts: std::collections::BTreeMap<&'static str, usize>,
    /// `[first, last, kind]` line runs, 1-based and inclusive. Lines in no run
    /// have no kind.
    pub runs: Vec<(usize, usize, &'static str)>,
    pub fns: Vec<Fn>,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct Fn {
    pub name: String,
    pub first: usize,
    pub last: usize,
    pub kind: &'static str,
}

/// The source with comments and the insides of string and char literals
/// replaced by spaces. Newlines stay, so byte offsets and line numbers match
/// the source, and braces in comments or strings are never counted.
pub fn mask(src: &str) -> Vec<u8> {
    let b = src.as_bytes();
    let mut out = b.to_vec();
    let blank = |out: &mut Vec<u8>, from: usize, to: usize| {
        for c in &mut out[from..to] {
            if *c != b'\n' {
                *c = b' ';
            }
        }
    };
    let mut i = 0;
    while i < b.len() {
        if b[i..].starts_with(b"//") {
            let end = b[i..]
                .iter()
                .position(|&c| c == b'\n')
                .map_or(b.len(), |n| i + n);
            blank(&mut out, i, end);
            i = end;
        } else if b[i..].starts_with(b"/*") {
            let (mut depth, mut j) = (1, i + 2);
            while j < b.len() && depth > 0 {
                if b[j..].starts_with(b"/*") {
                    depth += 1;
                    j += 2;
                } else if b[j..].starts_with(b"*/") {
                    depth -= 1;
                    j += 2;
                } else {
                    j += 1;
                }
            }
            blank(&mut out, i, j);
            i = j;
        } else if b[i] == b'"' || (b[i] == b'r' && raw_string_hashes(&b[i..]).is_some()) {
            let end = string_end(b, i);
            // Keep the quote marks, so a line holding a string still has code.
            blank(&mut out, i + 1, end.saturating_sub(1).max(i + 1));
            i = end;
        } else if b[i] == b'\'' {
            // A char literal is 'x' or '\..'; anything else is a lifetime.
            let end = if b.get(i + 1) == Some(&b'\\') {
                b[i + 2..]
                    .iter()
                    .position(|&c| c == b'\'')
                    .map(|n| i + 3 + n)
            } else if b.get(i + 2) == Some(&b'\'') {
                Some(i + 3)
            } else {
                None
            };
            match end {
                Some(end) => {
                    blank(&mut out, i + 1, end - 1);
                    i = end;
                }
                None => i += 1,
            }
        } else {
            i += 1;
        }
    }
    out
}

/// For `r"`, `r#"`, ... the number of `#`.
fn raw_string_hashes(b: &[u8]) -> Option<usize> {
    let hashes = b[1..].iter().take_while(|&&c| c == b'#').count();
    (b.get(1 + hashes) == Some(&b'"')).then_some(hashes)
}

/// The byte after the string literal that starts at `i`.
fn string_end(b: &[u8], i: usize) -> usize {
    if let Some(hashes) = (b[i] == b'r').then(|| raw_string_hashes(&b[i..])).flatten() {
        let close: Vec<u8> = std::iter::once(b'"')
            .chain(std::iter::repeat_n(b'#', hashes))
            .collect();
        let body = i + 2 + hashes;
        return b[body..]
            .windows(close.len())
            .position(|w| w == close.as_slice())
            .map_or(b.len(), |n| body + n + close.len());
    }
    let mut j = i + 1;
    while j < b.len() {
        match b[j] {
            b'\\' => j += 2,
            b'"' => return j + 1,
            _ => j += 1,
        }
    }
    b.len()
}

/// The closing brace of every `{`, by offset.
fn brace_pairs(m: &[u8]) -> std::collections::HashMap<usize, usize> {
    let mut open = Vec::new();
    let mut pairs = std::collections::HashMap::new();
    for (i, &c) in m.iter().enumerate() {
        match c {
            b'{' => open.push(i),
            b'}' => {
                if let Some(o) = open.pop() {
                    pairs.insert(o, i);
                }
            }
            _ => {}
        }
    }
    pairs
}

const fn is_ident(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

/// Offsets where `word` appears as a whole word.
fn words(m: &[u8], word: &str) -> Vec<usize> {
    let w = word.as_bytes();
    (0..m.len().saturating_sub(w.len() - 1))
        .filter(|&i| {
            m[i..].starts_with(w)
                && (i == 0 || !is_ident(m[i - 1]))
                && m.get(i + w.len()).is_none_or(|&c| !is_ident(c))
        })
        .collect()
}

fn next_non_space(m: &[u8], from: usize) -> Option<usize> {
    (from..m.len()).find(|&i| !m[i].is_ascii_whitespace())
}

/// The start of the item that holds offset `at`: just after the previous
/// `;`, `{` or `}`. Attributes and modifiers before `fn` are in this span.
fn item_start(m: &[u8], at: usize) -> usize {
    m[..at]
        .iter()
        .rposition(|&c| matches!(c, b';' | b'{' | b'}'))
        .map_or(0, |n| n + 1)
}

/// The end of an item whose header starts at `from`: the `;` that ends it, or
/// the closing brace of its body. A `{` inside a `requires`/`ensures` clause
/// that follows `match`, `if` or `else` is part of the clause, not the body.
fn item_end(m: &[u8], from: usize, pairs: &std::collections::HashMap<usize, usize>) -> usize {
    let mut depth = 0i32;
    let mut i = from;
    while i < m.len() {
        match m[i] {
            b'(' | b'[' => depth += 1,
            b')' | b']' => depth -= 1,
            b';' if depth == 0 => return i,
            b'{' if depth == 0 => {
                let clause = &m[from..i];
                let last_word = clause
                    .rsplit(|&c| matches!(c, b',' | b'\n'))
                    .next()
                    .unwrap_or_default();
                let in_clause = ["match", "if", "else"]
                    .iter()
                    .any(|w| !words(last_word, w).is_empty())
                    && ["requires", "ensures"]
                        .iter()
                        .any(|w| !words(clause, w).is_empty());
                let close = pairs.get(&i).copied().unwrap_or(m.len() - 1);
                if !in_clause {
                    return close;
                }
                i = close;
            }
            _ => {}
        }
        i += 1;
    }
    m.len() - 1
}

/// Reads one file. `path` is only copied into the result.
pub fn file_coverage(path: &str, src: &str) -> FileCoverage {
    let m = mask(src);
    let pairs = brace_pairs(&m);
    let line_starts: Vec<usize> = std::iter::once(0)
        .chain(
            m.iter()
                .enumerate()
                .filter(|(_, c)| **c == b'\n')
                .map(|(i, _)| i + 1),
        )
        .collect();
    let line_of = |off: usize| line_starts.partition_point(|&s| s <= off);
    let n_lines = src.lines().count();

    // `verus! { ... }` blocks and `#[cfg(test)] mod x { ... }` modules, by line.
    let block_after = |at: usize| {
        next_non_space(&m, at)
            .filter(|&o| m[o] == b'{')
            .and_then(|o| pairs.get(&o).map(|c| (o, *c)))
    };
    let verus: Vec<(usize, usize)> = words(&m, "verus")
        .into_iter()
        .filter(|&i| m.get(i + 5) == Some(&b'!'))
        .filter_map(|i| block_after(i + 6))
        .collect();
    let tests: Vec<(usize, usize)> = words(&m, "cfg")
        .into_iter()
        .filter(|&i| m[i..].starts_with(b"cfg(test)"))
        .filter_map(|i| {
            let after = i + m[i..].iter().position(|&c| c == b']')? + 1;
            let mod_at = next_non_space(&m, after).filter(|&o| m[o..].starts_with(b"mod "))?;
            let open = mod_at + m[mod_at..].iter().position(|&c| c == b'{' || c == b';')?;
            pairs.get(&open).map(|c| (open, *c))
        })
        .collect();
    let inside =
        |spans: &[(usize, usize)], off: usize| spans.iter().any(|&(a, b)| a <= off && off <= b);

    let mut fns = Vec::new();
    let mut items: Vec<(usize, usize, &'static str)> = Vec::new();
    // `fn` followed by a name; `fn(u8) -> u8` is a type, not an item.
    let fn_items = words(&m, "fn").into_iter().filter(|&at| {
        next_non_space(&m, at + 2).is_some_and(|o| m[o].is_ascii_alphabetic() || m[o] == b'_')
    });
    for at in fn_items.chain(words(&m, "assume_specification")) {
        if inside(&tests, at) {
            continue;
        }
        let start = item_start(&m, at);
        let header = &m[start..at];
        let end = item_end(&m, at, &pairs);
        let in_verus = inside(&verus, at);
        let body = &m[at..=end];
        let kind = if m[at..].starts_with(b"assume_specification")
            || !words(header, "external_body").is_empty()
        {
            "trusted"
        } else if !words(header, "spec").is_empty() || !words(header, "proof").is_empty() {
            "ghost"
        } else if !in_verus {
            "unverified"
        } else if ["requires", "ensures"]
            .iter()
            .any(|w| !words(body, w).is_empty())
        {
            "proven"
        } else {
            "no_panic"
        };
        // Doc comments and attributes above the fn are blank in the mask, so
        // the fn starts at its first line with code.
        let first = next_non_space(&m, start).unwrap_or(at);
        items.push((line_of(first), line_of(end), kind));
        // `fn name` or `assume_specification[ path ]`.
        let name = if m[at..].starts_with(b"fn") {
            let from = next_non_space(&m, at + 2).unwrap_or(at);
            src[from..]
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect()
        } else {
            let from = at + src[at..].find('[').map_or(0, |n| n + 1);
            src[from..]
                .split(']')
                .next()
                .unwrap_or_default()
                .trim()
                .to_owned()
        };
        fns.push(Fn {
            name,
            first: line_of(first),
            last: line_of(end),
            kind,
        });
    }
    fns.sort_by_key(|f| f.first);

    // The kind of each line. A fn inside another item (an impl, a verus!
    // block) wins over that item, and a later fn never overlaps an earlier one.
    let mut kind_of: Vec<Option<&'static str>> = vec![None; n_lines + 1];
    for &(a, b) in &verus {
        for k in &mut kind_of[line_of(a)..=line_of(b).min(n_lines)] {
            *k = Some("verus_item");
        }
    }
    for &(first, last, kind) in &items {
        for k in &mut kind_of[first..=last.min(n_lines)] {
            *k = Some(kind);
        }
    }
    for &(a, b) in &tests {
        for k in &mut kind_of[line_of(a)..=line_of(b).min(n_lines)] {
            *k = None;
        }
    }
    // `verus! {` and its closing `}` lines are not code of their own.
    for &(a, b) in &verus {
        kind_of[line_of(a)] = None;
        kind_of[line_of(b)] = None;
    }
    let has_code = |l: usize| {
        let end = line_starts
            .get(l)
            .copied()
            .unwrap_or(m.len())
            .saturating_sub(1);
        m[line_starts[l - 1]..end.max(line_starts[l - 1])]
            .iter()
            .any(|c| !c.is_ascii_whitespace())
    };

    let mut counts: std::collections::BTreeMap<&'static str, usize> =
        KINDS.iter().map(|k| (*k, 0)).collect();
    let mut runs: Vec<(usize, usize, &'static str)> = Vec::new();
    for (l, kind) in kind_of.iter().enumerate().skip(1) {
        let Some(kind) = kind.filter(|_| has_code(l)) else {
            continue;
        };
        *counts.entry(kind).or_default() += 1;
        match runs.last_mut() {
            Some(run) if run.2 == kind && run.1 + 1 == l => run.1 = l,
            _ => runs.push((l, l, kind)),
        }
    }
    FileCoverage {
        path: path.to_owned(),
        lines: n_lines,
        counts,
        runs,
        fns,
    }
}

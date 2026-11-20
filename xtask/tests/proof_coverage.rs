// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for sorting source lines by how much Verus checks them. The sample
//! file has one item of each kind, in the shapes the esdk and prim crates use.

use xtask::proof_coverage::{Fn, file_coverage};

const SAMPLE: &str = r#"use vstd::prelude::*;

verus! {

/// The big-endian value. A brace in a comment: {
pub open spec fn spec_be(b: [u8; 2]) -> int {
    b[0] as int * 256 + b[1] as int
}

pub fn checked(count: usize) -> (r: bool)
    ensures r == (count > 0),
{
    count > 0
}

fn only_no_panic(x: u8) -> u8 {
    x / 2
}

#[verifier::external_body]
fn wrapped(s: &[u8]) -> bool {
    std::str::from_utf8(s).is_ok()
}

pub assume_specification[ core::cmp::max ](a: u8, b: u8) -> (r: u8)
    ensures r >= a;

pub const LIMIT: usize = 4;

} // verus!

pub async fn adapter(s: &str) -> usize {
    let open = "{";
    s.len() + open.len()
}

#[cfg(test)]
mod tests {
    fn helper() {}
}
"#;

#[test]
fn each_fn_gets_the_kind_verus_gives_it() {
    let c = file_coverage("esdk/src/sample.rs", SAMPLE);
    let fns: Vec<(&str, &str)> = c.fns.iter().map(|f| (f.name.as_str(), f.kind)).collect();
    assert_eq!(
        fns,
        [
            ("spec_be", "ghost"),
            ("checked", "proven"),
            ("only_no_panic", "no_panic"),
            ("wrapped", "trusted"),
            ("core::cmp::max", "trusted"),
            ("adapter", "unverified"),
        ]
    );
    // Rejects fns inside a #[cfg(test)] module, which is not library code
    assert!(!c.fns.iter().any(|f| f.name == "helper"));
}

#[test]
fn a_fn_spans_from_its_first_code_line_to_its_closing_brace() {
    let c = file_coverage("esdk/src/sample.rs", SAMPLE);
    // The doc comment above spec_be is not part of it, and the `{` inside the
    // comment does not end it early.
    assert_eq!(
        c.fns[0],
        Fn {
            name: "spec_be".to_owned(),
            first: 6,
            last: 8,
            kind: "ghost"
        }
    );
    // The `{` inside the string in adapter does not end it early.
    let adapter = c.fns.iter().find(|f| f.name == "adapter").unwrap();
    assert_eq!((adapter.first, adapter.last), (32, 35));
}

#[test]
fn line_counts_skip_comments_blank_lines_and_tests() {
    let c = file_coverage("esdk/src/sample.rs", SAMPLE);
    assert_eq!(c.counts["ghost"], 3);
    assert_eq!(c.counts["proven"], 5);
    assert_eq!(c.counts["no_panic"], 3);
    // wrapped's three lines, its attribute, and assume_specification's two
    assert_eq!(c.counts["trusted"], 6);
    // the use line is outside verus!, so only LIMIT is a verus item
    assert_eq!(c.counts["verus_item"], 1);
    assert_eq!(c.counts["unverified"], 4);
}

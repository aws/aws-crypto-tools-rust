// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for checking the claims in `docs/verification-claims.toml` against
//! the code, and for reading Verus's output.

use xtask::proof_coverage::file_coverage;
use xtask::verification::{ClaimsFile, Mark, crate_results, crate_summaries, resolve_claims};

const HEADER: &str = "verus! {
pub fn edk_count_check(count: usize) -> (r: bool)
    ensures r == (count > 0),
{
    count > 0
}

pub fn not_described(x: u8) -> u8 {
    x / 2
}
}

pub async fn read_header(count: usize) -> bool {
    edk_count_check(count)
}
";

fn claims(toml_text: &str) -> ClaimsFile {
    toml::from_str(toml_text).unwrap()
}

fn files() -> Vec<xtask::proof_coverage::FileCoverage> {
    vec![file_coverage("esdk/src/header.rs", HEADER)]
}

#[test]
fn a_proven_claim_gets_the_lines_of_its_fns() {
    let file = claims(
        r#"
[[claim]]
area = "Message header"
mark = "proven"
text = "A message with no encrypted data keys is rejected."
fns = ["esdk/src/header.rs::edk_count_check"]
"#,
    );
    let (resolved, undescribed) = resolve_claims(file, &files(), &[]).unwrap();
    assert_eq!(resolved[0].mark, Mark::Proven);
    assert_eq!(resolved[0].places[0].first, Some(2));
    assert_eq!(resolved[0].places[0].last, Some(6));
    // Lists the checked fn no claim names
    assert_eq!(undescribed, ["esdk/src/header.rs::not_described"]);
}

#[test]
fn a_proven_claim_must_name_a_fn_inside_verus() {
    // Accepts a fn inside verus!
    let inside = r#"
[[claim]]
area = "a"
mark = "proven"
text = "t"
fns = ["esdk/src/header.rs::edk_count_check"]
"#;
    assert!(resolve_claims(claims(inside), &files(), &[]).is_ok());
    // Rejects a fn outside verus!, so an unchecked fn cannot be called proven
    let outside = inside.replace("edk_count_check", "read_header");
    let err = resolve_claims(claims(&outside), &files(), &[]).unwrap_err();
    assert_eq!(
        err,
        "claim \"t\": esdk/src/header.rs::read_header is unverified, not inside verus!"
    );
    // Rejects a fn that no longer exists
    let gone = inside.replace("edk_count_check", "renamed");
    let err = resolve_claims(claims(&gone), &files(), &[]).unwrap_err();
    assert_eq!(err, "claim \"t\": no fn renamed in esdk/src/header.rs");
}

#[test]
fn a_model_claim_must_name_a_model_that_passed() {
    let model = r#"
[[claim]]
area = "a"
mark = "model"
text = "t"
files = ["verification/commitment_ordering_proofs.rs"]
"#;
    // Accepts a model file that verified with no errors
    let passed = ["commitment_ordering_proofs.rs".to_owned()];
    assert!(resolve_claims(claims(model), &files(), &passed).is_ok());
    // Rejects it when that file did not pass
    let err = resolve_claims(claims(model), &files(), &[]).unwrap_err();
    assert_eq!(
        err,
        "claim \"t\": verification/commitment_ordering_proofs.rs did not pass make -C verification verify"
    );
}

#[test]
fn an_assumed_claim_names_nothing() {
    let assumed = r#"
[[claim]]
area = "a"
mark = "assumed"
text = "t"
"#;
    // Accepts an assumed claim with no fns or files
    assert!(resolve_claims(claims(assumed), &files(), &[]).is_ok());
    // Rejects one that names a fn, since that fn would look proven
    let named = format!("{assumed}fns = [\"esdk/src/header.rs::edk_count_check\"]\n");
    assert!(resolve_claims(claims(&named), &files(), &[]).is_err());
}

#[test]
fn crate_summary_counts_only_fns_that_ship() {
    let s = crate_summaries(&files());
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].name, "esdk");
    assert_eq!((s[0].fns_checked, s[0].fns_shipped), (2, 3));
}

#[test]
fn crate_results_count_only_the_named_crate() {
    let output = "\
    Compiling verus_builtin_macros v0.0.0
verification results:: 1858 verified, 0 errors
    Checking aws-mpl-primitives v0.1.0 (/repo/prim)
verification results:: 18 verified, 0 errors
    Checking aws-esdk v2.0.0 (/repo/esdk)
verification results:: 69 verified, 0 errors
    Checking aws-mpl-primitives v0.1.0 (/repo/prim)
verification results:: 18 verified, 0 errors
    Checking aws-esdk v2.0.0 (/repo/esdk)
verification results:: 68 verified, 1 error
";
    assert_eq!(crate_results(output, "aws-esdk"), [(69, 0), (68, 1)]);
    assert_eq!(
        crate_results(output, "aws-mpl-primitives"),
        [(18, 0), (18, 0)]
    );
}

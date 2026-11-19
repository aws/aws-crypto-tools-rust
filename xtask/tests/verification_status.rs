// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for checking the claims in `docs/verification-claims.toml` against
//! the code, and for reading Verus's output.

use xtask::proof_coverage::file_coverage;
use xtask::verification::{
    ClaimsFile, Mark, crate_results, crate_summaries, parse_threats, resolve_claims,
};

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

const THREAT_MODEL: &str = "\
## 8. Threat Identification (STRIDE)

### 8.2 Tampering

| ID | Threat | Asset | Boundary |
|----|--------|-------|----------|
| T1 | Message header modification | A6 | TB4 |

### 8.5 Denial of Service

| ID | Threat | Impact | Vector |
|----|--------|--------|--------|
| D1 | Excessive EDKs forcing many KMS Decrypt calls | Availability | TB4 |

## 9. Attack Trees

| X1 | Not a threat | - | - |
";

fn threats() -> Vec<xtask::verification::Threat> {
    parse_threats(THREAT_MODEL)
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
    let (resolved, undescribed) = resolve_claims(file, &files(), &[], &threats()).unwrap();
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
    assert!(resolve_claims(claims(inside), &files(), &[], &threats()).is_ok());
    // Rejects a fn outside verus!, so an unchecked fn cannot be called proven
    let outside = inside.replace("edk_count_check", "read_header");
    let err = resolve_claims(claims(&outside), &files(), &[], &threats()).unwrap_err();
    assert_eq!(
        err,
        "claim \"t\": esdk/src/header.rs::read_header is unverified, not inside verus!"
    );
    // Rejects a fn that no longer exists
    let gone = inside.replace("edk_count_check", "renamed");
    let err = resolve_claims(claims(&gone), &files(), &[], &threats()).unwrap_err();
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
    assert!(resolve_claims(claims(model), &files(), &passed, &threats()).is_ok());
    // Rejects it when that file did not pass
    let err = resolve_claims(claims(model), &files(), &[], &threats()).unwrap_err();
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
    assert!(resolve_claims(claims(assumed), &files(), &[], &threats()).is_ok());
    // Rejects one that names a fn, since that fn would look proven
    let named = format!("{assumed}fns = [\"esdk/src/header.rs::edk_count_check\"]\n");
    assert!(resolve_claims(claims(&named), &files(), &[], &threats()).is_err());
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

#[test]
fn threats_come_from_the_stride_tables_only() {
    let t = threats();
    let ids: Vec<(&str, &str)> = t
        .iter()
        .map(|x| (x.id.as_str(), x.category.as_str()))
        .collect();
    assert_eq!(ids, [("T1", "Tampering"), ("D1", "Denial of Service")]);
    assert_eq!(t[1].name, "Excessive EDKs forcing many KMS Decrypt calls");
}

#[test]
fn a_claim_must_name_a_threat_in_the_threat_model() {
    let claim = r#"
[[claim]]
area = "a"
mark = "assumed"
text = "t"
threats = ["D1"]
"#;
    // Accepts a threat id the threat model lists
    let (resolved, _) = resolve_claims(claims(claim), &files(), &[], &threats()).unwrap();
    assert_eq!(resolved[0].threats, ["D1"]);
    // Rejects an id it does not list, so a typo cannot hide a threat
    let err = resolve_claims(
        claims(&claim.replace("D1", "D9")),
        &files(),
        &[],
        &threats(),
    )
    .unwrap_err();
    assert_eq!(err, "claim \"t\": no threat D9 in docs/threat-model.md");
}

// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for reading the verification docs and the Verus output into
//! `docs/verification-status.json`. Each test uses a small copy of the real
//! document shapes.

use xtask::verification::{
    Part, crate_results, parse_levels, parse_recommendations, parse_report, targets,
};

const REPORT: &str = "\
## 3. Target coverage

| Target | Levels | Status | Residual (honestly scoped) |
|--------|--------|--------|-----------------------------|
| VR-001 key commitment verification | in_crate: decision (a); trusted: constant time (c) | **partly in-crate** | timing |
| VR-002 header auth tag ordering | model_only: tag check before body decrypt | **model only** | async |
| Infra: I/O seam | - | `esdk` is Verus-buildable | glue |

## 4. Next
";

const RECOMMENDATIONS: &str = r#"
```yaml
recommendation:
  id: VR-2026-001
  priority_score: 16.0
  target:
    library: aws-esdk
    file: esdk/src/message/header.rs
    function: validate_suite_data  # + esdk/src/key_derivation.rs::derive_key_v2
  property: "The derived commit key MUST equal the header's algorithm suite data."
  agent: verus-header-parsing-proofs
  threat_references:
    - { id: E3, category: Elevation of Privilege, description: "Mismatched commit key" }
  status: not_started
recommendation:
  id: VR-2026-002
  origin: capability-driven   # from the sweep
  status: model_only   # at 5ea2a804; not in-crate
  target:
    file: esdk/src/secret.rs (confinement module); callers in esdk/src/decrypt.rs, message/body/body_encrypt.rs
  threat_references:
    - { id: "(none)", category: "capability-driven", description: "No direct threat" }
```
"#;

#[test]
fn report_rows_keep_each_level_part_and_skip_rows_that_are_not_targets() {
    let rows = parse_report(REPORT).unwrap();
    let ids: Vec<&str> = rows.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(ids, ["VR-001", "VR-002"]);
    assert_eq!(rows[0].title, "key commitment verification");
    assert_eq!(
        rows[0].parts,
        [
            Part {
                level: "in_crate".to_owned(),
                what: "decision (a)".to_owned()
            },
            Part {
                level: "trusted".to_owned(),
                what: "constant time (c)".to_owned()
            },
        ]
    );
    assert_eq!(rows[1].residual, "async");
}

#[test]
fn levels_cell_rejects_a_word_that_is_not_a_level() {
    // Accepts a known level
    assert!(parse_levels("VR-001", "in_crate: decision").is_ok());
    // Rejects a misspelled level, so a typo can never show as a proof
    let err = parse_levels("VR-001", "in-crate: decision").unwrap_err();
    assert_eq!(err, "VR-001: `in-crate` is not a level");
}

#[test]
fn report_without_a_levels_column_is_an_error() {
    let old = REPORT.replace("| Target | Levels |", "| Target |");
    assert!(parse_report(&old).is_err());
}

#[test]
fn recommendations_give_short_ids_files_and_real_threats() {
    let recs = parse_recommendations(RECOMMENDATIONS);
    assert_eq!(recs.len(), 2);
    assert_eq!(recs[0].id, "VR-001");
    assert_eq!(recs[0].score, Some(16.0));
    assert_eq!(recs[0].files, ["esdk/src/message/header.rs"]);
    assert_eq!(recs[0].threats.len(), 1);
    assert_eq!(recs[0].threats[0].id, "E3");
    assert_eq!(recs[0].threats[0].category, "Elevation of Privilege");
    assert_eq!(recs[1].origin.as_deref(), Some("capability-driven"));
    assert_eq!(recs[1].status.as_deref(), Some("model_only"));
    assert_eq!(recs[1].files, ["esdk/src/secret.rs", "esdk/src/decrypt.rs"]);
    assert!(recs[1].threats.is_empty());
}

#[test]
fn targets_note_drift_only_when_the_yaml_claims_a_level_the_report_does_not_give() {
    let t = targets(
        parse_report(REPORT).unwrap(),
        parse_recommendations(RECOMMENDATIONS),
    );
    // Flags a YAML status the report does not back
    assert_eq!(
        t[0].drift.as_deref(),
        Some(
            "verification-recommendations.md says `not_started`, but the report gives in_crate, trusted."
        )
    );
    assert_eq!(t[0].origin, "threat");
    // Accepts a YAML status the report backs
    assert_eq!(t[1].drift, None);
    assert_eq!(t[1].origin, "capability");
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

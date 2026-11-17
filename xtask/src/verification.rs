// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Builds `docs/verification-status.json`, which the Verification page of the
//! Crypto Tools dashboard shows. The page has three parts, and this file holds
//! the data for each:
//!
//! - status: whether every Verus run passed, from running Verus now;
//! - count: how many fns and lines of each crate Verus checks, from
//!   [`crate::proof_coverage`];
//! - claims: the plain sentences in `docs/verification-claims.toml`, each
//!   checked against the code here so a claim cannot outlive its proof.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::proof_coverage::FileCoverage;

#[derive(Debug, Serialize)]
pub struct Status {
    pub generated: String,
    pub commit: String,
    pub verus: String,
    pub snapshot_note: &'static str,
    pub counts: Vec<Count>,
    pub crates: Vec<CrateSummary>,
    pub claims: Vec<Claim>,
    /// Fns inside `verus!` that no claim names, as `path::name`.
    pub undescribed: Vec<String>,
    /// What each line kind means, keyed as in [`crate::proof_coverage::KINDS`].
    pub line_kinds: BTreeMap<&'static str, &'static str>,
    pub files: Vec<FileCoverage>,
}

/// One Verus command and what each of its runs verified.
#[derive(Debug, Serialize)]
pub struct Count {
    pub name: String,
    pub cmd: String,
    /// `None` when the command ran but no result could be read from it.
    pub runs: Option<Vec<Run>>,
    /// Why `runs` is `None`.
    pub unavailable: Option<String>,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct Run {
    pub label: String,
    pub verified: u64,
    pub errors: u64,
}

/// How much of one crate Verus checks. Only fns that ship count: spec and
/// proof fns are not compiled into the library.
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct CrateSummary {
    pub name: String,
    pub fns_checked: usize,
    pub fns_shipped: usize,
    pub lines_checked: usize,
    pub lines_shipped: usize,
}

/// What the dashboard says for each line kind.
pub const LINE_KINDS: [(&str, &str); 6] = [
    ("proven", "Verus proves its requires/ensures and no panic"),
    (
        "no_panic",
        "In verus! with no requires/ensures: Verus proves only no panic",
    ),
    (
        "ghost",
        "spec or proof fn: rules and proofs, not compiled into the library",
    ),
    (
        "trusted",
        "external_body or assume_specification: assumed, not checked",
    ),
    ("verus_item", "A type or constant inside verus!"),
    ("unverified", "A fn outside verus!: Verus does not check it"),
];

const CHECKED: [&str; 2] = ["proven", "no_panic"];
const SHIPPED: [&str; 4] = ["proven", "no_panic", "trusted", "unverified"];

pub fn crate_summaries(files: &[FileCoverage]) -> Vec<CrateSummary> {
    let mut by_crate: BTreeMap<&str, CrateSummary> = BTreeMap::new();
    for f in files {
        let name = f.path.split('/').next().unwrap_or_default();
        let s = by_crate.entry(name).or_insert_with(|| CrateSummary {
            name: name.to_owned(),
            fns_checked: 0,
            fns_shipped: 0,
            lines_checked: 0,
            lines_shipped: 0,
        });
        for x in &f.fns {
            s.fns_checked += usize::from(CHECKED.contains(&x.kind));
            s.fns_shipped += usize::from(SHIPPED.contains(&x.kind));
        }
        s.lines_checked += CHECKED.iter().map(|k| f.counts[k]).sum::<usize>();
        s.lines_shipped += SHIPPED.iter().map(|k| f.counts[k]).sum::<usize>();
    }
    by_crate.into_values().collect()
}

/// `docs/verification-claims.toml`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimsFile {
    #[serde(rename = "claim")]
    pub claims: Vec<ClaimSpec>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimSpec {
    pub area: String,
    pub mark: Mark,
    pub text: String,
    #[serde(default)]
    pub fns: Vec<String>,
    #[serde(default)]
    pub files: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mark {
    /// Verus proves it about shipped code.
    Proven,
    /// Verus proves it about a copy of the code in `verification/`.
    Model,
    /// The proofs rely on it; no tool checks it.
    Assumed,
}

#[derive(Debug, Serialize)]
pub struct Claim {
    pub area: String,
    pub mark: Mark,
    pub text: String,
    pub places: Vec<Place>,
}

/// Where a claim is proven: a fn in shipped code, or a model file.
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct Place {
    pub path: String,
    pub name: Option<String>,
    pub first: Option<usize>,
    pub last: Option<usize>,
}

/// Checks each claim against the code and fills in where its fns are.
/// `model_files` are the proof files `make -C verification verify` verified
/// with no errors.
pub fn resolve_claims(
    file: ClaimsFile,
    files: &[FileCoverage],
    model_files: &[String],
) -> Result<(Vec<Claim>, Vec<String>), String> {
    let mut named = std::collections::BTreeSet::new();
    let mut claims = Vec::new();
    for c in file.claims {
        let what = format!("claim \"{}\"", c.text);
        let places = match c.mark {
            Mark::Proven => {
                if c.fns.is_empty() || !c.files.is_empty() {
                    return Err(format!("{what}: a proven claim names fns and no files"));
                }
                c.fns
                    .iter()
                    .map(|id| {
                        let (path, name) = id
                            .rsplit_once("::")
                            .ok_or_else(|| format!("{what}: `{id}` is not `path::name`"))?;
                        let f = files
                            .iter()
                            .find(|f| f.path == path)
                            .ok_or_else(|| format!("{what}: no file {path}"))?;
                        let found: Vec<_> = f.fns.iter().filter(|x| x.name == name).collect();
                        if found.is_empty() {
                            return Err(format!("{what}: no fn {name} in {path}"));
                        }
                        if let Some(x) = found
                            .iter()
                            .find(|x| !matches!(x.kind, "proven" | "no_panic" | "ghost"))
                        {
                            return Err(format!(
                                "{what}: {path}::{name} is {}, not inside verus!",
                                x.kind
                            ));
                        }
                        named.insert(id.clone());
                        Ok(Place {
                            path: path.to_owned(),
                            name: Some(name.to_owned()),
                            first: Some(found[0].first),
                            last: Some(found[0].last),
                        })
                    })
                    .collect::<Result<Vec<_>, String>>()?
            }
            Mark::Model => {
                if c.files.is_empty() || !c.fns.is_empty() {
                    return Err(format!("{what}: a model claim names files and no fns"));
                }
                c.files
                    .iter()
                    .map(|path| {
                        let base = path.strip_prefix("verification/").unwrap_or(path);
                        if !model_files.iter().any(|m| m == base) {
                            return Err(format!(
                                "{what}: {path} did not pass make -C verification verify"
                            ));
                        }
                        Ok(Place {
                            path: path.clone(),
                            name: None,
                            first: None,
                            last: None,
                        })
                    })
                    .collect::<Result<Vec<_>, String>>()?
            }
            Mark::Assumed => {
                if !c.fns.is_empty() || !c.files.is_empty() {
                    return Err(format!("{what}: an assumed claim names nothing"));
                }
                Vec::new()
            }
        };
        claims.push(Claim {
            area: c.area,
            mark: c.mark,
            text: c.text,
            places,
        });
    }
    // Exec fns a reader should know about. Spec and proof fns only support
    // other proofs, so they need no claim of their own.
    let undescribed = files
        .iter()
        .flat_map(|f| {
            f.fns
                .iter()
                .filter(|x| CHECKED.contains(&x.kind))
                .map(move |x| format!("{}::{}", f.path, x.name))
        })
        .filter(|id| !named.contains(id))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    Ok((claims, undescribed))
}

/// The `verification results:: N verified, M errors` lines that Verus prints
/// for one crate. cargo-verus prints each result after the `Checking <crate>`
/// line of the crate it verified, so a dependency's result (vstd, or prim when
/// verifying esdk) is not counted.
pub fn crate_results(output: &str, krate: &str) -> Vec<(u64, u64)> {
    let mut current = "";
    let mut results = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if let Some(rest) = line
            .strip_prefix("Checking ")
            .or_else(|| line.strip_prefix("Compiling "))
        {
            current = rest.split(' ').next().unwrap_or_default();
        } else if let Some(result) = verification_result(line)
            && current == krate
        {
            results.push(result);
        }
    }
    results
}

/// Every Verus result line, for the standalone models, where each file is
/// verified on its own.
pub fn all_results(output: &str) -> Vec<(u64, u64)> {
    output
        .lines()
        .filter_map(|l| verification_result(l.trim()))
        .collect()
}

fn verification_result(line: &str) -> Option<(u64, u64)> {
    let rest = line.strip_prefix("verification results:: ")?;
    let (verified, errors) = rest.split_once(" verified, ")?;
    let errors = errors
        .strip_suffix(" errors")
        .or_else(|| errors.strip_suffix(" error"))?;
    Some((verified.parse().ok()?, errors.parse().ok()?))
}

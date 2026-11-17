// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Builds `docs/verification-status.json`, which the Verification page of the
//! Crypto Tools dashboard shows.
//!
//! Each target's levels come from the Levels column of the target table in
//! `docs/verus-proofs-report.md`. Its other facts (property, score, origin,
//! threats, files) come from the YAML blocks in
//! `docs/verification-recommendations.md`. The YAML `status` field is known to
//! lag behind the report, so it is never used as the level. When it disagrees
//! with the report, the target gets a `drift` note instead.
//!
//! The verified counts come from running Verus at generation time. A run that
//! cannot produce a count is written as unavailable, never as an old number.

use std::collections::BTreeMap;

use serde::Serialize;

/// The levels, strongest first. A target part is never shown as a higher
/// level than the one the report gives it.
pub const LEVELS: [(&str, &str); 6] = [
    ("in_crate", "Verus proof of shipped code"),
    ("model_only", "Verus proof of a model, not shipped code"),
    ("compiler_lint", "Rust privacy and clippy, not Verus"),
    ("trusted", "Assumed, not proven"),
    ("deferred", "Target exists, not proven now"),
    ("not_started", "No proof yet"),
];

#[derive(Debug, Serialize)]
pub struct Status {
    pub generated: String,
    pub commit: String,
    pub verus: String,
    pub snapshot_note: &'static str,
    pub levels: BTreeMap<&'static str, &'static str>,
    pub counts: Vec<Count>,
    pub targets: Vec<Target>,
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

#[derive(Debug, Serialize)]
pub struct Target {
    pub id: String,
    pub title: String,
    pub origin: String,
    pub score: Option<f64>,
    pub property: Option<String>,
    pub agent: Option<String>,
    pub files: Vec<String>,
    pub threats: Vec<Threat>,
    pub parts: Vec<Part>,
    pub status: String,
    pub residual: String,
    pub yaml_status: Option<String>,
    pub drift: Option<String>,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct Part {
    pub level: String,
    pub what: String,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct Threat {
    pub id: String,
    pub category: String,
    pub description: String,
}

/// One row of the report's target table.
#[derive(Debug)]
pub struct ReportRow {
    pub id: String,
    pub title: String,
    pub parts: Vec<Part>,
    pub status: String,
    pub residual: String,
}

/// One `recommendation:` block of the recommendations YAML.
#[derive(Debug, Default)]
pub struct Recommendation {
    pub id: String,
    pub origin: Option<String>,
    pub status: Option<String>,
    pub score: Option<f64>,
    pub property: Option<String>,
    pub agent: Option<String>,
    pub files: Vec<String>,
    pub threats: Vec<Threat>,
}

/// Reads the target table: the table whose header starts with
/// `| Target | Levels |`. Rows that are not a `VR-` target are skipped.
pub fn parse_report(text: &str) -> Result<Vec<ReportRow>, String> {
    let mut lines = text
        .lines()
        .skip_while(|l| !l.starts_with("| Target | Levels |"));
    if lines.next().is_none() {
        return Err("the report has no `| Target | Levels |` table".to_owned());
    }
    let mut rows = Vec::new();
    for line in lines.skip(1).take_while(|l| l.starts_with('|')) {
        let cells: Vec<&str> = line.trim_matches('|').split(" | ").map(str::trim).collect();
        let [target, levels, status, residual] = cells.as_slice() else {
            return Err(format!("a target table row does not have 4 cells: {line}"));
        };
        let Some((id, title)) = target.split_once(' ') else {
            continue;
        };
        if !id.starts_with("VR-") {
            continue;
        }
        rows.push(ReportRow {
            id: id.to_owned(),
            title: title.to_owned(),
            parts: parse_levels(id, levels)?,
            status: (*status).to_owned(),
            residual: (*residual).to_owned(),
        });
    }
    Ok(rows)
}

/// Reads one Levels cell, `level: what; level: what`.
pub fn parse_levels(id: &str, cell: &str) -> Result<Vec<Part>, String> {
    let parts = cell
        .split(';')
        .map(|part| {
            let (level, what) = part
                .split_once(':')
                .ok_or_else(|| format!("{id}: Levels part `{part}` has no `level:`"))?;
            let level = level.trim();
            if !LEVELS.iter().any(|(key, _)| *key == level) {
                return Err(format!("{id}: `{level}` is not a level"));
            }
            Ok(Part {
                level: level.to_owned(),
                what: what.trim().to_owned(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if parts.is_empty() {
        return Err(format!("{id}: the Levels cell is empty"));
    }
    Ok(parts)
}

/// Reads every `recommendation:` block in the recommendations doc. The blocks
/// repeat the same top-level key, so they are not one valid YAML document;
/// this reads only the fields the dashboard shows, line by line.
pub fn parse_recommendations(text: &str) -> Vec<Recommendation> {
    let mut recs: Vec<Recommendation> = Vec::new();
    let mut section = "";
    for line in text.lines() {
        if line == "recommendation:" {
            recs.push(Recommendation::default());
            continue;
        }
        let Some(rec) = recs.last_mut() else {
            continue;
        };
        if let Some(field) = line.strip_prefix("  ").filter(|l| !l.starts_with(' ')) {
            let Some((key, value)) = field.split_once(':') else {
                continue;
            };
            section = key;
            let value = scalar(value);
            match key {
                "id" => rec.id = short_id(&value),
                "origin" => rec.origin = Some(value),
                "status" => rec.status = Some(value),
                "priority_score" => rec.score = value.parse().ok(),
                "property" => rec.property = Some(value),
                "agent" => rec.agent = Some(value),
                _ => {}
            }
        } else if section == "target"
            && let Some(value) = line.trim_start().strip_prefix("file:")
        {
            rec.files = source_paths(value);
        } else if section == "threat_references"
            && let Some(threat) = line.trim_start().strip_prefix("- {").and_then(flow_threat)
        {
            rec.threats.push(threat);
        }
    }
    recs
}

/// `VR-2026-001` in the YAML is `VR-001` in the report.
fn short_id(id: &str) -> String {
    match id.strip_prefix("VR-2026-") {
        Some(n) => format!("VR-{n}"),
        None => id.to_owned(),
    }
}

/// A plain YAML value: the text inside quotes, or the text before a `#` comment.
fn scalar(value: &str) -> String {
    let value = value.trim();
    if let Some(quoted) = value.strip_prefix('"') {
        return quoted.split('"').next().unwrap_or_default().to_owned();
    }
    value
        .split(" #")
        .next()
        .unwrap_or_default()
        .trim()
        .to_owned()
}

/// The repository paths in a `file:` value, which can be prose such as
/// `esdk/src/secret.rs (confinement module); callers in esdk/src/...`.
fn source_paths(value: &str) -> Vec<String> {
    value
        .split(|c: char| c.is_whitespace() || c == ',' || c == ';' || c == '(' || c == ')')
        .filter(|w| {
            w.ends_with(".rs")
                && ["esdk/", "prim/", "mpl/", "verification/"]
                    .iter()
                    .any(|dir| w.starts_with(dir))
        })
        .map(str::to_owned)
        .collect()
}

/// `{ id: E3, category: Tampering, description: "..." }` without its `- {`.
/// The `(none)` entry of a capability-driven target is not a threat.
fn flow_threat(entry: &str) -> Option<Threat> {
    let id = scalar(entry.split_once("id:")?.1.split(',').next()?);
    let category = scalar(
        entry
            .split_once("category:")?
            .1
            .split(", description:")
            .next()?,
    );
    let description = scalar(entry.split_once("description:")?.1.trim_end_matches('}'));
    (id != "(none)").then_some(Threat {
        id,
        category,
        description,
    })
}

/// Joins the report rows with their recommendations, in report order.
pub fn targets(rows: Vec<ReportRow>, recs: Vec<Recommendation>) -> Vec<Target> {
    let mut recs: BTreeMap<String, Recommendation> =
        recs.into_iter().map(|r| (r.id.clone(), r)).collect();
    rows.into_iter()
        .map(|row| {
            let rec = recs.remove(&row.id);
            let drift = drift(&row.parts, rec.as_ref());
            let rec = rec.unwrap_or_default();
            Target {
                origin: match rec.origin.as_deref() {
                    Some(o) if o.starts_with("capability") => "capability".to_owned(),
                    _ => "threat".to_owned(),
                },
                id: row.id,
                title: row.title,
                score: rec.score,
                property: rec.property,
                agent: rec.agent,
                files: rec.files,
                threats: rec.threats,
                parts: row.parts,
                status: row.status,
                residual: row.residual,
                yaml_status: rec.status,
                drift,
            }
        })
        .collect()
}

/// A note when the YAML status names a level the report does not give the
/// target, or when the target has no YAML block.
fn drift(parts: &[Part], rec: Option<&Recommendation>) -> Option<String> {
    let Some(rec) = rec else {
        return Some("No recommendation in verification-recommendations.md.".to_owned());
    };
    let status = rec.status.as_deref()?;
    // The YAML status words are free-form, such as `partly_in_crate` or
    // `deferred_model_of_removed_code`. The first level each one names is the
    // level it claims. `deferred` is checked before `model_only` because a
    // deferred target can still have an old model.
    let claimed = ["in_crate", "deferred", "model_only", "not_started"]
        .into_iter()
        .find(|level| status.contains(level))?;
    let report: Vec<&str> = parts.iter().map(|p| p.level.as_str()).collect();
    (!report.contains(&claimed)).then(|| {
        format!(
            "verification-recommendations.md says `{status}`, but the report gives {}.",
            report.join(", ")
        )
    })
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

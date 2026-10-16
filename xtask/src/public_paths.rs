// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! `cargo xtask check-public-paths`: every public item has exactly one public path.
//!
//! Reads each library's rustdoc JSON, walks its public modules from the crate root,
//! follows `pub use` re-exports (into the other library when a module is re-exported),
//! and fails when one item is reachable at two paths that `ALLOWED` does not list.
//! `#[doc(hidden)]` items are skipped.

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

/// A library to check, and the rustdoc JSON file `cargo rustdoc` writes for it.
pub struct Library {
    pub crate_name: &'static str,
    pub dir: &'static str,
}

pub const LIBRARIES: &[Library] = &[
    Library {
        crate_name: "aws_crypto_mpl",
        dir: "mpl",
    },
    Library {
        crate_name: "aws_esdk",
        dir: "esdk",
    },
];

/// Paths under these prefixes are deliberate second paths to another library's items,
/// so they are not counted. That library's own check covers them.
const ESCAPE_HATCHES: &[&str] = &["aws_esdk::mpl"];

/// Deliberate second paths, as in the AWS SDK for Rust: `Client` and `Config` at the
/// crate (or module) root, and in their own module.
const ALLOWED: &[&[&str]] = &[
    &["aws_esdk::Client", "aws_esdk::client::Client"],
    &["aws_esdk::Config", "aws_esdk::config::Config"],
    &[
        "aws_crypto_mpl::key_store::Client",
        "aws_crypto_mpl::key_store::client::Client",
    ],
    &[
        "aws_esdk::key_store::Client",
        "aws_esdk::key_store::client::Client",
    ],
];

struct Doc {
    json: Value,
    /// `paths` entries defined in this crate, by path.
    local_by_path: HashMap<Vec<String>, String>,
}

impl Doc {
    fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("could not read {}: {e}", path.display()))?;
        let json: Value = serde_json::from_str(&text)
            .map_err(|e| format!("could not parse {}: {e}", path.display()))?;
        let mut local_by_path = HashMap::new();
        for (id, entry) in json["paths"].as_object().into_iter().flatten() {
            if entry["crate_id"].as_u64() == Some(0) {
                local_by_path.insert(strings(&entry["path"]), id.clone());
            }
        }
        Ok(Self {
            json,
            local_by_path,
        })
    }

    fn item(&self, id: &str) -> Option<&Value> {
        self.json["index"].get(id)
    }

    /// The crate and canonical path that defines `id`, if rustdoc recorded one.
    fn origin(&self, id: &str) -> Option<(String, Vec<String>, String)> {
        let entry = self.json["paths"].get(id)?;
        let crate_id = entry["crate_id"].as_u64()?;
        let crate_name = if crate_id == 0 {
            self.json["index"][self.json["root"].to_string().trim_matches('"')]["name"]
                .as_str()?
                .to_owned()
        } else {
            self.json["external_crates"][crate_id.to_string()]["name"]
                .as_str()?
                .to_owned()
        };
        Some((
            crate_name,
            strings(&entry["path"]),
            entry["kind"].as_str().unwrap_or("").to_owned(),
        ))
    }
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .into_iter()
        .flatten()
        .filter_map(|s| s.as_str().map(str::to_owned))
        .collect()
}

fn id_key(v: &Value) -> Option<String> {
    match v {
        Value::Number(n) => Some(n.to_string()),
        Value::String(s) => Some(s.clone()),
        _ => None,
    }
}

fn is_hidden(item: &Value) -> bool {
    item["attrs"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|a| a.to_string().contains("doc(hidden)"))
}

/// Every public path to every item, keyed by the item's defining crate and path.
type Found = BTreeMap<(String, Vec<String>), BTreeSet<String>>;

fn walk(
    docs: &HashMap<String, Doc>,
    crate_name: &str,
    module_id: &str,
    prefix: &[String],
    visiting: &mut BTreeSet<(String, String)>,
    found: &mut Found,
) {
    let key = (crate_name.to_owned(), module_id.to_owned());
    if !visiting.insert(key.clone()) {
        return;
    }
    let doc = &docs[crate_name];
    let Some(module) = doc.item(module_id) else {
        visiting.remove(&key);
        return;
    };
    for child in module["inner"]["module"]["items"]
        .as_array()
        .into_iter()
        .flatten()
    {
        let Some(child_id) = id_key(child) else {
            continue;
        };
        let Some(item) = doc.item(&child_id) else {
            continue;
        };
        if item["visibility"].as_str() != Some("public") || is_hidden(item) {
            continue;
        }
        let inner = &item["inner"];
        if let Some(u) = inner.get("use") {
            if u["is_glob"].as_bool() == Some(true) {
                continue;
            }
            let name = u["name"].as_str().unwrap_or_default().to_owned();
            let path: Vec<String> = prefix.iter().cloned().chain([name]).collect();
            let Some(target) = id_key(&u["id"]) else {
                continue;
            };
            // A re-export of a module in this crate: walk it under the new name.
            if let Some(t) = doc.item(&target)
                && t["inner"].get("module").is_some()
            {
                walk(docs, crate_name, &target, &path, visiting, found);
                continue;
            }
            let Some((origin_crate, origin_path, kind)) = doc.origin(&target) else {
                continue;
            };
            // A re-export of another checked library's module: walk that module.
            if kind == "module"
                && let Some(other) = docs.get(&origin_crate)
                && let Some(mid) = other.local_by_path.get(&origin_path)
            {
                walk(docs, &origin_crate, mid, &path, visiting, found);
                continue;
            }
            found
                .entry((origin_crate, origin_path))
                .or_default()
                .insert(path.join("::"));
        } else if inner.get("module").is_some() {
            let name = item["name"].as_str().unwrap_or_default().to_owned();
            let path: Vec<String> = prefix.iter().cloned().chain([name]).collect();
            walk(docs, crate_name, &child_id, &path, visiting, found);
        } else {
            let name = item["name"].as_str().unwrap_or_default().to_owned();
            let path: Vec<String> = prefix.iter().cloned().chain([name]).collect();
            let origin = doc
                .origin(&child_id)
                .map(|(c, p, _)| (c, p))
                .unwrap_or_else(|| (crate_name.to_owned(), path.clone()));
            found.entry(origin).or_default().insert(path.join("::"));
        }
    }
    visiting.remove(&key);
}

/// The duplicate paths in `crate_name`'s public API that `ALLOWED` does not list.
fn duplicates(docs: &HashMap<String, Doc>, crate_name: &str) -> Vec<Vec<String>> {
    let doc = &docs[crate_name];
    let root = id_key(&doc.json["root"]).unwrap_or_default();
    let mut found = Found::new();
    walk(
        docs,
        crate_name,
        &root,
        &[crate_name.to_owned()],
        &mut BTreeSet::new(),
        &mut found,
    );
    let allowed: BTreeSet<BTreeSet<&str>> = ALLOWED
        .iter()
        .map(|set| set.iter().copied().collect())
        .collect();
    found
        .into_values()
        .map(|paths| {
            paths
                .into_iter()
                .filter(|p| {
                    !ESCAPE_HATCHES
                        .iter()
                        .any(|h| p == h || p.starts_with(&format!("{h}::")))
                })
                .collect::<BTreeSet<_>>()
        })
        .filter(|paths| paths.len() > 1)
        .filter(|paths| !allowed.contains(&paths.iter().map(String::as_str).collect()))
        .map(|paths| paths.into_iter().collect())
        .collect()
}

/// Build each library's rustdoc JSON and check it. Needs a nightly toolchain.
pub fn check(root: &Path) -> Result<(), String> {
    let mut docs = HashMap::new();
    for lib in LIBRARIES {
        let dir = root.join(lib.dir);
        let status = std::process::Command::new("cargo")
            .args([
                "+nightly",
                "rustdoc",
                "--quiet",
                "--lib",
                "--all-features",
                "--",
            ])
            .args(["-Z", "unstable-options", "--output-format", "json"])
            .current_dir(&dir)
            .status()
            .map_err(|e| format!("could not run cargo rustdoc in {}: {e}", dir.display()))?;
        if !status.success() {
            return Err(format!("cargo rustdoc failed in {}", dir.display()));
        }
        let json = dir
            .join("target/doc")
            .join(format!("{}.json", lib.crate_name));
        docs.insert(lib.crate_name.to_owned(), Doc::load(&json)?);
    }
    let mut failures = Vec::new();
    for lib in LIBRARIES {
        for paths in duplicates(&docs, lib.crate_name) {
            failures.push(format!("  {}", paths.join("  =  ")));
        }
    }
    if failures.is_empty() {
        println!("every public item has one public path");
        Ok(())
    } else {
        Err(format!(
            "these public paths name the same item; remove one, or add the set to ALLOWED in xtask/src/public_paths.rs:\n{}",
            failures.join("\n")
        ))
    }
}

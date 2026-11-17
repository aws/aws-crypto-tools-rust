// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Repository tasks.
//!
//! ```text
//! cargo xtask gen-errors          write each library's src/error/generated.rs from errors.toml
//! cargo xtask gen-errors --check  fail if any generated file is stale
//! cargo xtask verification-status run Verus and write docs/verification-status.json
//! ```

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use xtask::verification::{self, Count, Run};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["gen-errors"] => gen_errors(false),
        ["gen-errors", "--check"] => gen_errors(true),
        ["verification-status"] => verification_status(),
        _ => Err("usage: cargo xtask gen-errors [--check] | verification-status".to_owned()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask is in the repository root")
        .to_path_buf()
}

fn gen_errors(check: bool) -> Result<(), String> {
    let root = repo_root();
    let spec_path = root.join("errors.toml");
    let text = std::fs::read_to_string(&spec_path)
        .map_err(|e| format!("could not read {}: {e}", spec_path.display()))?;
    let spec = xtask::parse(&text)?;
    let mut stale = Vec::new();
    for out in xtask::generate(&spec)? {
        let contents = xtask::rustfmt(&out.contents)?;
        let path = root.join(&out.path);
        let current = std::fs::read_to_string(&path).unwrap_or_default();
        if current == contents {
            continue;
        }
        if check {
            stale.push(out.path);
        } else {
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)
                    .map_err(|e| format!("could not create {}: {e}", dir.display()))?;
            }
            std::fs::write(&path, contents)
                .map_err(|e| format!("could not write {}: {e}", path.display()))?;
            println!("wrote {}", out.path);
        }
    }
    if stale.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "generated error files are stale: {}\nrun `cargo xtask gen-errors` and commit the result",
            stale.join(", ")
        ))
    }
}

/// The feature sets `make -C esdk verus` and `make -C prim verus` verify, in
/// the order the Makefiles run them.
const CRATE_RUNS: [&str; 2] = [
    "default features",
    "--no-default-features --features aws-lc-sys",
];

fn verification_status() -> Result<(), String> {
    let root = repo_root();
    let read = |path: &str| {
        std::fs::read_to_string(root.join(path)).map_err(|e| format!("could not read {path}: {e}"))
    };
    let rows = verification::parse_report(&read("docs/verus-proofs-report.md")?)?;
    let recs = verification::parse_recommendations(&read("docs/verification-recommendations.md")?);

    let counts = vec![
        crate_count(&root, "esdk", "aws-esdk", "make -C esdk verus"),
        crate_count(&root, "prim", "aws-mpl-primitives", "make -C prim verus"),
        model_count(&root),
    ];
    for c in &counts {
        if let Some(why) = &c.unavailable {
            eprintln!("warning: no {} count: {why}", c.name);
        }
    }

    let status = verification::Status {
        generated: command_line(&root, "date", &["-u", "+%Y-%m-%dT%H:%M:%SZ"])?,
        commit: command_line(&root, "git", &["rev-parse", "HEAD"])?,
        verus: verus_version(),
        snapshot_note: "Counts come from one Verus run at generation time. Run `cargo xtask verification-status` again to refresh them.",
        levels: verification::LEVELS.into_iter().collect(),
        counts,
        targets: verification::targets(rows, recs),
    };
    let path = "docs/verification-status.json";
    let json = serde_json::to_string_pretty(&status).map_err(|e| e.to_string())? + "\n";
    std::fs::write(root.join(path), json).map_err(|e| format!("could not write {path}: {e}"))?;
    println!("wrote {path}");
    Ok(())
}

/// Runs one crate's `make verus` and keeps that crate's two results.
fn crate_count(root: &Path, dir: &str, krate: &str, cmd: &str) -> Count {
    // Verus skips a crate that cargo thinks is fresh, and then prints no result.
    if let Err(e) = touch(&root.join(dir).join("src/lib.rs")) {
        return unavailable(dir, cmd, e);
    }
    let output = match shell(root, cmd) {
        Ok(output) => output,
        Err(e) => return unavailable(dir, cmd, e),
    };
    let results = verification::crate_results(&output, krate);
    if results.len() != CRATE_RUNS.len() {
        return unavailable(
            dir,
            cmd,
            format!(
                "expected {} results for {krate}, found {}; last line: {}",
                CRATE_RUNS.len(),
                results.len(),
                output.lines().last().unwrap_or_default()
            ),
        );
    }
    let runs = CRATE_RUNS
        .iter()
        .zip(results)
        .map(|(label, (verified, errors))| Run {
            label: (*label).to_owned(),
            verified,
            errors,
        })
        .collect();
    Count {
        name: dir.to_owned(),
        cmd: cmd.to_owned(),
        runs: Some(runs),
        unavailable: None,
    }
}

/// Runs `make -C verification verify`, which verifies each model file on its
/// own after printing `== Verifying <file> ==`.
fn model_count(root: &Path) -> Count {
    let (name, cmd) = ("verification_models", "make -C verification verify");
    let output = match shell(root, cmd) {
        Ok(output) => output,
        Err(e) => return unavailable(name, cmd, e),
    };
    let files: Vec<&str> = output
        .lines()
        .filter_map(|l| l.strip_prefix("== Verifying ")?.strip_suffix(" =="))
        .collect();
    let results = verification::all_results(&output);
    if files.is_empty() || files.len() != results.len() {
        return unavailable(
            name,
            cmd,
            format!(
                "{} files started, {} results; last line: {}",
                files.len(),
                results.len(),
                output.lines().last().unwrap_or_default()
            ),
        );
    }
    let runs = files
        .into_iter()
        .zip(results)
        .map(|(file, (verified, errors))| Run {
            label: file.to_owned(),
            verified,
            errors,
        })
        .collect();
    Count {
        name: name.to_owned(),
        cmd: cmd.to_owned(),
        runs: Some(runs),
        unavailable: None,
    }
}

fn unavailable(name: &str, cmd: &str, why: String) -> Count {
    Count {
        name: name.to_owned(),
        cmd: cmd.to_owned(),
        runs: None,
        unavailable: Some(why),
    }
}

fn touch(path: &Path) -> Result<(), String> {
    std::fs::File::options()
        .append(true)
        .open(path)
        .and_then(|f| f.set_modified(std::time::SystemTime::now()))
        .map_err(|e| format!("could not touch {}: {e}", path.display()))
}

/// Runs a command with stderr merged into stdout, so cargo's `Checking` lines
/// and Verus's results stay in the order they were printed. A failing command
/// still returns its output: a proof with errors is a result, not a missing one.
fn shell(root: &Path, cmd: &str) -> Result<String, String> {
    let out = Command::new("sh")
        .arg("-c")
        .arg(format!("{cmd} 2>&1"))
        .current_dir(root)
        .output()
        .map_err(|e| format!("could not run `{cmd}`: {e}"))?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn command_line(root: &Path, program: &str, args: &[&str]) -> Result<String, String> {
    let out = Command::new(program)
        .args(args)
        .current_dir(root)
        .output()
        .map_err(|e| format!("could not run {program}: {e}"))?;
    if !out.status.success() {
        return Err(format!("{program} {} failed", args.join(" ")));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// The `Version:` line of `~/verus/verus --version`, the binary the Makefiles use.
fn verus_version() -> String {
    let verus = std::env::var("HOME").unwrap_or_default() + "/verus/verus";
    Command::new(verus)
        .arg("--version")
        .output()
        .ok()
        .and_then(|out| {
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .find_map(|l| l.trim().strip_prefix("Version: ").map(str::to_owned))
        })
        .unwrap_or_else(|| "unavailable".to_owned())
}

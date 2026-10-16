// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Repository tasks.
//!
//! ```text
//! cargo xtask gen-errors          write each library's src/error/generated.rs from errors.toml
//! cargo xtask gen-errors --check  fail if any generated file is stale
//! cargo xtask check-public-paths  fail if a public item has two public paths (needs nightly)
//! ```

use std::path::{Path, PathBuf};
use std::process::ExitCode;

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
        ["check-public-paths"] => xtask::public_paths::check(&repo_root()),
        _ => Err("usage: cargo xtask gen-errors [--check] | check-public-paths".to_owned()),
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

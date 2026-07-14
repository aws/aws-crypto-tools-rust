// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! CLI wiring built on top of `clap`.
//!
//! The command surface mirrors the MPL Dafny tool
//! (`MplManifestOptions.dfy` + `TestManifests.dfy`):
//!
//! * `encrypt-manifest` — generate an encrypt manifest for a project
//! * `encrypt`          — read an encrypt manifest, run it, emit a decrypt manifest
//! * `decrypt`          — read a decrypt manifest and verify it
//! * `list`             — enumerate registered projects
//!
//! Every project-scoped subcommand takes `--project <name>` to select which
//! implementation to invoke. `--test-name <uuid>` restricts execution to a
//! single vector.

use std::io::Write;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::error::Result;
use crate::projects::Registry;

/// Top-level CLI argument struct.
#[derive(Debug, Parser)]
#[command(
    name = "test-vectors",
    about = "Generate and run AWS Crypto Tools Rust test-vector manifests.",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

/// All supported subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// List every registered project.
    List,

    /// Write an encrypt manifest (and its `keys.json`) for `--project`.
    EncryptManifest {
        /// Project selector (see `list`).
        #[arg(long, value_name = "NAME")]
        project: String,

        /// Directory to write `manifest.json` and `keys.json` into.
        #[arg(long, value_name = "DIR")]
        output: PathBuf,
    },

    /// Read an encrypt manifest, run each vector, and write a decrypt
    /// manifest into `--decrypt-manifest-output`.
    Encrypt {
        /// Project selector (see `list`).
        #[arg(long, value_name = "NAME")]
        project: String,

        /// Directory containing the encrypt `manifest.json` (and `keys.json`).
        #[arg(long, value_name = "DIR")]
        manifest_path: PathBuf,

        /// Directory to write the resulting decrypt manifest into.
        #[arg(long, value_name = "DIR")]
        decrypt_manifest_output: PathBuf,

        /// Only run the vector with this UUID.
        #[arg(long, value_name = "UUID")]
        test_name: Option<String>,
    },

    /// Read a decrypt manifest and verify every vector.
    Decrypt {
        /// Project selector (see `list`).
        #[arg(long, value_name = "NAME")]
        project: String,

        /// Directory containing the decrypt `manifest.json` (and `keys.json`).
        #[arg(long, value_name = "DIR")]
        manifest_path: PathBuf,

        /// Only run the vector with this UUID.
        #[arg(long, value_name = "UUID")]
        test_name: Option<String>,
    },
}

/// Dispatch a parsed [`Cli`] against `registry`, writing any human output to
/// `out`. Splitting these out this way keeps `main.rs` a thin shim and lets
/// tests drive the CLI end-to-end with an in-memory buffer.
pub fn dispatch(cli: Cli, registry: &Registry, out: &mut dyn Write) -> Result<()> {
    match cli.command {
        Command::List => list_projects(registry, out),
        Command::EncryptManifest { project, output } => {
            let project = registry.get(&project)?;
            project.generate_manifest(&output)?;
            writeln!(
                out,
                "Wrote encrypt manifest for '{}' to {}",
                project.name(),
                output.display()
            )
            .ok();
            Ok(())
        }
        Command::Encrypt {
            project,
            manifest_path,
            decrypt_manifest_output,
            test_name,
        } => {
            let project = registry.get(&project)?;
            project.run_encrypt(
                &manifest_path,
                &decrypt_manifest_output,
                test_name.as_deref(),
            )?;
            writeln!(
                out,
                "Encrypt run for '{}' completed; decrypt manifest at {}",
                project.name(),
                decrypt_manifest_output.display()
            )
            .ok();
            Ok(())
        }
        Command::Decrypt {
            project,
            manifest_path,
            test_name,
        } => {
            let project = registry.get(&project)?;
            project.run_decrypt(&manifest_path, test_name.as_deref())?;
            writeln!(out, "Decrypt run for '{}' completed", project.name()).ok();
            Ok(())
        }
    }
}

fn list_projects(registry: &Registry, out: &mut dyn Write) -> Result<()> {
    writeln!(out, "Registered projects:").ok();
    for project in registry.iter() {
        writeln!(out, "  {:<6}  {}", project.name(), project.description()).ok();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::TestVectorError;
    use clap::Parser;
    use tempfile::tempdir;

    fn parse(argv: &[&str]) -> Cli {
        Cli::try_parse_from(argv).expect("parse")
    }

    #[test]
    fn list_prints_every_registered_project() {
        let cli = parse(&["test-vectors", "list"]);
        let mut buf = Vec::new();
        dispatch(cli, &Registry::all(), &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("mpl"), "output: {out}");
    }

    #[test]
    fn encrypt_manifest_writes_files_for_mpl() {
        let dir = tempdir().unwrap();
        let cli = parse(&[
            "test-vectors",
            "encrypt-manifest",
            "--project",
            "mpl",
            "--output",
            dir.path().to_str().unwrap(),
        ]);
        let mut buf = Vec::new();
        dispatch(cli, &Registry::all(), &mut buf).unwrap();
        assert!(dir.path().join("manifest.json").exists());
        assert!(dir.path().join("keys.json").exists());
    }

    #[test]
    fn unknown_project_returns_typed_error() {
        let cli = parse(&[
            "test-vectors",
            "encrypt-manifest",
            "--project",
            "nope",
            "--output",
            "/tmp/nope",
        ]);
        let mut buf = Vec::new();
        let err = dispatch(cli, &Registry::all(), &mut buf).unwrap_err();
        assert!(
            matches!(err, TestVectorError::UnknownProject(ref n) if n == "nope"),
            "unexpected: {err}"
        );
    }
}

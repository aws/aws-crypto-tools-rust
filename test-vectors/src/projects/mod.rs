// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Per-project vector generators.
//!
//! Every top-level Rust project this crate can produce vectors for (currently
//! `mpl`) is represented by a value implementing [`Project`]. Concrete
//! implementations may leave any hook unimplemented while the project is being
//! brought up — they should return [`TestVectorError::NotImplemented`] which
//! the CLI surfaces cleanly.
//!
//! To register a new project:
//!
//! 1. Add a module under `src/projects/<name>.rs`.
//! 2. Implement [`Project`] for it.
//! 3. Push a boxed instance into [`Registry::default`].

use std::path::Path;

use crate::error::Result;

pub mod mpl;

/// Vector generator contract implemented by every registered project.
///
/// The three action methods mirror the CLI subcommands:
///
/// * [`Project::generate_manifest`] — `encrypt-manifest`
/// * [`Project::run_encrypt`] — `encrypt`
/// * [`Project::run_decrypt`] — `decrypt`
///
/// `test_name` is an optional filter matching an exact vector UUID and is
/// honored on a best-effort basis by the implementation.
pub trait Project: Send + Sync {
    /// Short, machine-friendly identifier (e.g. `"mpl"`).
    fn name(&self) -> &'static str;

    /// Human-readable description shown by `test-vectors list`.
    fn description(&self) -> &'static str;

    /// Generate an encrypt manifest and `keys.json` under `output_dir`.
    fn generate_manifest(&self, output_dir: &Path) -> Result<()>;

    /// Read the encrypt manifest at `manifest_dir`, run each encrypt vector,
    /// and emit a decrypt manifest into `decrypt_manifest_dir`.
    fn run_encrypt(
        &self,
        manifest_dir: &Path,
        decrypt_manifest_dir: &Path,
        test_name: Option<&str>,
    ) -> Result<()>;

    /// Read the decrypt manifest at `manifest_dir` and verify every vector.
    fn run_decrypt(&self, manifest_dir: &Path, test_name: Option<&str>) -> Result<()>;
}

/// Registered projects available to the CLI.
///
/// The registry is populated at construction time and does not support runtime
/// insertion. Lookups are linear because the number of projects is tiny.
pub struct Registry {
    projects: Vec<Box<dyn Project>>,
}

impl Registry {
    /// Registry containing every project this crate knows about.
    pub fn all() -> Self {
        Self {
            projects: vec![Box::new(mpl::MplProject)],
        }
    }

    /// Iterate over the registered projects in declaration order.
    pub fn iter(&self) -> impl Iterator<Item = &dyn Project> {
        self.projects.iter().map(|b| b.as_ref())
    }

    /// Return the project matching `name`, or an [`UnknownProject`] error.
    ///
    /// [`UnknownProject`]: crate::error::TestVectorError::UnknownProject
    pub fn get(&self, name: &str) -> Result<&dyn Project> {
        self.projects
            .iter()
            .find(|p| p.name() == name)
            .map(|b| b.as_ref())
            .ok_or_else(|| crate::error::TestVectorError::UnknownProject(name.to_string()))
    }

    /// Names of all registered projects.
    pub fn names(&self) -> Vec<&'static str> {
        self.projects.iter().map(|p| p.name()).collect()
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::all()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_contains_the_expected_projects() {
        let registry = Registry::all();
        let names = registry.names();
        assert_eq!(names, vec!["mpl"]);
    }

    #[test]
    fn registry_get_returns_the_matching_project() {
        let registry = Registry::all();
        assert_eq!(registry.get("mpl").unwrap().name(), "mpl");
        assert!(registry.get("does-not-exist").is_err());
    }
}

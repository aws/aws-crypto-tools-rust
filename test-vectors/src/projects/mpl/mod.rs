// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! `mpl` project vector generator.
//!
//! The MPL vector suite exercises Cryptographic Material Managers and Keyrings
//! against every supported algorithm suite. Rather than re-derive the vector
//! set locally, the generator emits a small hand-authored sample that is
//! byte-compatible with the Dafny-produced `manifest.json`, along with a
//! `keys.json` containing the key entries those vectors reference.
//!
//! The list of key entries emitted into `keys.json` is derived from
//! [`SUPPORTED_KEY_GROUPS`] via [`keys::compose`]. The list of algorithm
//! suites emitted into the vector list is derived from
//! [`suite::SUPPORTED_SUITES`]. As new keyring or algorithm-suite support
//! lands in the Rust `mpl` crate, extend those two tables and every layer of
//! this project picks it up automatically.
//!
//! # Encrypt / decrypt runners
//!
//! Actual test-vector execution lives in [`runner`]:
//!
//! * [`runner::run_encrypt`] reads an encrypt manifest, exercises each
//!   hierarchy vector, and writes the resulting decrypt manifest.
//! * [`runner::run_decrypt`] reads a decrypt manifest and verifies each
//!   vector against `DefaultCmm::decrypt_materials`.
//!
//! # Hierarchy keyring: static keystore
//!
//! The Dafny reference does *not* run hierarchy vectors against a real
//! DynamoDB-backed keystore. It seeds branch/beacon key material into the
//! `static-branch-key` entry of `keys.json` and hands the keyring an
//! in-memory [`static_keystore::StaticKeyStore`] that returns that material
//! verbatim. The runner follows the same pattern; see
//! `dafny/KeyVectors/src/CreateStaticKeyStores.dfy` and
//! `KeyringFromKeyDescription.dfy::case Hierarchy(...)` for the reference.

pub mod keys;
pub mod runner;
pub mod static_keystore;
pub mod suite;

use std::path::Path;

use indexmap::IndexMap;
use serde_json::json;

use crate::error::Result;
use crate::manifest::encrypt::{EncryptManifest, EncryptTestVector, PositiveEncryptVector};
use crate::manifest::io::{DEFAULT_KEYS_URI, ensure_dir, keys_path, manifest_path, write_json};

use self::keys::KeyGroup;

use super::Project;

/// Static client string written into decrypt manifests attributed to this
/// project. Distinct from the Dafny tool's `"mpl-dafny"` so cross-language
/// artifacts remain attributable.
pub const CLIENT_NAME: &str = "mpl-rust";

/// Key groups the emitted `keys.json` includes.
///
/// Currently the Rust `mpl` crate only implements the AWS KMS hierarchical
/// keyring, so only [`KeyGroup::Hierarchy`] is registered. When a new keyring
/// implementation lands, append its group here so its keys.json entries start
/// shipping with generated manifests.
pub const SUPPORTED_KEY_GROUPS: &[KeyGroup] = &[KeyGroup::Hierarchy];

/// Vector generator for the `mpl` crate.
pub struct MplProject;

impl Project for MplProject {
    fn name(&self) -> &'static str {
        "mpl"
    }

    fn description(&self) -> &'static str {
        "AWS Cryptographic Material Providers Library vectors (CMM + Keyring test suite)"
    }

    fn generate_manifest(&self, output_dir: &Path) -> Result<()> {
        ensure_dir(output_dir)?;

        let manifest = build_sample_manifest();
        let keys_manifest = keys::compose(SUPPORTED_KEY_GROUPS)
            .map_err(|e| crate::error::TestVectorError::other(e.to_string()))?;

        write_json(&manifest_path(output_dir), &manifest)?;
        write_json(&keys_path(output_dir), &keys_manifest)?;
        Ok(())
    }

    fn run_encrypt(
        &self,
        manifest_dir: &Path,
        decrypt_manifest_dir: &Path,
        test_name: Option<&str>,
    ) -> Result<()> {
        runner::run_encrypt(manifest_dir, decrypt_manifest_dir, test_name)
    }

    fn run_decrypt(&self, manifest_dir: &Path, test_name: Option<&str>) -> Result<()> {
        runner::run_decrypt(manifest_dir, test_name)
    }
}

/// Build a small encrypt manifest that exercises the hierarchical KMS keyring
/// across every algorithm suite in [`suite::SUPPORTED_SUITES`]. Vector UUIDs
/// are freshly generated on each call so re-running the generator yields a
/// new-but-equivalent manifest.
fn build_sample_manifest() -> EncryptManifest {
    let mut manifest = EncryptManifest::new();
    manifest.keys = DEFAULT_KEYS_URI.to_string();

    for suite_hex in suite::supported_suite_hex_ids() {
        let vector = EncryptTestVector::PositiveKeyring(PositiveEncryptVector {
            description: format!("Generated Hierarchy KMS static-branch-key-1 {suite_hex}"),
            algorithm_suite_id: suite_hex.to_string(),
            encrypt_key_description: json!({
                "type": "aws-kms-hierarchy",
                "key": "static-branch-key-1"
            }),
            decrypt_key_description: json!({
                "type": "aws-kms-hierarchy",
                "key": "static-branch-key-1"
            }),
            encryption_context: IndexMap::new(),
            max_plaintext_length: None,
            required_encryption_context_keys: None,
            reproduced_encryption_context: None,
        });
        manifest.add_vector(vector);
    }

    manifest
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::TestVectorError;
    use crate::manifest::io::read_json;
    use crate::manifest::keys::KeyManifest;
    use tempfile::tempdir;

    #[test]
    fn generate_manifest_writes_both_files_with_expected_shape() {
        let dir = tempdir().unwrap();
        MplProject.generate_manifest(dir.path()).unwrap();

        assert!(dir.path().join("manifest.json").exists());
        assert!(dir.path().join("keys.json").exists());

        let manifest: EncryptManifest = read_json(&dir.path().join("manifest.json")).unwrap();
        assert_eq!(manifest.manifest.version, 4);
        assert_eq!(manifest.manifest.manifest_type, "awses-mpl-encrypt");
        assert_eq!(manifest.keys, "file://keys.json");
        assert_eq!(manifest.tests.len(), suite::SUPPORTED_SUITES.len());

        let keys_manifest: KeyManifest = read_json(&dir.path().join("keys.json")).unwrap();
        // Currently only the hierarchy group ships, so exactly its keys should
        // appear. Update this assertion when SUPPORTED_KEY_GROUPS is extended.
        assert_eq!(
            keys_manifest.keys.len(),
            KeyGroup::Hierarchy.key_ids().len()
        );
        assert!(keys_manifest.get("static-branch-key-1").is_some());
    }

    #[test]
    fn generated_keys_json_entries_match_reference_bytes() {
        // Every entry emitted by generate_manifest must be byte-identical to
        // its counterpart in the reference keys.json. This is the invariant
        // that lets cross-language artifacts interop.
        let dir = tempdir().unwrap();
        MplProject.generate_manifest(dir.path()).unwrap();

        let emitted: KeyManifest = read_json(&dir.path().join("keys.json")).unwrap();
        let reference = keys::all_keys();

        for (id, entry) in &emitted.keys {
            let ref_entry = reference
                .get(id)
                .unwrap_or_else(|| panic!("emitted key '{id}' not in reference registry"));
            assert_eq!(
                entry, ref_entry,
                "emitted entry '{id}' does not match reference"
            );
        }
    }

    #[test]
    fn every_referenced_key_in_the_manifest_is_present_in_keys_json() {
        // Fail loudly if a vector references a key that keys.json does not
        // contain — the encrypt/decrypt runners will need every such key.
        let dir = tempdir().unwrap();
        MplProject.generate_manifest(dir.path()).unwrap();

        let manifest: EncryptManifest = read_json(&dir.path().join("manifest.json")).unwrap();
        let keys_manifest: KeyManifest = read_json(&dir.path().join("keys.json")).unwrap();

        for (uuid, vector) in &manifest.tests {
            let key_id = match vector {
                EncryptTestVector::PositiveKeyring(v) => v
                    .encrypt_key_description
                    .get("key")
                    .and_then(|v| v.as_str())
                    .unwrap_or_else(|| panic!("vector {uuid} missing key field")),
                _ => continue,
            };
            assert!(
                keys_manifest.get(key_id).is_some(),
                "vector {uuid} references '{key_id}' but keys.json does not contain it"
            );
        }
    }

    #[test]
    fn run_encrypt_surfaces_wrong_manifest_type() {
        let dir = tempdir().unwrap();
        // Write a decrypt-typed manifest where the encrypt one is expected.
        write_json(
            &manifest_path(dir.path()),
            &json!({
                "manifest": {"version": 4, "type": "awses-mpl-decrypt"},
                "keys": "file://keys.json",
                "client": "mpl-rust",
                "tests": {}
            }),
        )
        .unwrap();

        let out = tempdir().unwrap();
        let err = MplProject
            .run_encrypt(dir.path(), out.path(), None)
            .unwrap_err();
        assert!(
            matches!(err, TestVectorError::Manifest { .. }),
            "unexpected: {err}"
        );
    }
}

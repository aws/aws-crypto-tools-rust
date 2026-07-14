// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end runners for the encrypt and decrypt manifest CLI paths.
//!
//! * [`run_encrypt`] loads an encrypt manifest, exercises every
//!   `positive-keyring` vector whose `encryptKeyDescription.type` is
//!   `aws-kms-hierarchy`, captures the resulting encrypted data keys and
//!   plaintext data key, and writes the corresponding decrypt manifest.
//! * [`run_decrypt`] loads a decrypt manifest and, for every
//!   `positive-keyring` vector under the same conditions, verifies the CMM
//!   returns the expected plaintext data key.
//!
//! Non-hierarchy key descriptions and negative vectors are skipped
//! (`skipped_count` in the summary printed to stdout); adding coverage for
//! them is a matter of extending [`build_cmm_for_description`].

use std::fs;
use std::path::Path;
use std::str;
use std::sync::Arc;

use aws_crypto_mpl::MaterialProviders;
use aws_crypto_mpl::cmm::{Cmm, DecryptMaterialsRequest, DefaultCmm, EncryptionMaterialsRequest};
use aws_crypto_mpl::keystore::Keystore;
use aws_crypto_mpl::structures::{
    DecryptionMaterials, EncryptedDataKey as MplEncryptedDataKey, EncryptionContext,
    EncryptionMaterials,
};
use indexmap::IndexMap;
use serde_json::Value;
use tokio::runtime::Builder;

use crate::error::{Result, TestVectorError};
use crate::manifest::codec;
use crate::manifest::decrypt::{
    DecryptManifest, DecryptResult, DecryptTestVector, EncryptedDataKey as ManifestEdk,
    PositiveDecryptVector,
};
use crate::manifest::encrypt::{EncryptManifest, EncryptTestVector, PositiveEncryptVector};
use crate::manifest::header;
use crate::manifest::io::{keys_path, manifest_path, read_json, resolve_keys_uri, write_json};
use crate::manifest::keys::KeyManifest;

use super::CLIENT_NAME;
use super::static_keystore::StaticKeyStore;
use super::suite;

/// The `type` string used by hierarchy keyring key descriptions.
const KEY_DESC_TYPE_HIERARCHY: &str = "aws-kms-hierarchy";

/// TTL passed to `create_aws_kms_hierarchical_keyring` — matches the
/// hardcoded `ttlSeconds := 11` in Dafny `KeyringFromKeyDescription.dfy`
/// so cross-language artifacts encrypt/decrypt against the same cache
/// horizon.
const HIERARCHY_TTL_SECONDS: u64 = 11;

/// Entry point for `MplProject::run_encrypt`. Reads the encrypt manifest at
/// `manifest_dir`, produces a decrypt manifest in `decrypt_manifest_dir`,
/// and copies the source `keys.json` alongside it byte-for-byte.
pub fn run_encrypt(
    manifest_dir: &Path,
    decrypt_manifest_dir: &Path,
    test_name: Option<&str>,
) -> Result<()> {
    let (encrypt_manifest, key_manifest, keys_source_path) = load_encrypt_inputs(manifest_dir)?;

    let rt = build_runtime()?;
    let mpl = MaterialProviders::default();

    let mut decrypt_manifest = DecryptManifest::new(CLIENT_NAME);
    decrypt_manifest.keys = encrypt_manifest.keys.clone();

    let mut summary = RunSummary::default();

    for (uuid, vector) in &encrypt_manifest.tests {
        if let Some(filter) = test_name
            && filter != uuid
        {
            continue;
        }

        let encrypt_vector = match vector {
            EncryptTestVector::PositiveKeyring(v) => v,
            _ => {
                // negative-encrypt / negative-decrypt aren't supported yet;
                // skip them so the runner can still emit vectors for the
                // ones it can handle.
                summary.skipped += 1;
                continue;
            }
        };

        if !is_hierarchy_key_description(&encrypt_vector.encrypt_key_description) {
            summary.skipped += 1;
            continue;
        }

        let decrypt_vector =
            rt.block_on(run_positive_encrypt(&mpl, &key_manifest, encrypt_vector))?;
        decrypt_manifest
            .tests
            .insert(uuid.clone(), DecryptTestVector::Positive(decrypt_vector));
        summary.processed += 1;
    }

    crate::manifest::io::ensure_dir(decrypt_manifest_dir)?;
    write_json(&manifest_path(decrypt_manifest_dir), &decrypt_manifest)?;
    // Copy the raw keys.json bytes so consumers of the decrypt manifest see
    // exactly the same key material as the encrypt manifest referenced.
    let keys_dest = keys_path(decrypt_manifest_dir);
    fs::copy(&keys_source_path, &keys_dest).map_err(|e| TestVectorError::io(&keys_dest, e))?;

    println!(
        "run_encrypt: processed {} vector(s), skipped {} (non-hierarchy or negative)",
        summary.processed, summary.skipped,
    );
    Ok(())
}

/// Entry point for `MplProject::run_decrypt`. Reads the decrypt manifest at
/// `manifest_dir` and verifies every supported `positive-keyring` vector.
pub fn run_decrypt(manifest_dir: &Path, test_name: Option<&str>) -> Result<()> {
    let (decrypt_manifest, key_manifest) = load_decrypt_inputs(manifest_dir)?;

    let rt = build_runtime()?;
    let mpl = MaterialProviders::default();

    let mut summary = RunSummary::default();

    for (uuid, vector) in &decrypt_manifest.tests {
        if let Some(filter) = test_name
            && filter != uuid
        {
            continue;
        }

        let decrypt_vector = match vector {
            DecryptTestVector::Positive(v) => v,
            DecryptTestVector::Negative(_) => {
                summary.skipped += 1;
                continue;
            }
        };

        if !is_hierarchy_key_description(&decrypt_vector.key_description) {
            summary.skipped += 1;
            continue;
        }

        rt.block_on(verify_positive_decrypt(
            &mpl,
            &key_manifest,
            uuid,
            decrypt_vector,
        ))?;
        summary.processed += 1;
    }

    println!(
        "run_decrypt: verified {} vector(s), skipped {}",
        summary.processed, summary.skipped,
    );
    Ok(())
}

// ─── inputs ──────────────────────────────────────────────────────────────────

/// Read and validate the encrypt manifest + its keys.json. Returns the parsed
/// values plus the on-disk path to the keys file so we can copy it verbatim.
fn load_encrypt_inputs(
    manifest_dir: &Path,
) -> Result<(EncryptManifest, KeyManifest, std::path::PathBuf)> {
    let manifest_p = manifest_path(manifest_dir);
    let encrypt_manifest: EncryptManifest = read_json(&manifest_p)?;
    if !encrypt_manifest.manifest.is_encrypt() {
        return Err(TestVectorError::manifest(
            manifest_p,
            format!(
                "expected type '{}' but found '{}'",
                header::ENCRYPT_MANIFEST_TYPE,
                encrypt_manifest.manifest.manifest_type
            ),
        ));
    }
    let keys_source_path = resolve_keys_uri(manifest_dir, &encrypt_manifest.keys)?;
    let key_manifest: KeyManifest = read_json(&keys_source_path)?;
    Ok((encrypt_manifest, key_manifest, keys_source_path))
}

fn load_decrypt_inputs(manifest_dir: &Path) -> Result<(DecryptManifest, KeyManifest)> {
    let manifest_p = manifest_path(manifest_dir);
    let decrypt_manifest: DecryptManifest = read_json(&manifest_p)?;
    if !decrypt_manifest.manifest.is_decrypt() {
        return Err(TestVectorError::manifest(
            manifest_p,
            format!(
                "expected type '{}' but found '{}'",
                header::DECRYPT_MANIFEST_TYPE,
                decrypt_manifest.manifest.manifest_type
            ),
        ));
    }
    let keys_source_path = resolve_keys_uri(manifest_dir, &decrypt_manifest.keys)?;
    let key_manifest: KeyManifest = read_json(&keys_source_path)?;
    Ok((decrypt_manifest, key_manifest))
}

// ─── per-vector encrypt ──────────────────────────────────────────────────────

/// Execute a single positive encrypt vector against a hierarchy CMM.
async fn run_positive_encrypt(
    mpl: &MaterialProviders,
    key_manifest: &KeyManifest,
    vector: &PositiveEncryptVector,
) -> Result<PositiveDecryptVector> {
    let (cmm, _key_id) =
        build_cmm_for_description(mpl, key_manifest, &vector.encrypt_key_description)?;

    let suite_id = suite::suite_id_from_hex(&vector.algorithm_suite_id)?;
    let policy = suite::commitment_policy_for(suite_id);
    let ec = manifest_ec_to_mpl(&vector.encryption_context);

    let mut request = EncryptionMaterialsRequest::new(ec, policy).with_algorithm_suite_id(suite_id);
    if let Some(keys) = &vector.required_encryption_context_keys {
        let byte_keys: std::collections::BTreeSet<Vec<u8>> =
            keys.iter().map(|k| k.as_bytes().to_vec()).collect();
        request = request.with_required_encryption_context_keys(byte_keys);
    }
    if let Some(max) = vector.max_plaintext_length {
        request = request.with_max_plaintext_length(max as u64);
    }

    let materials = cmm.get_encryption_materials(request).await.map_err(|e| {
        TestVectorError::other(format!(
            "get_encryption_materials failed for suite {}: {e}",
            vector.algorithm_suite_id
        ))
    })?;

    materials_to_decrypt_vector(vector, &materials)
}

/// Verify a single positive decrypt vector: build the CMM, call
/// `decrypt_materials`, and compare the plaintext data key against the
/// vector's expected value.
async fn verify_positive_decrypt(
    mpl: &MaterialProviders,
    key_manifest: &KeyManifest,
    uuid: &str,
    vector: &PositiveDecryptVector,
) -> Result<()> {
    let (cmm, _key_id) = build_cmm_for_description(mpl, key_manifest, &vector.key_description)?;

    let suite_id = suite::suite_id_from_hex(&vector.algorithm_suite_id)?;
    let policy = suite::commitment_policy_for(suite_id);
    let ec = manifest_ec_to_mpl(&vector.encryption_context);

    let edks = vector
        .encrypted_data_keys
        .iter()
        .map(manifest_edk_to_mpl)
        .collect::<Result<Vec<_>>>()?;

    let mut request = DecryptMaterialsRequest::new(suite_id, policy, edks, ec);
    if let Some(reproduced) = &vector.reproduced_encryption_context {
        request = request.with_reproduced_encryption_context(manifest_ec_to_mpl(reproduced));
    }

    let materials: DecryptionMaterials =
        cmm.decrypt_materials(request)
            .await
            .map_err(|e| TestVectorError::VectorFailure {
                name: uuid.to_string(),
                message: format!("decrypt_materials failed: {e}"),
            })?;

    // Compare plaintext data key against the expected value.
    let expected = vector.result.plaintext_data_key.as_ref().ok_or_else(|| {
        TestVectorError::VectorFailure {
            name: uuid.to_string(),
            message: "positive decrypt vector missing expected plaintextDataKey".into(),
        }
    })?;
    let actual_bytes = materials
        .plaintext_data_key()
        .ok_or_else(|| TestVectorError::VectorFailure {
            name: uuid.to_string(),
            message: "decrypt_materials returned no plaintext data key".into(),
        })?
        .as_bytes();
    let actual_b64 = codec::encode(actual_bytes);
    if &actual_b64 != expected {
        return Err(TestVectorError::VectorFailure {
            name: uuid.to_string(),
            message: format!("plaintext data key mismatch: expected {expected}, got {actual_b64}"),
        });
    }
    Ok(())
}

// ─── CMM construction ────────────────────────────────────────────────────────

/// Build a `DefaultCmm` wrapping a keyring resolved from `key_description`.
///
/// Currently only the `aws-kms-hierarchy` key description is supported;
/// callers gate on [`is_hierarchy_key_description`] before invoking this so
/// they can skip unsupported vectors cleanly.
fn build_cmm_for_description(
    mpl: &MaterialProviders,
    key_manifest: &KeyManifest,
    key_description: &Value,
) -> Result<(DefaultCmm, String)> {
    let (kind, key_name) = parse_key_description(key_description)?;
    if kind != KEY_DESC_TYPE_HIERARCHY {
        return Err(TestVectorError::NotImplemented {
            project: "mpl",
            operation: "build_cmm for non-hierarchy keyring",
        });
    }

    let entry = key_manifest.get(key_name).ok_or_else(|| {
        TestVectorError::other(format!(
            "keys.json does not contain '{key_name}' referenced by vector"
        ))
    })?;
    let static_keystore = StaticKeyStore::from_entry(entry)?;
    let branch_key_id = static_keystore.key_id().to_string();
    let keystore: Arc<dyn Keystore> = Arc::new(static_keystore);

    let keyring = mpl
        .create_aws_kms_hierarchical_keyring()
        .key_store(keystore)
        .branch_key_id(branch_key_id.clone())
        .ttl_seconds(HIERARCHY_TTL_SECONDS)
        .send()
        .map_err(|e| TestVectorError::other(format!("create_aws_kms_hierarchical_keyring: {e}")))?;
    Ok((DefaultCmm::new(Arc::new(keyring)), branch_key_id))
}

/// Extract `(type, key)` from a key description JSON object. Both fields must
/// be present and strings.
fn parse_key_description(desc: &Value) -> Result<(&str, &str)> {
    let obj = desc
        .as_object()
        .ok_or_else(|| TestVectorError::other("key description is not a JSON object"))?;
    let kind = obj
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| TestVectorError::other("key description missing 'type'"))?;
    let key_name = obj
        .get("key")
        .and_then(Value::as_str)
        .ok_or_else(|| TestVectorError::other("key description missing 'key'"))?;
    Ok((kind, key_name))
}

/// True iff `desc` selects the `aws-kms-hierarchy` keyring.
fn is_hierarchy_key_description(desc: &Value) -> bool {
    desc.get("type").and_then(Value::as_str) == Some(KEY_DESC_TYPE_HIERARCHY)
}

// ─── manifest ↔ mpl conversions ──────────────────────────────────────────────

/// Convert a manifest encryption context (string→string) into an
/// [`EncryptionContext`] (bytes→bytes). Every string is UTF-8 by construction.
fn manifest_ec_to_mpl(ec: &IndexMap<String, String>) -> EncryptionContext {
    let mut mpl_ec = EncryptionContext::new();
    for (k, v) in ec {
        mpl_ec.insert(k.as_bytes().to_vec(), v.as_bytes().to_vec());
    }
    mpl_ec
}

/// Convert an MPL encryption context back into a manifest-shaped
/// `IndexMap<String, String>`, in `EncryptionContext`'s natural iteration
/// order (which is `BTreeMap`, i.e. lexicographic by UTF-8 bytes).
fn mpl_ec_to_manifest(ec: &EncryptionContext) -> Result<IndexMap<String, String>> {
    let mut out = IndexMap::new();
    for (k, v) in ec.iter() {
        let key = str::from_utf8(k)
            .map_err(|_| TestVectorError::other("encryption context key is not valid UTF-8"))?;
        let value = str::from_utf8(v)
            .map_err(|_| TestVectorError::other("encryption context value is not valid UTF-8"))?;
        out.insert(key.to_string(), value.to_string());
    }
    Ok(out)
}

/// Convert an MPL encrypted data key into the manifest's base64-string form.
fn mpl_edk_to_manifest(edk: &MplEncryptedDataKey) -> ManifestEdk {
    ManifestEdk {
        key_provider_id: edk.key_provider_id.clone(),
        key_provider_info: codec::encode(&edk.key_provider_info),
        ciphertext: codec::encode(&edk.ciphertext),
    }
}

/// Convert a manifest encrypted data key back into an MPL one for the
/// decrypt path.
fn manifest_edk_to_mpl(edk: &ManifestEdk) -> Result<MplEncryptedDataKey> {
    Ok(MplEncryptedDataKey::new(
        edk.key_provider_id.clone(),
        codec::decode(&edk.key_provider_info)?,
        codec::decode(&edk.ciphertext)?,
    ))
}

/// Turn the encrypt-side [`EncryptionMaterials`] into a
/// [`PositiveDecryptVector`], mirroring the Dafny
/// `TestVectors.EncryptTestToDecryptVector`.
///
/// Notable choices, kept identical to the reference:
/// * The decrypt vector's `keyDescription` is `vector.decrypt_key_description`
///   (the encrypt vector already carried both encrypt- and decrypt-side
///   descriptions).
/// * The `encryptionContext` written into the decrypt vector is the
///   materials' final context with any `required_encryption_context_keys`
///   removed — those keys "MUST be reproduced" at decrypt time.
/// * The `description` gains a `->Decryption` suffix on the name half.
/// * `symmetric_signing_key` picks the first element of
///   `symmetric_signing_keys`, matching the Dafny fallback.
fn materials_to_decrypt_vector(
    encrypt_vector: &PositiveEncryptVector,
    materials: &EncryptionMaterials,
) -> Result<PositiveDecryptVector> {
    let full_ec = mpl_ec_to_manifest(materials.encryption_context())?;
    let required_keys = materials
        .required_encryption_context_keys()
        .iter()
        .map(|k| str::from_utf8(k).map(str::to_string))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| TestVectorError::other("required encryption context key is not UTF-8"))?;

    // "MUST be reproduced" keys are pulled out of the emitted EC.
    let mut decrypt_ec = IndexMap::new();
    for (k, v) in &full_ec {
        if !required_keys.contains(k) {
            decrypt_ec.insert(k.clone(), v.clone());
        }
    }

    let encrypted_data_keys: Vec<ManifestEdk> = materials
        .encrypted_data_keys()
        .iter()
        .map(mpl_edk_to_manifest)
        .collect();

    let plaintext_data_key = materials
        .plaintext_data_key()
        .map(|k| codec::encode(k.as_bytes()));
    let symmetric_signing_key = materials
        .symmetric_signing_keys()
        .and_then(|keys| keys.first())
        .map(|k| codec::encode(k.as_bytes()));

    // Description: reference format is "<name>->Decryption <suite-hex>".
    // We derive the name half from `encrypt_vector.description` by stripping
    // the trailing suite id and appending "->Decryption".
    let suite_hex = &encrypt_vector.algorithm_suite_id;
    let name_half = encrypt_vector
        .description
        .strip_suffix(&format!(" {suite_hex}"))
        .unwrap_or(&encrypt_vector.description);
    let description = format!("{name_half}->Decryption {suite_hex}");

    Ok(PositiveDecryptVector {
        description,
        algorithm_suite_id: encrypt_vector.algorithm_suite_id.clone(),
        key_description: encrypt_vector.decrypt_key_description.clone(),
        encrypted_data_keys,
        encryption_context: decrypt_ec,
        result: DecryptResult {
            plaintext_data_key,
            symmetric_signing_key,
            required_encryption_context_keys: required_keys,
        },
        reproduced_encryption_context: encrypt_vector.reproduced_encryption_context.clone(),
    })
}

// ─── runtime + summary ───────────────────────────────────────────────────────

fn build_runtime() -> Result<tokio::runtime::Runtime> {
    Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| TestVectorError::other(format!("failed to build tokio runtime: {e}")))
}

/// Tally of vectors processed vs. skipped during a run. Printed to stdout
/// at the end of each `run_*` call so operators can see progress.
#[derive(Debug, Default)]
struct RunSummary {
    processed: usize,
    skipped: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::projects::Project;
    use crate::projects::mpl::MplProject;
    use tempfile::tempdir;

    // End-to-end: generate an encrypt manifest, run it, and verify the
    // resulting decrypt manifest round-trips through run_decrypt.
    #[test]
    fn generate_then_encrypt_then_decrypt_round_trips_all_hierarchy_vectors() {
        let encrypt_dir = tempdir().unwrap();
        let decrypt_dir = tempdir().unwrap();

        MplProject.generate_manifest(encrypt_dir.path()).unwrap();
        MplProject
            .run_encrypt(encrypt_dir.path(), decrypt_dir.path(), None)
            .unwrap();

        // Emitted decrypt manifest must parse and have one entry per
        // supported ESDK suite (matches SAMPLE_ALGORITHM_SUITES).
        let decrypt_manifest: DecryptManifest =
            read_json(&manifest_path(decrypt_dir.path())).unwrap();
        assert!(decrypt_manifest.manifest.is_decrypt());
        assert_eq!(
            decrypt_manifest.tests.len(),
            suite::SUPPORTED_SUITES.len(),
            "one decrypt vector per supported ESDK suite"
        );
        assert!(decrypt_dir.path().join("keys.json").exists());

        // Verify the emitted manifest.
        MplProject.run_decrypt(decrypt_dir.path(), None).unwrap();
    }

    #[test]
    fn every_decrypt_vector_is_shaped_correctly() {
        let encrypt_dir = tempdir().unwrap();
        let decrypt_dir = tempdir().unwrap();

        MplProject.generate_manifest(encrypt_dir.path()).unwrap();
        MplProject
            .run_encrypt(encrypt_dir.path(), decrypt_dir.path(), None)
            .unwrap();

        let manifest: DecryptManifest = read_json(&manifest_path(decrypt_dir.path())).unwrap();

        for (uuid, vec) in &manifest.tests {
            let v = match vec {
                DecryptTestVector::Positive(v) => v,
                DecryptTestVector::Negative(_) => panic!("expected only positive vectors"),
            };
            // The generated hierarchy vector must reference the hierarchy
            // keyring on the decrypt side.
            assert_eq!(
                v.key_description.get("type").and_then(Value::as_str),
                Some("aws-kms-hierarchy"),
                "vector {uuid}: unexpected key description"
            );
            // Exactly one EDK per hierarchy vector (single-keyring flow).
            assert_eq!(
                v.encrypted_data_keys.len(),
                1,
                "vector {uuid}: expected exactly one EDK, got {}",
                v.encrypted_data_keys.len()
            );
            // Positive vectors must carry a plaintext data key.
            assert!(
                v.result.plaintext_data_key.is_some(),
                "vector {uuid}: positive vector missing plaintextDataKey"
            );
            // Description must have "->Decryption" appended before the suite id.
            let expected = format!(
                "Generated Hierarchy KMS static-branch-key-1->Decryption {}",
                v.algorithm_suite_id
            );
            assert_eq!(v.description, expected, "vector {uuid}: description");
        }
    }

    #[test]
    fn run_encrypt_with_test_name_filter_produces_a_single_vector() {
        let encrypt_dir = tempdir().unwrap();
        let decrypt_dir = tempdir().unwrap();

        MplProject.generate_manifest(encrypt_dir.path()).unwrap();

        // Pick any existing vector UUID from the emitted encrypt manifest.
        let encrypt_manifest: EncryptManifest =
            read_json(&manifest_path(encrypt_dir.path())).unwrap();
        let picked_uuid = encrypt_manifest.tests.keys().next().unwrap().clone();

        MplProject
            .run_encrypt(encrypt_dir.path(), decrypt_dir.path(), Some(&picked_uuid))
            .unwrap();

        let decrypt_manifest: DecryptManifest =
            read_json(&manifest_path(decrypt_dir.path())).unwrap();
        assert_eq!(decrypt_manifest.tests.len(), 1);
        assert!(decrypt_manifest.tests.contains_key(&picked_uuid));
    }

    #[test]
    fn run_encrypt_surfaces_wrong_manifest_type() {
        // A decrypt-typed manifest should not be accepted by run_encrypt.
        let dir = tempdir().unwrap();
        let out = tempdir().unwrap();
        write_json(
            &manifest_path(dir.path()),
            &serde_json::json!({
                "manifest": {"version": 4, "type": "awses-mpl-decrypt"},
                "keys": "file://keys.json",
                "client": "wrong",
                "tests": {}
            }),
        )
        .unwrap();

        let err = MplProject
            .run_encrypt(dir.path(), out.path(), None)
            .unwrap_err();
        assert!(
            matches!(err, TestVectorError::Manifest { .. }),
            "unexpected: {err}"
        );
    }

    #[test]
    fn keys_json_copied_alongside_decrypt_manifest_matches_source() {
        // Byte-parity: run_encrypt must copy the source keys.json verbatim,
        // never re-serialize it.
        let encrypt_dir = tempdir().unwrap();
        let decrypt_dir = tempdir().unwrap();

        MplProject.generate_manifest(encrypt_dir.path()).unwrap();
        MplProject
            .run_encrypt(encrypt_dir.path(), decrypt_dir.path(), None)
            .unwrap();

        let src = fs::read(keys_path(encrypt_dir.path())).unwrap();
        let dst = fs::read(keys_path(decrypt_dir.path())).unwrap();
        assert_eq!(src, dst);
    }
}

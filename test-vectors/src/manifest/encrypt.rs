// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Encrypt manifest types.
//!
//! Mirrors the JSON schema emitted by the MPL Dafny
//! `WriteJsonManifests.dfy`. The tagged enum discriminator is the JSON `type`
//! field which is one of `positive-keyring`, `negative-encrypt-keyring`, or
//! `negative-decrypt-keyring`. Unknown discriminators are rejected at
//! deserialize time.
//!
//! Key descriptions are intentionally kept as [`serde_json::Value`] since the
//! set of valid `KeyDescription` shapes is project-specific (aws-kms,
//! aws-kms-hierarchy, raw-aes, raw-rsa, static-material, multi-keyring, …).
//! Individual project generators are responsible for producing the correct
//! sub-schema.

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use super::header::ManifestHeader;

/// Top-level encrypt manifest as written to `manifest.json`.
///
/// ```json
/// {
///   "manifest": {"version": 4, "type": "awses-mpl-encrypt"},
///   "keys":     "file://keys.json",
///   "tests":    { "<uuid>": { "type": "positive-keyring", ... } }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptManifest {
    pub manifest: ManifestHeader,
    /// URI to the associated `keys.json`. The MPL tool always emits
    /// `"file://keys.json"` relative to the manifest directory.
    pub keys: String,
    /// Map of UUID -> vector. Preserves insertion order to keep diffs stable.
    pub tests: IndexMap<String, EncryptTestVector>,
}

impl EncryptManifest {
    /// Construct an empty manifest that points at the default `keys.json`.
    pub fn new() -> Self {
        Self {
            manifest: ManifestHeader::encrypt(),
            keys: "file://keys.json".to_string(),
            tests: IndexMap::new(),
        }
    }

    /// Add a vector under a deterministic UUID derived from the vector's
    /// contents and return that UUID.
    ///
    /// Two structurally identical vectors always hash to the same UUID, so
    /// regenerating the manifest produces byte-stable output as long as the
    /// vector set does not change. See [`vector_uuid`] for the exact recipe.
    pub fn add_vector(&mut self, vector: EncryptTestVector) -> String {
        let name = super::vector_uuid(&vector);
        self.tests.insert(name.clone(), vector);
        name
    }
}

impl Default for EncryptManifest {
    fn default() -> Self {
        Self::new()
    }
}

/// A single encrypt-manifest test vector.
///
/// The three variants match the MPL Dafny model:
///
/// * `positive-keyring` — encrypt is expected to succeed; the resulting
///   materials will be decrypted with `decryptKeyDescription`.
/// * `negative-encrypt-keyring` — encrypt is expected to fail with an error
///   matching `errorDescription`.
/// * `negative-decrypt-keyring` — encrypt is expected to succeed but the
///   subsequent decrypt should fail with `decryptErrorDescription`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum EncryptTestVector {
    #[serde(rename = "positive-keyring")]
    PositiveKeyring(PositiveEncryptVector),

    #[serde(rename = "negative-encrypt-keyring")]
    NegativeEncrypt(NegativeEncryptVector),

    #[serde(rename = "negative-decrypt-keyring")]
    NegativeDecrypt(NegativeDecryptVector),
}

/// A `positive-keyring` encrypt vector.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PositiveEncryptVector {
    pub description: String,
    pub algorithm_suite_id: String,
    pub encrypt_key_description: serde_json::Value,
    pub decrypt_key_description: serde_json::Value,
    pub encryption_context: IndexMap<String, String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_plaintext_length: Option<i64>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_encryption_context_keys: Option<Vec<String>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reproduced_encryption_context: Option<IndexMap<String, String>>,
}

/// A `negative-encrypt-keyring` encrypt vector.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NegativeEncryptVector {
    pub description: String,
    pub algorithm_suite_id: String,
    pub key_description: serde_json::Value,
    pub error_description: String,
    pub encryption_context: IndexMap<String, String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_plaintext_length: Option<i64>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_encryption_context_keys: Option<Vec<String>>,
}

/// A `negative-decrypt-keyring` encrypt vector. Encrypt succeeds, decrypt fails.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NegativeDecryptVector {
    pub description: String,
    pub algorithm_suite_id: String,
    pub encrypt_key_description: serde_json::Value,
    pub decrypt_key_description: serde_json::Value,
    pub decrypt_error_description: String,
    pub encryption_context: IndexMap<String, String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_plaintext_length: Option<i64>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_encryption_context_keys: Option<Vec<String>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reproduced_encryption_context: Option<IndexMap<String, String>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn positive_vector_round_trips() {
        let vector = EncryptTestVector::PositiveKeyring(PositiveEncryptVector {
            description: "Generated Hierarchy KMS static-branch-key-1 0478".into(),
            algorithm_suite_id: "0478".into(),
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

        let value = serde_json::to_value(&vector).unwrap();
        assert_eq!(value["type"], "positive-keyring");
        assert_eq!(value["algorithmSuiteId"], "0478");
        assert!(value.get("maxPlaintextLength").is_none());

        let parsed: EncryptTestVector = serde_json::from_value(value).unwrap();
        assert!(matches!(parsed, EncryptTestVector::PositiveKeyring(_)));
    }

    #[test]
    fn manifest_matches_mpl_shape() {
        let mut manifest = EncryptManifest::new();
        manifest.tests.insert(
            "38f454e1-334d-4b75-8034-694a36a386c1".into(),
            EncryptTestVector::PositiveKeyring(PositiveEncryptVector {
                description: "Generated Hierarchy KMS static-branch-key-1 0478".into(),
                algorithm_suite_id: "0478".into(),
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
            }),
        );

        let value = serde_json::to_value(&manifest).unwrap();
        assert_eq!(value["manifest"]["version"], 4);
        assert_eq!(value["manifest"]["type"], "awses-mpl-encrypt");
        assert_eq!(value["keys"], "file://keys.json");
        assert_eq!(
            value["tests"]["38f454e1-334d-4b75-8034-694a36a386c1"]["type"],
            "positive-keyring"
        );
    }

    #[test]
    fn negative_encrypt_vector_serializes_error_description() {
        let vector = EncryptTestVector::NegativeEncrypt(NegativeEncryptVector {
            description: "AES-128 with bogus context".into(),
            algorithm_suite_id: "0014".into(),
            key_description: json!({"type": "raw", "provider-id": "aws-raw-vectors-persistent-2", "key": "aes-128"}),
            error_description: "encryption context must be non-empty".into(),
            encryption_context: IndexMap::new(),
            max_plaintext_length: None,
            required_encryption_context_keys: None,
        });

        let value = serde_json::to_value(&vector).unwrap();
        assert_eq!(value["type"], "negative-encrypt-keyring");
        assert_eq!(
            value["errorDescription"],
            "encryption context must be non-empty"
        );
    }

    #[test]
    fn add_vector_produces_deterministic_uuid() {
        // Two manifests seeded with the same vector must produce the same
        // UUID for it — this is the property that keeps checked-in
        // manifests byte-stable across regeneration.
        fn build() -> EncryptManifest {
            let mut m = EncryptManifest::new();
            m.add_vector(EncryptTestVector::PositiveKeyring(PositiveEncryptVector {
                description: "seed".into(),
                algorithm_suite_id: "0478".into(),
                encrypt_key_description: json!({"type": "aws-kms-hierarchy", "key": "k"}),
                decrypt_key_description: json!({"type": "aws-kms-hierarchy", "key": "k"}),
                encryption_context: IndexMap::new(),
                max_plaintext_length: None,
                required_encryption_context_keys: None,
                reproduced_encryption_context: None,
            }));
            m
        }
        assert_eq!(
            build().tests.keys().next().unwrap(),
            build().tests.keys().next().unwrap(),
        );
    }

    #[test]
    fn distinct_vectors_produce_distinct_uuids() {
        // Sanity: differing content ⇒ differing UUID.
        let mut m = EncryptManifest::new();
        m.add_vector(EncryptTestVector::PositiveKeyring(PositiveEncryptVector {
            description: "a".into(),
            algorithm_suite_id: "0014".into(),
            encrypt_key_description: json!({"type": "aws-kms-hierarchy", "key": "k"}),
            decrypt_key_description: json!({"type": "aws-kms-hierarchy", "key": "k"}),
            encryption_context: IndexMap::new(),
            max_plaintext_length: None,
            required_encryption_context_keys: None,
            reproduced_encryption_context: None,
        }));
        m.add_vector(EncryptTestVector::PositiveKeyring(PositiveEncryptVector {
            description: "b".into(),
            algorithm_suite_id: "0478".into(),
            encrypt_key_description: json!({"type": "aws-kms-hierarchy", "key": "k"}),
            decrypt_key_description: json!({"type": "aws-kms-hierarchy", "key": "k"}),
            encryption_context: IndexMap::new(),
            max_plaintext_length: None,
            required_encryption_context_keys: None,
            reproduced_encryption_context: None,
        }));
        assert_eq!(m.tests.len(), 2);
    }
}

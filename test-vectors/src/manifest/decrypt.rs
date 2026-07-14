// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Decrypt manifest types.
//!
//! Mirrors the JSON schema emitted by the MPL Dafny
//! `WriteJsonManifests.dfy::DecryptTestVectorToJson`. The two variants match
//! `positive-keyring` and `negative-keyring` in the source.
//!
//! Byte-valued fields (`plaintextDataKey`, `symmetricSigningKey`,
//! `encryptedDataKey.*`) are serialized as base64 strings and stored here as
//! `String` so the JSON round-trips exactly.

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use super::header::ManifestHeader;

/// Top-level decrypt manifest as written to `manifest.json`.
///
/// ```json
/// {
///   "manifest": {"version": 4, "type": "awses-mpl-decrypt"},
///   "client":   "mpl-rust",
///   "keys":     "file://keys.json",
///   "tests":    { "<uuid>": { "type": "positive-keyring", ... } }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptManifest {
    pub manifest: ManifestHeader,
    /// Free-form string identifying the client that produced this manifest.
    /// The Dafny tool emits `"mpl-dafny"`; each Rust project should emit a
    /// distinctive value so cross-language artifacts remain attributable.
    pub client: String,
    pub keys: String,
    pub tests: IndexMap<String, DecryptTestVector>,
}

impl DecryptManifest {
    /// Construct an empty manifest attributed to `client`, pointing at the
    /// default `keys.json`.
    pub fn new(client: impl Into<String>) -> Self {
        Self {
            manifest: ManifestHeader::decrypt(),
            client: client.into(),
            keys: "file://keys.json".to_string(),
            tests: IndexMap::new(),
        }
    }

    /// Add a vector under a deterministic UUID derived from the vector's
    /// contents and return that UUID.
    ///
    /// Two structurally identical vectors always hash to the same UUID, so
    /// regenerating the manifest produces byte-stable output as long as the
    /// vector set does not change. See [`crate::manifest::vector_uuid`] for
    /// the exact recipe.
    pub fn add_vector(&mut self, vector: DecryptTestVector) -> String {
        let name = super::vector_uuid(&vector);
        self.tests.insert(name.clone(), vector);
        name
    }
}

/// One row of `tests` in a decrypt manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum DecryptTestVector {
    #[serde(rename = "positive-keyring")]
    Positive(PositiveDecryptVector),

    #[serde(rename = "negative-keyring")]
    Negative(NegativeDecryptVector),
}

/// A `positive-keyring` decrypt vector.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PositiveDecryptVector {
    pub description: String,
    pub algorithm_suite_id: String,
    pub key_description: serde_json::Value,
    pub encrypted_data_keys: Vec<EncryptedDataKey>,
    pub encryption_context: IndexMap<String, String>,
    pub result: DecryptResult,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reproduced_encryption_context: Option<IndexMap<String, String>>,
}

/// A `negative-keyring` decrypt vector — decrypt must fail.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NegativeDecryptVector {
    pub description: String,
    pub algorithm_suite_id: String,
    pub key_description: serde_json::Value,
    pub encrypted_data_keys: Vec<EncryptedDataKey>,
    pub encryption_context: IndexMap<String, String>,
    pub error_description: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reproduced_encryption_context: Option<IndexMap<String, String>>,
}

/// One encrypted data key attached to a decrypt vector.
///
/// The three byte fields are base64-encoded strings in the manifest. Callers
/// should use [`crate::manifest::codec`] helpers to decode them.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedDataKey {
    /// UTF-8 provider identifier.
    pub key_provider_id: String,
    /// base64-encoded provider info bytes.
    pub key_provider_info: String,
    /// base64-encoded ciphertext bytes.
    pub ciphertext: String,
}

/// The `result` field of a positive decrypt vector.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecryptResult {
    /// base64-encoded plaintext data key, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plaintext_data_key: Option<String>,

    /// base64-encoded symmetric signing key, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symmetric_signing_key: Option<String>,

    /// Encryption context keys that must be reproduced by the caller.
    #[serde(default)]
    pub required_encryption_context_keys: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_vector() -> DecryptTestVector {
        DecryptTestVector::Positive(PositiveDecryptVector {
            description: "test 0014".into(),
            algorithm_suite_id: "0014".into(),
            key_description: json!({"type": "raw", "provider-id": "static-material-keyring", "key": "aes-128"}),
            encrypted_data_keys: vec![EncryptedDataKey {
                key_provider_id: "static-material-keyring".into(),
                key_provider_info: "c3RhdGljLXBsYWludGV4dA==".into(),
                ciphertext: "AQEBAQEBAQEBAQEBAQEBAQ==".into(),
            }],
            encryption_context: IndexMap::new(),
            result: DecryptResult {
                plaintext_data_key: Some("AQEBAQEBAQEBAQEBAQEBAQ==".into()),
                symmetric_signing_key: None,
                required_encryption_context_keys: Vec::new(),
            },
            reproduced_encryption_context: None,
        })
    }

    #[test]
    fn positive_vector_matches_dafny_shape() {
        let value = serde_json::to_value(sample_vector()).unwrap();
        assert_eq!(value["type"], "positive-keyring");
        assert_eq!(value["algorithmSuiteId"], "0014");
        assert_eq!(
            value["encryptedDataKeys"][0]["keyProviderId"],
            "static-material-keyring"
        );
        assert_eq!(
            value["result"]["plaintextDataKey"],
            "AQEBAQEBAQEBAQEBAQEBAQ=="
        );
        assert!(value["result"].get("symmetricSigningKey").is_none());
    }

    #[test]
    fn manifest_round_trips() {
        let mut manifest = DecryptManifest::new("mpl-rust");
        manifest.tests.insert(
            "38f454e1-334d-4b75-8034-694a36a386c1".into(),
            sample_vector(),
        );

        let text = serde_json::to_string(&manifest).unwrap();
        let parsed: DecryptManifest = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed.manifest.manifest_type, "awses-mpl-decrypt");
        assert_eq!(parsed.client, "mpl-rust");
        assert_eq!(parsed.tests.len(), 1);
    }
}

// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! `keys.json` manifest types.
//!
//! Mirrors the schema consumed by the MPL Dafny KeyVectors component. Each
//! keys manifest is a flat map from key identifier to a heterogeneous entry
//! (static branch key, raw AES, RSA private key PEM, KMS key ARN, …).
//!
//! Rather than model every variant explicitly, entries are kept as
//! [`serde_json::Value`]. Callers that need typed access should downcast into
//! their own schema (see `projects::mpl` for an example).

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use super::header::ManifestHeader;

/// `type` string emitted at the top of a keys manifest.
pub const KEYS_MANIFEST_TYPE: &str = "keys";

/// Current version emitted for keys manifests. Matches the Dafny tool.
pub const CURRENT_KEYS_VERSION: u32 = 2;

/// Top-level `keys.json` document.
///
/// ```json
/// {
///   "manifest": {"type": "keys", "version": 2},
///   "keys":     { "aes-128": { ... }, "static-branch-key-1": { ... } }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyManifest {
    pub manifest: ManifestHeader,
    pub keys: IndexMap<String, serde_json::Value>,
}

impl KeyManifest {
    /// Construct an empty keys manifest at the current version.
    pub fn new() -> Self {
        Self {
            manifest: ManifestHeader {
                version: CURRENT_KEYS_VERSION,
                manifest_type: KEYS_MANIFEST_TYPE.to_string(),
            },
            keys: IndexMap::new(),
        }
    }

    /// Insert or replace a key entry.
    pub fn insert(&mut self, name: impl Into<String>, entry: serde_json::Value) {
        self.keys.insert(name.into(), entry);
    }

    /// Look up a key entry by name.
    pub fn get(&self, name: &str) -> Option<&serde_json::Value> {
        self.keys.get(name)
    }
}

impl Default for KeyManifest {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn keys_manifest_round_trips_and_preserves_insertion_order() {
        let mut manifest = KeyManifest::new();
        manifest.insert(
            "aes-128",
            json!({
                "encrypt": true,
                "decrypt": true,
                "algorithm": "aes",
                "type": "symmetric",
                "bits": 128,
                "encoding": "base64",
                "material": "AAECAwQFBgcICRAREhMUFQ==",
                "key-id": "aes-128"
            }),
        );
        manifest.insert(
            "static-branch-key-1",
            json!({
                "type": "static-branch-key",
                "encrypt": true,
                "decrypt": true,
                "key-id": "bd3842ff-3076-4092-9918-4395730050b8"
            }),
        );

        let value = serde_json::to_value(&manifest).unwrap();
        assert_eq!(value["manifest"]["type"], "keys");
        assert_eq!(value["manifest"]["version"], 2);
        assert_eq!(value["keys"]["aes-128"]["algorithm"], "aes");

        // Insertion order must be preserved so JSON output is stable.
        let keys: Vec<&str> = value["keys"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys, vec!["aes-128", "static-branch-key-1"]);
    }
}

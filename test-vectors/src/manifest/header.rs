// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Manifest header shared by both encrypt and decrypt manifests.

use serde::{Deserialize, Serialize};

/// Version emitted for every manifest this crate writes.
///
/// The MPL Dafny tool currently emits version `4` for both encrypt and decrypt
/// manifests. We use the same value so the JSON stays byte-compatible with
/// cross-language artifacts.
pub const CURRENT_MANIFEST_VERSION: u32 = 4;

/// `type` string for encrypt manifests.
pub const ENCRYPT_MANIFEST_TYPE: &str = "awses-mpl-encrypt";

/// `type` string for decrypt manifests.
pub const DECRYPT_MANIFEST_TYPE: &str = "awses-mpl-decrypt";

/// Header block written at the top of every manifest file.
///
/// ```json
/// { "version": 4, "type": "awses-mpl-encrypt" }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestHeader {
    pub version: u32,
    #[serde(rename = "type")]
    pub manifest_type: String,
}

impl ManifestHeader {
    /// Header for an encrypt manifest at the current manifest version.
    pub fn encrypt() -> Self {
        Self {
            version: CURRENT_MANIFEST_VERSION,
            manifest_type: ENCRYPT_MANIFEST_TYPE.to_string(),
        }
    }

    /// Header for a decrypt manifest at the current manifest version.
    pub fn decrypt() -> Self {
        Self {
            version: CURRENT_MANIFEST_VERSION,
            manifest_type: DECRYPT_MANIFEST_TYPE.to_string(),
        }
    }

    /// True if this header advertises an encrypt manifest.
    pub fn is_encrypt(&self) -> bool {
        self.manifest_type == ENCRYPT_MANIFEST_TYPE
    }

    /// True if this header advertises a decrypt manifest.
    pub fn is_decrypt(&self) -> bool {
        self.manifest_type == DECRYPT_MANIFEST_TYPE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_header_round_trips_through_json() {
        let header = ManifestHeader::encrypt();
        let json = serde_json::to_value(&header).unwrap();
        assert_eq!(json["version"], 4);
        assert_eq!(json["type"], "awses-mpl-encrypt");
        let parsed: ManifestHeader = serde_json::from_value(json).unwrap();
        assert_eq!(parsed, header);
        assert!(parsed.is_encrypt());
        assert!(!parsed.is_decrypt());
    }

    #[test]
    fn decrypt_header_round_trips_through_json() {
        let header = ManifestHeader::decrypt();
        let json = serde_json::to_value(&header).unwrap();
        assert_eq!(json["type"], "awses-mpl-decrypt");
        let parsed: ManifestHeader = serde_json::from_value(json).unwrap();
        assert!(parsed.is_decrypt());
    }
}

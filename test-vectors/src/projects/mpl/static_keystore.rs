// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! In-memory KeyStore for hierarchy-keyring test vectors.
//!
//! Mirrors the `StaticKeyStore` class defined by the MPL Dafny test-vectors
//! project in `dafny/KeyVectors/src/CreateStaticKeyStores.dfy`.
//!
//! # Why this exists
//!
//! Real hierarchy keyrings resolve branch/beacon keys by fetching a DynamoDB
//! record and unwrapping it with AWS KMS. Test vectors must be deterministic
//! and offline, so the Dafny reference project bakes the branch-key material
//! directly into the `static-branch-key` entry of `keys.json` and hands the
//! keyring a static [`Keystore`] implementation that serves that pre-baked
//! material verbatim.
//!
//! Behavior matches the Dafny `StaticKeyStore`:
//!
//! * `GetActiveBranchKey`, `GetBranchKeyVersion` return the pre-baked
//!   [`BranchKeyMaterials`] regardless of the requested version.
//! * `GetBeaconKey` returns the pre-baked beacon key.
//! * `GetKeyStoreInfo` returns hardcoded stub values (identical to the Dafny
//!   ones — matters for cross-language interop of any test that inspects
//!   the info).
//! * `CreateKeyStore`, `CreateKey`, `VersionKey` return an
//!   `Unsupported`-flavored [`KeystoreError`]. Test vectors are read-only.

use async_trait::async_trait;
use aws_crypto_mpl::keystore::error::KeystoreErrorKind;
use aws_crypto_mpl::keystore::{KeyStoreInfo, Keystore, KeystoreError, KmsConfiguration};
use aws_crypto_mpl::structures::{BeaconKeyMaterials, BranchKeyMaterials, EncryptionContext};
use serde_json::Value;

use crate::error::{Result, TestVectorError};
use crate::manifest::codec;

// Hardcoded values that the Dafny StaticKeyStore returns from
// GetKeyStoreInfo. Kept byte-identical to `CreateStaticKeyStores.dfy` so any
// cross-language test that inspects the info sees the same fields.
const STUB_KEYSTORE_ID: &str = "key-store-id";
const STUB_KEYSTORE_NAME: &str = "key-store-name";
const STUB_LOGICAL_KEYSTORE_NAME: &str = "logical-key-store-name";
const STUB_KMS_KEY_ARN: &str =
    "arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";

/// Number of bytes in a branch key. Matches [`BranchKeyMaterials`]'s
/// `[u8; 32]` field.
const BRANCH_KEY_LEN: usize = 32;

/// In-memory keystore that returns pre-baked branch/beacon key material.
///
/// Construct with [`StaticKeyStore::from_entry`] passing the `serde_json`
/// value of a `static-branch-key` entry from a parsed `keys.json`. Pass a
/// resulting `Arc<StaticKeyStore>` to
/// `MaterialProviders::create_aws_kms_hierarchical_keyring().key_store(…)`.
#[derive(Debug)]
pub struct StaticKeyStore {
    /// The `key-id` field from the keys.json entry — the branch-key id this
    /// store advertises. Requests for any other id return `RecordNotFound`.
    key_id: String,
    /// UUID version string as stored in the entry (`branchKeyVersion`).
    branch_key_version: String,
    /// Decoded 32-byte branch key material.
    branch_key: [u8; BRANCH_KEY_LEN],
    /// Decoded beacon key material. Length is not fixed by the MPL contract.
    beacon_key: Vec<u8>,
}

impl StaticKeyStore {
    /// Construct a `StaticKeyStore` from a decoded `static-branch-key`
    /// keys.json entry.
    ///
    /// # Errors
    ///
    /// Returns [`TestVectorError::Other`] when any required field is missing,
    /// mistyped, malformed base64, or when the decoded `branchKey` is not
    /// exactly 32 bytes.
    pub fn from_entry(entry: &Value) -> Result<Self> {
        let entry = entry.as_object().ok_or_else(|| {
            TestVectorError::other("static-branch-key entry is not a JSON object")
        })?;

        let key_id = required_str(entry, "key-id")?.to_string();
        let branch_key_version = required_str(entry, "branchKeyVersion")?.to_string();
        let branch_key_b64 = required_str(entry, "branchKey")?;
        let beacon_key_b64 = required_str(entry, "beaconKey")?;

        let branch_key_bytes = codec::decode(branch_key_b64)?;
        let branch_key: [u8; BRANCH_KEY_LEN] =
            branch_key_bytes.as_slice().try_into().map_err(|_| {
                TestVectorError::other(format!(
                    "branchKey must decode to exactly {BRANCH_KEY_LEN} bytes; got {}",
                    branch_key_bytes.len()
                ))
            })?;
        let beacon_key = codec::decode(beacon_key_b64)?;

        Ok(Self {
            key_id,
            branch_key_version,
            branch_key,
            beacon_key,
        })
    }

    /// The branch-key id this static store serves.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Reject any request whose `branch_key_id` doesn't match the seeded id.
    fn ensure_matches(&self, requested: &str) -> std::result::Result<(), KeystoreError> {
        if requested == self.key_id {
            Ok(())
        } else {
            Err(KeystoreError::new(
                KeystoreErrorKind::RecordNotFound,
                format!(
                    "StaticKeyStore seeded with '{}' but got request for '{}'",
                    self.key_id, requested
                ),
            ))
        }
    }
}

/// Helper: extract a required string field from a JSON object.
fn required_str<'a>(obj: &'a serde_json::Map<String, Value>, key: &str) -> Result<&'a str> {
    obj.get(key).and_then(Value::as_str).ok_or_else(|| {
        TestVectorError::other(format!(
            "static-branch-key entry missing required string field '{key}'"
        ))
    })
}

/// Uniform "not supported" error for the write operations. Matches the
/// Dafny `KeyStoreException(message := "Not Supported")` payload.
fn unsupported(op: &'static str) -> KeystoreError {
    KeystoreError::new(
        KeystoreErrorKind::Configuration,
        format!("StaticKeyStore does not support '{op}' — read-only test-vector keystore"),
    )
}

#[async_trait]
impl Keystore for StaticKeyStore {
    async fn get_key_store_info(&self) -> std::result::Result<KeyStoreInfo, KeystoreError> {
        Ok(KeyStoreInfo {
            keystore_id: STUB_KEYSTORE_ID.to_string(),
            keystore_name: STUB_KEYSTORE_NAME.to_string(),
            logical_keystore_name: STUB_LOGICAL_KEYSTORE_NAME.to_string(),
            grant_tokens: Vec::new(),
            kms_configuration: KmsConfiguration::KmsKeyArn(STUB_KMS_KEY_ARN.to_string()),
        })
    }

    async fn create_key_store(&self) -> std::result::Result<String, KeystoreError> {
        Err(unsupported("create_key_store"))
    }

    async fn create_key(
        &self,
        _branch_key_id: Option<String>,
        _encryption_context: Option<EncryptionContext>,
    ) -> std::result::Result<String, KeystoreError> {
        Err(unsupported("create_key"))
    }

    async fn version_key(&self, _branch_key_id: String) -> std::result::Result<(), KeystoreError> {
        Err(unsupported("version_key"))
    }

    async fn get_active_branch_key(
        &self,
        branch_key_id: String,
    ) -> std::result::Result<BranchKeyMaterials, KeystoreError> {
        self.ensure_matches(&branch_key_id)?;
        BranchKeyMaterials::new(
            self.branch_key,
            self.key_id.clone(),
            self.branch_key_version.clone(),
            EncryptionContext::new(),
        )
        .map_err(|e| KeystoreError::new(KeystoreErrorKind::Internal, e.to_string()))
    }

    async fn get_branch_key_version(
        &self,
        branch_key_id: String,
        _branch_key_version: String,
    ) -> std::result::Result<BranchKeyMaterials, KeystoreError> {
        // The Dafny StaticKeyStore ignores the requested version and always
        // returns the seeded material — the version field of the returned
        // materials is the seeded branchKeyVersion, not the requested one.
        // Matching that behavior keeps cross-language artifacts consistent.
        self.get_active_branch_key(branch_key_id).await
    }

    async fn get_beacon_key(
        &self,
        branch_key_id: String,
    ) -> std::result::Result<BeaconKeyMaterials, KeystoreError> {
        self.ensure_matches(&branch_key_id)?;
        Ok(BeaconKeyMaterials::new(
            self.key_id.clone(),
            EncryptionContext::new(),
            Some(self.beacon_key.clone()),
            None,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::projects::mpl::keys::all_keys;
    use serde_json::json;

    fn reference_entry() -> &'static Value {
        all_keys()
            .get("static-branch-key-1")
            .expect("reference keys.json must contain static-branch-key-1")
    }

    #[test]
    fn from_entry_parses_the_reference_static_branch_key() {
        let store = StaticKeyStore::from_entry(reference_entry()).unwrap();
        assert_eq!(store.key_id(), "bd3842ff-3076-4092-9918-4395730050b8");
        assert_eq!(
            store.branch_key_version,
            "e9ce18a3-edb5-4272-9f86-1cacb7997ff6"
        );
        assert_eq!(store.branch_key.len(), 32);
        // Beacon key is a 32-byte HMAC key in the reference data.
        assert_eq!(store.beacon_key.len(), 32);
    }

    #[test]
    fn from_entry_rejects_missing_field() {
        let bad = json!({
            "type": "static-branch-key",
            "key-id": "foo",
            "branchKeyVersion": "v1",
            // branchKey missing
            "beaconKey": "AAA="
        });
        let err = StaticKeyStore::from_entry(&bad).unwrap_err();
        assert!(
            format!("{err}").contains("branchKey"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn from_entry_rejects_wrong_branch_key_length() {
        // 16 bytes of base64, not 32.
        let bad = json!({
            "type": "static-branch-key",
            "key-id": "foo",
            "branchKeyVersion": "v1",
            "branchKey": codec::encode([0u8; 16]),
            "beaconKey": codec::encode([0u8; 32])
        });
        let err = StaticKeyStore::from_entry(&bad).unwrap_err();
        assert!(
            format!("{err}").contains("32 bytes"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn get_active_branch_key_returns_seeded_material() {
        let store = StaticKeyStore::from_entry(reference_entry()).unwrap();
        let materials = store
            .get_active_branch_key(store.key_id().to_string())
            .await
            .unwrap();
        assert_eq!(materials.branch_key_id(), store.key_id());
        assert_eq!(materials.branch_key_version(), &store.branch_key_version);
        assert_eq!(materials.branch_key(), &store.branch_key);
    }

    #[tokio::test]
    async fn get_active_branch_key_rejects_unknown_id() {
        let store = StaticKeyStore::from_entry(reference_entry()).unwrap();
        let err = store
            .get_active_branch_key("some-other-id".into())
            .await
            .unwrap_err();
        assert_eq!(err.kind(), &KeystoreErrorKind::RecordNotFound);
    }

    #[tokio::test]
    async fn get_branch_key_version_ignores_requested_version() {
        // The Dafny reference ignores the version argument and always returns
        // the seeded material; verify we behave the same.
        let store = StaticKeyStore::from_entry(reference_entry()).unwrap();
        let materials = store
            .get_branch_key_version(store.key_id().to_string(), "some-other-version".into())
            .await
            .unwrap();
        assert_eq!(materials.branch_key_version(), &store.branch_key_version);
    }

    #[tokio::test]
    async fn get_beacon_key_returns_seeded_material() {
        let store = StaticKeyStore::from_entry(reference_entry()).unwrap();
        let materials = store
            .get_beacon_key(store.key_id().to_string())
            .await
            .unwrap();
        assert_eq!(materials.beacon_key_id(), store.key_id());
        assert_eq!(materials.beacon_key(), Some(store.beacon_key.as_slice()));
    }

    #[tokio::test]
    async fn get_key_store_info_returns_dafny_stub_values() {
        // Values must match CreateStaticKeyStores.dfy byte-for-byte for
        // cross-language artifact interop.
        let store = StaticKeyStore::from_entry(reference_entry()).unwrap();
        let info = store.get_key_store_info().await.unwrap();
        assert_eq!(info.keystore_id, "key-store-id");
        assert_eq!(info.keystore_name, "key-store-name");
        assert_eq!(info.logical_keystore_name, "logical-key-store-name");
        assert!(info.grant_tokens.is_empty());
        match info.kms_configuration {
            KmsConfiguration::KmsKeyArn(arn) => {
                assert_eq!(
                    arn,
                    "arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
                );
            }
            other => panic!("expected KmsKeyArn, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn write_operations_report_unsupported() {
        let store = StaticKeyStore::from_entry(reference_entry()).unwrap();
        for kind in [
            store
                .create_key_store()
                .await
                .map(|_| ())
                .unwrap_err()
                .kind()
                .clone(),
            store
                .create_key(None, None)
                .await
                .map(|_| ())
                .unwrap_err()
                .kind()
                .clone(),
            store
                .version_key("any".into())
                .await
                .unwrap_err()
                .kind()
                .clone(),
        ] {
            assert_eq!(kind, KeystoreErrorKind::Configuration);
        }
    }
}

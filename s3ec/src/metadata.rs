// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! S3 object content metadata.
//!
//! Content metadata is the per-object information required to decrypt an
//! object: the encrypted data key, the content IV / message ID, the content
//! and wrapping algorithms, and (for committing suites) the key commitment.
//! This module serializes that information to and from the S3 object-metadata
//! map (the `x-amz-*` mapkeys) for the V2 and V3 formats used by the V4 S3EC
//! release.
//!
//! See `spec/s3-encryption/data-format/content-metadata.md`.

use std::collections::BTreeMap;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;

use crate::config::EncryptionAlgorithm;
use crate::error::{Result, S3EncryptionError};
use crate::keyring::WRAP_ALG_KMS_CONTEXT;

// ---------------------------------------------------------------------------
// MapKey constants.
//
//= spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
//# The "x-amz-" prefix denotes that the metadata is owned by an Amazon product and MUST be prepended to all S3EC metadata mapkeys.
// ---------------------------------------------------------------------------

/// V1 encrypted data key mapkey.
pub const ENCRYPTED_DATA_KEY_V1: &str = "x-amz-key";
/// V2 encrypted data key mapkey.
pub const ENCRYPTED_DATA_KEY_V2: &str = "x-amz-key-v2";
/// Wrapping (data-key encryption) algorithm mapkey (V1/V2).
pub const WRAP_ALGORITHM: &str = "x-amz-wrap-alg";
/// Material description / encryption context mapkey (V1/V2).
pub const MATERIALS_DESCRIPTION: &str = "x-amz-matdesc";
/// Content IV mapkey (V1/V2).
pub const CONTENT_IV: &str = "x-amz-iv";
/// Content cipher mapkey (V1/V2).
pub const CONTENT_CIPHER: &str = "x-amz-cek-alg";
/// Content cipher auth-tag length mapkey (V2).
pub const TAG_LENGTH: &str = "x-amz-tag-len";

/// V3 content cipher mapkey.
pub const CONTENT_CIPHER_V3: &str = "x-amz-c";
/// V3 encrypted data key mapkey.
pub const ENCRYPTED_DATA_KEY_V3: &str = "x-amz-3";
/// V3 material description mapkey.
pub const MAT_DESC_V3: &str = "x-amz-m";
/// V3 KMS encryption context mapkey.
pub const ENCRYPTION_CONTEXT_V3: &str = "x-amz-t";
/// V3 wrapping algorithm mapkey.
pub const WRAP_ALGORITHM_V3: &str = "x-amz-w";
/// V3 key commitment mapkey.
pub const KEY_COMMITMENT_V3: &str = "x-amz-d";
/// V3 message ID mapkey.
pub const MESSAGE_ID_V3: &str = "x-amz-i";

/// Content metadata for an S3EC-encrypted object.
///
/// Fields hold the already-encoded (base64 / JSON string) values exactly as
/// they are persisted in the S3 object-metadata map. Only the fields relevant
/// to a given format version are populated.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ObjectMetadata {
    /// `x-amz-key` — V1 encrypted data key (base64).
    pub encrypted_data_key_v1: Option<String>,
    /// `x-amz-key-v2` — V2 encrypted data key (base64).
    pub encrypted_data_key_v2: Option<String>,
    /// `x-amz-wrap-alg` — wrapping algorithm.
    pub wrap_algorithm: Option<String>,
    /// `x-amz-matdesc` — material description / encryption context (JSON).
    pub materials_description: Option<String>,
    /// `x-amz-iv` — content IV (base64).
    pub content_iv: Option<String>,
    /// `x-amz-cek-alg` — content cipher.
    pub content_cipher: Option<String>,
    /// `x-amz-tag-len` — content auth tag length in bits.
    pub tag_length: Option<String>,

    /// `x-amz-c` — V3 content cipher (suite ID as string).
    pub content_cipher_v3: Option<String>,
    /// `x-amz-3` — V3 encrypted data key (base64).
    pub encrypted_data_key_v3: Option<String>,
    /// `x-amz-m` — V3 material description (JSON).
    pub mat_desc_v3: Option<String>,
    /// `x-amz-t` — V3 KMS encryption context (JSON).
    pub encryption_context_v3: Option<String>,
    /// `x-amz-w` — V3 wrapping algorithm (compressed code).
    pub wrap_algorithm_v3: Option<String>,
    /// `x-amz-d` — V3 key commitment (base64).
    pub key_commitment_v3: Option<String>,
    /// `x-amz-i` — V3 message ID (base64).
    pub message_id_v3: Option<String>,
}

impl ObjectMetadata {
    /// Deserialize content metadata from an S3 object-metadata map.
    pub fn from_map(map: &BTreeMap<String, String>) -> Self {
        let get = |k: &str| map.get(k).cloned();
        Self {
            encrypted_data_key_v1: get(ENCRYPTED_DATA_KEY_V1),
            encrypted_data_key_v2: get(ENCRYPTED_DATA_KEY_V2),
            wrap_algorithm: get(WRAP_ALGORITHM),
            materials_description: get(MATERIALS_DESCRIPTION),
            content_iv: get(CONTENT_IV),
            content_cipher: get(CONTENT_CIPHER),
            tag_length: get(TAG_LENGTH),
            content_cipher_v3: get(CONTENT_CIPHER_V3),
            encrypted_data_key_v3: get(ENCRYPTED_DATA_KEY_V3),
            mat_desc_v3: get(MAT_DESC_V3),
            encryption_context_v3: get(ENCRYPTION_CONTEXT_V3),
            wrap_algorithm_v3: get(WRAP_ALGORITHM_V3),
            key_commitment_v3: get(KEY_COMMITMENT_V3),
            message_id_v3: get(MESSAGE_ID_V3),
        }
    }

    /// Serialize content metadata into an S3 object-metadata map, emitting only
    /// the populated mapkeys.
    pub fn to_map(&self) -> BTreeMap<String, String> {
        let mut map = BTreeMap::new();
        let mut put = |k: &str, v: &Option<String>| {
            if let Some(value) = v {
                map.insert(k.to_string(), value.clone());
            }
        };
        put(ENCRYPTED_DATA_KEY_V1, &self.encrypted_data_key_v1);
        put(ENCRYPTED_DATA_KEY_V2, &self.encrypted_data_key_v2);
        put(WRAP_ALGORITHM, &self.wrap_algorithm);
        put(MATERIALS_DESCRIPTION, &self.materials_description);
        put(CONTENT_IV, &self.content_iv);
        put(CONTENT_CIPHER, &self.content_cipher);
        put(TAG_LENGTH, &self.tag_length);
        put(CONTENT_CIPHER_V3, &self.content_cipher_v3);
        put(ENCRYPTED_DATA_KEY_V3, &self.encrypted_data_key_v3);
        put(MAT_DESC_V3, &self.mat_desc_v3);
        put(ENCRYPTION_CONTEXT_V3, &self.encryption_context_v3);
        put(WRAP_ALGORITHM_V3, &self.wrap_algorithm_v3);
        put(KEY_COMMITMENT_V3, &self.key_commitment_v3);
        put(MESSAGE_ID_V3, &self.message_id_v3);
        map
    }

    /// Whether the metadata is in the V1 format.
    pub fn is_v1_format(&self) -> bool {
        self.content_iv.is_some()
            && self.encrypted_data_key_v1.is_some()
            && self.encrypted_data_key_v2.is_none()
            && self.encrypted_data_key_v3.is_none()
    }

    //= spec/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
    //# If the metadata contains "x-amz-iv" and "x-amz-key-v2" but no other version exclusive keys then the object MUST be considered as an S3EC-encrypted object using the V2 format.
    /// Whether the metadata is in the V2 format.
    pub fn is_v2_format(&self) -> bool {
        self.content_iv.is_some()
            && self.encrypted_data_key_v2.is_some()
            && self.encrypted_data_key_v1.is_none()
            && self.encrypted_data_key_v3.is_none()
    }

    //= spec/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
    //# If the metadata contains "x-amz-3" and "x-amz-d" and "x-amz-i" but no other version exclusive keys then the object MUST be considered an S3EC-encrypted object using the V3 format.
    /// Whether the metadata is in the V3 format.
    pub fn is_v3_format(&self) -> bool {
        self.encrypted_data_key_v3.is_some()
            && self.key_commitment_v3.is_some()
            && self.message_id_v3.is_some()
            && self.encrypted_data_key_v1.is_none()
            && self.encrypted_data_key_v2.is_none()
    }

    //= spec/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
    //# If there are multiple mapkeys which are meant to be exclusive to different versions, such as "x-amz-key", "x-amz-key-v2", and "x-amz-3" then the S3EC SHOULD throw an exception.
    /// Whether the metadata carries encrypted-data-key mapkeys from more than
    /// one exclusive format version (a tamper / format-confusion signal).
    pub fn has_exclusive_key_collision(&self) -> bool {
        let count = [
            self.encrypted_data_key_v1.is_some(),
            self.encrypted_data_key_v2.is_some(),
            self.encrypted_data_key_v3.is_some(),
        ]
        .into_iter()
        .filter(|present| *present)
        .count();
        count > 1
    }

    /// Build V2 (non-committing AES-GCM) content metadata from the encryption
    /// outputs. The encrypted data key and IV are base64-encoded; the full
    /// encryption context (including the reserved content-algorithm key) is
    /// stored as JSON in `x-amz-matdesc`.
    pub fn for_v2(
        encrypted_data_key: &[u8],
        content_iv: &[u8],
        encryption_context: &BTreeMap<String, String>,
    ) -> Result<Self> {
        Ok(Self {
            encrypted_data_key_v2: Some(BASE64.encode(encrypted_data_key)),
            wrap_algorithm: Some(WRAP_ALG_KMS_CONTEXT.to_string()),
            materials_description: Some(encode_context(encryption_context)?),
            content_iv: Some(BASE64.encode(content_iv)),
            content_cipher: Some(
                EncryptionAlgorithm::AlgAes256GcmIv12Tag16NoKdf.content_cipher_value(),
            ),
            tag_length: Some("128".to_string()),
            ..Default::default()
        })
    }

    /// Build V3 (key-committing AES-GCM) content metadata from the encryption
    /// outputs. The encrypted data key, message ID, and key commitment are
    /// base64-encoded; the full encryption context is stored as JSON in
    /// `x-amz-t`.
    pub fn for_v3(
        suite: EncryptionAlgorithm,
        encrypted_data_key: &[u8],
        message_id: &[u8],
        key_commitment: &[u8],
        encryption_context: &BTreeMap<String, String>,
    ) -> Result<Self> {
        Ok(Self {
            content_cipher_v3: Some(suite.content_cipher_value()),
            encrypted_data_key_v3: Some(BASE64.encode(encrypted_data_key)),
            // "12" is the V3 compressed code for the kms+context wrapping algorithm.
            wrap_algorithm_v3: Some(v3_wrap_algorithm_to_code(WRAP_ALG_KMS_CONTEXT)?.to_string()),
            message_id_v3: Some(BASE64.encode(message_id)),
            key_commitment_v3: Some(BASE64.encode(key_commitment)),
            encryption_context_v3: Some(encode_context(encryption_context)?),
            ..Default::default()
        })
    }

    /// Decode a base64 metadata field, mapping decode failures to a format error.
    fn decode_b64(field: &str, value: &Option<String>) -> Result<Vec<u8>> {
        let value = value
            .as_ref()
            .ok_or_else(|| S3EncryptionError::Format(format!("missing metadata field: {field}")))?;
        BASE64
            .decode(value)
            .map_err(|e| S3EncryptionError::Format(format!("invalid base64 in {field}: {e}")))
    }

    /// The decoded V2 encrypted data key (`x-amz-key-v2`).
    pub fn v2_encrypted_data_key(&self) -> Result<Vec<u8>> {
        Self::decode_b64(ENCRYPTED_DATA_KEY_V2, &self.encrypted_data_key_v2)
    }

    /// The decoded content IV (`x-amz-iv`).
    pub fn content_iv_bytes(&self) -> Result<Vec<u8>> {
        Self::decode_b64(CONTENT_IV, &self.content_iv)
    }

    /// The decoded V3 encrypted data key (`x-amz-3`).
    pub fn v3_encrypted_data_key(&self) -> Result<Vec<u8>> {
        Self::decode_b64(ENCRYPTED_DATA_KEY_V3, &self.encrypted_data_key_v3)
    }

    /// The decoded V3 message ID (`x-amz-i`).
    pub fn v3_message_id(&self) -> Result<Vec<u8>> {
        Self::decode_b64(MESSAGE_ID_V3, &self.message_id_v3)
    }

    /// The decoded V3 key commitment (`x-amz-d`).
    pub fn v3_key_commitment(&self) -> Result<Vec<u8>> {
        Self::decode_b64(KEY_COMMITMENT_V3, &self.key_commitment_v3)
    }

    /// The stored encryption context for a V2 object, parsed from the JSON
    /// `x-amz-matdesc` material description.
    pub fn v2_stored_context(&self) -> Result<BTreeMap<String, String>> {
        parse_context(self.materials_description.as_deref())
    }

    /// The stored encryption context for a V3 object, parsed from the JSON
    /// `x-amz-t` encryption-context field.
    pub fn v3_stored_context(&self) -> Result<BTreeMap<String, String>> {
        parse_context(self.encryption_context_v3.as_deref())
    }
}

/// Serialize an encryption context to the JSON form stored in object metadata.
fn encode_context(context: &BTreeMap<String, String>) -> Result<String> {
    serde_json::to_string(context)
        .map_err(|e| S3EncryptionError::Format(format!("failed to encode encryption context: {e}")))
}

/// Parse the JSON encryption-context string stored in object metadata. A
/// missing field yields an empty context.
fn parse_context(value: Option<&str>) -> Result<BTreeMap<String, String>> {
    match value {
        None => Ok(BTreeMap::new()),
        Some(s) => serde_json::from_str(s).map_err(|e| {
            S3EncryptionError::Format(format!("failed to parse encryption context: {e}"))
        }),
    }
}

/// Translate a V3 compressed wrapping-algorithm code to its canonical name.
pub fn v3_wrap_algorithm_to_name(code: &str) -> Result<&'static str> {
    match code {
        //= spec/s3-encryption/data-format/content-metadata.md#v3-only
        //# - The wrapping algorithm value "02" MUST be translated to AES/GCM upon retrieval, and vice versa on write.
        "02" => Ok("AES/GCM"),
        //= spec/s3-encryption/data-format/content-metadata.md#v3-only
        //# - The wrapping algorithm value "12" MUST be translated to kms+context upon retrieval, and vice versa on write.
        "12" => Ok("kms+context"),
        //= spec/s3-encryption/data-format/content-metadata.md#v3-only
        //# - The wrapping algorithm value "22" MUST be translated to RSA-OAEP-SHA1 upon retrieval, and vice versa on write.
        "22" => Ok("RSA-OAEP-SHA1"),
        other => Err(S3EncryptionError::Format(format!(
            "unknown V3 wrapping algorithm code: {other}"
        ))),
    }
}

/// Translate a canonical wrapping-algorithm name to its V3 compressed code.
pub fn v3_wrap_algorithm_to_code(name: &str) -> Result<&'static str> {
    match name {
        "AES/GCM" => Ok("02"),
        "kms+context" => Ok("12"),
        "RSA-OAEP-SHA1" => Ok("22"),
        other => Err(S3EncryptionError::Format(format!(
            "wrapping algorithm has no V3 code: {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v2_metadata() -> ObjectMetadata {
        ObjectMetadata {
            encrypted_data_key_v2: Some("ZWRrYnl0ZXM=".to_string()),
            wrap_algorithm: Some("kms+context".to_string()),
            materials_description: Some("{}".to_string()),
            content_iv: Some("aXZieXRlcw==".to_string()),
            content_cipher: Some("AES/GCM/NoPadding".to_string()),
            tag_length: Some("128".to_string()),
            ..Default::default()
        }
    }

    fn v3_metadata() -> ObjectMetadata {
        ObjectMetadata {
            content_cipher_v3: Some("115".to_string()),
            encrypted_data_key_v3: Some("ZWRrYnl0ZXM=".to_string()),
            wrap_algorithm_v3: Some("12".to_string()),
            key_commitment_v3: Some("Y29tbWl0".to_string()),
            message_id_v3: Some("bXNnaWQ=".to_string()),
            encryption_context_v3: Some("{}".to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn v2_round_trips_through_map() {
        let md = v2_metadata();
        let map = md.to_map();
        assert_eq!(map.get(ENCRYPTED_DATA_KEY_V2).unwrap(), "ZWRrYnl0ZXM=");
        assert_eq!(map.get(CONTENT_CIPHER).unwrap(), "AES/GCM/NoPadding");
        assert_eq!(map.get(TAG_LENGTH).unwrap(), "128");
        // V3-only keys must be absent.
        assert!(!map.contains_key(CONTENT_CIPHER_V3));
        assert_eq!(ObjectMetadata::from_map(&map), md);
    }

    #[test]
    fn v3_round_trips_through_map() {
        let md = v3_metadata();
        let map = md.to_map();
        assert_eq!(map.get(ENCRYPTED_DATA_KEY_V3).unwrap(), "ZWRrYnl0ZXM=");
        assert_eq!(map.get(KEY_COMMITMENT_V3).unwrap(), "Y29tbWl0");
        assert_eq!(map.get(MESSAGE_ID_V3).unwrap(), "bXNnaWQ=");
        // V1/V2 keys must be absent.
        assert!(!map.contains_key(ENCRYPTED_DATA_KEY_V2));
        assert!(!map.contains_key(TAG_LENGTH));
        assert_eq!(ObjectMetadata::from_map(&map), md);
    }

    #[test]
    fn format_detection_is_exclusive() {
        let v2 = v2_metadata();
        assert!(v2.is_v2_format());
        assert!(!v2.is_v1_format());
        assert!(!v2.is_v3_format());

        let v3 = v3_metadata();
        assert!(v3.is_v3_format());
        assert!(!v3.is_v1_format());
        assert!(!v3.is_v2_format());
    }

    #[test]
    fn exclusive_key_collision_detected() {
        let mut md = v2_metadata();
        assert!(!md.has_exclusive_key_collision());
        // Inject a V3 key alongside the V2 key.
        md.encrypted_data_key_v3 = Some("ZXh0cmE=".to_string());
        assert!(md.has_exclusive_key_collision());
        assert!(!md.is_v2_format());
        assert!(!md.is_v3_format());
    }

    #[test]
    fn v3_wrap_algorithm_translation_round_trips() {
        for (code, name) in [
            ("02", "AES/GCM"),
            ("12", "kms+context"),
            ("22", "RSA-OAEP-SHA1"),
        ] {
            assert_eq!(v3_wrap_algorithm_to_name(code).unwrap(), name);
            assert_eq!(v3_wrap_algorithm_to_code(name).unwrap(), code);
        }
        assert!(v3_wrap_algorithm_to_name("99").is_err());
        assert!(v3_wrap_algorithm_to_code("AES/CBC").is_err());
    }

    fn ctx() -> BTreeMap<String, String> {
        [
            ("user".to_string(), "alice".to_string()),
            ("aws:x-amz-cek-alg".to_string(), "115".to_string()),
        ]
        .into_iter()
        .collect()
    }

    #[test]
    fn for_v2_builds_decodable_metadata() {
        let edk = b"encrypted-data-key";
        let iv = [0xABu8; 12];
        let md = ObjectMetadata::for_v2(edk, &iv, &ctx()).unwrap();

        assert!(md.is_v2_format());
        assert_eq!(md.wrap_algorithm.as_deref(), Some("kms+context"));
        assert_eq!(md.content_cipher.as_deref(), Some("AES/GCM/NoPadding"));
        assert_eq!(md.tag_length.as_deref(), Some("128"));

        // Round-trips through the S3 metadata map and back to decoded bytes.
        let parsed = ObjectMetadata::from_map(&md.to_map());
        assert_eq!(parsed.v2_encrypted_data_key().unwrap(), edk);
        assert_eq!(parsed.content_iv_bytes().unwrap(), iv);
        assert_eq!(parsed.v2_stored_context().unwrap(), ctx());
    }

    #[test]
    fn for_v3_builds_decodable_metadata() {
        let suite = EncryptionAlgorithm::AlgAes256GcmHkdfSha512CommitKey;
        let edk = b"encrypted-data-key";
        let message_id = [0x11u8; 28];
        let commitment = [0x22u8; 28];
        let md = ObjectMetadata::for_v3(suite, edk, &message_id, &commitment, &ctx()).unwrap();

        assert!(md.is_v3_format());
        assert_eq!(md.content_cipher_v3.as_deref(), Some("115"));
        assert_eq!(md.wrap_algorithm_v3.as_deref(), Some("12"));

        let parsed = ObjectMetadata::from_map(&md.to_map());
        assert_eq!(parsed.v3_encrypted_data_key().unwrap(), edk);
        assert_eq!(parsed.v3_message_id().unwrap(), message_id);
        assert_eq!(parsed.v3_key_commitment().unwrap(), commitment);
        assert_eq!(parsed.v3_stored_context().unwrap(), ctx());
    }
}

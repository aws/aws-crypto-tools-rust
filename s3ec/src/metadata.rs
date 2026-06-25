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
use crate::keyring::{WRAP_ALG_AES_GCM, WRAP_ALG_KMS_CONTEXT, WRAP_ALG_RSA_OAEP_SHA1};

// MapKey constants. Every value below begins with the `x-amz-` prefix, never
// the server-managed `x-amz-meta-` prefix, and is pure US-ASCII.

//= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
//# The "x-amz-" prefix denotes that the metadata is owned by an Amazon product and MUST be prepended to all S3EC metadata mapkeys.
//
//= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
//= reason=Every mapkey constant carries the "x-amz-" prefix only; the "x-amz-meta-" prefix is never embedded in any constant.
//# The "x-amz-meta-" prefix is automatically added by the S3 server and MUST NOT be included in implementation code.
//
//= ../spec/s3-encryption/data-format/content-metadata.md#us-ascii-preferred-string
//= reason=Every mapkey constant is an ASCII string literal.
//# Thus,
//# Content Metadata MapKeys SHOULD be restricted to US-ASCII.
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

/// The `x-amz-cek-alg` content-cipher value for non-committing AES-GCM (V1/V2).
pub const CONTENT_CIPHER_GCM: &str = "AES/GCM/NoPadding";
/// The `x-amz-cek-alg` content-cipher value for the legacy AES-CBC suite (V1/V2).
pub const CONTENT_CIPHER_CBC: &str = "AES/CBC/PKCS5Padding";

//= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
//# - This mapkey ("x-amz-c") SHOULD be represented by a constant named "CONTENT_CIPHER_V3" or similar in the implementation code.
/// V3 content cipher mapkey.
pub const CONTENT_CIPHER_V3: &str = "x-amz-c";

//= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
//# - This mapkey ("x-amz-3") SHOULD be represented by a constant named "ENCRYPTED_DATA_KEY_V3" or similar in the implementation code.
/// V3 encrypted data key mapkey.
pub const ENCRYPTED_DATA_KEY_V3: &str = "x-amz-3";

//= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
//# - This mapkey ("x-amz-m") SHOULD be represented by a constant named "MAT_DESC_V3" or similar in the implementation code.
/// V3 material description mapkey.
pub const MAT_DESC_V3: &str = "x-amz-m";

//= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
//# - This mapkey ("x-amz-t") SHOULD be represented by a constant named "ENCRYPTION_CONTEXT_V3" or similar in the implementation code.
/// V3 KMS encryption context mapkey.
pub const ENCRYPTION_CONTEXT_V3: &str = "x-amz-t";

//= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
//# - This mapkey ("x-amz-w") SHOULD be represented by a constant named "ENCRYPTED_DATA_KEY_ALGORITHM_V3" or similar in the implementation code.
/// V3 wrapping algorithm mapkey.
pub const WRAP_ALGORITHM_V3: &str = "x-amz-w";

//= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
//# - This mapkey ("x-amz-d") SHOULD be represented by a constant named "KEY_COMMITMENT_V3" or similar in the implementation code.
/// V3 key commitment mapkey.
pub const KEY_COMMITMENT_V3: &str = "x-amz-d";

//= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
//# - This mapkey ("x-amz-i") SHOULD be represented by a constant named "MESSAGE_ID_V3" or similar in the implementation code.
/// V3 message ID mapkey.
pub const MESSAGE_ID_V3: &str = "x-amz-i";

/// User-metadata mapkey set on an instruction-file S3 object marking it as an
/// S3EC instruction file. The cross-implementation harness asserts its presence
/// on the written `.instruction` object.
pub const INSTRUCTION_FILE_MARKER: &str = "x-amz-crypto-instr-file";

//= ../spec/s3-encryption/data-format/metadata-strategy.md#instruction-file
//# The default Instruction File behavior uses the same S3 object key as its associated object suffixed with ".instruction".
/// The default instruction-file S3 object key suffix.
pub const DEFAULT_INSTRUCTION_FILE_SUFFIX: &str = ".instruction";

/// Content metadata for an S3EC-encrypted object.
///
/// Fields hold the already-encoded (base64 / JSON string) values exactly as
/// they are persisted in the S3 object-metadata map. Only the fields relevant
/// to a given format version are populated.
///
/// Scope exceptions: this client writes only the V2 and V3 formats (never V1)
/// and never the legacy AES-CBC content cipher, does not persist the plaintext
/// object length, and treats all metadata strings as US-ASCII. The MAY/SHOULD
/// requirements for those unimplemented behaviors are recorded below.
//= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
//= type=exception
//= reason=This client never writes the V1 format, so it does not emit x-amz-matdesc for V1 objects.
//# - The mapkey "x-amz-matdesc" MUST be present for V1 format objects.
//
//= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
//= type=exception
//= reason=The plaintext object length is not stored by this client.
//# - The mapkey "x-amz-unencrypted-content-length" SHOULD be present for V1 format objects.
//
//= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
//= type=exception
//= reason=The plaintext object length is not stored by this client.
//# - The mapkey "x-amz-unencrypted-content-length" SHOULD be present for V2 format objects.
//
//= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
//= type=exception
//= reason=This client never writes the legacy AES-CBC content cipher, so the CBC tag-len-absent rule has no write path.
//# - If the object is encrypted using AES-CBC for content encryption, then the the mapkey "x-amz-tag-len" MUST NOT be present.
//
//= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
//= type=exception
//= reason=Raw-keyring V3 objects use an empty Material Description, so x-amz-m is omitted (a reader defaults it to {}).
//# - The mapkey "x-amz-m" SHOULD be present for V3 format objects that use Raw Keyring Material Description.
//
//= ../spec/s3-encryption/data-format/content-metadata.md#us-ascii-preferred-string
//= type=exception
//= reason=This client emits US-ASCII mapkeys only; UTF-8 support is deferred (tracked separately).
//# An implementation MAY support UTF-8.
//
//= ../spec/s3-encryption/data-format/content-metadata.md#us-ascii-preferred-string
//= type=exception
//= reason=UTF-8 support is deferred; the client constructs ASCII metadata and does not scan input for non-ASCII.
//# If an implementation does NOT support UTF-8,
//# then the implementation SHOULD throw an error if non-US-ASCII characters are encountered;
//# the error SHOULD detail that the implementation does not support non-US-ASCII characters but encountered non-US-ASCII characters.
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

    /// Split the content metadata for an instruction-file write into
    /// `(object_metadata, instruction_file_metadata)`.
    ///
    /// The object metadata portion is stored on the encrypted S3 object; the
    /// instruction file portion is serialized to JSON and stored in the
    /// sidecar `.instruction` object.
    pub fn split_for_instruction_file(&self) -> (BTreeMap<String, String>, BTreeMap<String, String>) {
        let mut object_metadata = BTreeMap::new();
        let mut instruction_file = BTreeMap::new();

        if self.encrypted_data_key_v3.is_some() {
            // V3: the content-related metadata stays in the object metadata,
            // and only the encrypted-data-key-related metadata is written to
            // the instruction file (so the data key can be re-encrypted in
            // place without rewriting the object).
            let mut put_obj = |k: &str, v: &Option<String>| {
                if let Some(value) = v {
                    object_metadata.insert(k.to_string(), value.clone());
                }
            };
            //= ../spec/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
            //# - The V3 message format MUST store the mapkey "x-amz-c" and its value in the Object Metadata when writing with an Instruction File.
            //
            //= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //= reason=x-amz-c, x-amz-d, x-amz-i go only into object_metadata here; they are never added to the instruction_file map.
            //# In the V3 format, the mapkeys "x-amz-c", "x-amz-d", and "x-amz-i" MUST be stored exclusively in the Object Metadata.
            put_obj(CONTENT_CIPHER_V3, &self.content_cipher_v3);
            //= ../spec/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
            //# - The V3 message format MUST store the mapkey "x-amz-d" and its value in the Object Metadata when writing with an Instruction File.
            put_obj(KEY_COMMITMENT_V3, &self.key_commitment_v3);
            //= ../spec/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
            //# - The V3 message format MUST store the mapkey "x-amz-i" and its value in the Object Metadata when writing with an Instruction File.
            put_obj(MESSAGE_ID_V3, &self.message_id_v3);

            let mut put_inst = |k: &str, v: &Option<String>| {
                if let Some(value) = v {
                    instruction_file.insert(k.to_string(), value.clone());
                }
            };
            //= ../spec/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
            //# - The V3 message format MUST store the mapkey "x-amz-3" and its value in the Instruction File.
            put_inst(ENCRYPTED_DATA_KEY_V3, &self.encrypted_data_key_v3);
            //= ../spec/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
            //# - The V3 message format MUST store the mapkey "x-amz-w" and its value in the Instruction File.
            put_inst(WRAP_ALGORITHM_V3, &self.wrap_algorithm_v3);
            //= ../spec/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
            //# - The V3 message format MUST store the mapkey "x-amz-m" and its value (when present in the content metadata) in the Instruction File.
            put_inst(MAT_DESC_V3, &self.mat_desc_v3);
            //= ../spec/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
            //# - The V3 message format MUST store the mapkey "x-amz-t" and its value (when present in the content metadata) in the Instruction File.
            put_inst(ENCRYPTION_CONTEXT_V3, &self.encryption_context_v3);
        } else {
            //= ../spec/s3-encryption/data-format/metadata-strategy.md#v1-v2-instruction-files
            //# In the V1/V2 message format, all of the content metadata MUST be stored in the Instruction File.
            instruction_file = self.to_map();
        }

        (object_metadata, instruction_file)
    }

    //= ../spec/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
    //# - If the metadata contains "x-amz-iv" and "x-amz-key" but no other version exclusive keys then the object MUST be considered as an S3EC-encrypted object using the V1 format.
    /// Whether the metadata is in the V1 format.
    pub fn is_v1_format(&self) -> bool {
        //= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //# - The mapkey "x-amz-iv" MUST be present for V1 format objects.
        self.content_iv.is_some()
            //= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //# - The mapkey "x-amz-key" MUST be present for V1 format objects.
            && self.encrypted_data_key_v1.is_some()
            //= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //= reason=A V2/V3 data-key mapkey present alongside the V1 key makes is_v1_format() false, so the caller rejects rather than treating it as V1.
            //# - If mapkeys exclusive to other (non-V1) format versions is present,the S3EC SHOULD throw an exception.
            && self.encrypted_data_key_v2.is_none()
            && self.encrypted_data_key_v3.is_none()
    }

    //= ../spec/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
    //# - If the metadata contains "x-amz-iv" and "x-amz-key-v2" but no other version exclusive keys then the object MUST be considered as an S3EC-encrypted object using the V2 format.
    /// Whether the metadata is in the V2 format.
    pub fn is_v2_format(&self) -> bool {
        self.content_iv.is_some()
            && self.encrypted_data_key_v2.is_some()
            //= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //= reason=A V1/V3 data-key mapkey present alongside the V2 key makes is_v2_format() false, so the caller rejects rather than treating it as V2.
            //# - If a mapkey exclusive to other (non-V2) format versions is present, the S3EC SHOULD throw an exception.
            && self.encrypted_data_key_v1.is_none()
            && self.encrypted_data_key_v3.is_none()
    }

    //= ../spec/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
    //# - If the metadata contains "x-amz-3" and "x-amz-d" and "x-amz-i" but no other version exclusive keys then the object MUST be considered an S3EC-encrypted object using the V3 format.
    /// Whether the metadata is in the V3 format.
    pub fn is_v3_format(&self) -> bool {
        self.encrypted_data_key_v3.is_some()
            && self.key_commitment_v3.is_some()
            && self.message_id_v3.is_some()
            //= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //= reason=A V1/V2 data-key mapkey present alongside the V3 keys makes is_v3_format() false, so the caller rejects rather than treating it as V3.
            //# - If a mapkey exclusive to other (non-V3) format versions is present, the S3EC SHOULD throw an exception.
            && self.encrypted_data_key_v1.is_none()
            && self.encrypted_data_key_v2.is_none()
    }

    //= ../spec/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
    //= reason=When no version predicate matches, the caller falls back to fetching the instruction file (see client.rs GetObject path).
    //# If the object matches none of the V1/V2/V3 formats, the S3EC MUST attempt to get the instruction file.
    /// Whether the object metadata matches none of the known V1/V2/V3 formats.
    ///
    /// When this is true, the GetObject path falls back to fetching the
    /// instruction file before failing.
    pub fn matches_no_known_format(&self) -> bool {
        !self.is_v1_format() && !self.is_v2_format() && !self.is_v3_format()
    }

    //= ../spec/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
    //# If there are multiple mapkeys which are meant to be exclusive to different versions, such as "x-amz-key", "x-amz-key-v2", and "x-amz-3" then the S3EC SHOULD throw an exception.
    //
    //= ../spec/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
    //= reason=Carrying data-key mapkeys from more than one version is the deviation case; the caller rejects when this returns true.
    //# In general, if there is any deviation from the above format, with the exception of additional unrelated mapkeys, then the S3EC SHOULD throw an exception.
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
            //= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //# - The mapkey "x-amz-key-v2" MUST be present for V2 format objects.
            encrypted_data_key_v2: Some(BASE64.encode(encrypted_data_key)),
            //= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //# - The mapkey "x-amz-wrap-alg" MUST be present for V2 format objects.
            wrap_algorithm: Some(WRAP_ALG_KMS_CONTEXT.to_string()),
            //= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //# - The mapkey "x-amz-matdesc" MUST be present for V2 format objects.
            materials_description: Some(encode_context(encryption_context)?),
            //= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //# - The mapkey "x-amz-iv" MUST be present for V2 format objects.
            content_iv: Some(BASE64.encode(content_iv)),
            //= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //# - The mapkey "x-amz-cek-alg" MUST be present for V2 format objects.
            //
            //= ../spec/s3-encryption/data-format/content-metadata.md#algorithm-suite-and-message-format-version-compatibility
            //= reason=for_v2 is only built for the GCM_IV12 suite, whose content cipher is written here, persisting it as V2.
            //# Objects encrypted with ALG_AES_256_GCM_IV12_TAG16_NO_KDF MUST use the V2 message format version only.
            content_cipher: Some(
                EncryptionAlgorithm::AlgAes256GcmIv12Tag16NoKdf.content_cipher_value(),
            ),
            //= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //# - The mapkey "x-amz-tag-len" MAY be present for V2 format objects.
            //
            //= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //# - If the object is encrypted using AES-GCM for content encryption, then the the mapkey "x-amz-tag-len" MUST be present.
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
            //= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //# - The mapkey "x-amz-c" MUST be present for V3 format objects.
            //
            //= ../spec/s3-encryption/data-format/content-metadata.md#algorithm-suite-and-message-format-version-compatibility
            //= reason=for_v3 is built for the committing suite, whose content cipher is written here, persisting it as V3.
            //# Objects encrypted with ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY MUST use the V3 message format version only.
            content_cipher_v3: Some(suite.content_cipher_value()),
            //= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //# - The mapkey "x-amz-3" MUST be present for V3 format objects.
            encrypted_data_key_v3: Some(BASE64.encode(encrypted_data_key)),
            // "12" is the V3 compressed code for the kms+context wrapping algorithm.
            //= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //# - The mapkey "x-amz-w" MUST be present for V3 format objects.
            //
            //= ../spec/s3-encryption/data-format/content-metadata.md#v3-only
            //# - The wrapping algorithm value "12" MUST be translated to kms+context upon retrieval, and vice versa on write.
            wrap_algorithm_v3: Some(v3_wrap_algorithm_to_code(WRAP_ALG_KMS_CONTEXT)?.to_string()),
            //= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //# - The mapkey "x-amz-i" MUST be present for V3 format objects.
            message_id_v3: Some(BASE64.encode(message_id)),
            //= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //# - The mapkey "x-amz-d" MUST be present for V3 format objects.
            key_commitment_v3: Some(BASE64.encode(key_commitment)),
            //= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //# - The mapkey "x-amz-t" SHOULD be present for V3 format objects that use KMS Encryption Context.
            //
            //= ../spec/s3-encryption/data-format/content-metadata.md#v3-only
            //= reason=for_v3 wraps with kms+context, so the KMS Encryption Context is stored in x-amz-t.
            //# The Encryption Context value MUST be used for wrapping algorithm `kms+context` or `12`.
            encryption_context_v3: Some(encode_context(encryption_context)?),
            ..Default::default()
        })
    }

    /// Build V3 raw-AES key-committing content metadata. Differs from
    /// [`Self::for_v3`] only in the data-key wrapping: the wrapping algorithm
    /// is `AES/GCM` (V3 code "02") and no AWS KMS encryption context (`x-amz-t`)
    /// is stored, since raw keyrings do not persist an encryption context. The
    /// material description (`x-amz-m`) is omitted, which a reader defaults to
    /// the empty map.
    pub fn for_v3_raw_aes(
        suite: EncryptionAlgorithm,
        encrypted_data_key: &[u8],
        message_id: &[u8],
        key_commitment: &[u8],
    ) -> Result<Self> {
        Ok(Self {
            content_cipher_v3: Some(suite.content_cipher_value()),
            encrypted_data_key_v3: Some(BASE64.encode(encrypted_data_key)),
            //= ../spec/s3-encryption/data-format/content-metadata.md#v3-only
            //# - The wrapping algorithm value "02" MUST be translated to AES/GCM upon retrieval, and vice versa on write.
            wrap_algorithm_v3: Some(v3_wrap_algorithm_to_code(WRAP_ALG_AES_GCM)?.to_string()),
            message_id_v3: Some(BASE64.encode(message_id)),
            key_commitment_v3: Some(BASE64.encode(key_commitment)),
            ..Default::default()
        })
    }

    /// Build V2 raw-AES non-committing AES-GCM content metadata. The wrapping
    /// algorithm is `AES/GCM`; no encryption context is stored (the material
    /// description defaults to the empty map).
    pub fn for_v2_raw_aes(encrypted_data_key: &[u8], content_iv: &[u8]) -> Result<Self> {
        Ok(Self {
            encrypted_data_key_v2: Some(BASE64.encode(encrypted_data_key)),
            wrap_algorithm: Some(WRAP_ALG_AES_GCM.to_string()),
            materials_description: Some("{}".to_string()),
            content_iv: Some(BASE64.encode(content_iv)),
            content_cipher: Some(
                EncryptionAlgorithm::AlgAes256GcmIv12Tag16NoKdf.content_cipher_value(),
            ),
            tag_length: Some("128".to_string()),
            ..Default::default()
        })
    }

    /// Build V3 raw-RSA key-committing content metadata. Differs from
    /// [`Self::for_v3`] only in the data-key wrapping: the wrapping algorithm
    /// is `RSA-OAEP-SHA1` (V3 code "22") and no AWS KMS encryption context
    /// (`x-amz-t`) is stored, since raw keyrings do not persist one. The
    /// material description (`x-amz-m`) is omitted, which a reader defaults to
    /// the empty map.
    pub fn for_v3_raw_rsa(
        suite: EncryptionAlgorithm,
        encrypted_data_key: &[u8],
        message_id: &[u8],
        key_commitment: &[u8],
    ) -> Result<Self> {
        Ok(Self {
            content_cipher_v3: Some(suite.content_cipher_value()),
            encrypted_data_key_v3: Some(BASE64.encode(encrypted_data_key)),
            //= ../spec/s3-encryption/data-format/content-metadata.md#v3-only
            //# - The wrapping algorithm value "22" MUST be translated to RSA-OAEP-SHA1 upon retrieval, and vice versa on write.
            wrap_algorithm_v3: Some(v3_wrap_algorithm_to_code(WRAP_ALG_RSA_OAEP_SHA1)?.to_string()),
            message_id_v3: Some(BASE64.encode(message_id)),
            key_commitment_v3: Some(BASE64.encode(key_commitment)),
            ..Default::default()
        })
    }

    /// Build V2 raw-RSA non-committing AES-GCM content metadata. The wrapping
    /// algorithm is `RSA-OAEP-SHA1`; no encryption context is stored (the
    /// material description defaults to the empty map).
    pub fn for_v2_raw_rsa(encrypted_data_key: &[u8], content_iv: &[u8]) -> Result<Self> {
        Ok(Self {
            encrypted_data_key_v2: Some(BASE64.encode(encrypted_data_key)),
            wrap_algorithm: Some(WRAP_ALG_RSA_OAEP_SHA1.to_string()),
            materials_description: Some("{}".to_string()),
            content_iv: Some(BASE64.encode(content_iv)),
            content_cipher: Some(
                EncryptionAlgorithm::AlgAes256GcmIv12Tag16NoKdf.content_cipher_value(),
            ),
            tag_length: Some("128".to_string()),
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

    /// The content-encryption algorithm of a V1/V2 object, read from the
    /// `x-amz-cek-alg` content-cipher mapkey.
    ///
    /// The V2 metadata format is shared by both the non-committing AES-GCM
    /// suite and the legacy AES-CBC suite; the content cipher distinguishes
    /// them.
    pub fn v2_content_algorithm(&self) -> Result<EncryptionAlgorithm> {
        match self.content_cipher.as_deref() {
            Some(CONTENT_CIPHER_GCM) => Ok(EncryptionAlgorithm::AlgAes256GcmIv12Tag16NoKdf),
            //= ../spec/s3-encryption/data-format/content-metadata.md#algorithm-suite-and-message-format-version-compatibility
            //= reason=The CBC suite is resolved here from the V2 metadata format, the version this client persists CBC under.
            //# Objects encrypted with ALG_AES_256_CBC_IV16_NO_KDF MAY use either the V1 or V2 message format version.
            Some(CONTENT_CIPHER_CBC) => Ok(EncryptionAlgorithm::AlgAes256CbcIv16NoKdf),
            Some(other) => Err(S3EncryptionError::Format(format!(
                "unknown content encryption algorithm: {other}"
            ))),
            None => Err(S3EncryptionError::Format(
                "V2 format object missing required x-amz-cek-alg metadata".to_string(),
            )),
        }
    }

    /// The decoded V3 encrypted data key (`x-amz-3`).
    pub fn v3_encrypted_data_key(&self) -> Result<Vec<u8>> {
        Self::decode_b64(ENCRYPTED_DATA_KEY_V3, &self.encrypted_data_key_v3)
    }

    /// The decoded V3 message ID (`x-amz-i`).
    pub fn v3_message_id(&self) -> Result<Vec<u8>> {
        Self::decode_b64(MESSAGE_ID_V3, &self.message_id_v3)
    }

    /// The content-encryption algorithm of a V3 object, read from the
    /// `x-amz-c` content-cipher mapkey.
    ///
    /// The only valid V3 content-cipher value is the integer suite ID `115`,
    /// which denotes `ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY`. The stored value
    /// is bound into the key-commitment/derivation inputs and the GCM AAD, so a
    /// reader MUST resolve the suite from it (rather than assuming one) and
    /// reject any other value; otherwise a tampered `x-amz-c` would be ignored
    /// and the object would still decrypt.
    pub fn v3_content_algorithm(&self) -> Result<EncryptionAlgorithm> {
        let committing = EncryptionAlgorithm::AlgAes256GcmHkdfSha512CommitKey;
        //= ../spec/s3-encryption/data-format/content-metadata.md#v2-v3-shared
        //# - AES/GCM/NoPadding
        //# - AES/CBC/PKCS5Padding
        //# - 115
        match self.content_cipher_v3.as_deref() {
            Some(v) if v == committing.content_cipher_value() => Ok(committing),
            Some(other) => Err(S3EncryptionError::Format(format!(
                "unknown content encryption algorithm: {other}"
            ))),
            None => Err(S3EncryptionError::Format(
                "V3 format object missing required x-amz-c metadata".to_string(),
            )),
        }
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
        //= ../spec/s3-encryption/data-format/content-metadata.md#v3-only
        //= reason=parse_context maps a missing x-amz-t to an empty BTreeMap.
        //# If the mapkey x-amz-t is not present, the default Material Description value MUST be set to an empty map (`{}`).
        parse_context(self.encryption_context_v3.as_deref())
    }

    /// The stored Material Description for a V3 object, parsed from the JSON
    /// `x-amz-m` field. Used for raw (AES/GCM, RSA-OAEP-SHA1) wrapping
    /// algorithms; a missing field yields the empty map.
    pub fn v3_material_description(&self) -> Result<BTreeMap<String, String>> {
        //= ../spec/s3-encryption/data-format/content-metadata.md#v3-only
        //= reason=x-amz-m carries the Material Description consumed by the raw AES/GCM and RSA-OAEP-SHA1 wrapping paths.
        //# The Material Description MUST be used for wrapping algorithms `AES/GCM` (`02`) and `RSA-OAEP-SHA1` (`22`).
        //
        //= ../spec/s3-encryption/data-format/content-metadata.md#v3-only
        //= reason=parse_context maps a missing x-amz-m to an empty BTreeMap.
        //# If the mapkey x-amz-m is not present, the default Material Description value MUST be set to an empty map (`{}`).
        parse_context(self.mat_desc_v3.as_deref())
    }
}

/// Serialize an encryption context to the JSON form stored in object metadata.
fn encode_context(context: &BTreeMap<String, String>) -> Result<String> {
    serde_json::to_string(context)
        .map_err(|e| S3EncryptionError::Format(format!("failed to encode encryption context: {e}")))
}

/// Parse the JSON encryption-context string stored in object metadata. A
/// missing field yields an empty context.
///
/// The S3 web server's "double encoding" scheme is not applied or decoded:
/// this client stores and reads the JSON string verbatim.
//= ../spec/s3-encryption/data-format/content-metadata.md#v1-v2-shared
//= type=exception
//= reason=The matdesc JSON is stored/read verbatim; S3 double-encoding is not applied (tracked separately).
//# This string MAY be encoded by the esoteric double-encoding scheme used by the S3 web server.
//
//= ../spec/s3-encryption/data-format/content-metadata.md#v3-only
//= type=exception
//= reason=The x-amz-m JSON is stored/read verbatim; S3 double-encoding is not applied.
//# This material description string MAY be encoded by the esoteric double-encoding scheme used by the S3 web server.
//
//= ../spec/s3-encryption/data-format/content-metadata.md#v3-only
//= type=exception
//= reason=The x-amz-t JSON is stored/read verbatim; S3 double-encoding is not applied.
//# This encryption context string MAY be encoded by the esoteric double-encoding scheme used by the S3 web server.
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
        //= ../spec/s3-encryption/data-format/content-metadata.md#v3-only
        //# - The wrapping algorithm value "02" MUST be translated to AES/GCM upon retrieval, and vice versa on write.
        "02" => Ok("AES/GCM"),
        //= ../spec/s3-encryption/data-format/content-metadata.md#v3-only
        //# - The wrapping algorithm value "12" MUST be translated to kms+context upon retrieval, and vice versa on write.
        "12" => Ok("kms+context"),
        //= ../spec/s3-encryption/data-format/content-metadata.md#v3-only
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


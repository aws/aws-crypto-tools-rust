// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for S3 object content metadata serialization, format detection, and
//! V3 wrapping-algorithm translation.
//!
//! Covers `spec/s3-encryption/data-format/content-metadata.md`.

use std::collections::BTreeMap;

use aws_s3_encryption::config::EncryptionAlgorithm;
use aws_s3_encryption::error::S3EncryptionError;
use aws_s3_encryption::metadata::{
    self, v3_wrap_algorithm_to_code, v3_wrap_algorithm_to_name, ObjectMetadata, CONTENT_CIPHER,
    CONTENT_CIPHER_CBC, CONTENT_CIPHER_V3, CONTENT_IV, ENCRYPTED_DATA_KEY_V2, ENCRYPTED_DATA_KEY_V3,
    ENCRYPTION_CONTEXT_V3, KEY_COMMITMENT_V3, MAT_DESC_V3, MATERIALS_DESCRIPTION, MESSAGE_ID_V3,
    TAG_LENGTH, WRAP_ALGORITHM, WRAP_ALGORITHM_V3,
};

// A representative V2 (non-committing AES-GCM) metadata fixture.
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

// A representative V3 (key-committing AES-GCM, kms+context) metadata fixture.
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

fn ctx() -> BTreeMap<String, String> {
    [
        ("user".to_string(), "alice".to_string()),
        ("aws:x-amz-cek-alg".to_string(), "115".to_string()),
    ]
    .into_iter()
    .collect()
}

// The sole valid V3 content cipher ("115") resolves to the committing suite.
#[test]
fn v3_content_algorithm_accepts_committing_suite() {
    let md = v3_metadata();
    //= ../spec/s3-encryption/data-format/content-metadata.md#v2-v3-shared
    //= type=test
    //# - AES/GCM/NoPadding
    //# - AES/CBC/PKCS5Padding
    //# - 115
    assert_eq!(
        md.v3_content_algorithm().unwrap(),
        EncryptionAlgorithm::AlgAes256GcmHkdfSha512CommitKey
    );
}

// A mutated `x-amz-c` must be rejected, not silently ignored.
#[test]
fn v3_content_algorithm_rejects_mutated_content_cipher() {
    let mut md = v3_metadata();
    md.content_cipher_v3 = Some("not-115".to_string());
    let err = md.v3_content_algorithm().unwrap_err();
    assert!(matches!(err, S3EncryptionError::Format(_)));
}

// A missing `x-amz-c` is a format error.
#[test]
fn v3_content_algorithm_rejects_missing_content_cipher() {
    let mut md = v3_metadata();
    md.content_cipher_v3 = None;
    let err = md.v3_content_algorithm().unwrap_err();
    assert!(matches!(err, S3EncryptionError::Format(_)));
}

// The two valid V1/V2 content ciphers resolve to their suites; CBC reuses the
// V2 metadata format. Unknown/missing ciphers are format errors.
#[test]
fn v2_content_algorithm_detects_cipher() {
    let mut md = v2_metadata();
    assert_eq!(
        md.v2_content_algorithm().unwrap(),
        EncryptionAlgorithm::AlgAes256GcmIv12Tag16NoKdf
    );

    md.content_cipher = Some(CONTENT_CIPHER_CBC.to_string());
    //= ../spec/s3-encryption/data-format/content-metadata.md#algorithm-suite-and-message-format-version-compatibility
    //= type=test
    //# Objects encrypted with ALG_AES_256_CBC_IV16_NO_KDF MAY use either the V1 or V2 message format version.
    assert_eq!(
        md.v2_content_algorithm().unwrap(),
        EncryptionAlgorithm::AlgAes256CbcIv16NoKdf
    );

    md.content_cipher = Some("AES/XTS/NoPadding".to_string());
    assert!(md.v2_content_algorithm().is_err());
    md.content_cipher = None;
    assert!(md.v2_content_algorithm().is_err());
}

// V2 metadata round-trips through the S3 object-metadata map, carrying the
// required V2 mapkeys and no V3-only keys.
#[test]
fn v2_round_trips_through_map() {
    let md = v2_metadata();
    let map = md.to_map();

    //= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
    //= type=test
    //# - The mapkey "x-amz-key-v2" MUST be present for V2 format objects.
    assert_eq!(map.get(ENCRYPTED_DATA_KEY_V2).unwrap(), "ZWRrYnl0ZXM=");
    //= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
    //= type=test
    //# - The mapkey "x-amz-matdesc" MUST be present for V2 format objects.
    assert_eq!(map.get(MATERIALS_DESCRIPTION).unwrap(), "{}");
    //= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
    //= type=test
    //# - The mapkey "x-amz-wrap-alg" MUST be present for V2 format objects.
    assert_eq!(map.get(WRAP_ALGORITHM).unwrap(), "kms+context");
    //= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
    //= type=test
    //# - The mapkey "x-amz-iv" MUST be present for V2 format objects.
    assert_eq!(map.get(CONTENT_IV).unwrap(), "aXZieXRlcw==");
    //= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
    //= type=test
    //# - The mapkey "x-amz-cek-alg" MUST be present for V2 format objects.
    assert_eq!(map.get(CONTENT_CIPHER).unwrap(), "AES/GCM/NoPadding");
    //= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
    //= type=test
    //# - The mapkey "x-amz-tag-len" MAY be present for V2 format objects.
    //
    //= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
    //= type=test
    //# - If the object is encrypted using AES-GCM for content encryption, then the the mapkey "x-amz-tag-len" MUST be present.
    assert_eq!(map.get(TAG_LENGTH).unwrap(), "128");

    assert!(!map.contains_key(CONTENT_CIPHER_V3));
    assert_eq!(ObjectMetadata::from_map(&map), md);
}

// V3 metadata round-trips through the S3 object-metadata map, carrying the
// required V3 mapkeys and no V1/V2 keys.
#[test]
fn v3_round_trips_through_map() {
    let md = v3_metadata();
    let map = md.to_map();

    //= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
    //= type=test
    //# - The mapkey "x-amz-3" MUST be present for V3 format objects.
    assert_eq!(map.get(ENCRYPTED_DATA_KEY_V3).unwrap(), "ZWRrYnl0ZXM=");
    //= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
    //= type=test
    //# - The mapkey "x-amz-c" MUST be present for V3 format objects.
    assert_eq!(map.get(CONTENT_CIPHER_V3).unwrap(), "115");
    //= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
    //= type=test
    //# - The mapkey "x-amz-w" MUST be present for V3 format objects.
    assert_eq!(map.get(WRAP_ALGORITHM_V3).unwrap(), "12");
    //= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
    //= type=test
    //# - The mapkey "x-amz-t" SHOULD be present for V3 format objects that use KMS Encryption Context.
    assert_eq!(map.get(ENCRYPTION_CONTEXT_V3).unwrap(), "{}");
    //= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
    //= type=test
    //# - The mapkey "x-amz-d" MUST be present for V3 format objects.
    assert_eq!(map.get(KEY_COMMITMENT_V3).unwrap(), "Y29tbWl0");
    //= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
    //= type=test
    //# - The mapkey "x-amz-i" MUST be present for V3 format objects.
    assert_eq!(map.get(MESSAGE_ID_V3).unwrap(), "bXNnaWQ=");

    assert!(!map.contains_key(ENCRYPTED_DATA_KEY_V2));
    assert!(!map.contains_key(TAG_LENGTH));
    assert_eq!(ObjectMetadata::from_map(&map), md);
}

// The mapkey constants carry the `x-amz-` prefix and never embed the
// server-managed `x-amz-meta-` prefix, and are pure US-ASCII.
#[test]
fn mapkey_constants_use_x_amz_prefix_only() {
    let keys = [
        ENCRYPTED_DATA_KEY_V2,
        WRAP_ALGORITHM,
        MATERIALS_DESCRIPTION,
        CONTENT_CIPHER,
        TAG_LENGTH,
        CONTENT_CIPHER_V3,
        ENCRYPTED_DATA_KEY_V3,
        MAT_DESC_V3,
        ENCRYPTION_CONTEXT_V3,
        WRAP_ALGORITHM_V3,
        KEY_COMMITMENT_V3,
        MESSAGE_ID_V3,
    ];
    for k in keys {
        //= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=test
        //# The "x-amz-" prefix denotes that the metadata is owned by an Amazon product and MUST be prepended to all S3EC metadata mapkeys.
        assert!(k.starts_with("x-amz-"), "{k} missing x-amz- prefix");
        //= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=test
        //# The "x-amz-meta-" prefix is automatically added by the S3 server and MUST NOT be included in implementation code.
        assert!(!k.starts_with("x-amz-meta-"), "{k} embeds x-amz-meta-");
        //= ../spec/s3-encryption/data-format/content-metadata.md#us-ascii-preferred-string
        //= type=test
        //# Thus,
        //# Content Metadata MapKeys SHOULD be restricted to US-ASCII.
        assert!(k.is_ascii(), "{k} is not US-ASCII");
    }
}

// The V3 SHOULD-named constants exist with the spec-recommended values.
#[test]
fn v3_constant_names_match_spec() {
    //= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
    //= type=test
    //# - This mapkey ("x-amz-c") SHOULD be represented by a constant named "CONTENT_CIPHER_V3" or similar in the implementation code.
    assert_eq!(CONTENT_CIPHER_V3, "x-amz-c");
    //= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
    //= type=test
    //# - This mapkey ("x-amz-3") SHOULD be represented by a constant named "ENCRYPTED_DATA_KEY_V3" or similar in the implementation code.
    assert_eq!(ENCRYPTED_DATA_KEY_V3, "x-amz-3");
    //= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
    //= type=test
    //# - This mapkey ("x-amz-m") SHOULD be represented by a constant named "MAT_DESC_V3" or similar in the implementation code.
    assert_eq!(MAT_DESC_V3, "x-amz-m");
    //= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
    //= type=test
    //# - This mapkey ("x-amz-t") SHOULD be represented by a constant named "ENCRYPTION_CONTEXT_V3" or similar in the implementation code.
    assert_eq!(ENCRYPTION_CONTEXT_V3, "x-amz-t");
    //= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
    //= type=test
    //# - This mapkey ("x-amz-w") SHOULD be represented by a constant named "ENCRYPTED_DATA_KEY_ALGORITHM_V3" or similar in the implementation code.
    assert_eq!(WRAP_ALGORITHM_V3, "x-amz-w");
    //= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
    //= type=test
    //# - This mapkey ("x-amz-d") SHOULD be represented by a constant named "KEY_COMMITMENT_V3" or similar in the implementation code.
    assert_eq!(KEY_COMMITMENT_V3, "x-amz-d");
    //= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
    //= type=test
    //# - This mapkey ("x-amz-i") SHOULD be represented by a constant named "MESSAGE_ID_V3" or similar in the implementation code.
    assert_eq!(MESSAGE_ID_V3, "x-amz-i");
}

// Format detection is mutually exclusive across V1, V2, and V3, keyed on the
// version-exclusive data-key mapkeys.
#[test]
fn format_detection_is_exclusive() {
    // V1 fixture: x-amz-iv + x-amz-key, no other version's key.
    let v1 = ObjectMetadata {
        encrypted_data_key_v1: Some("djFrZXk=".to_string()),
        content_iv: Some("aXZieXRlcw==".to_string()),
        ..Default::default()
    };
    //= ../spec/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
    //= type=test
    //# - If the metadata contains "x-amz-iv" and "x-amz-key" but no other version exclusive keys then the object MUST be considered as an S3EC-encrypted object using the V1 format.
    assert!(v1.is_v1_format());
    assert!(!v1.is_v2_format());
    assert!(!v1.is_v3_format());

    let v2 = v2_metadata();
    //= ../spec/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
    //= type=test
    //# - If the metadata contains "x-amz-iv" and "x-amz-key-v2" but no other version exclusive keys then the object MUST be considered as an S3EC-encrypted object using the V2 format.
    assert!(v2.is_v2_format());
    assert!(!v2.is_v1_format());
    assert!(!v2.is_v3_format());

    let v3 = v3_metadata();
    //= ../spec/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
    //= type=test
    //# - If the metadata contains "x-amz-3" and "x-amz-d" and "x-amz-i" but no other version exclusive keys then the object MUST be considered an S3EC-encrypted object using the V3 format.
    assert!(v3.is_v3_format());
    assert!(!v3.is_v1_format());
    assert!(!v3.is_v2_format());
}

// A V1 fixture must require both x-amz-iv AND x-amz-key, and reject any other
// version's exclusive key.
#[test]
fn v1_detection_requires_iv_and_key_and_rejects_other_versions() {
    // Missing x-amz-key is not V1.
    let no_key = ObjectMetadata {
        content_iv: Some("aXZieXRlcw==".to_string()),
        ..Default::default()
    };
    //= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
    //= type=test
    //# - The mapkey "x-amz-key" MUST be present for V1 format objects.
    assert!(!no_key.is_v1_format());

    // Missing x-amz-iv is not V1.
    let no_iv = ObjectMetadata {
        encrypted_data_key_v1: Some("djFrZXk=".to_string()),
        ..Default::default()
    };
    //= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
    //= type=test
    //# - The mapkey "x-amz-iv" MUST be present for V1 format objects.
    assert!(!no_iv.is_v1_format());

    // x-amz-key + x-amz-key-v2 together: not V1 (non-V1 exclusive key present).
    let mixed = ObjectMetadata {
        encrypted_data_key_v1: Some("djFrZXk=".to_string()),
        encrypted_data_key_v2: Some("djJrZXk=".to_string()),
        content_iv: Some("aXZieXRlcw==".to_string()),
        ..Default::default()
    };
    //= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
    //= type=test
    //# - If mapkeys exclusive to other (non-V1) format versions is present,the S3EC SHOULD throw an exception.
    assert!(!mixed.is_v1_format());
}

// A non-V2 exclusive key alongside the V2 key disqualifies V2 detection.
#[test]
fn v2_detection_rejects_other_version_keys() {
    let mut md = v2_metadata();
    md.encrypted_data_key_v3 = Some("djNrZXk=".to_string());
    //= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
    //= type=test
    //# - If a mapkey exclusive to other (non-V2) format versions is present, the S3EC SHOULD throw an exception.
    assert!(!md.is_v2_format());
}

// A non-V3 exclusive key alongside the V3 keys disqualifies V3 detection.
#[test]
fn v3_detection_rejects_other_version_keys() {
    let mut md = v3_metadata();
    md.encrypted_data_key_v1 = Some("djFrZXk=".to_string());
    //= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
    //= type=test
    //# - If a mapkey exclusive to other (non-V3) format versions is present, the S3EC SHOULD throw an exception.
    assert!(!md.is_v3_format());
}

// Metadata that carries data-key mapkeys from multiple exclusive versions is
// flagged as a collision (the deviation case), and matches no single format.
#[test]
fn exclusive_key_collision_detected() {
    let mut md = v2_metadata();
    assert!(!md.has_exclusive_key_collision());

    md.encrypted_data_key_v3 = Some("ZXh0cmE=".to_string());
    //= ../spec/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
    //= type=test
    //# If there are multiple mapkeys which are meant to be exclusive to different versions, such as "x-amz-key", "x-amz-key-v2", and "x-amz-3" then the S3EC SHOULD throw an exception.
    //
    //= ../spec/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
    //= type=test
    //# In general, if there is any deviation from the above format, with the exception of additional unrelated mapkeys, then the S3EC SHOULD throw an exception.
    assert!(md.has_exclusive_key_collision());
    assert!(!md.is_v2_format());
    assert!(!md.is_v3_format());
}

// Metadata that matches none of the known formats triggers the instruction-file
// fallback.
#[test]
fn unrecognized_metadata_matches_no_known_format() {
    let empty = ObjectMetadata::default();
    //= ../spec/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
    //= type=test
    //# If the object matches none of the V1/V2/V3 formats, the S3EC MUST attempt to get the instruction file.
    assert!(empty.matches_no_known_format());
    assert!(!v2_metadata().matches_no_known_format());
}

// for_v2 builds GCM-suite V2 metadata that decodes back to the inputs, and
// pins the GCM suite to the V2 message format.
#[test]
fn for_v2_builds_decodable_metadata() {
    let edk = b"encrypted-data-key";
    let iv = [0xABu8; 12];
    let md = ObjectMetadata::for_v2(edk, &iv, &ctx()).unwrap();

    assert!(md.is_v2_format());
    //= ../spec/s3-encryption/data-format/content-metadata.md#algorithm-suite-and-message-format-version-compatibility
    //= type=test
    //# Objects encrypted with ALG_AES_256_GCM_IV12_TAG16_NO_KDF MUST use the V2 message format version only.
    assert_eq!(md.content_cipher.as_deref(), Some("AES/GCM/NoPadding"));
    assert_eq!(md.wrap_algorithm.as_deref(), Some("kms+context"));
    assert_eq!(md.tag_length.as_deref(), Some("128"));

    let parsed = ObjectMetadata::from_map(&md.to_map());
    assert_eq!(parsed.v2_encrypted_data_key().unwrap(), edk);
    assert_eq!(parsed.content_iv_bytes().unwrap(), iv);
    assert_eq!(parsed.v2_stored_context().unwrap(), ctx());
}

// for_v3 builds committing-suite V3 metadata that decodes back to the inputs,
// pins the committing suite to V3, and stores the KMS encryption context in
// x-amz-t under the kms+context wrapping algorithm.
#[test]
fn for_v3_builds_decodable_metadata() {
    let suite = EncryptionAlgorithm::AlgAes256GcmHkdfSha512CommitKey;
    let edk = b"encrypted-data-key";
    let message_id = [0x11u8; 28];
    let commitment = [0x22u8; 28];
    let md = ObjectMetadata::for_v3(suite, edk, &message_id, &commitment, &ctx()).unwrap();

    assert!(md.is_v3_format());
    //= ../spec/s3-encryption/data-format/content-metadata.md#algorithm-suite-and-message-format-version-compatibility
    //= type=test
    //# Objects encrypted with ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY MUST use the V3 message format version only.
    assert_eq!(md.content_cipher_v3.as_deref(), Some("115"));
    //= ../spec/s3-encryption/data-format/content-metadata.md#v3-only
    //= type=test
    //# The Encryption Context value MUST be used for wrapping algorithm `kms+context` or `12`.
    assert_eq!(md.wrap_algorithm_v3.as_deref(), Some("12"));

    let parsed = ObjectMetadata::from_map(&md.to_map());
    assert_eq!(parsed.v3_encrypted_data_key().unwrap(), edk);
    assert_eq!(parsed.v3_message_id().unwrap(), message_id);
    assert_eq!(parsed.v3_key_commitment().unwrap(), commitment);
    assert_eq!(parsed.v3_stored_context().unwrap(), ctx());
}

// A V3 object with no x-amz-t defaults the stored encryption context to the
// empty map.
#[test]
fn v3_missing_encryption_context_defaults_to_empty() {
    let mut md = v3_metadata();
    md.encryption_context_v3 = None;
    //= ../spec/s3-encryption/data-format/content-metadata.md#v3-only
    //= type=test
    //# If the mapkey x-amz-t is not present, the default Material Description value MUST be set to an empty map (`{}`).
    assert_eq!(md.v3_stored_context().unwrap(), BTreeMap::new());
}

// for_v3_raw_aes wraps with the AES/GCM ("02") algorithm and stores the raw
// Material Description, defaulting the absent x-amz-m to the empty map.
#[test]
fn for_v3_raw_aes_uses_aes_gcm_wrap() {
    let suite = EncryptionAlgorithm::AlgAes256GcmHkdfSha512CommitKey;
    let edk = b"aes-wrapped-data-key";
    let message_id = [0x33u8; 28];
    let commitment = [0x44u8; 28];
    let md = ObjectMetadata::for_v3_raw_aes(suite, edk, &message_id, &commitment).unwrap();

    assert!(md.is_v3_format());
    //= ../spec/s3-encryption/data-format/content-metadata.md#v3-only
    //= type=test
    //= reason=Raw AES wraps the data key, and the writer emits the "02" code for AES/GCM.
    //# The Material Description MUST be used for wrapping algorithms `AES/GCM` (`02`) and `RSA-OAEP-SHA1` (`22`).
    assert_eq!(md.wrap_algorithm_v3.as_deref(), Some("02"));
    assert!(md.encryption_context_v3.is_none());
    assert!(md.mat_desc_v3.is_none());

    // Absent x-amz-m defaults the Material Description to the empty map.
    //= ../spec/s3-encryption/data-format/content-metadata.md#v3-only
    //= type=test
    //# If the mapkey x-amz-m is not present, the default Material Description value MUST be set to an empty map (`{}`).
    assert_eq!(md.v3_material_description().unwrap(), BTreeMap::new());

    let parsed = ObjectMetadata::from_map(&md.to_map());
    assert_eq!(parsed.v3_encrypted_data_key().unwrap(), edk);
}

// for_v3_raw_rsa wraps with the RSA-OAEP-SHA1 ("22") algorithm.
#[test]
fn for_v3_raw_rsa_uses_rsa_oaep_wrap() {
    let suite = EncryptionAlgorithm::AlgAes256GcmHkdfSha512CommitKey;
    let edk = b"rsa-wrapped-data-key";
    let message_id = [0x55u8; 28];
    let commitment = [0x66u8; 28];
    let md = ObjectMetadata::for_v3_raw_rsa(suite, edk, &message_id, &commitment).unwrap();

    assert!(md.is_v3_format());
    assert_eq!(md.wrap_algorithm_v3.as_deref(), Some("22"));
    assert!(md.encryption_context_v3.is_none());

    let parsed = ObjectMetadata::from_map(&md.to_map());
    assert_eq!(parsed.v3_encrypted_data_key().unwrap(), edk);
}

// The V3 compressed wrapping-algorithm codes translate to and from their
// canonical names, in both directions.
#[test]
fn v3_wrap_algorithm_02_translates_to_aes_gcm() {
    //= ../spec/s3-encryption/data-format/content-metadata.md#v3-only
    //= type=test
    //# - The wrapping algorithm value "02" MUST be translated to AES/GCM upon retrieval, and vice versa on write.
    assert_eq!(v3_wrap_algorithm_to_name("02").unwrap(), "AES/GCM");
    assert_eq!(v3_wrap_algorithm_to_code("AES/GCM").unwrap(), "02");
}

#[test]
fn v3_wrap_algorithm_12_translates_to_kms_context() {
    //= ../spec/s3-encryption/data-format/content-metadata.md#v3-only
    //= type=test
    //# - The wrapping algorithm value "12" MUST be translated to kms+context upon retrieval, and vice versa on write.
    assert_eq!(v3_wrap_algorithm_to_name("12").unwrap(), "kms+context");
    assert_eq!(v3_wrap_algorithm_to_code("kms+context").unwrap(), "12");
}

#[test]
fn v3_wrap_algorithm_22_translates_to_rsa_oaep() {
    //= ../spec/s3-encryption/data-format/content-metadata.md#v3-only
    //= type=test
    //# - The wrapping algorithm value "22" MUST be translated to RSA-OAEP-SHA1 upon retrieval, and vice versa on write.
    assert_eq!(v3_wrap_algorithm_to_name("22").unwrap(), "RSA-OAEP-SHA1");
    assert_eq!(v3_wrap_algorithm_to_code("RSA-OAEP-SHA1").unwrap(), "22");

    // Unknown codes/names are errors.
    assert!(v3_wrap_algorithm_to_name("99").is_err());
    assert!(v3_wrap_algorithm_to_code("AES/CBC").is_err());
}

// In the V3 format, x-amz-c, x-amz-d, and x-amz-i are stored exclusively in the
// object metadata; the instruction file never carries them.
#[test]
fn v3_split_keeps_c_d_i_in_object_metadata_only() {
    let md = v3_metadata();
    let (object_map, instruction_map) = md.split_for_instruction_file();

    //= ../spec/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
    //= type=test
    //# In the V3 format, the mapkeys "x-amz-c", "x-amz-d", and "x-amz-i" MUST be stored exclusively in the Object Metadata.
    for k in [CONTENT_CIPHER_V3, KEY_COMMITMENT_V3, MESSAGE_ID_V3] {
        assert!(object_map.contains_key(k), "{k} must be in object metadata");
        assert!(
            !instruction_map.contains_key(k),
            "{k} must not be in instruction file"
        );
    }
    // The encrypted data key still goes to the instruction file.
    assert!(instruction_map.contains_key(ENCRYPTED_DATA_KEY_V3));
}

// The default instruction-file suffix is the spec-defined ".instruction".
#[test]
fn default_instruction_file_suffix_is_dot_instruction() {
    assert_eq!(metadata::DEFAULT_INSTRUCTION_FILE_SUFFIX, ".instruction");
}

// The client neither applies nor decodes the S3 server's "double encoding":
// a stored material-description / encryption-context JSON value is returned
// verbatim. A value containing a literal "%41" (which a double-decoding pass
// would rewrite to "A") must survive untouched.
#[test]
fn stored_context_is_returned_untouched() {
    let md = ObjectMetadata {
        materials_description: Some(r#"{"k":"v%41"}"#.to_string()),
        ..Default::default()
    };
    let parsed = md.v2_stored_context().unwrap();
    //= ../spec/s3-encryption/data-format/metadata-strategy.md#object-metadata
    //= type=test
    //= reason=the "%41" value is returned as-is, not decoded to "A", proving no double-decoding transform is applied.
    //# If the S3EC does not support decoding the S3 Server's "double encoding" then it MUST return the content metadata untouched.
    assert_eq!(parsed.get("k").map(String::as_str), Some("v%41"));
}

// split_for_instruction_file routes each V3 mapkey to its spec-mandated
// location: the content-related keys (x-amz-c/d/i) stay in the Object
// Metadata, while the data-key-related keys (x-amz-3/w/m/t) go to the
// Instruction File. The fixture populates x-amz-m and x-amz-t so the
// "when present" keys are exercised.
#[test]
fn v3_split_routes_each_mapkey_to_its_location() {
    let md = ObjectMetadata {
        content_cipher_v3: Some("115".to_string()),
        encrypted_data_key_v3: Some("ZWRrYnl0ZXM=".to_string()),
        wrap_algorithm_v3: Some("02".to_string()),
        key_commitment_v3: Some("Y29tbWl0".to_string()),
        message_id_v3: Some("bXNnaWQ=".to_string()),
        mat_desc_v3: Some(r#"{"who":"alice"}"#.to_string()),
        encryption_context_v3: Some(r#"{"aws:x-amz-cek-alg":"115"}"#.to_string()),
        ..Default::default()
    };
    let (object_map, instruction_map) = md.split_for_instruction_file();

    // Content-related mapkeys: stored in the Object Metadata.

    //= ../spec/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
    //= type=test
    //# - The V3 message format MUST store the mapkey "x-amz-c" and its value in the Object Metadata when writing with an Instruction File.
    assert!(object_map.contains_key(CONTENT_CIPHER_V3));

    //= ../spec/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
    //= type=test
    //# - The V3 message format MUST store the mapkey "x-amz-d" and its value in the Object Metadata when writing with an Instruction File.
    assert!(object_map.contains_key(KEY_COMMITMENT_V3));

    //= ../spec/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
    //= type=test
    //# - The V3 message format MUST store the mapkey "x-amz-i" and its value in the Object Metadata when writing with an Instruction File.
    assert!(object_map.contains_key(MESSAGE_ID_V3));

    // Data-key-related mapkeys: stored in the Instruction File.

    //= ../spec/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
    //= type=test
    //# - The V3 message format MUST store the mapkey "x-amz-3" and its value in the Instruction File.
    assert!(instruction_map.contains_key(ENCRYPTED_DATA_KEY_V3));

    //= ../spec/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
    //= type=test
    //# - The V3 message format MUST store the mapkey "x-amz-w" and its value in the Instruction File.
    assert!(instruction_map.contains_key(WRAP_ALGORITHM_V3));

    //= ../spec/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
    //= type=test
    //# - The V3 message format MUST store the mapkey "x-amz-m" and its value (when present in the content metadata) in the Instruction File.
    assert!(instruction_map.contains_key(MAT_DESC_V3));

    //= ../spec/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
    //= type=test
    //# - The V3 message format MUST store the mapkey "x-amz-t" and its value (when present in the content metadata) in the Instruction File.
    assert!(instruction_map.contains_key(ENCRYPTION_CONTEXT_V3));
}

// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for spec/client-apis/decrypt.md#parse-the-header
//! and spec/client-apis/decrypt.md#behavior

#[allow(clippy::duplicate_mod)]
mod fixtures;
mod test_helpers;

use aws_esdk::types::*;
use aws_esdk::*;
use test_helpers::*;

#[tokio::test(flavor = "multi_thread")]
async fn test_unsupported_version_rejected() {
    let keyring = test_keyring().await;
    let plaintext = b"unsupported version test";

    let esdk = Client::default();
    let valid_ct = esdk
        .encrypt()
        .plaintext(plaintext)
        .keyring(keyring.clone())
        .send()
        .await
        .unwrap()
        .into_ciphertext();

    // Byte 0 is the version field — set to an unsupported value
    let mut tampered_ct = valid_ct.clone();
    tampered_ct[0] = 0xFF;

    //= spec/client-apis/decrypt.md#parse-the-header
    //= type=test
    //= reason=Supported version byte → Ok; unsupported value 0xFF → Serialization error
    //# The value MUST be a [supported version](../data-format/message-header.md#supported-versions).
    assert!(
        esdk.decrypt()
            .ciphertext(&valid_ct)
            .keyring(keyring.clone())
            .send()
            .await
            .is_ok(),
        "supported version must decrypt"
    );
    assert!(
        esdk.decrypt()
            .ciphertext(&tampered_ct)
            .keyring(keyring.clone())
            .send()
            .await
            .unwrap_err()
            .is_serialization(),
        "unsupported version byte must produce Serialization error"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_unsupported_content_type_v1_rejected() {
    let keyring = test_keyring().await;
    let plaintext = b"unsupported content type v1 test";

    let esdk = esdk_v1();
    let valid_ct = esdk
        .encrypt()
        .plaintext(plaintext)
        .keyring(keyring.clone())
        .algorithm_suite_id(AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256)
        .send()
        .await
        .unwrap()
        .into_ciphertext();

    let (content_type_offset, _, _, _) = parse_v1_trailing_offsets(&valid_ct);
    let original_content_type = valid_ct[content_type_offset];
    assert!(
        original_content_type == 1 || original_content_type == 2,
        "sanity check: content type should be 1 or 2, got {original_content_type}"
    );

    let mut tampered_ct = valid_ct.clone();
    tampered_ct[content_type_offset] = 0xFF; // unsupported content type

    //= spec/client-apis/decrypt.md#v1-header-deserialization
    //= type=test
    //= reason=Supported content type byte → Ok; unsupported value 0xFF → Serialization error
    //# The value MUST be a [supported content type](../data-format/message-header.md#supported-content-types).
    assert!(
        esdk.decrypt()
            .ciphertext(&valid_ct)
            .keyring(keyring.clone())
            .send()
            .await
            .is_ok(),
        "supported content type must decrypt"
    );
    assert!(
        esdk.decrypt()
            .ciphertext(&tampered_ct)
            .keyring(keyring.clone())
            .send()
            .await
            .unwrap_err()
            .is_serialization(),
        "unsupported V1 content type must produce Serialization error"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_unsupported_content_type_v2_rejected() {
    let keyring = test_keyring().await;
    let plaintext = b"unsupported content type v2 test";

    let esdk = Client::default();
    let valid_ct = esdk
        .encrypt()
        .plaintext(plaintext)
        .keyring(keyring.clone())
        .send()
        .await
        .unwrap()
        .into_ciphertext();

    let fields = parse_v2_header_field_offsets(&valid_ct);
    let (_, ct_start, _) = fields
        .iter()
        .find(|(n, _, _)| *n == "Content Type")
        .expect("V2 header must have Content Type field");
    let original_content_type = valid_ct[*ct_start];
    assert!(
        original_content_type == 1 || original_content_type == 2,
        "sanity check: content type should be 1 or 2, got {original_content_type}"
    );

    let mut tampered_ct = valid_ct.clone();
    tampered_ct[*ct_start] = 0xFF; // unsupported content type

    //= spec/client-apis/decrypt.md#v2-header-deserialization
    //= type=test
    //= reason=Supported content type byte → Ok; unsupported value 0xFF → Serialization error
    //# The value MUST be a [supported content type](../data-format/message-header.md#supported-content-types).
    assert!(
        esdk.decrypt()
            .ciphertext(&valid_ct)
            .keyring(keyring.clone())
            .send()
            .await
            .is_ok(),
        "supported content type must decrypt"
    );
    assert!(
        esdk.decrypt()
            .ciphertext(&tampered_ct)
            .keyring(keyring.clone())
            .send()
            .await
            .unwrap_err()
            .is_serialization(),
        "unsupported V2 content type must produce Serialization error"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_unsupported_type_rejected() {
    let keyring = test_keyring().await;
    let plaintext = b"unsupported type test";

    let esdk = esdk_v1();
    let valid_ct = esdk
        .encrypt()
        .plaintext(plaintext)
        .keyring(keyring.clone())
        .algorithm_suite_id(AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256)
        .send()
        .await
        .unwrap()
        .into_ciphertext();

    // V1 layout: byte 0 = version (0x01), byte 1 = type (0x80)
    assert_eq!(valid_ct[1], 0x80, "sanity check: V1 type should be 0x80");

    let mut tampered_ct = valid_ct.clone();
    tampered_ct[1] = 0xFF; // unsupported type

    //= spec/client-apis/decrypt.md#v1-header-deserialization
    //= type=test
    //= reason=Supported type byte (0x80) → Ok; unsupported value 0xFF → Serialization error
    //# The value MUST be a [supported type](../data-format/message-header.md#supported-types).
    assert!(
        esdk.decrypt()
            .ciphertext(&valid_ct)
            .keyring(keyring.clone())
            .send()
            .await
            .is_ok(),
        "supported type must decrypt"
    );
    assert!(
        esdk.decrypt()
            .ciphertext(&tampered_ct)
            .keyring(keyring.clone())
            .send()
            .await
            .unwrap_err()
            .is_serialization(),
        "unsupported V1 type byte must produce Serialization error"
    );
}

// TODO(native-mpl): relies on multi-keyring which the native MPL doesn't yet implement.
/*
#[tokio::test(flavor = "multi_thread")]
async fn test_max_encrypted_data_keys_enforcement() {
    // Create two keyrings and a multi-keyring to produce 2 EDKs on the wire.
    let keyring1 = test_keyring().await;
    let (ns2, name2) = namespace_and_name(1);
    let keyring2 = mpl()
        .create_raw_aes_keyring()
        .key_namespace(ns2)
        .key_name(name2)
        .wrapping_key(aws_smithy_types::Blob::new([1u8; 32]))
        .wrapping_alg(aws_mpl_legacy::dafny::types::AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .send()
        .await
        .unwrap();
    let multi_keyring = mpl()
        .create_multi_keyring()
        .generator(keyring1.clone())
        .child_keyrings(vec![keyring2])
        .send()
        .await
        .unwrap();

    let plaintext = b"max edk decrypt test";
    let ct = Client::default().encrypt().plaintext(plaintext).keyring(multi_keyring.clone()).send().await.unwrap().ciphertext;

    let allowing = esdk_with_max_edks(2);
    let limiting = esdk_with_max_edks(1);

    //= spec/client-apis/decrypt.md#v2-header-deserialization
    //= type=test
    //= reason=2 EDKs on wire + max=2 → Ok; same ct + max=1 → Serialization error, halting deserialization
    //# If the number of [encrypted data keys](../framework/structures.md#encrypted-data-keys)
    //# deserialized from the [message header](../data-format/message-header.md)
    //# is greater than the [maximum number of encrypted data keys](client.md#maximum-number-of-encrypted-data-keys) configured in the [client](client.md),
    //# then as soon as that can be determined during deserializing
    //# decrypt MUST process no more bytes and yield an error.
    assert!(
        allowing.decrypt().ciphertext(&ct).keyring(multi_keyring.clone()).send().await.is_ok(),
        "max=2 must decrypt 2-EDK ct"
    );
    assert_eq!(
        limiting.decrypt().ciphertext(&ct).keyring(multi_keyring).send().await.unwrap_err().kind,
        ErrorKind::Serialization,
        "max=1 with 2 EDKs on wire must produce Serialization error"
    );
}
*/

#[tokio::test(flavor = "multi_thread")]
async fn test_no_header_info_released_before_verification() {
    // Tamper with the header auth tag so header verification fails.
    // The non-streaming decrypt must return an error with no partial output.
    let keyring = test_keyring().await;
    let plaintext = b"no header info before verification";

    let esdk = Client::default();
    let valid_ct = esdk
        .encrypt()
        .plaintext(plaintext)
        .keyring(keyring.clone())
        .send()
        .await
        .unwrap()
        .into_ciphertext();

    let mut tampered_ct = valid_ct.clone();
    tampered_ct[10] ^= 0xFF;

    //= spec/client-apis/decrypt.md#v2-header-deserialization
    //= type=test
    //= reason=Untampered ct decrypts (Ok with output); tampered header byte → Cryptographic error with no DecryptOutput, so nothing released
    //# Until the [header is verified](#verify-the-header), this operation MUST NOT
    //# release any parsed information from the header.
    assert!(
        esdk.decrypt()
            .ciphertext(&valid_ct)
            .keyring(keyring.clone())
            .send()
            .await
            .is_ok(),
        "valid ct must decrypt"
    );
    assert!(
        esdk.decrypt()
            .ciphertext(&tampered_ct)
            .keyring(keyring.clone())
            .send()
            .await
            .unwrap_err()
            .is_cryptographic(),
        "tampered header must produce Cryptographic error, no output"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_v1_header_auth_tag_deserialized_and_verified() {
    // Tamper the V1 header auth tag to prove it was deserialized and used for verification.
    let keyring = test_keyring().await;
    let plaintext = b"v1 header auth tag tamper test";

    let esdk = esdk_v1();
    let valid_ct = esdk
        .encrypt()
        .plaintext(plaintext)
        .keyring(keyring.clone())
        .algorithm_suite_id(AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256)
        .send()
        .await
        .unwrap()
        .into_ciphertext();

    // V1 header auth: IV(12) + Tag(16) at the end of the header, before the body.
    // Tamper the last byte of the header (part of the auth tag).
    let body_start = find_body_start(&valid_ct, 4096).expect("body start");
    let auth_tag_last_byte = body_start - 1;
    let mut tampered_ct = valid_ct.clone();
    tampered_ct[auth_tag_last_byte] ^= 0xFF;

    //= spec/client-apis/decrypt.md#v1-header-deserialization
    //= type=test
    //= reason=V1 header authentication (IV + tag) is deserialized and verified during decrypt
    //# The Decrypt operation MUST then deserialize the
    //# [Header Authentication Version 1.0](../data-format/message-header.md#header-authentication-version-10):
    //
    //= spec/client-apis/decrypt.md#v1-header-deserialization
    //= type=test
    //= reason=Untampered V1 message decrypts; tampered V1 auth tag byte → Cryptographic error, proving the tag was deserialized and used
    //# - MUST deserialize the [Authentication Tag](../data-format/message-header.md#authentication-tag).
    assert!(
        esdk.decrypt()
            .ciphertext(&valid_ct)
            .keyring(keyring.clone())
            .send()
            .await
            .is_ok(),
        "valid V1 ct must decrypt"
    );
    assert!(
        esdk.decrypt()
            .ciphertext(&tampered_ct)
            .keyring(keyring.clone())
            .send()
            .await
            .unwrap_err()
            .is_cryptographic(),
        "tampered V1 auth tag must produce Cryptographic error"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_v1_header_auth_iv_deserialized_and_used() {
    // Tamper the V1 header auth IV to prove it was deserialized and used for verification.
    let keyring = test_keyring().await;
    let plaintext = b"v1 header auth iv tamper test";

    let esdk = esdk_v1();
    let valid_ct = esdk
        .encrypt()
        .plaintext(plaintext)
        .keyring(keyring.clone())
        .algorithm_suite_id(AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256)
        .send()
        .await
        .unwrap()
        .into_ciphertext();

    // V1 header auth IV is 12 bytes immediately before the 16-byte auth tag, which
    // is immediately before the body. Tamper its first byte.
    let body_start = find_body_start(&valid_ct, 4096).expect("body start");
    let iv_start = body_start - 16 - 12; // 16 bytes tag + 12 bytes IV before body
    let mut tampered_ct = valid_ct.clone();
    tampered_ct[iv_start] ^= 0xFF;

    //= spec/client-apis/decrypt.md#v1-header-deserialization
    //= type=test
    //= reason=Untampered V1 message decrypts; tampered V1 header auth IV byte → Cryptographic error, proving IV was deserialized and used
    //# - MUST deserialize the [IV](../data-format/message-header.md#iv).
    assert!(
        esdk.decrypt()
            .ciphertext(&valid_ct)
            .keyring(keyring.clone())
            .send()
            .await
            .is_ok(),
        "valid V1 ct must decrypt"
    );
    assert!(
        esdk.decrypt()
            .ciphertext(&tampered_ct)
            .keyring(keyring.clone())
            .send()
            .await
            .unwrap_err()
            .is_cryptographic(),
        "tampered V1 header auth IV must produce Cryptographic error"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_v1_header_body_fields_parsed_from_wire() {
    // Drives `read_header_body` and asserts each V1 field at its on-wire offset.
    use aws_esdk::__test_internals::*;

    let keyring = test_keyring().await;
    let plaintext = b"v1 fields parse test";

    let ct = esdk_v1()
        .encrypt()
        .plaintext(plaintext)
        .keyring(keyring)
        .algorithm_suite_id(AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256)
        .send()
        .await
        .unwrap()
        .into_ciphertext();

    // Parse the V1 header body via the production deserialization function.
    let mut cursor = std::io::Cursor::new(ct.as_slice());
    let mut raw = Vec::new();
    let header_body = read_header_body(&mut cursor, None, &mut raw)
        .await
        .expect("V1 header body must parse");
    // A V1 message parses to a V1 header body (message format version 1).
    assert_eq!(
        header_body.algorithm_suite().message_format_version(),
        1,
        "expected V1 body"
    );

    // Independent on-wire field offsets for V1 trailing fields.
    let (content_type_offset, reserved_offset, iv_length_offset, frame_length_offset) =
        parse_v1_trailing_offsets(&ct);

    //= spec/client-apis/decrypt.md#parse-the-header
    //= type=test
    //= reason=the V1 message's fields parse at V1.0-spec offsets, proving the order followed the Version field
    //# The header deserialization order MUST follow the [Header Body Version 1.0](../data-format/message-header.md#header-body-version-10)
    //# or [Header Body Version 2.0](../data-format/message-header.md#header-body-version-20) specification,
    //# depending on the [Version](../data-format/message-header.md#version) field in the message header.
    //
    //= spec/client-apis/decrypt.md#v1-header-deserialization
    //= type=test
    //= reason=Type at wire byte 1 begins the V1.0 header-body field order verified below
    //# If the value of the deserialized version field is [1.0](../data-format/message-header.md#supported-versions),
    //# the remaining header fields MUST be deserialized according to the
    //# [Header Body Version 1.0](../data-format/message-header.md#header-body-version-10) specification:
    //
    //= spec/client-apis/decrypt.md#v1-header-deserialization
    //= type=test
    //= reason=Wire byte 1 = 0x80 (Customer AED); read_header_body consumed it as Type
    //# - MUST deserialize the [Type](../data-format/message-header.md#type).
    assert_eq!(ct[1], 0x80, "V1 type byte must be 0x80 (Customer AED)");

    //= spec/client-apis/decrypt.md#v1-header-deserialization
    //= type=test
    //= reason=Parsed alg suite binary_id equals wire bytes 2..4
    //# - MUST deserialize the [Algorithm Suite ID](../data-format/message-header.md#algorithm-suite-id).
    assert_eq!(
        header_body.algorithm_suite().id(),
        [ct[2], ct[3]],
        "parsed alg suite binary_id equals wire bytes"
    );

    //= spec/client-apis/decrypt.md#v1-header-deserialization
    //= type=test
    //= reason=V1 message_id is 16 wire bytes (4..20); pub accessor returns those bytes
    //# - MUST deserialize the [Message ID](../data-format/message-header.md#message-id).
    assert_eq!(
        header_body.message_id().len(),
        16,
        "V1 message_id is 16 bytes"
    );
    assert_eq!(
        header_body.message_id(),
        &ct[4..20],
        "parsed message_id equals wire bytes 4..20"
    );

    //= spec/client-apis/decrypt.md#v1-header-deserialization
    //= type=test
    //= reason=AAD length field (wire bytes 20..22) = 0 for empty EC; AAD section on wire is exactly the 2-byte length field
    //# - MUST deserialize the [AAD](../data-format/message-header.md#aad).
    let aad_declared_len = u16::from_be_bytes([ct[20], ct[21]]) as usize;
    assert_eq!(
        aad_declared_len, 0,
        "empty EC ⇒ AAD declared length is 0 on wire"
    );
    let aad_section_len = 2 + aad_declared_len; // 2-byte length field + declared bytes

    //= spec/client-apis/decrypt.md#v1-header-deserialization
    //= type=test
    //= reason=EDK count and bodies consumed; content_type_offset is past EDK section
    //# - MUST deserialize the [Encrypted Data Keys](../data-format/message-header.md#encrypted-data-keys).
    let edk_section_start = 20 + aad_section_len;
    let edk_count_on_wire = u16::from_be_bytes([ct[edk_section_start], ct[edk_section_start + 1]]);
    assert_eq!(
        edk_count_on_wire, 1,
        "single keyring produces 1 EDK on wire"
    );
    assert!(
        content_type_offset > edk_section_start,
        "EDK section bytes consumed before content_type"
    );

    //= spec/client-apis/decrypt.md#v1-header-deserialization
    //= type=test
    //= reason=Content type byte at trailing offset = 0x02 (Framed)
    //# - MUST deserialize the [Content Type](../data-format/message-header.md#content-type).
    assert_eq!(
        ct[content_type_offset], 0x02,
        "default content type is Framed (0x02)"
    );

    //= spec/client-apis/decrypt.md#v1-header-deserialization
    //= type=test
    //= reason=Reserved is 4 zero bytes at expected offset (per spec)
    //# - MUST deserialize the [Reserved](../data-format/message-header.md#reserved).
    assert_eq!(
        &ct[reserved_offset..reserved_offset + 4],
        &[0u8; 4],
        "Reserved must be 4 zero bytes"
    );

    //= spec/client-apis/decrypt.md#v1-header-deserialization
    //= type=test
    //= reason=IV Length is 1 byte at expected offset, value=12 for AES-GCM suite
    //# - MUST deserialize the [IV Length](../data-format/message-header.md#iv-length).
    assert_eq!(
        ct[iv_length_offset], 12,
        "V1 IV Length byte must equal AES-GCM IV length (12)"
    );

    //= spec/client-apis/decrypt.md#v1-header-deserialization
    //= type=test
    //= reason=Frame length is 4 wire bytes BE = 4096 (default)
    //# - MUST deserialize the [Frame Length](../data-format/message-header.md#frame-length).
    let fl_value = u32::from_be_bytes([
        ct[frame_length_offset],
        ct[frame_length_offset + 1],
        ct[frame_length_offset + 2],
        ct[frame_length_offset + 3],
    ]);
    assert_eq!(fl_value, 4096, "default frame length on wire = 4096");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_v2_header_body_fields_parsed_from_wire() {
    // Drives `read_header_body` and asserts each V2 field at its on-wire offset,
    // then tampers the V2 auth tag byte to confirm it was deserialized and used.
    use aws_esdk::__test_internals::*;

    let keyring = test_keyring().await;
    let plaintext = b"v2 fields parse test";

    let esdk = Client::default();
    let ct = esdk
        .encrypt()
        .plaintext(plaintext)
        .keyring(keyring.clone())
        .send()
        .await
        .unwrap()
        .into_ciphertext();

    // Parse the V2 header body via the production deserialization function.
    let mut cursor = std::io::Cursor::new(ct.as_slice());
    let mut raw = Vec::new();
    let header_body = read_header_body(&mut cursor, None, &mut raw)
        .await
        .expect("V2 header body must parse");
    // A V2 message parses to a V2 header body (message format version 2).
    assert_eq!(
        header_body.algorithm_suite().message_format_version(),
        2,
        "expected V2 body"
    );

    // Independent on-wire field offsets for V2 header.
    let fields = parse_v2_header_field_offsets(&ct);
    let get = |name: &'static str| -> (usize, usize) {
        let (_, s, e) = fields
            .iter()
            .find(|(n, _, _)| *n == name)
            .unwrap_or_else(|| panic!("V2 header must contain field {name}"));
        (*s, *e)
    };

    //= spec/client-apis/decrypt.md#v2-header-deserialization
    //= type=test
    //= reason=Algorithm Suite ID is deserialized at the first V2.0 header-body offset, beginning the V2.0 field order
    //# If the value of the deserialized version field is [2.0](../data-format/message-header.md#supported-versions),
    //# the remaining header fields MUST be deserialized according to the
    //# [Header Body Version 2.0](../data-format/message-header.md#header-body-version-20) specification:
    //
    //= spec/client-apis/decrypt.md#v2-header-deserialization
    //= type=test
    //= reason=Parsed alg suite binary_id equals on-wire bytes; read_header_body consumed them
    //# - MUST deserialize the [Algorithm Suite ID](../data-format/message-header.md#algorithm-suite-id).
    let (suite_start, suite_end) = get("Algorithm Suite ID");
    assert_eq!(suite_end - suite_start, 2, "Algorithm Suite ID is 2 bytes");
    assert_eq!(
        header_body.algorithm_suite().id(),
        [ct[suite_start], ct[suite_start + 1]],
        "parsed alg suite binary_id equals wire bytes"
    );

    //= spec/client-apis/decrypt.md#v2-header-deserialization
    //= type=test
    //= reason=V2 message_id is 32 wire bytes; pub accessor returns those bytes
    //# - MUST deserialize the [Message ID](../data-format/message-header.md#message-id).
    let (mid_start, mid_end) = get("Message ID");
    assert_eq!(mid_end - mid_start, 32, "V2 message_id is 32 bytes");
    assert_eq!(
        header_body.message_id(),
        &ct[mid_start..mid_end],
        "parsed message_id equals wire bytes"
    );

    //= spec/client-apis/decrypt.md#v2-header-deserialization
    //= type=test
    //= reason=AAD section length on wire equals 2-byte length field + declared bytes
    //# - MUST deserialize the [AAD](../data-format/message-header.md#aad).
    let (aad_start, aad_end) = get("AAD");
    let aad_declared = u16::from_be_bytes([ct[aad_start], ct[aad_start + 1]]) as usize;
    assert_eq!(
        aad_end - aad_start,
        2 + aad_declared,
        "AAD on-wire span = 2 (length field) + declared bytes"
    );

    //= spec/client-apis/decrypt.md#v2-header-deserialization
    //= type=test
    //= reason=EDK count read at expected offset = 1 (single keyring)
    //# - MUST deserialize the [Encrypted Data Keys](../data-format/message-header.md#encrypted-data-keys).
    let (edk_start, _) = get("Encrypted Data Keys");
    let edk_count_on_wire = u16::from_be_bytes([ct[edk_start], ct[edk_start + 1]]);
    assert_eq!(
        edk_count_on_wire, 1,
        "single keyring produces 1 EDK on wire"
    );

    //= spec/client-apis/decrypt.md#v2-header-deserialization
    //= type=test
    //= reason=Content type byte at expected offset = 0x02 (Framed)
    //# - MUST deserialize the [Content Type](../data-format/message-header.md#content-type).
    let (ct_start, ct_end) = get("Content Type");
    assert_eq!(ct_end - ct_start, 1, "content type is 1 byte on wire");
    assert_eq!(ct[ct_start], 0x02, "default content type is Framed (0x02)");

    //= spec/client-apis/decrypt.md#v2-header-deserialization
    //= type=test
    //= reason=Frame length is 4 wire bytes BE = 4096 (default)
    //# - MUST deserialize the [Frame Length](../data-format/message-header.md#frame-length).
    let (fl_start, fl_end) = get("Frame Length");
    assert_eq!(fl_end - fl_start, 4, "frame length is 4 bytes");
    let fl_value = u32::from_be_bytes([
        ct[fl_start],
        ct[fl_start + 1],
        ct[fl_start + 2],
        ct[fl_start + 3],
    ]);
    assert_eq!(fl_value, 4096, "default frame length = 4096");

    //= spec/client-apis/decrypt.md#v2-header-deserialization
    //= type=test
    //= reason=Algorithm Suite Data is 32 wire bytes (V2 commit key field)
    //# - MUST deserialize the [Algorithm Suite Data](../data-format/message-header.md#algorithm-suite-data).
    let (sd_start, sd_end) = get("Algorithm Suite Data");
    assert_eq!(sd_end - sd_start, 32, "V2 Algorithm Suite Data is 32 bytes");

    // Flip the first header auth tag byte, right after Algorithm Suite Data.
    // A Cryptographic error shows decrypt verified the header with the tag it read.
    let auth_tag_offset = sd_end;
    let auth_tag_end = auth_tag_offset + 16;
    assert!(
        auth_tag_end <= ct.len(),
        "auth tag bytes are present in wire after Algorithm Suite Data"
    );
    let mut tampered_ct = ct.clone();
    tampered_ct[auth_tag_offset] ^= 0xFF;

    //= spec/client-apis/decrypt.md#v2-header-deserialization
    //= type=test
    //= reason=V2 header authentication (tag only) is deserialized and verified during decrypt
    //# The Decrypt operation MUST then deserialize the
    //# [Header Authentication Version 2.0](../data-format/message-header.md#header-authentication-version-20):
    //
    //= spec/client-apis/decrypt.md#v2-header-deserialization
    //= type=test
    //= reason=Untampered ct decrypts; tampered V2 auth tag byte → Cryptographic error, proving the auth tag was deserialized and used
    //# - MUST deserialize the [Authentication Tag](../data-format/message-header.md#authentication-tag).
    assert!(
        esdk.decrypt()
            .ciphertext(&ct)
            .keyring(keyring.clone())
            .send()
            .await
            .is_ok(),
        "valid V2 ct must decrypt"
    );
    assert!(
        esdk.decrypt()
            .ciphertext(&tampered_ct)
            .keyring(keyring.clone())
            .send()
            .await
            .unwrap_err()
            .is_cryptographic(),
        "tampered V2 auth tag must produce Cryptographic error"
    );
}

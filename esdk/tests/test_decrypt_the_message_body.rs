// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for spec/client-apis/decrypt.md#decrypt-the-message-body

#[allow(clippy::duplicate_mod)]
mod fixtures;
mod test_helpers;

use aws_esdk::types::*;
use aws_esdk::*;
use std::num::NonZeroU32;
use test_helpers::*;

#[tokio::test(flavor = "multi_thread")]
async fn test_decrypt_final_frame_content_length_validation() {
    // Encrypt a message, then tamper with the final frame's content length field
    // to exceed the frame length. Decrypt must fail.
    let pt = vec![0xEEu8; 5];
    let valid_ct = encrypt_with_frame_length(&pt, 10).await;

    // First, verify the untampered content_length is <= frame_length on wire
    let frames = parse_all_frames(&valid_ct, 10);
    let final_frame = frames.last().unwrap();
    assert!(final_frame.is_final);
    //= spec/client-apis/decrypt.md#decrypt-the-message-body
    //= type=test
    //= reason=On-wire content_length (5) <= frame_length (10) verified directly
    //# MUST ensure that the length of the encrypted content field is
    //# less than or equal to the frame length deserialized in the message header.
    assert!(
        final_frame.content_length <= 10,
        "untampered: content_length {} must be <= frame_length 10",
        final_frame.content_length
    );

    // Now tamper: set content_length to 11 (exceeds frame_length=10)
    let mut tampered_ct = valid_ct.clone();
    for i in 0..tampered_ct.len().saturating_sub(24) {
        if tampered_ct[i..i + 4] == ENDFRAME_MARKER {
            let bad_len = 11u32.to_be_bytes();
            tampered_ct[i + 20..i + 24].copy_from_slice(&bad_len);
            break;
        }
    }

    let keyring = test_keyring().await;

    //= spec/client-apis/decrypt.md#decrypt-the-message-body
    //= type=test
    //= reason=Untampered ct decrypts; content_length tampered to 11 (> frame_length=10) → Serialization error
    //# If this is a final frame, this MUST be determined by using the [final frame encrypted content length](../data-format/message-body.md#final-frame-encrypted-content-length).
    assert!(
        Client::default()
            .decrypt()
            .ciphertext(&valid_ct)
            .keyring(keyring.clone())
            .send()
            .await
            .is_ok(),
        "valid ct must decrypt"
    );
    assert!(
        Client::default()
            .decrypt()
            .ciphertext(&tampered_ct)
            .keyring(keyring)
            .send()
            .await
            .unwrap_err()
            .is_serialization(),
        "content_length > frame_length must produce Serialization error"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_decrypt_fails_on_tampered_auth_tag() {
    let pt = vec![0xABu8; 20];
    let valid_ct = encrypt_with_frame_length(&pt, 10).await;
    let body_start = find_body_start(&valid_ct, 10).expect("must find body");
    let tag_end = body_start + 4 + IV_LEN + 10 + TAG_LEN - 1;

    let mut tampered_ct = valid_ct.clone();
    tampered_ct[tag_end] ^= 0xFF;

    let keyring = test_keyring().await;

    //= spec/client-apis/decrypt.md#decrypt-the-message-body
    //= type=test
    //= reason=tampered auth tag fails AEAD authentication; valid ct decrypts
    //# Once at least a single frame is deserialized (or the entire body in the nonframed case),
    //# the Decrypt operation MUST decrypt and authenticate the frame (or body) using the
    //# [authenticated encryption algorithm](../framework/algorithm-suites.md#encryption-algorithm)
    //# specified by the [algorithm suite](../framework/algorithm-suites.md), with the following inputs:
    //
    //= spec/client-apis/decrypt.md#decrypt-the-message-body
    //= type=test
    //= reason=tampering the frame's auth tag fails AEAD; valid ct decrypts
    //# - The tag MUST be the authentication tag deserialized from the frame or body.
    //
    //= spec/client-apis/decrypt.md#decrypt-the-message-body
    //= type=test
    //= reason=The derived data key is the frame AEAD key; the valid ct decrypts only under it, and the tampered tag below → Cryptographic error
    //# - The cipherkey MUST be the derived data key
    //
    //= spec/client-apis/decrypt.md#decrypt-the-message-body
    //= type=test
    //= reason=Untampered ct decrypts; tampered auth tag byte → Cryptographic error
    //# If this decryption fails, this operation MUST immediately halt and fail.
    assert!(
        Client::default()
            .decrypt()
            .ciphertext(&valid_ct)
            .keyring(keyring.clone())
            .send()
            .await
            .is_ok(),
        "valid ct must decrypt"
    );
    assert!(
        Client::default()
            .decrypt()
            .ciphertext(&tampered_ct)
            .keyring(keyring)
            .send()
            .await
            .unwrap_err()
            .is_cryptographic(),
        "tampered auth tag must produce Cryptographic error"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_frame_fields_deserialized_from_wire() {
    // Directly verify each frame field is present at the correct wire offset.
    // 30 bytes / frame_length=10 → 2 regular + 1 final = 3 frames.
    let pt = vec![0xABu8; 30];
    let ct = encrypt_with_frame_length(&pt, 10).await;
    let frames = parse_all_frames(&ct, 10);
    assert_eq!(frames.len(), 3, "expected 3 frames (2 regular + 1 final)");

    // Regular frame 1: verify deserialized fields on wire
    let f = &frames[0];
    //= spec/client-apis/decrypt.md#decrypt-the-message-body
    //= type=test
    //= reason=each regular-frame field is asserted at its Regular-Frame-spec wire offset below
    //# Regular frame deserialization MUST conform to the [Regular Frame](../data-format/message-body.md#regular-frame) specification.
    //
    //= spec/client-apis/decrypt.md#decrypt-the-message-body
    //= type=test
    //= reason=each regular-frame field (seq, IV, content, tag) is parsed at its spec offset
    //# For a regular frame, each field MUST be deserialized according to its specification:
    //
    //= spec/client-apis/decrypt.md#decrypt-the-message-body
    //= type=test
    //= reason=On-wire seq_num at expected offset proves it was deserialized
    //# - MUST deserialize the [Sequence Number](../data-format/message-body.md#regular-frame-sequence-number).
    assert_eq!(f.seq_num, 1, "frame 1 seq_num must be 1");
    assert_eq!(f.seq_num_bytes.len(), 4, "seq_num is 4 bytes on wire");

    //= spec/client-apis/decrypt.md#decrypt-the-message-body
    //= type=test
    //= reason=On-wire IV at expected offset proves it was deserialized
    //# - MUST deserialize the [IV](../data-format/message-body.md#regular-frame-iv).
    assert_eq!(f.iv.len(), IV_LEN, "IV is 12 bytes on wire");
    assert_eq!(f.iv_offset, f.seq_num_offset + 4, "IV follows seq_num");

    //= spec/client-apis/decrypt.md#decrypt-the-message-body
    //= type=test
    //= reason=the on-wire regular-frame content span equals the header frame length (asserted below)
    //# If this is a regular frame, this MUST be determined by using the [frame length](../data-format/message-header.md#frame-length)
    //# deserialized from the message header.
    //
    //= spec/client-apis/decrypt.md#decrypt-the-message-body
    //= type=test
    //= reason=On-wire content at expected offset proves it was deserialized
    //# - MUST deserialize the [Encrypted Content](../data-format/message-body.md#regular-frame-encrypted-content).
    assert_eq!(
        f.content.len(),
        10,
        "regular frame content is frame_length bytes"
    );
    assert_eq!(f.content_offset, f.iv_offset + IV_LEN, "content follows IV");

    //= spec/client-apis/decrypt.md#decrypt-the-message-body
    //= type=test
    //= reason=On-wire tag at expected offset proves it was deserialized
    //# - MUST deserialize the [Authentication Tag](../data-format/message-body.md#regular-frame-authentication-tag).
    assert_eq!(f.tag.len(), TAG_LEN, "auth tag is 16 bytes on wire");
    assert_eq!(f.tag_offset, f.content_offset + 10, "tag follows content");

    // Final frame: verify content_length field
    let ff = &frames[2];
    assert!(ff.is_final, "frame 3 must be final");
    //= spec/client-apis/decrypt.md#decrypt-the-message-body
    //= type=test
    //= reason=On-wire content_length field in final frame proves it was deserialized
    //# - MUST deserialize the [Encrypted Content Length](../data-format/message-body.md#final-frame-encrypted-content-length).
    assert_eq!(
        ff.content_length_bytes.unwrap().len(),
        4,
        "content_length is 4 bytes"
    );
    assert_eq!(
        ff.content_length, 10,
        "final frame content = remaining 10 bytes"
    );

    // The body AAD is an AES-GCM input, not on the wire: tamper a content byte so
    // the AAD-bound frame tag no longer verifies, and confirm the valid ct decrypts.
    let mut content_tampered = ct.clone();
    content_tampered[f.content_offset] ^= 0xFF;
    //= spec/client-apis/decrypt.md#decrypt-the-message-body
    //= type=test
    //= reason=The body AAD is bound into each frame's AEAD tag; tampering content → Cryptographic error, and a wrong AAD would fail the valid decrypt
    //# - The AAD MUST be the serialized [message body AAD](../data-format/message-body-aad.md),
    //# constructed according to the [Message Body AAD](../data-format/message-body-aad.md) specification, as follows:
    assert_eq!(
        decrypt_ciphertext(&ct).await.into_plaintext().into_inner(),
        pt,
        "valid ct must decrypt"
    );
    assert!(
        decrypt_ciphertext_result(&content_tampered)
            .await
            .unwrap_err()
            .is_cryptographic(),
        "tampering frame content must fail AEAD authentication"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_decrypt_no_unauthenticated_plaintext_released() {
    // Tamper with encrypted content in the first frame. Decrypt must fail
    // and return no plaintext at all.
    let pt = vec![0xABu8; 20];
    let valid_ct = encrypt_with_frame_length(&pt, 10).await;
    let body_start = find_body_start(&valid_ct, 10).expect("must find body");
    let tamper_offset = body_start + 4 + IV_LEN + 1;

    let mut tampered_ct = valid_ct.clone();
    tampered_ct[tamper_offset] ^= 0xFF;

    let keyring = test_keyring().await;

    //= spec/client-apis/decrypt.md#decrypt-the-message-body
    //= type=test
    //= reason=tampering the frame's encrypted content fails AEAD; valid ct decrypts
    //# - The ciphertext MUST be the encrypted content deserialized from the frame or body.
    //
    //= spec/client-apis/decrypt.md#decrypt-the-message-body
    //= type=test
    //= reason=Untampered body decrypts (Ok includes plaintext); tampered body returns Err with no DecryptOutput, so no plaintext released
    //# This operation MUST NOT release any unauthenticated plaintext.
    assert!(
        Client::default()
            .decrypt()
            .ciphertext(&valid_ct)
            .keyring(keyring.clone())
            .send()
            .await
            .is_ok(),
        "valid ct must decrypt"
    );
    assert!(
        Client::default()
            .decrypt()
            .ciphertext(&tampered_ct)
            .keyring(keyring)
            .send()
            .await
            .unwrap_err()
            .is_cryptographic(),
        "tampered body must produce Cryptographic error, no plaintext"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_decrypt_final_frame_held_until_signature_verification() {
    // Encrypt with a signing algorithm suite, then tamper with the signature.
    // Decrypt must fail, proving the final frame plaintext was held back
    // pending signature verification and never released.
    let keyring = test_keyring().await;
    let pt = vec![0xABu8; 16];
    let valid_ct = Client::default()
        .encrypt()
        .plaintext(&pt)
        .keyring(keyring.clone())
        .frame_length(NonZeroU32::new(4096).unwrap())
        .algorithm_suite_id(AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384)
        .send()
        .await
        .unwrap()
        .into_ciphertext()
        .into_inner();

    // Tamper with the last byte of the signature to cause verification failure
    let mut tampered_ct = valid_ct.clone();
    let last = tampered_ct.len() - 1;
    tampered_ct[last] ^= 0xFF;

    //= spec/client-apis/decrypt.md#decrypt-the-message-body
    //= type=test
    //= reason=Untampered ct decrypts (Ok with plaintext); tampered signature → Err, so final frame plaintext was held back and never reaches caller
    //# Any plaintext decrypted from [nonframed data](../data-format/message-body.md#nonframed-data) or
    //# a final frame in a streamed Decrypt operation MUST NOT be released until [signature verification](#verify-the-signature)
    //# successfully completes.
    assert!(
        Client::default()
            .decrypt()
            .ciphertext(&valid_ct)
            .keyring(keyring.clone())
            .send()
            .await
            .is_ok(),
        "valid ct must decrypt"
    );
    assert!(
        Client::default()
            .decrypt()
            .ciphertext(&tampered_ct)
            .keyring(keyring)
            .send()
            .await
            .unwrap_err()
            .is_cryptographic(),
        "tampered signature must produce a Cryptographic error, no plaintext"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_unframed_decrypt_fails_on_tampered_auth_tag() {
    // Tamper with the authentication tag in the external V2 nonframed vector. Decrypt must fail.
    let valid_ct = EXTERNAL_V2_NONFRAMED_CT.to_vec();
    let mut tampered_ct = valid_ct.clone();
    let last = tampered_ct.len() - 1;
    tampered_ct[last] ^= 0xFF;

    //= spec/client-apis/decrypt.md#nonframed-message-body-decryption
    //= type=test
    //= reason=the external vector's deserialized encrypted content is used as the AEAD ciphertext; the valid vector decrypts
    //# - The ciphertext MUST be the [Encrypted Content](../data-format/message-body.md#nonframed-data-encrypted-content) deserialized from the message body.
    //
    //= spec/client-apis/decrypt.md#nonframed-message-body-decryption
    //= type=test
    //= reason=the external vector decrypts only if the derived data key is used as the nonframed cipherkey; a wrong key fails AEAD
    //# - The cipherkey MUST be the derived data key.
    assert!(
        try_decrypt_external_nonframed(Version::V2, &valid_ct)
            .await
            .is_ok(),
        "valid external vector must decrypt"
    );
    //= spec/client-apis/decrypt.md#nonframed-message-body-decryption
    //= type=test
    //= reason=tampering the nonframed auth tag → AEAD failure, proving the deserialized tag is used
    //# - The tag MUST be the [Authentication Tag](../data-format/message-body.md#nonframed-data-authentication-tag) deserialized from the message body.
    //
    //= spec/client-apis/decrypt.md#nonframed-message-body-decryption
    //= type=test
    //= reason=tampered auth tag → Cryptographic error, so decryption halts on failure
    //# If this decryption fails, this operation MUST immediately halt and fail.
    assert!(
        try_decrypt_external_nonframed(Version::V2, &tampered_ct)
            .await
            .unwrap_err()
            .is_cryptographic(),
        "tampered nonframed auth tag must produce Cryptographic error"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_sequence_number_end_value_is_0xffffffff() {
    let pt = vec![0xBBu8; 5];
    let ct = encrypt_with_frame_length(&pt, 4096).await;
    let frames = parse_all_frames(&ct, 4096);
    assert_eq!(frames.len(), 1, "single final frame expected");
    let f = &frames[0];
    assert!(f.is_final, "frame must be a final frame");

    // Byte-level check: the ENDFRAME marker is 0xFFFFFFFF at the frame start
    //= spec/client-apis/decrypt.md#decrypt-the-message-body
    //= type=test
    //= reason=the final-frame marker and fields are asserted at their Final-Frame-spec wire offsets below
    //# Final frame deserialization MUST conform to the [Final Frame](../data-format/message-body.md#final-frame) specification.
    //
    //= spec/client-apis/decrypt.md#decrypt-the-message-body
    //= type=test
    //= reason=each final-frame field (marker, seq, IV, content-length, content, tag) parses at its spec offset
    //# For a final frame, each field MUST be deserialized according to its specification:
    //
    //= spec/client-apis/decrypt.md#decrypt-the-message-body
    //= type=test
    //= reason=On-wire bytes at frame start are exactly 0xFF 0xFF 0xFF 0xFF
    //# The value MUST be `0xFFFFFFFF`.
    let marker = f
        .endframe_marker_bytes
        .expect("final frame must have endframe marker");
    assert_eq!(
        marker,
        &[0xFF, 0xFF, 0xFF, 0xFF],
        "endframe marker must be 0xFFFFFFFF byte-by-byte"
    );

    //= spec/client-apis/decrypt.md#decrypt-the-message-body
    //= type=test
    //= reason=Endframe marker field present at frame_offset on wire
    //# - MUST deserialize the [Sequence Number End](../data-format/message-body.md#sequence-number-end).
    assert_eq!(
        f.endframe_marker_offset,
        Some(f.frame_offset),
        "endframe marker at frame start"
    );

    //= spec/client-apis/decrypt.md#decrypt-the-message-body
    //= type=test
    //= reason=Seq num field at expected offset, value=1 for single final frame
    //# - MUST deserialize the [Sequence Number](../data-format/message-body.md#final-frame-sequence-number).
    assert_eq!(f.seq_num, 1, "final frame seq_num must be 1");
    assert_eq!(
        f.seq_num_offset,
        f.frame_offset + 4,
        "seq_num follows endframe marker"
    );

    //= spec/client-apis/decrypt.md#decrypt-the-message-body
    //= type=test
    //= reason=IV field at expected offset, 12 bytes
    //# - MUST deserialize the [IV](../data-format/message-body.md#final-frame-iv).
    assert_eq!(f.iv.len(), IV_LEN, "IV is 12 bytes");
    assert_eq!(f.iv_offset, f.seq_num_offset + 4, "IV follows seq_num");

    //= spec/client-apis/decrypt.md#decrypt-the-message-body
    //= type=test
    //= reason=Content length field at expected offset, 4 bytes, value=5
    //# - MUST deserialize the [Encrypted Content Length](../data-format/message-body.md#final-frame-encrypted-content-length).
    let cl_bytes = f
        .content_length_bytes
        .expect("final frame has content_length field");
    assert_eq!(cl_bytes.len(), 4, "content_length is 4 bytes on wire");
    assert_eq!(
        f.content_length, 5,
        "content_length = plaintext length for final frame"
    );

    //= spec/client-apis/decrypt.md#decrypt-the-message-body
    //= type=test
    //= reason=Encrypted content at expected offset, length matches content_length field
    //# - MUST deserialize the [Encrypted Content](../data-format/message-body.md#final-frame-encrypted-content).
    assert_eq!(
        f.content.len(),
        5,
        "encrypted content = content_length bytes"
    );

    //= spec/client-apis/decrypt.md#decrypt-the-message-body
    //= type=test
    //= reason=Auth tag at expected offset, 16 bytes
    //# - MUST deserialize the [Authentication Tag](../data-format/message-body.md#final-frame-authentication-tag).
    assert_eq!(f.tag.len(), TAG_LEN, "auth tag is 16 bytes");
    assert_eq!(f.tag_offset, f.content_offset + 5, "tag follows content");

    // Round-trip corroboration
    let result = decrypt_ciphertext(&ct).await.into_plaintext().into_inner();
    assert_eq!(result, pt);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_decrypt_first_frame_sequence_number_is_one() {
    // Parse the on-wire ciphertext and verify the first frame's sequence number is 1.
    let pt = vec![0xAAu8; 30];
    let ct = encrypt_with_frame_length(&pt, 10).await;
    let frames = parse_all_frames(&ct, 10);
    assert!(frames.len() >= 2, "need at least 2 frames");
    //= spec/client-apis/decrypt.md#decrypt-the-message-body
    //= type=test
    //= reason=On-wire first frame seq_num == 1 proves requirement
    //# If this is framed data and the first frame sequentially, this value MUST be 1.
    //
    //= spec/client-apis/decrypt.md#decrypt-the-message-body
    //= type=test
    //= reason=Wire parse extracts seq_num from first 4 bytes, proving deserialization
    //# - MUST deserialize the [Sequence Number](../data-format/message-body.md#regular-frame-sequence-number).
    assert_eq!(
        frames[0].seq_num, 1,
        "first frame sequence number must be 1 on the wire"
    );
    // Round-trip corroboration
    let result = decrypt_ciphertext(&ct).await.into_plaintext().into_inner();
    assert_eq!(result, pt);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_decrypt_sequence_numbers_increment() {
    // 50 bytes at frame_length=10 → 4 regular + 1 final = 5 frames.
    let pt = vec![0xBBu8; 50];
    let ct = encrypt_with_frame_length(&pt, 10).await;
    let frames = parse_all_frames(&ct, 10);
    assert_eq!(
        frames.len(),
        5,
        "50 bytes / 10-byte frames = 4 regular + 1 final"
    );

    // Verify regular frames have incrementing sequence numbers on wire
    for (i, frame) in frames[..4].iter().enumerate() {
        assert!(!frame.is_final, "frame {i} must be regular");
        assert_eq!(frame.seq_num, (i + 1) as u32, "frame {i}: seq_num on wire");
        // Byte-level: seq_num bytes encode the expected value in big-endian
        let expected_bytes = ((i + 1) as u32).to_be_bytes();
        assert_eq!(
            frame.seq_num_bytes, &expected_bytes,
            "frame {i}: seq_num bytes"
        );
    }

    //= spec/client-apis/decrypt.md#decrypt-the-message-body
    //= type=test
    //= reason=On-wire seq_nums 1..5 verified byte-by-byte across 5 frames
    //# Otherwise, this value MUST be 1 greater than the value of the sequence number
    //# of the previous frame.
    assert_eq!(frames[4].seq_num, 5, "final frame seq_num must be 5");

    // Verify final frame has endframe marker on wire
    //= spec/client-apis/decrypt.md#decrypt-the-message-body
    //= type=test
    //= reason=parsed frames show 0xFFFFFFFF→final, otherwise regular
    //# If deserializing [framed data](../data-format/message-body.md#framed-data),
    //# the Decrypt operation MUST use the first 4 bytes of a frame to determine
    //# whether the operation will deserialize the frame as a [final frame](../data-format/message-body.md#final-frame)
    //# or [regular frame](../data-format/message-body.md#regular-frame).
    //
    //= spec/client-apis/decrypt.md#decrypt-the-message-body
    //= type=test
    //= reason=each frame's first 4 bytes are parsed to classify the frame
    //# The Decrypt operation MUST inspect the first 4 bytes of each frame.
    //
    //= spec/client-apis/decrypt.md#decrypt-the-message-body
    //= type=test
    //= reason=Final frame's first 4 bytes are 0xFFFFFFFF on wire
    //# If the first 4 bytes have a value of 0xFFFFFFFF,
    //# the Decrypt operation MUST treat them as the [Sequence Number End](../data-format/message-body.md#sequence-number-end)
    //# and deserialize the following bytes according to the [final frame spec](../data-format/message-body.md#final-frame).
    let marker = frames[4]
        .endframe_marker_bytes
        .expect("final frame has marker");
    assert_eq!(marker, &[0xFF, 0xFF, 0xFF, 0xFF]);

    // Regular frames: first 4 bytes are NOT 0xFFFFFFFF
    //= spec/client-apis/decrypt.md#decrypt-the-message-body
    //= type=test
    //= reason=Regular frames' first 4 bytes != 0xFFFFFFFF, treated as seq num
    //# Otherwise, the Decrypt operation MUST treat them as the [Sequence Number](../data-format/message-body.md#regular-frame-sequence-number)
    //# and deserialize the following bytes according to the [regular frame spec](../data-format/message-body.md#regular-frame).
    for frame in &frames[..4] {
        assert!(
            frame.endframe_marker_bytes.is_none(),
            "regular frame must not have endframe marker"
        );
    }

    // Round-trip corroboration
    let result = decrypt_ciphertext(&ct).await.into_plaintext().into_inner();
    assert_eq!(result, pt);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_nonframed_body_fields_deserialized_from_wire() {
    // Parse the external V2 nonframed vector directly and verify each field.
    let body = parse_external_nonframed_body(EXTERNAL_V2_NONFRAMED_CT, Version::V2);

    //= spec/client-apis/decrypt.md#nonframed-message-body-decryption
    //= type=test
    //= reason=External vector's IV field is 12 bytes at expected offset
    //# - The IV MUST be the [IV](../data-format/message-body.md#nonframed-data-iv) deserialized from the message body.
    assert_eq!(body.iv.len(), IV_LEN, "nonframed IV must be 12 bytes");

    //= spec/client-apis/decrypt.md#decrypt-the-message-body
    //= type=test
    //= reason=Encrypted content length field equals expected plaintext length (10240)
    //# If this is nonframed data, this MUST be determined by using the [nonframed data encrypted content length](../data-format/message-body.md#nonframed-data-encrypted-content-length).
    assert_eq!(
        body.encrypted_content_length as usize,
        EXTERNAL_V2_NONFRAMED_PT.len(),
        "encrypted content length must equal plaintext length"
    );

    //= spec/client-apis/decrypt.md#nonframed-message-body-decryption
    //= type=test
    //= reason=nonframed body AAD sequence number is 1 (IV encodes seq=1)
    //# - The [sequence number](../data-format/message-body-aad.md#sequence-number) MUST be `1`.
    //
    //= spec/client-apis/decrypt.md#decrypt-the-message-body
    //= type=test
    //= reason=On-wire seq_num for nonframed is always 1 (checked via AAD construction)
    //# If this is nonframed data, this value MUST be 1.
    // The IV's last 4 bytes encode the sequence number for nonframed data.
    let iv_seq = u32::from_be_bytes([body.iv[8], body.iv[9], body.iv[10], body.iv[11]]);
    assert_eq!(iv_seq, 1, "nonframed IV sequence number must be 1");

    //= spec/client-apis/decrypt.md#decrypt-the-message-body
    //= type=test
    //= reason=nonframed content type dispatches to the nonframed reader; framed dispatches to the framed reader
    //# The Decrypt operation MUST use the [content type](../data-format/message-header.md#content-type) field parsed from the
    //# message header to determine whether the operation will deserialize the message bytes as
    //# [framed data](../data-format/message-body.md#framed-data) or
    //# [nonframed data](../data-format/message-body.md#nonframed-data).
    //
    //= spec/client-apis/decrypt.md#nonframed-message-body-decryption
    //= type=test
    //= reason=external nonframed vector parses per the Nonframed Data spec and decrypts
    //# Nonframed data deserialization MUST conform to the [Nonframed Data](../data-format/message-body.md#nonframed-data) specification.
    //
    //= spec/client-apis/decrypt.md#nonframed-message-body-decryption
    //= type=test
    //= reason=the external nonframed vector (independent authority) decrypts only if our reconstructed body AAD matches its AAD
    //# - The AAD MUST be the serialized [message body AAD](../data-format/message-body-aad.md),
    //# constructed with:
    //
    //= spec/client-apis/decrypt.md#nonframed-message-body-decryption
    //= type=test
    //= reason=External vector decrypts to known plaintext; proves all AES-GCM inputs correct
    //# If a message has the [nonframed](../data-format/message-body.md#nonframed-data) content type,
    //# the Decrypt operation MUST deserialize the message body according to the
    //# [nonframed data specification](../data-format/message-body.md#nonframed-data)
    //# and decrypt it using the [authenticated encryption algorithm](../framework/algorithm-suites.md#encryption-algorithm)
    //# specified by the [algorithm suite](../framework/algorithm-suites.md), with the following inputs:
    let result = decrypt_external_nonframed_vector(Version::V2).await;
    assert_eq!(result, EXTERNAL_V2_NONFRAMED_PT);
}

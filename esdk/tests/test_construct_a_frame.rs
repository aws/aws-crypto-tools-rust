// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for spec/client-apis/encrypt.md#construct-a-frame

#[allow(clippy::duplicate_mod)]
mod fixtures;
mod test_helpers;

use aws_esdk::*;
use std::num::NonZeroU32;
use test_helpers::*;

#[tokio::test(flavor = "multi_thread")]
async fn test_construct_frame_aead_inputs_authenticated() {
    // Cipherkey and message ID are AAD/key inputs to AES-GCM that never appear on
    // the wire, so they are proven by the valid decrypt (a wrong value fails the
    // authenticated decrypt). Sequence number, content, auth tag, and content
    // length ARE on the wire, so they are proven by tampering each field and
    // asserting the specific rejection. Multi-frame, non-signing suite so the
    // frame auth tag is the integrity layer under test.
    let keyring = test_keyring().await;
    let pt: Vec<u8> = (0u8..=200).collect(); // 201 bytes / frame_length 50 → 4 regular + 1 final
    let ct = Client::default()
        .encrypt()
        .plaintext(&pt)
        .keyring(keyring.clone())
        .frame_length(NonZeroU32::new(50).unwrap())
        .algorithm_suite_id(AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey)
        .send()
        .await
        .unwrap()
        .ciphertext;

    let frames = parse_all_frames(&ct, 50);
    let first = &frames[0];
    let final_frame = frames.last().expect("final frame");

    let mut content_tampered = ct.clone();
    content_tampered[first.content_offset] ^= 0xFF;
    let mut seq_tampered = ct.clone();
    seq_tampered[first.seq_num_offset + 3] ^= 0x02; // frame 1 seq 1 → 3
    let mut content_length_tampered = ct.clone();
    let clen_off = final_frame
        .content_length_offset
        .expect("final content length");
    content_length_tampered[clen_off + 3] ^= 0x01; // declared content length 1 → 0, still <= frame length

    //= spec/client-apis/encrypt.md#construct-a-frame
    //= type=test
    //= reason=The frame AEAD key is the EDK-derived data key; decrypt with any other key fails this valid AEAD decrypt
    //# - The cipherkey MUST be the derived data key
    //
    //= spec/client-apis/encrypt.md#construct-a-frame
    //= type=test
    //= reason=decrypt inserts the header message ID into each frame's body AAD; a mismatched ID fails this valid AEAD decrypt
    //# - The [message ID](../data-format/message-body-aad.md#message-id) MUST be the same as the
    //# [message ID](../data-format/message-header.md#message-id) serialized in the header of this message.
    assert_eq!(
        decrypt_with_keyring(&ct, &keyring).await,
        pt,
        "valid multi-frame ct must decrypt"
    );

    //= spec/client-apis/encrypt.md#construct-a-frame
    //= type=test
    //= reason=Flipping one encrypted-content byte → Cryptographic error, so each frame carries the AEAD ciphertext+tag
    //# To construct a regular or final frame that represents the next frame in the encrypted message's body,
    //# the Encrypt operation MUST calculate the encrypted content and an authentication tag using the
    //# [authenticated encryption algorithm](../framework/algorithm-suites.md#encryption-algorithm)
    //# specified by the [algorithm suite](../framework/algorithm-suites.md),
    //# with the following inputs:
    //
    //= spec/client-apis/encrypt.md#construct-a-frame
    //= type=test
    //= reason=Tampering the encrypted content breaks the body-AAD-bound AEAD tag → Cryptographic error
    //# - The AAD MUST be the serialized [message body AAD](../data-format/message-body-aad.md),
    //# constructed according to the [Message Body AAD](../data-format/message-body-aad.md) specification, as follows:
    //
    //= spec/client-apis/encrypt.md#construct-a-frame
    //= type=test
    //= reason=The body AAD content string is bound into the AEAD tag; tampering content → Cryptographic error
    //# - The [Body AAD Content](../data-format/message-body-aad.md#body-aad-content) MUST be the structure defined in
    //# [Message Body AAD](../data-format/message-body-aad.md).
    assert!(
        try_decrypt_with_keyring(&content_tampered, &keyring)
            .await
            .unwrap_err()
            .is_cryptographic(),
        "tampered frame content must fail AEAD authentication"
    );

    //= spec/client-apis/encrypt.md#construct-a-frame
    //= type=test
    //= reason=Changing frame 1's on-wire sequence number from 1 → Serialization error, so the serialized value is the frame's sequence number
    //# - The [sequence number](../data-format/message-body-aad.md#sequence-number) MUST be the sequence
    //# number of the frame being encrypted.
    assert!(
        try_decrypt_with_keyring(&seq_tampered, &keyring)
            .await
            .unwrap_err()
            .is_serialization(),
        "tampered frame sequence number must be rejected"
    );

    //= spec/client-apis/encrypt.md#construct-a-frame
    //= type=test
    //= reason=On-wire declared length equals the 1 remaining plaintext byte; in-bounds tamper (1→0) breaks the AAD-bound AEAD tag → Cryptographic error
    //# - The [content length](../data-format/message-body-aad.md#content-length) MUST have a value
    //# equal to the length of the plaintext being encrypted.
    assert_eq!(
        final_frame.content_length, 1,
        "final frame's declared content length must equal the 1 remaining plaintext byte"
    );
    assert!(
        try_decrypt_with_keyring(&content_length_tampered, &keyring)
            .await
            .unwrap_err()
            .is_cryptographic(),
        "tampered final-frame content length must fail AEAD authentication"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_construct_frame_iv_is_padded_sequence_number() {
    // 35 bytes / frame_length=10 → 3 regular + 1 final (≥3 distinct seq nums).
    let pt = vec![0xAAu8; 35];
    let ct = encrypt_with_frame_length(&pt, 10).await;
    let frames = parse_all_frames(&ct, 10);
    assert_eq!(frames.len(), 4);

    //= spec/client-apis/encrypt.md#construct-a-frame
    //= type=test
    //# - The IV MUST be the [sequence number](../data-format/message-body-aad.md#sequence-number)
    //# used in the message body AAD for this frame,
    //# padded to the [IV length](../data-format/message-header.md#iv-length).
    for (i, f) in frames.iter().enumerate() {
        assert_eq!(f.iv.len(), IV_LEN, "frame {i}");
        let iv_seq = u32::from_be_bytes([f.iv[8], f.iv[9], f.iv[10], f.iv[11]]);
        assert_eq!(
            iv_seq, f.seq_num,
            "frame {i}: IV low 4 bytes != seq {}",
            f.seq_num
        );
        assert_eq!(
            &f.iv[0..8],
            &[0u8; 8],
            "frame {i}: IV high 8 bytes != zero pad"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_construct_frame_sequence_number_starts_at_one_and_increments() {
    // 40 bytes / frame_length=10 → 4 frames at seq 1..=4.
    let pt = vec![0xCCu8; 40];
    let ct = encrypt_with_frame_length(&pt, 10).await;
    let frames = parse_all_frames(&ct, 10);
    assert_eq!(frames.len(), 4);

    //= spec/client-apis/encrypt.md#construct-a-frame
    //= type=test
    //# If this is the first frame sequentially, the sequence number value MUST be 1.
    assert_eq!(frames[0].seq_num, 1);

    //= spec/client-apis/encrypt.md#construct-a-frame
    //= type=test
    //# Otherwise, the sequence number value MUST be 1 greater than the value of the sequence number
    //# of the previous frame.
    for i in 1..frames.len() {
        assert_eq!(frames[i].seq_num, frames[i - 1].seq_num + 1, "frame {i}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_construct_frame_regular_frame_plaintext_equals_frame_length() {
    // 25 bytes / frame_length=10 → 2 regular (10) + 1 final (5).
    let pt = vec![0xBBu8; 25];
    let frame_length = 10u32;
    let ct = encrypt_with_frame_length(&pt, frame_length).await;
    let frames = parse_all_frames(&ct, frame_length);
    let regular: Vec<_> = frames.iter().filter(|f| !f.is_final).collect();
    assert_eq!(regular.len(), 2);

    //= spec/client-apis/encrypt.md#construct-a-frame
    //= type=test
    //# - For a regular frame the length of this plaintext MUST equal the frame length.
    //
    //= spec/client-apis/encrypt.md#construct-a-frame
    //= type=test
    //# - For a regular frame the length of this plaintext subsequence MUST equal the frame length.
    for (i, f) in regular.iter().enumerate() {
        let Ok(content_len) = u32::try_from(f.content.len()) else {
            panic!("content length exceeds u32::MAX");
        };
        assert_eq!(content_len, frame_length, "regular frame {i}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_construct_frame_final_frame_plaintext_at_most_frame_length() {
    let frame_length = 10u32;
    // (label, pt_len, expected_final_len): less-than, equal, greater-with-partial.
    for (label, pt_len, expected_final_len) in [
        ("less", 7usize, 7u32),
        ("equal", 10usize, 10u32),
        ("greater_partial", 13usize, 3u32),
    ] {
        let pt = vec![0xDDu8; pt_len];
        let ct = encrypt_with_frame_length(&pt, frame_length).await;
        let final_frame = parse_final_frame(&ct, frame_length);

        //= spec/client-apis/encrypt.md#construct-a-frame
        //= type=test
        //# - For a final frame this MUST be the length of the remaining plaintext bytes
        //# which have not yet been encrypted,
        //# whose length MUST be equal to or less than the frame length.
        //
        //= spec/client-apis/encrypt.md#construct-a-frame
        //= type=test
        //# - For a final frame this MUST be the remaining plaintext bytes which have not yet been encrypted,
        //# whose length MUST be equal to or less than the frame length.
        let Ok(final_len) = u32::try_from(final_frame.content.len()) else {
            panic!("content length exceeds u32::MAX");
        };
        assert_eq!(final_len, expected_final_len, "{label}");
        assert!(final_len <= frame_length, "{label}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_construct_frame_plaintext_subsequence_consumed_in_order() {
    // All-distinct bytes: any reorder, skip, or duplication breaks equality.
    let keyring = test_keyring().await;
    let pt: Vec<u8> = (0..=255).collect();
    let ct = Client::default()
        .encrypt()
        .plaintext(&pt)
        .keyring(keyring.clone())
        .frame_length(NonZeroU32::new(50).unwrap())
        .send()
        .await
        .unwrap()
        .ciphertext;

    //= spec/client-apis/encrypt.md#construct-a-frame
    //= type=test
    //# - The plaintext MUST be the next subsequence of consumable plaintext bytes that have not yet been encrypted.
    let result = Client::default()
        .decrypt()
        .ciphertext(&ct)
        .keyring(keyring)
        .send()
        .await
        .unwrap()
        .plaintext;
    assert_eq!(result, pt);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_construct_frame_regular_frame_field_serialization() {
    // 25 bytes / frame_length=10 → 2 regular frames at seq 1 and 2.
    let pt = vec![0xEEu8; 25];
    let frame_length = 10u32;
    let ct = encrypt_with_frame_length(&pt, frame_length).await;
    let frames = parse_all_frames(&ct, frame_length);
    let regular: Vec<_> = frames.iter().filter(|f| !f.is_final).collect();
    assert_eq!(regular.len(), 2);

    for (i, f) in regular.iter().enumerate() {
        let Ok(idx_u32) = u32::try_from(i) else {
            panic!("index exceeds u32::MAX");
        };
        let expected_seq = idx_u32 + 1;

        //= spec/client-apis/encrypt.md#construct-a-frame
        //= type=test
        //# - MUST serialize the [Sequence Number](../data-format/message-body.md#regular-frame-sequence-number).
        //# The value MUST be the sequence number of this frame.
        assert_eq!(f.seq_num, expected_seq, "frame {i}");

        //= spec/client-apis/encrypt.md#construct-a-frame
        //= type=test
        //# - MUST serialize the [IV](../data-format/message-body.md#regular-frame-iv).
        //# The value MUST be the IV used when calculating the encrypted content for this frame.
        assert_eq!(f.iv.len(), IV_LEN, "frame {i}");

        //= spec/client-apis/encrypt.md#construct-a-frame
        //= type=test
        //# - MUST serialize the [Encrypted Content](../data-format/message-body.md#regular-frame-encrypted-content).
        //# The value MUST be the encrypted content calculated for this frame.
        let Ok(content_len) = u32::try_from(f.content.len()) else {
            panic!("content length exceeds u32::MAX");
        };
        assert_eq!(content_len, frame_length, "frame {i}");

        //= spec/client-apis/encrypt.md#construct-a-frame
        //= type=test
        //# - MUST serialize the [Authentication Tag](../data-format/message-body.md#regular-frame-authentication-tag).
        //# The value MUST be the authentication tag output when calculating the encrypted content for this frame.
        assert_eq!(f.tag.len(), TAG_LEN, "frame {i}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_construct_frame_final_frame_field_serialization() {
    // 13 bytes / frame_length=10 → 1 regular (seq 1) + 1 final (seq 2, len 3).
    const PT_LEN: usize = 13;
    const FRAME_LEN: u32 = 10;
    const FINAL_CONTENT_LEN: u32 = (PT_LEN as u32) - FRAME_LEN; // 3

    let pt = vec![0x42u8; PT_LEN];
    let ct = encrypt_with_frame_length(&pt, FRAME_LEN).await;
    let final_frame = parse_final_frame(&ct, FRAME_LEN);

    //= spec/client-apis/encrypt.md#construct-a-frame
    //= type=test
    //# - MUST serialize the [Sequence Number End](../data-format/message-body.md#sequence-number-end).
    assert_eq!(
        final_frame
            .endframe_marker_bytes
            .expect("final frame has marker"),
        &ENDFRAME_MARKER
    );

    //= spec/client-apis/encrypt.md#construct-a-frame
    //= type=test
    //# - MUST serialize the [Sequence Number](../data-format/message-body.md#final-frame-sequence-number).
    //# The value MUST be the sequence number of this frame.
    assert_eq!(final_frame.seq_num, 2);

    //= spec/client-apis/encrypt.md#construct-a-frame
    //= type=test
    //# - MUST serialize the [IV](../data-format/message-body.md#final-frame-iv).
    assert_eq!(final_frame.iv.len(), IV_LEN);

    //= spec/client-apis/encrypt.md#construct-a-frame
    //= type=test
    //# - MUST serialize the [Encrypted Content Length](../data-format/message-body.md#final-frame-encrypted-content-length).
    // The on-wire content-length field decodes to FINAL_CONTENT_LEN.
    assert_eq!(final_frame.content_length, FINAL_CONTENT_LEN);

    //= spec/client-apis/encrypt.md#construct-a-frame
    //= type=test
    //# - MUST serialize the [Encrypted Content](../data-format/message-body.md#final-frame-encrypted-content).
    // The on-wire content slice is FINAL_CONTENT_LEN bytes long.
    let Ok(content_len) = u32::try_from(final_frame.content.len()) else {
        panic!("content length exceeds u32::MAX");
    };
    assert_eq!(content_len, FINAL_CONTENT_LEN);

    //= spec/client-apis/encrypt.md#construct-a-frame
    //= type=test
    //# - MUST serialize the [Authentication Tag](../data-format/message-body.md#final-frame-authentication-tag).
    assert_eq!(final_frame.tag.len(), TAG_LEN);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_construct_frame_streaming_frame_released() {
    let keyring = test_keyring().await;
    let plaintext = vec![0xAAu8; 50];
    let mut reader = std::io::Cursor::new(&plaintext);
    let mut output = Vec::new();
    Client::default()
        .encrypt_stream()
        .keyring(keyring.clone())
        .frame_length(NonZeroU32::new(10).unwrap())
        .send(&mut reader, &mut output)
        .await
        .expect("streaming encrypt");

    //= spec/client-apis/encrypt.md#construct-a-frame
    //= type=test
    //= reason=premature release of a partial frame would leave the ciphertext unparseable
    //# The serialized frame bytes MUST NOT be released until the entire frame has been serialized.
    //
    //= spec/client-apis/encrypt.md#construct-a-frame
    //= type=test
    //# If the Encrypt operation is streaming the encrypted message and
    //# the entire frame has been serialized,
    //# the serialized frame MUST be released.
    assert!(!output.is_empty());

    let decrypted = Client::default()
        .decrypt()
        .ciphertext(&output)
        .keyring(keyring)
        .send()
        .await
        .unwrap();
    assert_eq!(decrypted.plaintext, plaintext);
}

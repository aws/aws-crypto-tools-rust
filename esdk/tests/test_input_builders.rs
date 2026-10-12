// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for the operation fluent builders' setters.

mod test_helpers;

use aws_crypto_mpl::cmm::DefaultCmm;
use aws_esdk::{
    AlgorithmSuiteId, CommitmentPolicy, EncryptionContext, Esdk, SharedCmm, SharedKeyring,
};
use std::num::NonZeroU32;
use test_helpers::{count_frames, esdk_with, test_keyring};

const SUITE: AlgorithmSuiteId = AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256;
const POLICY: CommitmentPolicy = CommitmentPolicy::ForbidEncryptAllowDecrypt;
const DEFAULT_SUITE: AlgorithmSuiteId = AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384;
const FRAME_LENGTH: u32 = 1024;

fn ec() -> EncryptionContext {
    let mut ec = EncryptionContext::new();
    ec.insert("k", "v");
    ec
}

fn conflicting_ec() -> EncryptionContext {
    let mut ec = EncryptionContext::new();
    ec.insert("k", "other");
    ec
}

fn frame_length() -> NonZeroU32 {
    NonZeroU32::new(FRAME_LENGTH).unwrap()
}

/// Two full frames plus a one-byte final frame at `FRAME_LENGTH`.
fn plaintext() -> Vec<u8> {
    vec![0x42; 2 * FRAME_LENGTH as usize + 1]
}

#[tokio::test(flavor = "multi_thread")]
async fn test_send_requires_plaintext_and_ciphertext() {
    let keyring = SharedKeyring::new(test_keyring().await);
    let esdk = Esdk::default();

    let err = esdk
        .encrypt()
        .keyring(keyring.clone())
        .send()
        .await
        .expect_err("encrypt must fail without a plaintext");
    assert!(err.is_validation(), "{:?}", err);

    let err = esdk
        .decrypt()
        .keyring(keyring)
        .send()
        .await
        .expect_err("decrypt must fail without a ciphertext");
    assert!(err.is_validation(), "{:?}", err);
}

// The non-committing SUITE only encrypts under POLICY, so success shows the
// suite was applied; the frame count shows the frame length was applied.
#[tokio::test(flavor = "multi_thread")]
async fn test_encrypt_setters_take_effect() {
    let keyring = SharedKeyring::new(test_keyring().await);
    let esdk = esdk_with(POLICY);
    let plaintext = plaintext();

    let out = esdk
        .encrypt()
        .plaintext(&plaintext)
        .encryption_context(ec())
        .keyring(keyring.clone())
        .algorithm_suite_id(SUITE)
        .frame_length(frame_length())
        .send()
        .await
        .unwrap();
    assert_eq!(out.algorithm_suite_id, SUITE);
    assert_eq!(out.encryption_context, ec());
    assert_eq!(count_frames(&out.ciphertext, FRAME_LENGTH), (2, 1));

    let out = esdk
        .encrypt()
        .plaintext(&plaintext)
        .set_encryption_context(Some(ec()))
        .set_keyring(Some(keyring.clone()))
        .set_algorithm_suite_id(Some(SUITE))
        .set_frame_length(Some(frame_length()))
        .send()
        .await
        .unwrap();
    assert_eq!(out.algorithm_suite_id, SUITE);
    assert_eq!(out.encryption_context, ec());
    assert_eq!(count_frames(&out.ciphertext, FRAME_LENGTH), (2, 1));

    let out = Esdk::default()
        .encrypt()
        .plaintext(&plaintext)
        .keyring(keyring.clone())
        .algorithm_suite_id(SUITE)
        .set_algorithm_suite_id(None)
        .frame_length(frame_length())
        .set_frame_length(None)
        .encryption_context(ec())
        .set_encryption_context(None)
        .send()
        .await
        .unwrap();
    assert_eq!(out.algorithm_suite_id, DEFAULT_SUITE);
    assert_eq!(count_frames(&out.ciphertext, 4096), (0, 1));
    assert!(!out.encryption_context.contains_key("k"));

    let cmm = SharedCmm::new(DefaultCmm::new(keyring.clone()));
    Esdk::default()
        .encrypt()
        .plaintext(&plaintext)
        .cmm(cmm.clone())
        .send()
        .await
        .expect("encrypt with only a CMM must succeed");

    Esdk::default()
        .encrypt()
        .plaintext(&plaintext)
        .keyring(keyring)
        .set_keyring(None)
        .set_cmm(Some(cmm))
        .send()
        .await
        .expect("set_keyring(None) must leave only the CMM");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_encrypt_stream_setters_take_effect() {
    let keyring = SharedKeyring::new(test_keyring().await);
    let esdk = esdk_with(POLICY);
    let plaintext = plaintext();

    let mut ct = Vec::new();
    let out = esdk
        .encrypt_stream()
        .encryption_context(ec())
        .keyring(keyring.clone())
        .algorithm_suite_id(SUITE)
        .frame_length(frame_length())
        .data_size(plaintext.len())
        .send(plaintext.as_slice(), &mut ct)
        .await
        .unwrap();
    assert_eq!(out.algorithm_suite_id, SUITE);
    assert_eq!(out.encryption_context, ec());
    assert_eq!(count_frames(&ct, FRAME_LENGTH), (2, 1));

    let mut ct = Vec::new();
    let out = esdk
        .encrypt_stream()
        .set_encryption_context(Some(ec()))
        .set_keyring(Some(keyring.clone()))
        .set_algorithm_suite_id(Some(SUITE))
        .set_frame_length(Some(frame_length()))
        .set_data_size(Some(plaintext.len()))
        .send(plaintext.as_slice(), &mut ct)
        .await
        .unwrap();
    assert_eq!(out.algorithm_suite_id, SUITE);
    assert_eq!(out.encryption_context, ec());
    assert_eq!(count_frames(&ct, FRAME_LENGTH), (2, 1));

    let err = Esdk::default()
        .encrypt_stream()
        .keyring(keyring.clone())
        .data_size(1)
        .send(plaintext.as_slice(), Vec::new())
        .await
        .expect_err("plaintext longer than data_size must fail");
    assert!(err.is_validation(), "{:?}", err);

    Esdk::default()
        .encrypt_stream()
        .keyring(keyring.clone())
        .data_size(1)
        .set_data_size(None)
        .send(plaintext.as_slice(), Vec::new())
        .await
        .expect("set_data_size(None) must clear the bound");

    let cmm = SharedCmm::new(DefaultCmm::new(keyring));
    Esdk::default()
        .encrypt_stream()
        .cmm(cmm.clone())
        .send(plaintext.as_slice(), Vec::new())
        .await
        .expect("encrypt_stream with cmm must succeed");
    Esdk::default()
        .encrypt_stream()
        .set_cmm(Some(cmm))
        .send(plaintext.as_slice(), Vec::new())
        .await
        .expect("encrypt_stream with set_cmm must succeed");
}

// A reproduced encryption context that conflicts with the message fails, so a
// matching one succeeding and a conflicting one failing shows it was applied.
#[tokio::test(flavor = "multi_thread")]
async fn test_decrypt_setters_take_effect() {
    let keyring = SharedKeyring::new(test_keyring().await);
    let esdk = esdk_with(POLICY);
    let ct = esdk
        .encrypt()
        .plaintext(b"plaintext")
        .encryption_context(ec())
        .keyring(keyring.clone())
        .algorithm_suite_id(SUITE)
        .send()
        .await
        .unwrap()
        .ciphertext;

    let out = esdk
        .decrypt()
        .ciphertext(&ct)
        .encryption_context(ec())
        .keyring(keyring.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(out.plaintext, b"plaintext");
    assert_eq!(out.algorithm_suite_id, SUITE);

    let err = esdk
        .decrypt()
        .ciphertext(&ct)
        .encryption_context(conflicting_ec())
        .keyring(keyring.clone())
        .send()
        .await
        .expect_err("conflicting encryption context must fail");
    assert!(err.is_encryption_context_mismatch(), "{:?}", err);

    let err = esdk
        .decrypt()
        .ciphertext(&ct)
        .set_encryption_context(Some(conflicting_ec()))
        .set_keyring(Some(keyring.clone()))
        .send()
        .await
        .expect_err("conflicting encryption context must fail");
    assert!(err.is_encryption_context_mismatch(), "{:?}", err);

    esdk.decrypt()
        .ciphertext(&ct)
        .keyring(keyring.clone())
        .encryption_context(conflicting_ec())
        .set_encryption_context(None)
        .send()
        .await
        .expect("set_encryption_context(None) must clear the reproduced context");

    let cmm = SharedCmm::new(DefaultCmm::new(keyring.clone()));
    esdk.decrypt()
        .ciphertext(&ct)
        .cmm(cmm.clone())
        .send()
        .await
        .expect("decrypt with only a CMM must succeed");
    esdk.decrypt()
        .ciphertext(&ct)
        .keyring(keyring)
        .set_keyring(None)
        .set_cmm(Some(cmm))
        .send()
        .await
        .expect("set_keyring(None) must leave only the CMM");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_decrypt_stream_setters_take_effect() {
    let keyring = SharedKeyring::new(test_keyring().await);
    let esdk = Esdk::default();
    let ct = esdk
        .encrypt()
        .plaintext(b"plaintext")
        .encryption_context(ec())
        .keyring(keyring.clone())
        .send()
        .await
        .unwrap()
        .ciphertext;

    let mut pt = Vec::new();
    esdk.decrypt_stream()
        .encryption_context(ec())
        .keyring(keyring.clone())
        .send(ct.as_slice(), &mut pt)
        .await
        .unwrap();
    assert_eq!(pt, b"plaintext");

    let err = esdk
        .decrypt_stream()
        .encryption_context(conflicting_ec())
        .keyring(keyring.clone())
        .send(ct.as_slice(), Vec::new())
        .await
        .expect_err("conflicting encryption context must fail");
    assert!(err.is_encryption_context_mismatch(), "{:?}", err);

    let err = esdk
        .decrypt_stream()
        .set_encryption_context(Some(conflicting_ec()))
        .set_keyring(Some(keyring.clone()))
        .send(ct.as_slice(), Vec::new())
        .await
        .expect_err("conflicting encryption context must fail");
    assert!(err.is_encryption_context_mismatch(), "{:?}", err);

    let cmm = SharedCmm::new(DefaultCmm::new(keyring));
    esdk.decrypt_stream()
        .cmm(cmm.clone())
        .send(ct.as_slice(), Vec::new())
        .await
        .expect("decrypt_stream with cmm must succeed");
    esdk.decrypt_stream()
        .set_cmm(Some(cmm))
        .send(ct.as_slice(), Vec::new())
        .await
        .expect("decrypt_stream with set_cmm must succeed");
}

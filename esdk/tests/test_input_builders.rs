// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for the operation fluent builders' setters.

mod test_helpers;

use aws_crypto_mpl::cmm::DefaultCmm;
use aws_esdk::{
    AlgorithmSuiteId, Client, CommitmentPolicy, EncryptionContext, SharedCmm, SharedKeyring,
};
use std::num::{NonZeroU32, NonZeroUsize};
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
    let esdk = Client::default();

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

// The non-committing SUITE encrypts only under POLICY, so success shows the suite was set.
// The frame count shows the frame length was set.
#[tokio::test(flavor = "multi_thread")]
async fn test_encrypt_setters_take_effect() {
    let keyring = SharedKeyring::new(test_keyring().await);
    let esdk = esdk_with(POLICY);
    let plaintext = plaintext();

    let out = esdk
        .encrypt()
        .plaintext(&plaintext)
        .set_encryption_context(Some(ec()))
        .keyring(keyring.clone())
        .algorithm_suite_id(SUITE)
        .frame_length(frame_length())
        .send()
        .await
        .unwrap();
    assert_eq!(out.algorithm_suite_id(), SUITE);
    assert_eq!(*out.encryption_context(), ec());
    assert_eq!(count_frames(out.ciphertext(), FRAME_LENGTH), (2, 1));

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
    assert_eq!(out.algorithm_suite_id(), SUITE);
    assert_eq!(*out.encryption_context(), ec());
    assert_eq!(count_frames(out.ciphertext(), FRAME_LENGTH), (2, 1));

    let out = Client::default()
        .encrypt()
        .plaintext(&plaintext)
        .keyring(keyring.clone())
        .algorithm_suite_id(SUITE)
        .set_algorithm_suite_id(None)
        .frame_length(frame_length())
        .set_frame_length(None)
        .set_encryption_context(Some(ec()))
        .set_encryption_context(None)
        .send()
        .await
        .unwrap();
    assert_eq!(out.algorithm_suite_id(), DEFAULT_SUITE);
    assert_eq!(count_frames(out.ciphertext(), 4096), (0, 1));
    assert!(!out.encryption_context().contains_key("k"));

    let cmm = SharedCmm::new(DefaultCmm::new(keyring.clone()));
    Client::default()
        .encrypt()
        .plaintext(&plaintext)
        .cmm(cmm.clone())
        .send()
        .await
        .expect("encrypt with only a CMM must succeed");

    Client::default()
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
        .set_encryption_context(Some(ec()))
        .keyring(keyring.clone())
        .algorithm_suite_id(SUITE)
        .frame_length(frame_length())
        .data_size(plaintext.len())
        .plaintext(plaintext.as_slice())
        .ciphertext(&mut ct)
        .send()
        .await
        .unwrap();
    assert_eq!(out.algorithm_suite_id(), SUITE);
    assert_eq!(*out.encryption_context(), ec());
    assert_eq!(count_frames(&ct, FRAME_LENGTH), (2, 1));

    let mut ct = Vec::new();
    let out = esdk
        .encrypt_stream()
        .set_encryption_context(Some(ec()))
        .set_keyring(Some(keyring.clone()))
        .set_algorithm_suite_id(Some(SUITE))
        .set_frame_length(Some(frame_length()))
        .set_data_size(Some(plaintext.len()))
        .plaintext(plaintext.as_slice())
        .ciphertext(&mut ct)
        .send()
        .await
        .unwrap();
    assert_eq!(out.algorithm_suite_id(), SUITE);
    assert_eq!(*out.encryption_context(), ec());
    assert_eq!(count_frames(&ct, FRAME_LENGTH), (2, 1));

    let err = Client::default()
        .encrypt_stream()
        .keyring(keyring.clone())
        .data_size(1)
        .plaintext(plaintext.as_slice())
        .ciphertext(Vec::new())
        .send()
        .await
        .expect_err("plaintext longer than data_size must fail");
    assert!(err.is_validation(), "{:?}", err);

    Client::default()
        .encrypt_stream()
        .keyring(keyring.clone())
        .data_size(1)
        .set_data_size(None)
        .plaintext(plaintext.as_slice())
        .ciphertext(Vec::new())
        .send()
        .await
        .expect("set_data_size(None) must clear the bound");

    let cmm = SharedCmm::new(DefaultCmm::new(keyring.clone()));
    Client::default()
        .encrypt_stream()
        .cmm(cmm.clone())
        .plaintext(plaintext.as_slice())
        .ciphertext(Vec::new())
        .send()
        .await
        .expect("encrypt_stream with cmm must succeed");
    Client::default()
        .encrypt_stream()
        .set_cmm(Some(cmm))
        .plaintext(plaintext.as_slice())
        .ciphertext(Vec::new())
        .send()
        .await
        .expect("encrypt_stream with set_cmm must succeed");

    let mut ct = Vec::new();
    Client::default()
        .encrypt_stream()
        .keyring(keyring.clone())
        .set_plaintext(Some(Box::new(plaintext.as_slice())))
        .set_ciphertext(Some(Box::new(&mut ct)))
        .send()
        .await
        .expect("set_plaintext and set_ciphertext must set the streams");
    assert!(!ct.is_empty());

    let no_plaintext = Client::default()
        .encrypt_stream()
        .keyring(keyring.clone())
        .ciphertext(Vec::new())
        .send()
        .await;
    let no_ciphertext = Client::default()
        .encrypt_stream()
        .keyring(keyring)
        .plaintext(plaintext.as_slice())
        .send()
        .await;
    for (case, result) in [("plaintext", no_plaintext), ("ciphertext", no_ciphertext)] {
        let err = result.expect_err("a missing stream must fail");
        assert!(err.is_validation(), "{case}: {err:?}");
    }
}

// A matching reproduced encryption context succeeds and a conflicting one fails.
#[tokio::test(flavor = "multi_thread")]
async fn test_decrypt_setters_take_effect() {
    let keyring = SharedKeyring::new(test_keyring().await);
    let esdk = esdk_with(POLICY);
    let ct = esdk
        .encrypt()
        .plaintext(b"plaintext")
        .set_encryption_context(Some(ec()))
        .keyring(keyring.clone())
        .algorithm_suite_id(SUITE)
        .send()
        .await
        .unwrap()
        .into_ciphertext();

    let out = esdk
        .decrypt()
        .ciphertext(&ct)
        .set_encryption_context(Some(ec()))
        .keyring(keyring.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(out.plaintext(), b"plaintext");
    assert_eq!(out.algorithm_suite_id(), SUITE);

    let err = esdk
        .decrypt()
        .ciphertext(&ct)
        .set_encryption_context(Some(conflicting_ec()))
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
        .set_encryption_context(Some(conflicting_ec()))
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
    let esdk = Client::default();
    let ct = esdk
        .encrypt()
        .plaintext(b"plaintext")
        .set_encryption_context(Some(ec()))
        .keyring(keyring.clone())
        .send()
        .await
        .unwrap()
        .into_ciphertext();

    let mut pt = Vec::new();
    esdk.decrypt_stream()
        .set_encryption_context(Some(ec()))
        .keyring(keyring.clone())
        .ciphertext(ct.as_slice())
        .plaintext(&mut pt)
        .send()
        .await
        .unwrap();
    assert_eq!(pt, b"plaintext");

    let err = esdk
        .decrypt_stream()
        .set_encryption_context(Some(conflicting_ec()))
        .keyring(keyring.clone())
        .ciphertext(ct.as_slice())
        .plaintext(Vec::new())
        .send()
        .await
        .expect_err("conflicting encryption context must fail");
    assert!(err.is_encryption_context_mismatch(), "{:?}", err);

    let err = esdk
        .decrypt_stream()
        .set_encryption_context(Some(conflicting_ec()))
        .set_keyring(Some(keyring.clone()))
        .ciphertext(ct.as_slice())
        .plaintext(Vec::new())
        .send()
        .await
        .expect_err("conflicting encryption context must fail");
    assert!(err.is_encryption_context_mismatch(), "{:?}", err);

    let cmm = SharedCmm::new(DefaultCmm::new(keyring.clone()));
    esdk.decrypt_stream()
        .cmm(cmm.clone())
        .ciphertext(ct.as_slice())
        .plaintext(Vec::new())
        .send()
        .await
        .expect("decrypt_stream with cmm must succeed");
    esdk.decrypt_stream()
        .set_cmm(Some(cmm))
        .ciphertext(ct.as_slice())
        .plaintext(Vec::new())
        .send()
        .await
        .expect("decrypt_stream with set_cmm must succeed");

    let mut pt = Vec::new();
    esdk.decrypt_stream()
        .keyring(keyring.clone())
        .set_ciphertext(Some(Box::new(ct.as_slice())))
        .set_plaintext(Some(Box::new(&mut pt)))
        .send()
        .await
        .expect("set_ciphertext and set_plaintext must set the streams");
    assert_eq!(pt, b"plaintext");

    let no_ciphertext = esdk
        .decrypt_stream()
        .keyring(keyring.clone())
        .plaintext(Vec::new())
        .send()
        .await;
    let no_plaintext = esdk
        .decrypt_stream()
        .keyring(keyring)
        .ciphertext(ct.as_slice())
        .send()
        .await;
    for (case, result) in [("ciphertext", no_ciphertext), ("plaintext", no_plaintext)] {
        let err = result.expect_err("a missing stream must fail");
        assert!(err.is_validation(), "{case}: {err:?}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_getters_return_set_values() {
    let keyring = SharedKeyring::new(test_keyring().await);
    let cmm = SharedCmm::new(DefaultCmm::new(keyring.clone()));
    let bytes = plaintext();
    let edks = NonZeroUsize::new(3).unwrap();
    let esdk = Client::default();

    let b = Client::builder();
    assert_eq!(
        (b.get_commitment_policy(), b.get_max_encrypted_data_keys()),
        (&None, &None)
    );
    let b = b.commitment_policy(POLICY).max_encrypted_data_keys(edks);
    assert_eq!(b.get_commitment_policy(), &Some(POLICY));
    assert_eq!(b.get_max_encrypted_data_keys(), &Some(edks));

    let b = esdk.encrypt();
    assert!(b.get_plaintext().is_none() && b.get_encryption_context().is_none());
    assert!(b.get_keyring().is_none() && b.get_cmm().is_none());
    assert!(b.get_algorithm_suite_id().is_none() && b.get_frame_length().is_none());
    let b = b
        .plaintext(&bytes)
        .set_encryption_context(Some(ec()))
        .keyring(keyring.clone())
        .cmm(cmm.clone())
        .algorithm_suite_id(SUITE)
        .frame_length(frame_length());
    assert_eq!(b.get_plaintext(), &Some(bytes.as_slice()));
    assert_eq!(b.get_encryption_context(), &Some(ec()));
    assert!(b.get_keyring().is_some() && b.get_cmm().is_some());
    assert_eq!(b.get_algorithm_suite_id(), &Some(SUITE));
    assert_eq!(b.get_frame_length(), &Some(frame_length()));

    let b = esdk.encrypt_stream();
    assert!(b.get_plaintext().is_none() && b.get_ciphertext().is_none());
    assert!(b.get_encryption_context().is_none() && b.get_data_size().is_none());
    assert!(b.get_keyring().is_none() && b.get_cmm().is_none());
    assert!(b.get_algorithm_suite_id().is_none() && b.get_frame_length().is_none());
    let b = b
        .plaintext(bytes.as_slice())
        .ciphertext(Vec::new())
        .set_encryption_context(Some(ec()))
        .keyring(keyring.clone())
        .cmm(cmm.clone())
        .algorithm_suite_id(SUITE)
        .frame_length(frame_length())
        .data_size(bytes.len());
    assert_eq!(b.get_encryption_context(), &Some(ec()));
    assert!(b.get_keyring().is_some() && b.get_cmm().is_some());
    assert_eq!(b.get_algorithm_suite_id(), &Some(SUITE));
    assert_eq!(b.get_frame_length(), &Some(frame_length()));
    assert_eq!(b.get_data_size(), &Some(bytes.len()));
    assert!(b.get_plaintext().is_some() && b.get_ciphertext().is_some());

    let b = esdk.decrypt();
    assert!(b.get_ciphertext().is_none() && b.get_encryption_context().is_none());
    assert!(b.get_keyring().is_none() && b.get_cmm().is_none());
    let b = b
        .ciphertext(&bytes)
        .set_encryption_context(Some(ec()))
        .keyring(keyring.clone())
        .cmm(cmm.clone());
    assert_eq!(b.get_ciphertext(), &Some(bytes.as_slice()));
    assert_eq!(b.get_encryption_context(), &Some(ec()));
    assert!(b.get_keyring().is_some() && b.get_cmm().is_some());

    let b = esdk.decrypt_stream();
    assert!(b.get_ciphertext().is_none() && b.get_plaintext().is_none());
    assert!(b.get_encryption_context().is_none());
    assert!(b.get_keyring().is_none() && b.get_cmm().is_none());
    let b = b
        .ciphertext(bytes.as_slice())
        .plaintext(Vec::new())
        .set_encryption_context(Some(ec()))
        .keyring(keyring)
        .cmm(cmm);
    assert!(b.get_ciphertext().is_some() && b.get_plaintext().is_some());
    assert_eq!(b.get_encryption_context(), &Some(ec()));
    assert!(b.get_keyring().is_some() && b.get_cmm().is_some());
}

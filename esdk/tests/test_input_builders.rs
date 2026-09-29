// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for the operation input builders.

mod test_helpers;

use aws_crypto_mpl::cmm::DefaultCmm;
use aws_esdk::{
    AlgorithmSuiteId, CommitmentPolicy, DecryptInput, DecryptStreamInput, EncryptInput,
    EncryptStreamInput, EncryptionContext, ErrorKind, SharedCmm, SharedKeyring,
};
use std::num::NonZeroU32;
use std::num::NonZeroUsize;
use test_helpers::test_keyring;

const SUITE: AlgorithmSuiteId = AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256;
const POLICY: CommitmentPolicy = CommitmentPolicy::ForbidEncryptAllowDecrypt;

fn cap() -> NonZeroUsize {
    NonZeroUsize::new(3).unwrap()
}

fn ec() -> EncryptionContext {
    let mut ec = EncryptionContext::new();
    ec.insert("k", "v");
    ec
}

fn frame_length() -> NonZeroU32 {
    NonZeroU32::new(1024).unwrap()
}

fn same_keyring(a: Option<&SharedKeyring>, b: &SharedKeyring) -> bool {
    a.is_some_and(|a| SharedKeyring::ptr_eq(a, b))
}

fn same_cmm(a: Option<&SharedCmm>, b: &SharedCmm) -> bool {
    a.is_some_and(|a| SharedCmm::ptr_eq(a, b))
}

#[tokio::test(flavor = "multi_thread")]
async fn test_build_requires_plaintext_and_ciphertext() {
    let keyring = SharedKeyring::new(test_keyring().await);
    let err = EncryptInput::builder()
        .keyring(keyring.clone())
        .build()
        .expect_err("EncryptInput build must fail without a plaintext");
    assert_eq!(err.kind(), ErrorKind::ValidationError);

    let err = DecryptInput::builder()
        .keyring(keyring)
        .build()
        .expect_err("DecryptInput build must fail without a ciphertext");
    assert_eq!(err.kind(), ErrorKind::ValidationError);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_encrypt_input_setters_round_trip() {
    let keyring = SharedKeyring::new(test_keyring().await);
    let ec = ec();
    let plaintext = b"plaintext";

    let input = EncryptInput::builder()
        .plaintext(plaintext)
        .encryption_context(ec.clone())
        .keyring(keyring.clone())
        .algorithm_suite_id(SUITE)
        .frame_length(frame_length())
        .max_encrypted_data_keys(cap())
        .commitment_policy(POLICY)
        .build()
        .unwrap();
    assert_eq!(input.plaintext(), plaintext);
    assert_eq!(input.encryption_context(), &ec);
    assert!(same_keyring(input.keyring(), &keyring));
    assert!(input.cmm().is_none());
    assert_eq!(input.algorithm_suite_id(), Some(SUITE));
    assert_eq!(input.frame_length(), frame_length());
    assert_eq!(input.max_encrypted_data_keys(), Some(cap()));
    assert_eq!(input.commitment_policy(), POLICY);

    let input = EncryptInput::builder()
        .plaintext(plaintext)
        .set_encryption_context(Some(ec.clone()))
        .set_keyring(Some(keyring.clone()))
        .set_algorithm_suite_id(Some(SUITE))
        .set_frame_length(Some(frame_length()))
        .set_max_encrypted_data_keys(Some(cap()))
        .set_commitment_policy(Some(POLICY))
        .build()
        .unwrap();
    assert_eq!(input.encryption_context(), &ec);
    assert!(same_keyring(input.keyring(), &keyring));
    assert_eq!(input.algorithm_suite_id(), Some(SUITE));
    assert_eq!(input.frame_length(), frame_length());
    assert_eq!(input.max_encrypted_data_keys(), Some(cap()));
    assert_eq!(input.commitment_policy(), POLICY);

    let input = EncryptInput::builder()
        .plaintext(plaintext)
        .keyring(keyring.clone())
        .algorithm_suite_id(SUITE)
        .set_algorithm_suite_id(None)
        .frame_length(frame_length())
        .set_frame_length(None)
        .max_encrypted_data_keys(cap())
        .set_max_encrypted_data_keys(None)
        .commitment_policy(POLICY)
        .set_commitment_policy(None)
        .encryption_context(ec)
        .set_encryption_context(None)
        .build()
        .unwrap();
    assert_eq!(input.algorithm_suite_id(), None);
    assert_eq!(input.frame_length().get(), 4096);
    assert_eq!(input.max_encrypted_data_keys(), None);
    assert_eq!(
        input.commitment_policy(),
        CommitmentPolicy::RequireEncryptRequireDecrypt
    );
    assert!(input.encryption_context().is_empty());

    let cmm = SharedCmm::new(DefaultCmm::new(keyring.clone()));
    let input = EncryptInput::builder()
        .plaintext(plaintext)
        .cmm(cmm.clone())
        .build()
        .unwrap();
    assert!(same_cmm(input.cmm(), &cmm));
    assert!(input.keyring().is_none());

    let input = EncryptInput::builder()
        .plaintext(plaintext)
        .keyring(keyring)
        .set_keyring(None)
        .set_cmm(Some(cmm.clone()))
        .build()
        .unwrap();
    assert!(same_cmm(input.cmm(), &cmm));
    assert!(input.keyring().is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_encrypt_stream_input_setters_round_trip() {
    let keyring = SharedKeyring::new(test_keyring().await);
    let ec = ec();

    let input = EncryptStreamInput::builder()
        .encryption_context(ec.clone())
        .keyring(keyring.clone())
        .algorithm_suite_id(SUITE)
        .frame_length(frame_length())
        .data_size(42)
        .max_encrypted_data_keys(cap())
        .commitment_policy(POLICY)
        .build()
        .unwrap();
    assert_eq!(input.encryption_context(), &ec);
    assert!(same_keyring(input.keyring(), &keyring));
    assert_eq!(input.algorithm_suite_id(), Some(SUITE));
    assert_eq!(input.frame_length(), frame_length());
    assert_eq!(input.data_size(), Some(42));
    assert_eq!(input.max_encrypted_data_keys(), Some(cap()));
    assert_eq!(input.commitment_policy(), POLICY);

    let input = EncryptStreamInput::builder()
        .set_encryption_context(Some(ec))
        .set_keyring(Some(keyring.clone()))
        .set_algorithm_suite_id(Some(SUITE))
        .set_frame_length(Some(frame_length()))
        .set_data_size(Some(42))
        .set_max_encrypted_data_keys(Some(cap()))
        .set_commitment_policy(Some(POLICY))
        .build()
        .unwrap();
    assert!(same_keyring(input.keyring(), &keyring));
    assert_eq!(input.algorithm_suite_id(), Some(SUITE));
    assert_eq!(input.frame_length(), frame_length());
    assert_eq!(input.data_size(), Some(42));
    assert_eq!(input.max_encrypted_data_keys(), Some(cap()));
    assert_eq!(input.commitment_policy(), POLICY);

    let input = EncryptStreamInput::builder()
        .keyring(keyring.clone())
        .data_size(42)
        .set_data_size(None)
        .build()
        .unwrap();
    assert_eq!(input.data_size(), None);

    let cmm = SharedCmm::new(DefaultCmm::new(keyring));
    let input = EncryptStreamInput::builder()
        .cmm(cmm.clone())
        .build()
        .unwrap();
    assert!(same_cmm(input.cmm(), &cmm));
    let input = EncryptStreamInput::builder()
        .set_cmm(Some(cmm.clone()))
        .build()
        .unwrap();
    assert!(same_cmm(input.cmm(), &cmm));
}

#[tokio::test(flavor = "multi_thread")]
async fn test_decrypt_input_setters_round_trip() {
    let keyring = SharedKeyring::new(test_keyring().await);
    let ec = ec();
    let ciphertext = b"ciphertext";

    let input = DecryptInput::builder()
        .ciphertext(ciphertext)
        .encryption_context(ec.clone())
        .keyring(keyring.clone())
        .max_encrypted_data_keys(cap())
        .commitment_policy(POLICY)
        .build()
        .unwrap();
    assert_eq!(input.ciphertext(), ciphertext);
    assert_eq!(input.encryption_context(), &ec);
    assert!(same_keyring(input.keyring(), &keyring));
    assert!(input.cmm().is_none());
    assert_eq!(input.max_encrypted_data_keys(), Some(cap()));
    assert_eq!(input.commitment_policy(), POLICY);

    let input = DecryptInput::builder()
        .ciphertext(ciphertext)
        .set_encryption_context(Some(ec))
        .set_keyring(Some(keyring.clone()))
        .set_max_encrypted_data_keys(Some(cap()))
        .set_commitment_policy(Some(POLICY))
        .build()
        .unwrap();
    assert!(same_keyring(input.keyring(), &keyring));
    assert_eq!(input.max_encrypted_data_keys(), Some(cap()));
    assert_eq!(input.commitment_policy(), POLICY);

    let cmm = SharedCmm::new(DefaultCmm::new(keyring));
    let input = DecryptInput::builder()
        .ciphertext(ciphertext)
        .cmm(cmm.clone())
        .build()
        .unwrap();
    assert!(same_cmm(input.cmm(), &cmm));
    let input = DecryptInput::builder()
        .ciphertext(ciphertext)
        .set_cmm(Some(cmm.clone()))
        .build()
        .unwrap();
    assert!(same_cmm(input.cmm(), &cmm));
}

#[tokio::test(flavor = "multi_thread")]
async fn test_decrypt_stream_input_setters_round_trip() {
    let keyring = SharedKeyring::new(test_keyring().await);
    let ec = ec();

    let input = DecryptStreamInput::builder()
        .encryption_context(ec.clone())
        .keyring(keyring.clone())
        .max_encrypted_data_keys(cap())
        .commitment_policy(POLICY)
        .build()
        .unwrap();
    assert_eq!(input.encryption_context(), &ec);
    assert!(same_keyring(input.keyring(), &keyring));
    assert_eq!(input.max_encrypted_data_keys(), Some(cap()));
    assert_eq!(input.commitment_policy(), POLICY);

    let input = DecryptStreamInput::builder()
        .set_encryption_context(Some(ec))
        .set_keyring(Some(keyring.clone()))
        .set_max_encrypted_data_keys(Some(cap()))
        .set_commitment_policy(Some(POLICY))
        .build()
        .unwrap();
    assert!(same_keyring(input.keyring(), &keyring));
    assert_eq!(input.max_encrypted_data_keys(), Some(cap()));
    assert_eq!(input.commitment_policy(), POLICY);

    let cmm = SharedCmm::new(DefaultCmm::new(keyring));
    let input = DecryptStreamInput::builder()
        .cmm(cmm.clone())
        .build()
        .unwrap();
    assert!(same_cmm(input.cmm(), &cmm));
    let input = DecryptStreamInput::builder()
        .set_cmm(Some(cmm.clone()))
        .build()
        .unwrap();
    assert!(same_cmm(input.cmm(), &cmm));
}

// The builder_from_encrypt helpers carry every shared field of the
// encrypt input over.
#[tokio::test(flavor = "multi_thread")]
async fn test_builder_from_encrypt_copies_shared_fields() {
    let keyring = SharedKeyring::new(test_keyring().await);
    let ec = ec();
    let enc = EncryptInput::builder()
        .plaintext(b"pt")
        .encryption_context(ec.clone())
        .keyring(keyring.clone())
        .max_encrypted_data_keys(cap())
        .commitment_policy(POLICY)
        .build()
        .unwrap();

    let dec = DecryptInput::builder_from_encrypt(&enc)
        .ciphertext(b"ct")
        .build()
        .unwrap();
    assert_eq!(dec.ciphertext(), b"ct");
    assert_eq!(dec.encryption_context(), &ec);
    assert!(same_keyring(dec.keyring(), &keyring));
    assert_eq!(dec.max_encrypted_data_keys(), Some(cap()));
    assert_eq!(dec.commitment_policy(), POLICY);

    let dec = DecryptStreamInput::builder_from_encrypt(&enc)
        .build()
        .unwrap();
    assert_eq!(dec.encryption_context(), &ec);
    assert!(same_keyring(dec.keyring(), &keyring));
    assert_eq!(dec.max_encrypted_data_keys(), Some(cap()));
    assert_eq!(dec.commitment_policy(), POLICY);
}

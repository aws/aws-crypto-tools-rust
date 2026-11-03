// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for `RequiredEncryptionContextCmm` (Dafny RequiredEncryptionContextCMM.dfy).

use aws_crypto_mpl::cmm::{DefaultCmm, RequiredEncryptionContextCmm, SharedCmm};
use aws_crypto_mpl::keyring::RawAesKeyring;
use aws_crypto_mpl::types::{
    AesWrappingAlg, AlgorithmSuiteId, CommitmentPolicy, EncryptionContext, EsdkAlgorithmSuiteId,
    EsdkCommitmentPolicy,
};

const POLICY: CommitmentPolicy =
    CommitmentPolicy::Esdk(EsdkCommitmentPolicy::RequireEncryptRequireDecrypt);
const SUITE: AlgorithmSuiteId =
    AlgorithmSuiteId::Esdk(EsdkAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey);

fn cmm() -> SharedCmm {
    let keyring = RawAesKeyring::builder()
        .key_namespace("ns")
        .key_name("name")
        .wrapping_key(vec![9u8; 32])
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()
        .unwrap();
    SharedCmm::new(
        RequiredEncryptionContextCmm::builder()
            .underlying_cmm(DefaultCmm::new(keyring))
            .required_encryption_context_keys("tenant")
            .build()
            .unwrap(),
    )
}

fn ec(pairs: &[(&str, &str)]) -> EncryptionContext {
    let mut ec = EncryptionContext::new();
    for (k, v) in pairs {
        ec.insert(*k, *v);
    }
    ec
}

#[test]
fn build_needs_an_underlying_cmm_and_a_key() {
    assert!(
        RequiredEncryptionContextCmm::builder()
            .required_encryption_context_keys("k")
            .build()
            .unwrap_err()
            .is_validation()
    );
    let keyring = RawAesKeyring::builder()
        .key_namespace("ns")
        .key_name("name")
        .wrapping_key(vec![9u8; 32])
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()
        .unwrap();
    assert!(
        RequiredEncryptionContextCmm::builder()
            .underlying_cmm(DefaultCmm::new(keyring))
            .build()
            .unwrap_err()
            .is_validation()
    );
}

#[tokio::test]
async fn required_keys_are_marked_on_encrypt_and_must_be_reproduced_on_decrypt() {
    let cmm = cmm();
    let missing = cmm
        .get_encryption_materials()
        .set_encryption_context(Some(ec(&[("other", "x")])))
        .commitment_policy(POLICY)
        .send()
        .await
        .unwrap_err();
    assert!(missing.is_encryption_context_mismatch(), "{missing:?}");

    let enc = cmm
        .get_encryption_materials()
        .set_encryption_context(Some(ec(&[("tenant", "a"), ("other", "x")])))
        .commitment_policy(POLICY)
        .algorithm_suite_id(SUITE)
        .send()
        .await
        .unwrap()
        .into_encryption_materials();
    assert!(enc.required_encryption_context_keys().contains("tenant"));

    let decrypt = |reproduced: Option<EncryptionContext>| {
        cmm.decrypt_materials()
            .algorithm_suite_id(SUITE)
            .commitment_policy(POLICY)
            .set_encrypted_data_keys(Some(enc.encrypted_data_keys().to_vec()))
            .set_encryption_context(Some(ec(&[("other", "x")])))
            .set_reproduced_encryption_context(reproduced)
            .send()
    };
    assert!(
        decrypt(None)
            .await
            .unwrap_err()
            .is_encryption_context_mismatch()
    );
    assert!(
        decrypt(Some(ec(&[("other", "x")])))
            .await
            .unwrap_err()
            .is_encryption_context_mismatch()
    );
    assert!(
        decrypt(Some(ec(&[("tenant", "a"), ("other", "y")])))
            .await
            .unwrap_err()
            .is_encryption_context_mismatch()
    );
    let dec = decrypt(Some(ec(&[("tenant", "a")])))
        .await
        .unwrap()
        .into_decryption_materials();
    assert!(
        dec.plaintext_data_key()
            .unwrap()
            .ct_eq(enc.plaintext_data_key().unwrap())
    );
    assert_eq!(dec.encryption_context().get("tenant"), Some("a"));
}

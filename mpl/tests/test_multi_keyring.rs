// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Multi-keyring tests, ported from the Dafny `TestMultiKeyring.dfy`.

use aws_crypto_mpl::keyring::{MultiKeyring, RawAesKeyring, SharedKeyring};
use aws_crypto_mpl::shared::IntoShared;
use aws_crypto_mpl::types::AesWrappingAlg;
use aws_crypto_mpl::types::{
    AlgorithmSuiteId, DecryptionMaterials, EncryptedDataKey, EncryptionContext,
    EncryptionMaterials, EsdkAlgorithmSuiteId, PlaintextDataKey,
};

const SUITE: AlgorithmSuiteId =
    AlgorithmSuiteId::Esdk(EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf);

fn ec() -> EncryptionContext {
    let mut ec = EncryptionContext::new();
    ec.insert("keyA", "valA");
    ec
}

fn enc_materials(suite: AlgorithmSuiteId, pdk: Option<Vec<u8>>) -> EncryptionMaterials {
    EncryptionMaterials::builder()
        .algorithm_suite_id(suite)
        .set_encryption_context(Some(ec()))
        .set_plaintext_data_key(pdk.map(PlaintextDataKey::new))
        .build()
        .unwrap()
}

fn dec_materials(suite: AlgorithmSuiteId, pdk: Option<Vec<u8>>) -> DecryptionMaterials {
    DecryptionMaterials::builder()
        .algorithm_suite_id(suite)
        .set_encryption_context(Some(ec()))
        .set_plaintext_data_key(pdk.map(PlaintextDataKey::new))
        .build()
        .unwrap()
}

fn aes(name: &str, byte: u8) -> RawAesKeyring {
    RawAesKeyring::builder()
        .key_namespace("multi-namespace")
        .key_name(name)
        .wrapping_key(vec![byte; 32])
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()
        .unwrap()
}

async fn decrypt(
    k: &MultiKeyring,
    edks: Vec<EncryptedDataKey>,
) -> Result<Vec<u8>, aws_crypto_mpl::Error> {
    Ok(k.on_decrypt()
        .materials(dec_materials(SUITE, None))
        .set_encrypted_data_keys(Some(edks))
        .send()
        .await?
        .into_materials()
        .plaintext_data_key()
        .unwrap()
        .as_bytes()
        .to_vec())
}

#[tokio::test]
async fn the_generator_and_every_child_wrap_the_data_key() {
    let k = MultiKeyring::builder()
        .generator(aes("gen", 1))
        .child_keyrings(aes("child1", 2))
        .child_keyrings(aes("child2", 3))
        .build()
        .unwrap();
    let out = k
        .on_encrypt()
        .materials(enc_materials(SUITE, None))
        .send()
        .await
        .unwrap()
        .into_materials();
    let pdk = out.plaintext_data_key().unwrap().as_bytes().to_vec();
    let edks = out.encrypted_data_keys().to_vec();
    assert_eq!(edks.len(), 3);

    // Any single EDK decrypts, through the generator or a child.
    for edk in &edks {
        assert_eq!(decrypt(&k, vec![edk.clone()]).await.unwrap(), pdk);
    }
    // A child alone decrypts its own EDK.
    let child_only = MultiKeyring::builder()
        .child_keyrings(aes("child2", 3))
        .build()
        .unwrap();
    assert_eq!(decrypt(&child_only, edks).await.unwrap(), pdk);
}

#[tokio::test]
async fn children_only_wrap_a_supplied_data_key() {
    let k = MultiKeyring::builder()
        .child_keyrings(aes("child", 2))
        .build()
        .unwrap();
    let out = k
        .on_encrypt()
        .materials(enc_materials(SUITE, Some(vec![5u8; 32])))
        .send()
        .await
        .unwrap()
        .into_materials();
    assert_eq!(out.encrypted_data_keys().len(), 1);
    assert_eq!(
        decrypt(&k, out.encrypted_data_keys().to_vec())
            .await
            .unwrap(),
        vec![5u8; 32]
    );
}

#[tokio::test]
async fn children_only_without_a_data_key_fails() {
    let k = MultiKeyring::builder()
        .child_keyrings(aes("child", 2))
        .build()
        .unwrap();
    let err = k
        .on_encrypt()
        .materials(enc_materials(SUITE, None))
        .send()
        .await
        .unwrap_err();
    assert!(err.is_invalid_materials(), "{err:?}");
}

#[tokio::test]
async fn a_generator_with_a_data_key_already_present_fails() {
    let k = MultiKeyring::builder()
        .generator(aes("gen", 1))
        .build()
        .unwrap();
    let err = k
        .on_encrypt()
        .materials(enc_materials(SUITE, Some(vec![5u8; 32])))
        .send()
        .await
        .unwrap_err();
    assert!(err.is_invalid_materials(), "{err:?}");
}

#[tokio::test]
async fn a_failing_child_fails_encrypt() {
    let bad_rsa = aws_crypto_mpl::keyring::RawRsaKeyring::builder()
        .key_namespace("ns")
        .key_name("n")
        .padding_scheme(aws_crypto_mpl::types::PaddingScheme::Pkcs1)
        .public_key(b"not a key".to_vec())
        .build()
        .unwrap();
    let k = MultiKeyring::builder()
        .generator(aes("gen", 1))
        .child_keyrings(bad_rsa)
        .build()
        .unwrap();
    let err = k
        .on_encrypt()
        .materials(enc_materials(SUITE, None))
        .send()
        .await
        .unwrap_err();
    assert!(err.is_cryptographic(), "{err:?}");
}

#[tokio::test]
async fn decrypt_collects_every_keyrings_failure() {
    let k = MultiKeyring::builder()
        .generator(aes("gen", 1))
        .child_keyrings(aes("child", 2))
        .build()
        .unwrap();
    let err = decrypt(&k, Vec::new()).await.unwrap_err();
    assert_eq!(err.collected().len(), 2, "{err:?}");
}

#[tokio::test]
async fn decrypt_with_a_data_key_already_present_fails() {
    let k = MultiKeyring::builder()
        .generator(aes("gen", 1))
        .build()
        .unwrap();
    let err = k
        .on_decrypt()
        .materials(dec_materials(SUITE, Some(vec![0u8; 32])))
        .set_encrypted_data_keys(Some(Vec::new()))
        .send()
        .await
        .unwrap_err();
    assert!(err.is_invalid_materials(), "{err:?}");
}

#[test]
fn the_builder_needs_a_generator_or_a_child() {
    assert!(MultiKeyring::builder().build().unwrap_err().is_validation());
    assert!(
        MultiKeyring::builder()
            .set_child_keyrings(Some(Vec::new()))
            .build()
            .unwrap_err()
            .is_validation()
    );

    let generator: SharedKeyring = aes("gen", 1).into_shared();
    let k = MultiKeyring::builder()
        .set_generator(Some(generator))
        .set_child_keyrings(Some(vec![aes("child", 2).into_shared()]))
        .build()
        .unwrap();
    assert_eq!(k.name(), "multi");
    assert!(k.generator().is_some());
    assert_eq!(k.child_keyrings().len(), 1);
    let debug = format!("{k:?}");
    assert!(debug.contains("MultiKeyring"), "{debug}");
    assert!(format!("{:?}", MultiKeyring::builder()).contains("MultiKeyringBuilder"));
}

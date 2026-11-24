// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::support::*;
use aws_crypto_mpl::types::{
    AlgorithmSuiteId, DecryptionMaterials, EncryptionContext, EncryptionMaterials,
    EsdkAlgorithmSuiteId,
};

const SUITE: AlgorithmSuiteId =
    AlgorithmSuiteId::Esdk(EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256);

/// Fails unless a data key that `keyring` wraps is one that `make_raw_aes_keyring()` unwraps,
/// which needs the same namespace, name, wrapping key and wrapping algorithm.
async fn assert_same_key(keyring: &RawAesKeyring) {
    let encryption_materials = EncryptionMaterials::builder()
        .algorithm_suite_id(SUITE)
        .set_encryption_context(Some(EncryptionContext::new()))
        .build()
        .unwrap();
    let encrypted = keyring
        .on_encrypt()
        .materials(encryption_materials)
        .send()
        .await
        .unwrap()
        .into_materials();
    let decryption_materials = DecryptionMaterials::builder()
        .algorithm_suite_id(SUITE)
        .set_encryption_context(Some(EncryptionContext::new()))
        .build()
        .unwrap();
    let decrypted = make_raw_aes_keyring()
        .on_decrypt()
        .materials(decryption_materials)
        .set_encrypted_data_keys(Some(encrypted.encrypted_data_keys().to_vec()))
        .send()
        .await
        .unwrap()
        .into_materials();
    assert_eq!(
        decrypted.plaintext_data_key().unwrap().as_bytes(),
        encrypted.plaintext_data_key().unwrap().as_bytes()
    );
}

#[tokio::test]
async fn builder() -> Result<(), Error> {
    // api-example: api=raw-aes-keyring frame way=builder
    let raw_aes_keyring = RawAesKeyring::builder()
        // api-example: options
        .key_namespace("my-key-namespace")
        .key_name("my-key-name")
        .wrapping_key(wrapping_key_from_secret_store())
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        // api-example: tail
        .build()?;
    // api-example: end
    assert_same_key(&raw_aes_keyring).await;
    Ok(())
}

#[tokio::test]
async fn key_namespace() -> Result<(), Error> {
    // api-example: api=raw-aes-keyring way=key_namespace have="a string" takes=&str default
    let raw_aes_keyring = RawAesKeyring::builder()
        // api-example: setter
        .key_namespace("my-key-namespace")
        .key_name("my-key-name")
        .wrapping_key(wrapping_key_from_secret_store())
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()?;
    // api-example: end
    assert_eq!(raw_aes_keyring.key_namespace(), "my-key-namespace");

    // api-example: api=raw-aes-keyring way=key_namespace have="a string from your config" takes=String
    let key_namespace: String = app_config().key_namespace;
    // api-example: call
    let raw_aes_keyring = RawAesKeyring::builder()
        // api-example: setter
        .key_namespace(key_namespace)
        .key_name("my-key-name")
        .wrapping_key(wrapping_key_from_secret_store())
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()?;
    // api-example: end
    assert_same_key(&raw_aes_keyring).await;

    // api-example: api=raw-aes-keyring way=set_key_namespace have="a string" takes=Option<String> alt
    let raw_aes_keyring = RawAesKeyring::builder()
        // api-example: setter
        .set_key_namespace(Some("my-key-namespace".to_string()))
        .key_name("my-key-name")
        .wrapping_key(wrapping_key_from_secret_store())
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()?;
    // api-example: end
    assert_same_key(&raw_aes_keyring).await;

    // api-example: api=raw-aes-keyring way=key_namespace left-out fails=validation
    let result = RawAesKeyring::builder()
        .key_name("my-key-name")
        .wrapping_key(wrapping_key_from_secret_store())
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build();
    // api-example: end
    assert!(result.is_err_and(|error| error.is_validation()));
    Ok(())
}

#[tokio::test]
async fn key_name() -> Result<(), Error> {
    // api-example: api=raw-aes-keyring way=key_name have="a string" takes=&str default
    let raw_aes_keyring = RawAesKeyring::builder()
        .key_namespace("my-key-namespace")
        // api-example: setter
        .key_name("my-key-name")
        .wrapping_key(wrapping_key_from_secret_store())
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()?;
    // api-example: end
    assert_eq!(raw_aes_keyring.key_name(), "my-key-name");

    // api-example: api=raw-aes-keyring way=key_name have="a string from your config" takes=String
    let key_name: String = app_config().key_name;
    // api-example: call
    let raw_aes_keyring = RawAesKeyring::builder()
        .key_namespace("my-key-namespace")
        // api-example: setter
        .key_name(key_name)
        .wrapping_key(wrapping_key_from_secret_store())
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()?;
    // api-example: end
    assert_same_key(&raw_aes_keyring).await;

    // api-example: api=raw-aes-keyring way=set_key_name have="a string" takes=Option<String> alt
    let raw_aes_keyring = RawAesKeyring::builder()
        .key_namespace("my-key-namespace")
        // api-example: setter
        .set_key_name(Some("my-key-name".to_string()))
        .wrapping_key(wrapping_key_from_secret_store())
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()?;
    // api-example: end
    assert_same_key(&raw_aes_keyring).await;

    // api-example: api=raw-aes-keyring way=key_name left-out fails=validation
    let result = RawAesKeyring::builder()
        .key_namespace("my-key-namespace")
        .wrapping_key(wrapping_key_from_secret_store())
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build();
    // api-example: end
    assert!(result.is_err_and(|error| error.is_validation()));
    Ok(())
}

#[tokio::test]
async fn wrapping_key() -> Result<(), Error> {
    // api-example: api=raw-aes-keyring way=wrapping_key have="bytes from a secret store" takes=Vec<u8> default
    let wrapping_key: Vec<u8> = wrapping_key_from_secret_store();
    // api-example: call
    let raw_aes_keyring = RawAesKeyring::builder()
        .key_namespace("my-key-namespace")
        .key_name("my-key-name")
        // api-example: setter
        .wrapping_key(wrapping_key)
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()?;
    // api-example: end
    assert_same_key(&raw_aes_keyring).await;

    // api-example: api=raw-aes-keyring way=wrapping_key have="bytes in memory" takes=&[u8]
    let wrapping_key: &[u8] = &[0x01; 32];
    // api-example: call
    let raw_aes_keyring = RawAesKeyring::builder()
        .key_namespace("my-key-namespace")
        .key_name("my-key-name")
        // api-example: setter
        .wrapping_key(wrapping_key)
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()?;
    // api-example: end
    assert_same_key(&raw_aes_keyring).await;

    // api-example: api=raw-aes-keyring way=set_wrapping_key have="bytes from a secret store" takes=Option<Vec<u8>> alt
    let wrapping_key: Option<Vec<u8>> = Some(wrapping_key_from_secret_store());
    // api-example: call
    let raw_aes_keyring = RawAesKeyring::builder()
        .key_namespace("my-key-namespace")
        .key_name("my-key-name")
        // api-example: setter
        .set_wrapping_key(wrapping_key)
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()?;
    // api-example: end
    assert_same_key(&raw_aes_keyring).await;

    // api-example: api=raw-aes-keyring way=wrapping_key have="a key of the wrong length" takes=Vec<u8> fails=validation
    let wrapping_key: Vec<u8> = vec![0x01; 16];
    // api-example: call
    let result = RawAesKeyring::builder()
        .key_namespace("my-key-namespace")
        .key_name("my-key-name")
        // api-example: setter
        .wrapping_key(wrapping_key)
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build();
    // api-example: end
    assert!(result.is_err_and(|error| error.is_validation()));

    // api-example: api=raw-aes-keyring way=wrapping_key left-out fails=validation
    let result = RawAesKeyring::builder()
        .key_namespace("my-key-namespace")
        .key_name("my-key-name")
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build();
    // api-example: end
    assert!(result.is_err_and(|error| error.is_validation()));
    Ok(())
}

#[tokio::test]
async fn wrapping_alg() -> Result<(), Error> {
    // api-example: api=raw-aes-keyring way=wrapping_alg have="one of the listed choices" takes=AesWrappingAlg default
    let raw_aes_keyring = RawAesKeyring::builder()
        .key_namespace("my-key-namespace")
        .key_name("my-key-name")
        .wrapping_key(wrapping_key_from_secret_store())
        // api-example: setter
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()?;
    // api-example: end
    assert_eq!(
        raw_aes_keyring.wrapping_alg(),
        AesWrappingAlg::AlgAes256GcmIv12Tag16
    );

    // api-example: api=raw-aes-keyring way=set_wrapping_alg have="one of the listed choices" takes=Option<AesWrappingAlg> alt
    let raw_aes_keyring = RawAesKeyring::builder()
        .key_namespace("my-key-namespace")
        .key_name("my-key-name")
        .wrapping_key(wrapping_key_from_secret_store())
        // api-example: setter
        .set_wrapping_alg(Some(AesWrappingAlg::AlgAes256GcmIv12Tag16))
        .build()?;
    // api-example: end
    assert_same_key(&raw_aes_keyring).await;

    // api-example: api=raw-aes-keyring way=wrapping_alg left-out fails=validation
    let result = RawAesKeyring::builder()
        .key_namespace("my-key-namespace")
        .key_name("my-key-name")
        .wrapping_key(wrapping_key_from_secret_store())
        .build();
    // api-example: end
    assert!(result.is_err_and(|error| error.is_validation()));
    Ok(())
}

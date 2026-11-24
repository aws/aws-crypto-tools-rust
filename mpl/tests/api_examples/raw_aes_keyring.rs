// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::app_config;
use aws_crypto_mpl::Error;
use aws_crypto_mpl::keyring::RawAesKeyring;
use aws_crypto_mpl::types::{
    AesWrappingAlg, AlgorithmSuiteId, DecryptionMaterials, EncryptionContext, EncryptionMaterials,
    EsdkAlgorithmSuiteId,
};

const SUITE: AlgorithmSuiteId =
    AlgorithmSuiteId::Esdk(EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256);

/// Stands in for reading the key from a secret store.
fn wrapping_key_from_secret_store() -> Vec<u8> {
    vec![0x01; 32]
}

/// Fails unless a data key that `encrypting_keyring` wraps is one that `decrypting_keyring` unwraps,
/// which needs the same namespace, name, wrapping key and wrapping algorithm.
async fn assert_same_key(encrypting_keyring: &RawAesKeyring, decrypting_keyring: &RawAesKeyring) {
    let encryption_materials = EncryptionMaterials::builder()
        .algorithm_suite_id(SUITE)
        .set_encryption_context(Some(EncryptionContext::new()))
        .build()
        .unwrap();
    let encrypted = encrypting_keyring
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
    let decrypted = decrypting_keyring
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
    let wrapping_key = wrapping_key_from_secret_store();
    // api-example: api=raw-aes-keyring way=builder kind=pass have="bytes from a secret store"
    // snippet-start
    let raw_aes_keyring = RawAesKeyring::builder()
        .key_namespace("my-key-namespace")
        .key_name("my-key-name")
        .wrapping_key(wrapping_key)
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()?;
    // snippet-end
    assert_same_key(&raw_aes_keyring, &super::raw_aes_keyring()).await;
    Ok(())
}

#[tokio::test]
async fn key_namespace() -> Result<(), Error> {
    let wrapping_key = wrapping_key_from_secret_store();
    let app_config = app_config();
    // api-example: api=raw-aes-keyring way=key_namespace takes=&str kind=pass have="a string"
    // snippet-start
    let raw_aes_keyring = RawAesKeyring::builder()
        .key_namespace("my-key-namespace")
        .key_name("my-key-name")
        .wrapping_key(wrapping_key.clone())
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()?;
    // snippet-end
    assert_eq!(raw_aes_keyring.key_namespace(), "my-key-namespace");

    // api-example: api=raw-aes-keyring way=key_namespace takes=String kind=pass have="a string from your config"
    // snippet-start
    let key_namespace: String = app_config.key_namespace;
    let raw_aes_keyring_from_string = RawAesKeyring::builder()
        .key_namespace(key_namespace)
        .key_name("my-key-name")
        .wrapping_key(wrapping_key.clone())
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()?;
    // snippet-end
    assert_same_key(&raw_aes_keyring, &raw_aes_keyring_from_string).await;

    // api-example: api=raw-aes-keyring way=set_key_namespace takes=Option<String> kind=pass have="a value that may be missing"
    // snippet-start
    let key_namespace: Option<String> = Some("my-key-namespace".to_string());
    let raw_aes_keyring_from_option = RawAesKeyring::builder()
        .set_key_namespace(key_namespace)
        .key_name("my-key-name")
        .wrapping_key(wrapping_key.clone())
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()?;
    // snippet-end
    assert_same_key(&raw_aes_keyring, &raw_aes_keyring_from_option).await;

    // api-example: api=raw-aes-keyring way=key_namespace kind=missing
    // snippet-start
    let result = RawAesKeyring::builder()
        .key_name("my-key-name")
        .wrapping_key(wrapping_key)
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build();
    // snippet-end
    assert!(result.unwrap_err().is_validation());
    Ok(())
}

#[tokio::test]
async fn key_name() -> Result<(), Error> {
    let wrapping_key = wrapping_key_from_secret_store();
    let app_config = app_config();
    // api-example: api=raw-aes-keyring way=key_name takes=&str kind=pass have="a string"
    // snippet-start
    let raw_aes_keyring = RawAesKeyring::builder()
        .key_namespace("my-key-namespace")
        .key_name("my-key-name")
        .wrapping_key(wrapping_key.clone())
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()?;
    // snippet-end
    assert_eq!(raw_aes_keyring.key_name(), "my-key-name");

    // api-example: api=raw-aes-keyring way=key_name takes=String kind=pass have="a string from your config"
    // snippet-start
    let key_name: String = app_config.key_name;
    let raw_aes_keyring_from_string = RawAesKeyring::builder()
        .key_namespace("my-key-namespace")
        .key_name(key_name)
        .wrapping_key(wrapping_key.clone())
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()?;
    // snippet-end
    assert_same_key(&raw_aes_keyring, &raw_aes_keyring_from_string).await;

    // api-example: api=raw-aes-keyring way=set_key_name takes=Option<String> kind=pass have="a value that may be missing"
    // snippet-start
    let key_name: Option<String> = Some("my-key-name".to_string());
    let raw_aes_keyring_from_option = RawAesKeyring::builder()
        .key_namespace("my-key-namespace")
        .set_key_name(key_name)
        .wrapping_key(wrapping_key.clone())
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()?;
    // snippet-end
    assert_same_key(&raw_aes_keyring, &raw_aes_keyring_from_option).await;

    // api-example: api=raw-aes-keyring way=key_name kind=missing
    // snippet-start
    let result = RawAesKeyring::builder()
        .key_namespace("my-key-namespace")
        .wrapping_key(wrapping_key)
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build();
    // snippet-end
    assert!(result.unwrap_err().is_validation());
    Ok(())
}

#[tokio::test]
async fn wrapping_key() -> Result<(), Error> {
    // api-example: api=raw-aes-keyring way=wrapping_key takes=Vec<u8> kind=pass have="bytes from a secret store"
    // snippet-start
    let wrapping_key: Vec<u8> = wrapping_key_from_secret_store();
    let raw_aes_keyring = RawAesKeyring::builder()
        .key_namespace("my-key-namespace")
        .key_name("my-key-name")
        .wrapping_key(wrapping_key)
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()?;
    // snippet-end

    let key_bytes = wrapping_key_from_secret_store();
    // api-example: api=raw-aes-keyring way=wrapping_key takes=&[u8] kind=pass have="bytes in memory"
    // snippet-start
    let wrapping_key: &[u8] = &key_bytes;
    let raw_aes_keyring_from_slice = RawAesKeyring::builder()
        .key_namespace("my-key-namespace")
        .key_name("my-key-name")
        .wrapping_key(wrapping_key)
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()?;
    // snippet-end
    assert_same_key(&raw_aes_keyring, &raw_aes_keyring_from_slice).await;

    // api-example: api=raw-aes-keyring way=set_wrapping_key takes=Option<Vec<u8>> kind=pass have="a value that may be missing"
    // snippet-start
    let wrapping_key: Option<Vec<u8>> = Some(wrapping_key_from_secret_store());
    let raw_aes_keyring_from_option = RawAesKeyring::builder()
        .key_namespace("my-key-namespace")
        .key_name("my-key-name")
        .set_wrapping_key(wrapping_key)
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()?;
    // snippet-end
    assert_same_key(&raw_aes_keyring, &raw_aes_keyring_from_option).await;

    // api-example: api=raw-aes-keyring way=wrapping_key kind=missing
    // snippet-start
    let result = RawAesKeyring::builder()
        .key_namespace("my-key-namespace")
        .key_name("my-key-name")
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build();
    // snippet-end
    assert!(result.unwrap_err().is_validation());

    // api-example: api=raw-aes-keyring way=wrapping_key takes=Vec<u8> kind=reject
    // snippet-start
    let too_short_wrapping_key = vec![0x01; 16];
    let result = RawAesKeyring::builder()
        .key_namespace("my-key-namespace")
        .key_name("my-key-name")
        .wrapping_key(too_short_wrapping_key)
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build();
    // snippet-end
    assert!(result.unwrap_err().is_validation());
    Ok(())
}

#[tokio::test]
async fn wrapping_alg() -> Result<(), Error> {
    let wrapping_key = wrapping_key_from_secret_store();
    // api-example: api=raw-aes-keyring way=wrapping_alg takes=AesWrappingAlg kind=pass have="one of the listed choices"
    // snippet-start
    let raw_aes_keyring = RawAesKeyring::builder()
        .key_namespace("my-key-namespace")
        .key_name("my-key-name")
        .wrapping_key(wrapping_key.clone())
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()?;
    // snippet-end
    assert_eq!(
        raw_aes_keyring.wrapping_alg(),
        AesWrappingAlg::AlgAes256GcmIv12Tag16
    );

    // api-example: api=raw-aes-keyring way=set_wrapping_alg takes=Option<AesWrappingAlg> kind=pass have="a value that may be missing"
    // snippet-start
    let wrapping_alg: Option<AesWrappingAlg> = Some(AesWrappingAlg::AlgAes256GcmIv12Tag16);
    let raw_aes_keyring_from_option = RawAesKeyring::builder()
        .key_namespace("my-key-namespace")
        .key_name("my-key-name")
        .wrapping_key(wrapping_key.clone())
        .set_wrapping_alg(wrapping_alg)
        .build()?;
    // snippet-end
    assert_same_key(&raw_aes_keyring, &raw_aes_keyring_from_option).await;

    // api-example: api=raw-aes-keyring way=wrapping_alg kind=missing
    // snippet-start
    let result = RawAesKeyring::builder()
        .key_namespace("my-key-namespace")
        .key_name("my-key-name")
        .wrapping_key(wrapping_key)
        .build();
    // snippet-end
    assert!(result.unwrap_err().is_validation());
    Ok(())
}

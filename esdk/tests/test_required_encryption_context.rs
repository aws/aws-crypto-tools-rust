// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for the Required Encryption Context CMM feature.
//! Covers spec/client-apis/encrypt.md#get-the-encryption-materials
//! and spec/client-apis/decrypt.md#get-the-decryption-materials,
//! focusing on the reproduced encryption context passed through the CMM.
//!
//! TODO(native-mpl): every test in this file is disabled during the migration
//! to the native `aws-crypto-mpl`. They depend on capabilities the native MPL
//! intentionally omits:
//!   - the Required Encryption Context CMM
//!     (`create_required_encryption_context_cmm`) — native MPL exposes only
//!     `DefaultCmm`, and `EncryptInput` has no required-encryption-context-keys
//!     field, so the "filter EC out of the header AAD, supply it as reproduced
//!     EC on decrypt" behavior these tests assert cannot be expressed;
//!   - the multi-keyring (`create_multi_keyring`);
//!   - the AWS KMS keyring (`create_aws_kms_keyring`);
//!   - the raw RSA keyring (`create_raw_rsa_keyring`) + Dafny RSA key-pair
//!     generation;
//!   - the AWS KMS hierarchical keyring wired through a Dafny keystore client.
//!
//! Re-enable (and port to the native API) once the native MPL grows a
//! Required Encryption Context CMM and the corresponding keyrings.

/*
#[allow(clippy::duplicate_mod)]
mod fixtures;
mod test_helpers;
use aws_esdk::*;
use fixtures::*;

// THIS IS A TESTING RESOURCE DO NOT USE IN A PRODUCTION ENVIRONMENT

async fn get_rsa_keyring(mpl: &MplClient) -> KeyringRef {
    let keys = generate_key_pair(2048).await;
    let (namespace, name) = namespace_and_name(0);
    mpl.create_raw_rsa_keyring()
        .key_namespace(namespace)
        .key_name(name)
        .padding_scheme(PaddingScheme::OaepSha1Mgf1)
        .public_key(keys.public_key.unwrap().pem.unwrap().as_ref())
        .private_key(keys.private_key.unwrap().pem.unwrap().as_ref())
        .send()
        .await
        .unwrap()
}

async fn get_aes_keyring(mpl: &MplClient) -> KeyringRef {
    let (namespace, name) = namespace_and_name(0);
    mpl.create_raw_aes_keyring()
        .key_namespace(namespace)
        .key_name(name)
        .wrapping_key(Blob::new([0; 32]))
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .send()
        .await
        .unwrap()
}

async fn get_kms_keyring(mpl: &MplClient) -> KeyringRef {
    let client_supplier = mpl.create_default_client_supplier().send().await.unwrap();
    let kms_client = client_supplier
        .get_client()
        .region("us-west-2")
        .send()
        .await
        .unwrap();

    mpl.create_aws_kms_keyring()
        .kms_key_id(KEY_ARN)
        .kms_client(kms_client)
        .send()
        .await
        .unwrap()
}

async fn get_hierarchical_keyring(mpl: &MplClient) -> KeyringRef {
    let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let kms_client = aws_sdk_kms::Client::new(&sdk_config);
    let ddb_client = aws_sdk_dynamodb::Client::new(&sdk_config);
    let kms_config = KmsConfiguration::KmsKeyArn(HIERARCHY_KEY_ARN.to_string());

    let key_store_config = KeyStoreConfig::builder()
        .kms_client(kms_client)
        .ddb_client(ddb_client)
        .ddb_table_name(BRANCH_KEY_STORE_NAME)
        .logical_key_store_name(LOGICAL_KEY_STORE_NAME)
        .kms_configuration(kms_config)
        .build()
        .unwrap();

    let key_store = KeystoreClient::from_conf(key_store_config).unwrap();

    mpl.create_aws_kms_hierarchical_keyring()
        .key_store(key_store)
        .branch_key_id(BRANCH_KEY_ID)
        .ttl_seconds(600000)
        .send()
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn test_repr_encryption_context_with_same_ec_happy_case() {
    let plaintext = "asdf".as_bytes();
    let mpl = mpl();

    // get keyrings
    let rsa_keyring = get_rsa_keyring(&mpl).await;
    let kms_keyring = get_kms_keyring(&mpl).await;
    let aes_keyring = get_aes_keyring(&mpl).await;
    let h_keyring = get_hierarchical_keyring(&mpl).await;

    let multi_keyring = mpl
        .create_multi_keyring()
        .generator(aes_keyring.clone())
        .child_keyrings([rsa_keyring.clone(), kms_keyring.clone(), h_keyring.clone()])
        .send()
        .await
        .unwrap();

    // HAPPY CASE 1
    // Test supply same encryption context on encrypt and decrypt NO filtering
    let encryption_context = small_encryption_context(SmallEncryptionContextVariation::AB);

    let encrypt_input = EncryptInput::with_legacy_keyring(
        plaintext,
        encryption_context.clone(),
        multi_keyring.clone(),
    );
    let encrypt_output = encrypt(&encrypt_input).await.unwrap();
    let esdk_ciphertext = encrypt_output.ciphertext;

    // Test RSA
    let mut decrypt_input = DecryptInput::with_legacy_keyring(
        &esdk_ciphertext,
        encryption_context,
        rsa_keyring.clone(),
    );
    let decrypt_output = decrypt(&decrypt_input).await.unwrap();
    assert_eq!(decrypt_output.plaintext, plaintext);

    // Test KMS
    decrypt_input.keyring = Some(Keyring::Legacy(kms_keyring.clone()));
    let decrypt_output = decrypt(&decrypt_input).await.unwrap();
    assert_eq!(decrypt_output.plaintext, plaintext);

    // Test AES
    decrypt_input.keyring = Some(Keyring::Legacy(aes_keyring.clone()));
    let decrypt_output = decrypt(&decrypt_input).await.unwrap();
    assert_eq!(decrypt_output.plaintext, plaintext);

    // Test Hierarchy Keyring
    decrypt_input.keyring = Some(Keyring::Legacy(h_keyring.clone()));
    let decrypt_output = decrypt(&decrypt_input).await.unwrap();
    assert_eq!(decrypt_output.plaintext, plaintext);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_remove_on_encrypt_and_supply_on_decrypt_happy_case() {
    let plaintext = "asdf".as_bytes();
    let mpl = mpl();

    // get keyrings
    let rsa_keyring = get_rsa_keyring(&mpl).await;
    let kms_keyring = get_kms_keyring(&mpl).await;
    let aes_keyring = get_aes_keyring(&mpl).await;
    let h_keyring = get_hierarchical_keyring(&mpl).await;

    let multi_keyring = mpl
        .create_multi_keyring()
        .generator(aes_keyring.clone())
        .child_keyrings([rsa_keyring.clone(), kms_keyring.clone(), h_keyring.clone()])
        .send()
        .await
        .unwrap();

    // Happy Test Case 2
    let encryption_context = small_encryption_context(SmallEncryptionContextVariation::AB);
    let reproduced_encryption_context =
        small_encryption_context(SmallEncryptionContextVariation::A);
    let required_encryption_context_keys =
        small_encryption_context_keys(SmallEncryptionContextVariation::A);

    // TEST RSA
    let default_cmm = mpl
        .create_default_cryptographic_materials_manager()
        .keyring(multi_keyring.clone())
        .send()
        .await
        .unwrap();

    let req_cmm = mpl
        .create_required_encryption_context_cmm()
        .underlying_cmm(default_cmm)
        .required_encryption_context_keys(required_encryption_context_keys)
        .send()
        .await
        .unwrap();

    let encrypt_input = EncryptInput::with_legacy_cmm(plaintext, encryption_context, req_cmm);
    let encrypt_output = encrypt(&encrypt_input).await.unwrap();
    let esdk_ciphertext = encrypt_output.ciphertext;

    let mut decrypt_input = DecryptInput::with_legacy_keyring(
        &esdk_ciphertext,
        reproduced_encryption_context,
        rsa_keyring.clone(),
    );
    let decrypt_output = decrypt(&decrypt_input).await.unwrap();
    assert_eq!(decrypt_output.plaintext, plaintext);

    // Test KMS
    decrypt_input.keyring = Some(Keyring::Legacy(kms_keyring.clone()));
    let decrypt_output = decrypt(&decrypt_input).await.unwrap();
    assert_eq!(decrypt_output.plaintext, plaintext);

    // Test AES
    decrypt_input.keyring = Some(Keyring::Legacy(aes_keyring.clone()));
    let decrypt_output = decrypt(&decrypt_input).await.unwrap();
    assert_eq!(decrypt_output.plaintext, plaintext);

    // Test Hierarchy Keyring
    decrypt_input.keyring = Some(Keyring::Legacy(h_keyring.clone()));
    let decrypt_output = decrypt(&decrypt_input).await.unwrap();
    assert_eq!(decrypt_output.plaintext, plaintext);
}
*/

// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for the Required Encryption Context CMM feature.
//! Covers spec/client-apis/encrypt.md#get-the-encryption-materials
//! and spec/client-apis/decrypt.md#get-the-decryption-materials,
//! focusing on the reproduced encryption context passed through the CMM.
//!
//! TODO(native-mpl): every test in this file is disabled during the migration
//! to the native `aws-crypto-mpl`. They depend on capabilities the native MPL
//! does not yet implement:
//!   - the Required Encryption Context CMM
//!     (`create_required_encryption_context_cmm`) — native MPL exposes only
//!     `DefaultCmm`, and `Client::encrypt` has no required-encryption-context-keys
//!     field, so the "filter EC out of the header AAD, supply it as reproduced
//!     EC on decrypt" behavior these tests assert cannot be expressed;
//!   - the multi-keyring (`create_multi_keyring`);
//!   - the AWS KMS keyring (`create_aws_kms_keyring`);
//!   - the raw RSA keyring (`create_raw_rsa_keyring`) + Dafny RSA key-pair
//!     generation;
//!   - the AWS KMS hierarchical keyring wired through a Dafny key store client.
//!
//! Re-enable (and port to the native API) once the native MPL grows a
//! Required Encryption Context CMM and the corresponding keyrings.

/*
#[allow(clippy::duplicate_mod)]
mod fixtures;
mod test_helpers;
use aws_esdk::*;
use aws_esdk::types::*;
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

    let key_store = KeyStoreClient::from_conf(key_store_config).unwrap();

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

    let esdk = Client::default();
    let encrypt_output = esdk
        .encrypt()
        .plaintext(plaintext)
        .encryption_context(encryption_context.clone())
        .keyring(multi_keyring.clone())
        .send()
        .await
        .unwrap();
    let esdk_ciphertext = encrypt_output.ciphertext;

    // Test RSA
    let decrypt_with = |keyring| {
        esdk.decrypt()
            .ciphertext(&esdk_ciphertext)
            .encryption_context(encryption_context.clone())
            .keyring(keyring)
            .send()
    };
    let decrypt_output = decrypt_with(rsa_keyring.clone()).await.unwrap();
    //= spec/client-apis/decrypt.md#get-the-decryption-materials
    //= type=test
    //= reason=Decrypt supplies the same EC used on encrypt and succeeds, proving the reproduced EC is the input EC
    //# - Reproduced Encryption Context: This MUST be the [input](#input) encryption context.
    assert_eq!(decrypt_output.plaintext, plaintext);

    // Test KMS
    let decrypt_output = decrypt_with(kms_keyring.clone()).await.unwrap();
    assert_eq!(decrypt_output.plaintext, plaintext);

    // Test AES
    let decrypt_output = decrypt_with(aes_keyring.clone()).await.unwrap();
    assert_eq!(decrypt_output.plaintext, plaintext);

    // Test Hierarchy Keyring
    let decrypt_output = decrypt_with(h_keyring.clone()).await.unwrap();
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

    let esdk = Client::default();
    let encrypt_output = esdk
        .encrypt()
        .plaintext(plaintext)
        .encryption_context(encryption_context)
        .cmm(req_cmm)
        .send()
        .await
        .unwrap();
    let esdk_ciphertext = encrypt_output.ciphertext;

    //= spec/client-apis/decrypt.md#get-the-decryption-materials
    //= type=test
    //# - Reproduced Encryption Context: This MUST be the [input](#input) encryption context.
    let decrypt_with = |keyring| {
        esdk.decrypt()
            .ciphertext(&esdk_ciphertext)
            .encryption_context(reproduced_encryption_context.clone())
            .keyring(keyring)
            .send()
    };
    let decrypt_output = decrypt_with(rsa_keyring.clone()).await.unwrap();
    //= spec/client-apis/encrypt.md#authentication-tag
    //= type=test
    //= reason=Decrypt with reproduced EC succeeds; proves encrypt AAD included filtered EC
    //# The encryption context to only authenticate MUST be the [encryption context](../framework/structures.md#encryption-context)
    //# in the [encryption materials](../framework/structures.md#encryption-materials)
    //# filtered to only contain key value pairs listed in
    //# the [encryption material's](../framework/structures.md#encryption-materials)
    //# [required encryption context keys](../framework/structures.md#required-encryption-context-keys)
    //# serialized according to the [encryption context serialization specification](../framework/structures.md#serialization).
    assert_eq!(decrypt_output.plaintext, plaintext);

    // Test KMS
    let decrypt_output = decrypt_with(kms_keyring.clone()).await.unwrap();
    assert_eq!(decrypt_output.plaintext, plaintext);

    // Test AES
    let decrypt_output = decrypt_with(aes_keyring.clone()).await.unwrap();
    assert_eq!(decrypt_output.plaintext, plaintext);

    // Test Hierarchy Keyring
    let decrypt_output = decrypt_with(h_keyring.clone()).await.unwrap();
    assert_eq!(decrypt_output.plaintext, plaintext);
}
*/

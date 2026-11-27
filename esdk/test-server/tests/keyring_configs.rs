// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Every modeled keyring and CMM builds from its `CreateClient` config.
//! The offline ones also round-trip a message; the AWS KMS ones only build,
//! because building contacts no AWS service when every key is supplied.

use aws_esdk_test_server::handlers::AppState;
use aws_esdk_test_server::model::{
    AesWrappingAlg, AwsKmsKeyringConfig, CreateClientRequest, CryptographicMaterialsManager,
    DecryptRequest, DefaultCmmConfig, EncryptRequest, EsdkClientConfig, EsdkCommitmentPolicy,
    Keyring, MultiKeyringConfig, RawAesKeyringConfig,
};
use std::collections::BTreeMap;

const KMS_KEY_ARN: &str =
    "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f";

fn raw_aes(key_name: &str, key_byte: u8) -> Keyring {
    Keyring {
        raw_aes: Some(RawAesKeyringConfig {
            key_namespace: "esdk-test-server".to_owned(),
            key_name: key_name.to_owned(),
            wrapping_key: vec![key_byte; 32],
            wrapping_alg: AesWrappingAlg::Alg256,
        }),
        ..Default::default()
    }
}

fn default_cmm(keyring: Keyring) -> CryptographicMaterialsManager {
    CryptographicMaterialsManager {
        default_cmm: Some(DefaultCmmConfig { keyring }),
        ..Default::default()
    }
}

fn config(cmm: CryptographicMaterialsManager) -> CreateClientRequest {
    CreateClientRequest {
        config: EsdkClientConfig {
            commitment_policy: EsdkCommitmentPolicy::RequireEncryptRequireDecrypt,
            max_encrypted_data_keys: None,
            cmm,
        },
    }
}

async fn create(state: &AppState, cmm: CryptographicMaterialsManager) -> String {
    state
        .create_client(config(cmm))
        .await
        .unwrap_or_else(|e| panic!("CreateClient failed: {}", e.message()))
        .client_id
}

fn ec() -> BTreeMap<String, String> {
    BTreeMap::from([("purpose".to_owned(), "keyring-configs".to_owned())])
}

async fn encrypt(state: &AppState, client_id: &str) -> Vec<u8> {
    state
        .encrypt(EncryptRequest {
            client_id: client_id.to_owned(),
            plaintext: b"keyring configs".to_vec(),
            encryption_context: Some(ec()),
            algorithm_suite_id: None,
            frame_length: None,
        })
        .await
        .unwrap_or_else(|e| panic!("Encrypt failed: {}", e.message()))
        .ciphertext
}

async fn decrypt(state: &AppState, client_id: &str, ciphertext: Vec<u8>) -> Vec<u8> {
    state
        .decrypt(DecryptRequest {
            client_id: client_id.to_owned(),
            ciphertext,
            encryption_context: Some(ec()),
        })
        .await
        .unwrap_or_else(|e| panic!("Decrypt failed: {}", e.message()))
        .plaintext
}

/// Encrypt with `encrypt_cmm`, decrypt with `decrypt_cmm`, and check the plaintext survives.
async fn round_trip(
    encrypt_cmm: CryptographicMaterialsManager,
    decrypt_cmm: CryptographicMaterialsManager,
) {
    let state = AppState::new();
    let encryptor = create(&state, encrypt_cmm).await;
    let decryptor = create(&state, decrypt_cmm).await;
    let ciphertext = encrypt(&state, &encryptor).await;
    assert_eq!(
        decrypt(&state, &decryptor, ciphertext).await,
        b"keyring configs"
    );
}

#[tokio::test]
async fn multi_keyring_child_decrypts_alone() {
    let multi = Keyring {
        multi: Some(MultiKeyringConfig {
            generator: Some(Box::new(raw_aes("generator", 1))),
            child_keyrings: vec![raw_aes("child", 2)],
        }),
        ..Default::default()
    };
    round_trip(default_cmm(multi), default_cmm(raw_aes("child", 2))).await;
}

#[tokio::test]
async fn aws_kms_keyring_builds() {
    let keyring = Keyring {
        aws_kms: Some(AwsKmsKeyringConfig {
            kms_key_id: KMS_KEY_ARN.to_owned(),
            grant_tokens: None,
        }),
        ..Default::default()
    };
    create(&AppState::new(), default_cmm(keyring)).await;
}

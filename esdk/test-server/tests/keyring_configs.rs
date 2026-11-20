// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The Caching CMM builds from its `CreateClient` config and caches data keys
//! across the messages a client encrypts.

use aws_esdk_test_server::handlers::AppState;
use aws_esdk_test_server::model::{
    AesWrappingAlg, CachingCmmConfig, CreateClientRequest, CryptographicMaterialsManager,
    DecryptRequest, DefaultCmmConfig, EncryptRequest, EsdkClientConfig, EsdkCommitmentPolicy,
    Keyring, RawAesKeyringConfig,
};
use std::collections::BTreeMap;

fn raw_aes() -> Keyring {
    Keyring {
        raw_aes: Some(RawAesKeyringConfig {
            key_namespace: "esdk-test-server".to_owned(),
            key_name: "raw-aes".to_owned(),
            wrapping_key: (0u8..32).collect(),
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

fn caching(
    underlying: CryptographicMaterialsManager,
    limit_messages: Option<i64>,
    shared_cache_name: Option<&str>,
) -> CryptographicMaterialsManager {
    CryptographicMaterialsManager {
        caching: Some(CachingCmmConfig {
            underlying_cmm: Box::new(underlying),
            cache_limit_ttl_seconds: 60,
            partition_id: shared_cache_name.map(str::to_owned),
            limit_bytes: None,
            limit_messages,
            shared_cache_name: shared_cache_name.map(str::to_owned),
        }),
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

async fn create_err(cmm: CryptographicMaterialsManager) -> String {
    match AppState::new().create_client(config(cmm)).await {
        Ok(_) => panic!("CreateClient must fail"),
        Err(e) => e.message().to_owned(),
    }
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

/// The encrypted data key section of a V2 message header: the count and every key.
fn edks(ciphertext: &[u8]) -> Vec<u8> {
    let u16_at = |at: usize| usize::from(u16::from_be_bytes([ciphertext[at], ciphertext[at + 1]]));
    // Version (1), suite id (2), message id (32), then the AAD length and the AAD.
    let start = 37 + u16_at(35);
    let mut at = start + 2;
    for _ in 0..u16_at(start) {
        // Provider id, provider info, and ciphertext, each with a 2-byte length.
        for _ in 0..3 {
            at += 2 + u16_at(at);
        }
    }
    ciphertext[start..at].to_vec()
}

#[tokio::test]
async fn caching_cmm_reuses_the_data_key() {
    let state = AppState::new();
    let client_id = create(&state, caching(default_cmm(raw_aes()), None, None)).await;
    let first = encrypt(&state, &client_id).await;
    let second = encrypt(&state, &client_id).await;
    assert_eq!(edks(&first), edks(&second));
    assert_eq!(
        decrypt(&state, &client_id, second).await,
        b"keyring configs"
    );
}

#[tokio::test]
async fn caching_cmm_message_limit_forces_a_new_data_key() {
    let state = AppState::new();
    let client_id = create(&state, caching(default_cmm(raw_aes()), Some(1), None)).await;
    let first = encrypt(&state, &client_id).await;
    let second = encrypt(&state, &client_id).await;
    assert_ne!(edks(&first), edks(&second));
}

#[tokio::test]
async fn caching_cmms_share_a_named_cache() {
    let state = AppState::new();
    let a = create(
        &state,
        caching(default_cmm(raw_aes()), None, Some("shared")),
    )
    .await;
    let b = create(
        &state,
        caching(default_cmm(raw_aes()), None, Some("shared")),
    )
    .await;
    let c = create(&state, caching(default_cmm(raw_aes()), None, None)).await;
    let from_a = encrypt(&state, &a).await;
    assert_eq!(edks(&from_a), edks(&encrypt(&state, &b).await));
    assert_ne!(edks(&from_a), edks(&encrypt(&state, &c).await));
}

#[tokio::test]
async fn caching_cmm_rejects_a_negative_limit() {
    let message = create_err(caching(default_cmm(raw_aes()), Some(-1), None)).await;
    assert!(message.contains("limitMessages"), "{message}");
}

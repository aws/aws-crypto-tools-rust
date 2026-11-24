// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Helpers and imports that the examples use.
//! The tests in this folder and the generated api_example_combos test both use this module.

pub use aws_esdk::cmm::{DefaultCmm, SharedCmm};
pub use aws_esdk::keyring::RawAesKeyring;
pub use aws_esdk::mpl::shared::IntoShared;
pub use aws_esdk::types::{AesWrappingAlg, AlgorithmSuiteId, CommitmentPolicy, EncryptionContext};
pub use aws_esdk::{Client, Config, Error};

/// Stands in for settings that the customer's application loads.
pub struct AppConfig {
    pub tenant: String,
}

pub fn app_config() -> AppConfig {
    AppConfig {
        tenant: "my-tenant".to_string(),
    }
}

pub fn make_raw_aes_keyring() -> RawAesKeyring {
    RawAesKeyring::builder()
        .key_namespace("my-key-namespace")
        .key_name("my-key-name")
        .wrapping_key(vec![0x01; 32])
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()
        .expect("a raw AES keyring with every option set builds")
}

/// A message that `make_raw_aes_keyring()` encrypted, with the encryption context `tenant = my-tenant`.
pub async fn make_encrypted_message() -> Vec<u8> {
    Client::default()
        .encrypt()
        .plaintext(b"my secret data")
        .encryption_context("tenant", "my-tenant")
        .keyring(make_raw_aes_keyring())
        .send()
        .await
        .expect("encrypt with a raw AES keyring succeeds")
        .into_ciphertext()
        .into_inner()
}

/// Decrypts `ciphertext` with `make_raw_aes_keyring()`.
pub async fn decrypt(ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    Ok(Client::default()
        .decrypt()
        .ciphertext(ciphertext)
        .keyring(make_raw_aes_keyring())
        .send()
        .await?
        .into_plaintext()
        .into_inner())
}

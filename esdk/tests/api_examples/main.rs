// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! An example of every way to build the ESDK client and to call encrypt and decrypt.
//!
//! scripts/api-examples/surface.py lists the ways from the public API.
//! Each `// api-example:` line names one of those ways, and the code between
//! `// snippet-start` and `// snippet-end` under it is what a customer writes for it.
//! The api-examples script in aws-crypto-tools-commons collects these snippets for the API examples dashboard,
//! and fails CI when a way has no example.
//! Everything outside the markers is setup and assertions, which the dashboard does not show.

mod client;
mod decrypt;
mod encrypt;

use aws_esdk::keyring::RawAesKeyring;
use aws_esdk::types::AesWrappingAlg;
use aws_esdk::{Client, Error};

/// Stands in for settings that the customer's application loads.
struct AppConfig {
    tenant: String,
}

fn app_config() -> AppConfig {
    AppConfig {
        tenant: "my-tenant".to_string(),
    }
}

fn raw_aes_keyring() -> RawAesKeyring {
    RawAesKeyring::builder()
        .key_namespace("my-key-namespace")
        .key_name("my-key-name")
        .wrapping_key(vec![0x01; 32])
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()
        .expect("a raw AES keyring with every option set builds")
}

/// A message that `raw_aes_keyring` encrypted, with the encryption context `tenant = my-tenant`.
async fn encrypted_message() -> Vec<u8> {
    Client::default()
        .encrypt()
        .plaintext(b"my secret data")
        .encryption_context("tenant", "my-tenant")
        .keyring(raw_aes_keyring())
        .send()
        .await
        .expect("encrypt with a raw AES keyring succeeds")
        .into_ciphertext()
        .into_inner()
}

/// Decrypts `ciphertext` with `raw_aes_keyring`.
async fn decrypt(ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    Ok(Client::default()
        .decrypt()
        .ciphertext(ciphertext)
        .keyring(raw_aes_keyring())
        .send()
        .await?
        .into_plaintext()
        .into_inner())
}

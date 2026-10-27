// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines a custom keyring by implementing the [`Keyring`] trait.
//!
//! `AuditKeyring` wraps a raw AES keyring and logs which key providers each call uses.
//! It encrypts through an [`ItemEncryptor`], so the example needs no table.
//!
//! Runs offline.

use std::collections::HashMap;

use aws_db_esdk::async_trait;
use aws_db_esdk::aws_sdk_dynamodb::types::AttributeValue;
use aws_db_esdk::keyring::{
    Keyring, OnDecryptInput, OnDecryptOutput, OnEncryptInput, OnEncryptOutput, RawAesKeyring,
};
use aws_db_esdk::mpl::Error as MplError;
use aws_db_esdk::mpl::types::EncryptedDataKey;
use aws_db_esdk::types::{AesWrappingAlg, CryptoAction};
use aws_db_esdk::{ItemEncryptor, TableConfig};

/// Wraps another keyring and logs the key providers of the encrypted data keys each call writes or tries.
#[derive(Clone)]
struct AuditKeyring {
    inner: RawAesKeyring,
}

fn providers(edks: &[EncryptedDataKey]) -> Vec<&str> {
    edks.iter().map(EncryptedDataKey::key_provider_id).collect()
}

#[async_trait]
impl Keyring for AuditKeyring {
    async fn on_encrypt(&self, input: OnEncryptInput) -> Result<OnEncryptOutput, MplError> {
        let output = self
            .inner
            .on_encrypt()
            .materials(input.into_materials())
            .send()
            .await?;
        println!(
            "audit: encrypt wrote data keys for {:?}",
            providers(output.materials().encrypted_data_keys())
        );
        Ok(output)
    }

    async fn on_decrypt(&self, input: OnDecryptInput) -> Result<OnDecryptOutput, MplError> {
        println!(
            "audit: decrypt tried data keys from {:?}",
            providers(input.encrypted_data_keys())
        );
        let (materials, encrypted_data_keys) = input.into_parts();
        self.inner
            .on_decrypt()
            .materials(materials)
            .encrypted_data_keys(encrypted_data_keys)
            .send()
            .await
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // For demonstration only.
    // A real application must load its wrapping key from a secure store, never hardcode it.
    let inner = RawAesKeyring::builder()
        .key_namespace("my-key-namespace")
        .key_name("my-key-name")
        .wrapping_key(vec![0x2A; 32])
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()?;

    let table = TableConfig::builder()
        .partition_key_name("partition_key")
        .attribute_actions_on_encrypt("partition_key", CryptoAction::SignOnly)
        .attribute_actions_on_encrypt("sensitive_data", CryptoAction::EncryptAndSign)
        .keyring(AuditKeyring { inner })
        .build()?;
    let encryptor = ItemEncryptor::builder()
        .table("CustomKeyringExample", table)
        .build()?;

    let item = HashMap::from([
        (
            "partition_key".to_string(),
            AttributeValue::S("CustomKeyringExample".into()),
        ),
        (
            "sensitive_data".to_string(),
            AttributeValue::S("encrypt and sign me!".into()),
        ),
    ]);

    let encrypted = encryptor
        .encrypt_item()
        .plaintext_item(item.clone())
        .send()
        .await?;
    let decrypted = encryptor
        .decrypt_item()
        .encrypted_item(encrypted.into_encrypted_item())
        .send()
        .await?;

    assert_eq!(
        decrypted.plaintext_item(),
        &item,
        "Decryption failed: item mismatch"
    );
    println!("Success! Encrypted and decrypted an item through a custom keyring.");
    Ok(())
}

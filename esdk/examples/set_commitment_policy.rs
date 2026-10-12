// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Encrypts and decrypts under a non-default commitment policy.
//!
//! The default policy, `RequireEncryptRequireDecrypt`, encrypts and decrypts only with key-committing suites.
//! Use `ForbidEncryptAllowDecrypt` only while migrating from an ESDK version 1.x that cannot read committing messages,
//! and move to the default once every reader is upgraded.
//!
//! An `Esdk` client applies its policy to every operation it starts.
//!
//! Runs offline.

use aws_crypto_mpl::{AesGcm, RawAesKeyring};
use aws_esdk::{CommitmentPolicy, EncryptionContext, Esdk};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let esdk = Esdk::builder()
        .commitment_policy(CommitmentPolicy::ForbidEncryptAllowDecrypt)
        .build();

    // For demonstration only.
    // A real application must load its wrapping key from a secure store, never hardcode it.
    let keyring = RawAesKeyring::builder()
        .key_namespace("my-key-namespace")
        .key_name("my-key-name")
        .wrapping_key(vec![0x01u8; 32])
        .wrapping_alg(AesGcm::Aes256Gcm)
        .build()?;

    let plaintext = b"Hello World";

    let mut encryption_context = EncryptionContext::new();
    encryption_context.insert("purpose", "example");

    let encrypted = esdk
        .encrypt()
        .plaintext(plaintext)
        .encryption_context(encryption_context.clone())
        .keyring(keyring.clone())
        .send()
        .await?;

    let decrypted = esdk
        .decrypt()
        .ciphertext(&encrypted.ciphertext)
        .encryption_context(encryption_context)
        .keyring(keyring)
        .send()
        .await?;

    assert_eq!(
        decrypted.plaintext, plaintext,
        "Decryption failed: plaintext mismatch"
    );
    println!(
        "Success! Encrypted with {:?} under ForbidEncryptAllowDecrypt.",
        encrypted.algorithm_suite_id
    );
    Ok(())
}

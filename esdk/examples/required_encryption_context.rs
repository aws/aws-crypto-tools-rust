// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Encrypts and decrypts a message with a required encryption context.
//!
//! A required-encryption-context CMM names encryption-context keys that are authenticated but not stored in the message.
//! The decryptor must supply those keys again (the reproduced encryption context), so they are bound to the message without taking up space on the wire.

use aws_esdk::{DecryptInput, EncryptInput, EncryptionContext, decrypt, encrypt, mpl};
use aws_mpl_legacy::dafny::types::AesWrappingAlg;
use aws_smithy_types::Blob;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mpl = mpl();

    // For demonstration only: a real application must source its wrapping key from a secure store and never hardcode it.
    let keyring = mpl
        .create_raw_aes_keyring()
        .key_namespace("my-key-namespace")
        .key_name("my-key-name")
        .wrapping_key(Blob::new([0x01u8; 32]))
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .send()
        .await?;

    // Wrap the keyring in a default CMM, then in a required-encryption-context CMM that marks "tenant" as a required key.
    let default_cmm = mpl
        .create_default_cryptographic_materials_manager()
        .keyring(keyring.clone())
        .send()
        .await?;
    let required_ec_cmm = mpl
        .create_required_encryption_context_cmm()
        .underlying_cmm(default_cmm)
        .required_encryption_context_keys(vec!["tenant".to_string()])
        .send()
        .await?;

    let plaintext = b"Hello World";

    // "tenant" is authenticated but not written to the message; "purpose" is written as usual.
    let mut encryption_context = EncryptionContext::new();
    encryption_context.insert("tenant".to_string(), "tenant-a".to_string());
    encryption_context.insert("purpose".to_string(), "required-ec-example".to_string());

    let encrypted = encrypt(&EncryptInput::with_legacy_cmm(
        plaintext,
        encryption_context,
        required_ec_cmm,
    ))
    .await?;

    // Decrypt must reproduce the required key that was not stored in the message.
    let mut reproduced_context = EncryptionContext::new();
    reproduced_context.insert("tenant".to_string(), "tenant-a".to_string());

    let decrypted = decrypt(&DecryptInput::with_legacy_keyring(
        &encrypted.ciphertext,
        reproduced_context,
        keyring,
    ))
    .await?;

    assert_eq!(
        decrypted.plaintext, plaintext,
        "Decryption failed: plaintext mismatch"
    );
    println!("Success! Encryption and decryption completed successfully.");
    Ok(())
}

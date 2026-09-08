// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! One-shot encrypt/decrypt round trip with a raw AES keyring. Runs offline.

use aws_esdk::{DecryptInput, EncryptInput, EncryptionContext, decrypt, encrypt, mpl};
use aws_mpl_legacy::dafny::types::AesWrappingAlg;
use aws_smithy_types::Blob;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // For demonstration only: a real application must source its wrapping key
    // from a secure store and never hardcode it.
    let wrapping_key = [0x01u8; 32];

    // The namespace and name identify this wrapping key. Decrypt must use a
    // keyring with the same namespace, name, key, and wrapping algorithm.
    let keyring = mpl()
        .create_raw_aes_keyring()
        .key_namespace("my-key-namespace")
        .key_name("my-key-name")
        .wrapping_key(Blob::new(wrapping_key))
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .send()
        .await?;

    let plaintext = b"Hello World";

    // The encryption context is authenticated, not encrypted, and is bound to
    // the message. The same context must be reproducible on decrypt.
    let mut encryption_context = EncryptionContext::new();
    encryption_context.insert("purpose".to_string(), "raw-aes-example".to_string());

    let encrypted = encrypt(&EncryptInput::with_legacy_keyring(
        plaintext,
        encryption_context.clone(),
        keyring.clone(),
    ))
    .await?;

    let decrypted = decrypt(&DecryptInput::with_legacy_keyring(
        &encrypted.ciphertext,
        encryption_context,
        keyring,
    ))
    .await?;

    assert_eq!(
        decrypted.plaintext, plaintext,
        "round-trip plaintext must match"
    );
    println!("Success! Raw AES keyring encrypt/decrypt round trip completed.");
    Ok(())
}

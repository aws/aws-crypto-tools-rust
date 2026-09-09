// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Example demonstrating use of streaming APIs.
//!
//! Streamed encrypt/decrypt is for data too large to hold in memory at once.
//! `encrypt_stream` and `decrypt_stream` read from any `Read` source and write to any `Write` sink,
//! so you can stream a whole file (or socket) straight through.
//!
//! This example encrypts a plaintext file to a ciphertext file, then decrypts that back to a third file.
//!
//! A non-signing suite is used so streamed decrypt works regardless of message size;
//! the ESDK refuses streamed decrypt of a multi-frame signed message.

use std::fs::{self, File};
use std::io::Write;

use aws_esdk::{
    DecryptStreamInput, EncryptStreamInput, EncryptionContext, EsdkAlgorithmSuiteId,
    decrypt_stream, encrypt_stream, mpl,
};
use aws_mpl_legacy::dafny::types::AesWrappingAlg;
use aws_smithy_types::Blob;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!("esdk-streaming-example-{}", std::process::id()));
    fs::create_dir_all(&dir)?;
    let plaintext_path = dir.join("plaintext.txt");
    let ciphertext_path = dir.join("ciphertext.bin");
    let decrypted_path = dir.join("decrypted.txt");

    // Seed a plaintext file to encrypt. In practice this file already exists.
    let plaintext = b"the quick brown fox jumps over the lazy dog";
    File::create(&plaintext_path)?.write_all(plaintext)?;

    // For demonstration only: a real application must source its wrapping
    // key from a secure store and never hardcode it.
    let wrapping_key = [0x01u8; 32];
    let keyring = mpl()
        .create_raw_aes_keyring()
        .key_namespace("my-key-namespace")
        .key_name("my-key-name")
        .wrapping_key(Blob::new(wrapping_key))
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .send()
        .await?;

    // The encryption context is authenticated, not encrypted. It is bound to
    // the message and must be reproducible on decrypt.
    let mut encryption_context = EncryptionContext::new();
    encryption_context.insert("purpose".to_string(), "streaming-example".to_string());
    encryption_context.insert("is not".to_string(), "secret".to_string());

    // Encrypt the plaintext file straight into the ciphertext file.
    let mut enc_input =
        EncryptStreamInput::with_legacy_keyring(encryption_context.clone(), keyring.clone());
    enc_input.algorithm_suite_id = Some(EsdkAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey);
    {
        let mut input = File::open(&plaintext_path)?;
        let mut output = File::create(&ciphertext_path)?;
        encrypt_stream(&mut input, &mut output, &enc_input).await?;
    }

    // Decrypt the ciphertext file back into the decrypted file.
    // Note: decrypt_stream writes plaintext to the sink before verification completes.
    // The function returns normally only if the whole message authenticates.
    // If the function returns an error, you MUST discard the decrypted file/output.
    let dec_input = DecryptStreamInput::with_legacy_keyring(encryption_context, keyring);
    {
        let mut input = File::open(&ciphertext_path)?;
        let mut output = File::create(&decrypted_path)?;
        decrypt_stream(&mut input, &mut output, &dec_input).await?;
    }

    // The decrypted file matches the original plaintext (demo check only).
    assert_eq!(
        fs::read(&decrypted_path)?,
        plaintext,
        "Decryption failed: decrypted file differs from plaintext"
    );

    fs::remove_dir_all(&dir)?;
    println!("Success! Streaming encryption and decryption completed successfully.");
    Ok(())
}

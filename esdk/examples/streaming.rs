// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Encrypts a file into a second file with `encrypt_stream`, then decrypts it into a third with `decrypt_stream`.
//!
//! The one-shot `encrypt` and `decrypt` hold the whole message in memory.
//! The streaming APIs read from any `Read` and write to any `Write`,
//! so a file or socket of any size passes through in bounded memory.
//!
//! The example uses a non-signing suite: streamed decrypt rejects a multi-frame signed message.
//!
//! Runs offline.

use std::fs::{self, File};
use std::io::Write;

use aws_crypto_mpl::{AesGcm, RawAesKeyring};
use aws_esdk::{
    AlgorithmSuiteId, DecryptStreamInput, EncryptStreamInput, EncryptionContext, decrypt_stream,
    encrypt_stream,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!("esdk-streaming-example-{}", std::process::id()));
    fs::create_dir_all(&dir)?;
    let plaintext_path = dir.join("plaintext.txt");
    let ciphertext_path = dir.join("ciphertext.bin");
    let decrypted_path = dir.join("decrypted.txt");

    // Stands in for a file the application already has.
    let plaintext = b"the quick brown fox jumps over the lazy dog";
    File::create(&plaintext_path)?.write_all(plaintext)?;

    // For demonstration only.
    // A real application must load its wrapping key from a secure store, never hardcode it.
    let wrapping_key = vec![0x01u8; 32];
    let keyring = RawAesKeyring::builder()
        .key_namespace("my-key-namespace")
        .key_name("my-key-name")
        .wrapping_key(wrapping_key)
        .wrapping_alg(AesGcm::Aes256Gcm)
        .build()?;

    // The encryption context is authenticated, not encrypted, and is bound to the message.
    let mut encryption_context = EncryptionContext::new();
    encryption_context.insert("purpose", "streaming-example");
    encryption_context.insert("is not", "secret");

    let enc_input = EncryptStreamInput::builder()
        .encryption_context(encryption_context.clone())
        .keyring(keyring.clone())
        .algorithm_suite_id(AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey)
        .build()?;
    {
        let mut input = File::open(&plaintext_path)?;
        let mut output = File::create(&ciphertext_path)?;
        if let Err(e) = encrypt_stream(&mut input, &mut output, &enc_input).await {
            // On error the ciphertext file is incomplete; delete it.
            drop(output);
            let _ = fs::remove_file(&ciphertext_path);
            return Err(e.into());
        }
    }

    // decrypt_stream writes plaintext to `output` before it has verified the whole message.
    // It returns Ok only if the whole message authenticates.
    let dec_input = DecryptStreamInput::builder()
        .encryption_context(encryption_context)
        .keyring(keyring)
        .build()?;
    {
        let mut input = File::open(&ciphertext_path)?;
        let mut output = File::create(&decrypted_path)?;
        if let Err(e) = decrypt_stream(&mut input, &mut output, &dec_input).await {
            // On error the plaintext written so far is unverified; delete it unused.
            drop(output);
            let _ = fs::remove_file(&decrypted_path);
            return Err(e.into());
        }
    }

    assert_eq!(
        fs::read(&decrypted_path)?,
        plaintext,
        "Decryption failed: decrypted file differs from plaintext"
    );

    fs::remove_dir_all(&dir)?;
    println!("Success! Streaming encryption and decryption completed successfully.");
    Ok(())
}

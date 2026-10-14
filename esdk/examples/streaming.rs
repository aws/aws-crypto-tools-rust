// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Encrypts a file into a second file with `encrypt_stream`, then decrypts it into a third with `decrypt_stream`.
//!
//! The one-shot `encrypt` and `decrypt` hold the whole message in memory.
//! The streaming APIs read from any tokio `AsyncRead` and write to any `AsyncWrite`,
//! so a file, socket, or S3 object of any size passes through in bounded memory.
//!
//! The example uses a non-signing suite: streamed decrypt rejects a multi-frame signed message.
//!
//! Runs offline.

use tokio::fs::{self, File};

use aws_crypto_mpl::{AesGcm, RawAesKeyring};
use aws_esdk::{AlgorithmSuiteId, EncryptionContext};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!("esdk-streaming-example-{}", std::process::id()));
    fs::create_dir_all(&dir).await?;
    let plaintext_path = dir.join("plaintext.txt");
    let ciphertext_path = dir.join("ciphertext.bin");
    let decrypted_path = dir.join("decrypted.txt");

    // Stands in for a file the application already has.
    let plaintext = b"the quick brown fox jumps over the lazy dog";
    fs::write(&plaintext_path, plaintext).await?;

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
    let encryption_context =
        EncryptionContext::from([("purpose", "streaming-example"), ("is not", "secret")]);

    let esdk = aws_esdk::Client::default();

    let input = File::open(&plaintext_path).await?;
    let output = File::create(&ciphertext_path).await?;
    let result = esdk
        .encrypt_stream()
        .set_encryption_context(Some(encryption_context.clone()))
        .keyring(keyring.clone())
        .algorithm_suite_id(AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey)
        .send(input, output)
        .await;
    if let Err(e) = result {
        // On error the ciphertext file is incomplete; delete it.
        let _ = fs::remove_file(&ciphertext_path).await;
        return Err(e.into());
    }

    // decrypt_stream writes plaintext to `output` before it has verified the whole message.
    // It returns Ok only if the whole message authenticates.
    let input = File::open(&ciphertext_path).await?;
    let output = File::create(&decrypted_path).await?;
    let result = esdk
        .decrypt_stream()
        .set_encryption_context(Some(encryption_context))
        .keyring(keyring)
        .send(input, output)
        .await;
    if let Err(e) = result {
        // On error the plaintext written so far is unverified; delete it unused.
        let _ = fs::remove_file(&decrypted_path).await;
        return Err(e.into());
    }

    assert_eq!(
        fs::read(&decrypted_path).await?,
        plaintext,
        "Decryption failed: decrypted file differs from plaintext"
    );

    fs::remove_dir_all(&dir).await?;
    println!("Success! Streaming encryption and decryption completed successfully.");
    Ok(())
}

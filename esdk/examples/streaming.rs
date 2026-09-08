// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Streamed file encrypt/decrypt with a raw AES keyring. Runs offline.
//!
//! Streaming is for data too large to hold in memory at once. `encrypt_stream`
//! and `decrypt_stream` read from any `Read` and write to any `Write`, so a
//! whole file (or socket) flows through in bounded memory. This example
//! encrypts a plaintext file to a ciphertext file, then decrypts it back.

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

    // For demonstration only: a real application must source its wrapping key
    // from a secure store and never hardcode it.
    let keyring = mpl()
        .create_raw_aes_keyring()
        .key_namespace("my-key-namespace")
        .key_name("my-key-name")
        .wrapping_key(Blob::new([0x01u8; 32]))
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .send()
        .await?;

    // The encryption context is authenticated, not encrypted, and must be
    // reproducible on decrypt.
    let mut encryption_context = EncryptionContext::new();
    encryption_context.insert("purpose".to_string(), "streaming-example".to_string());

    // A non-signing suite lets streamed decrypt handle any message size:
    // streamed decrypt refuses a multi-frame message under a signing suite.
    let mut enc_input =
        EncryptStreamInput::with_legacy_keyring(encryption_context.clone(), keyring.clone());
    enc_input.algorithm_suite_id = Some(EsdkAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey);

    {
        let mut plaintext_file = File::open(&plaintext_path)?;
        let mut ciphertext_file = File::create(&ciphertext_path)?;
        encrypt_stream(&mut plaintext_file, &mut ciphertext_file, &enc_input).await?;
    }

    // Streamed decrypt writes plaintext to the sink before the whole message is
    // verified. It returns normally only if the message authenticates; if it
    // errors, discard whatever it wrote.
    let dec_input = DecryptStreamInput::with_legacy_keyring(encryption_context, keyring);
    {
        let mut ciphertext_file = File::open(&ciphertext_path)?;
        let mut decrypted_file = File::create(&decrypted_path)?;
        decrypt_stream(&mut ciphertext_file, &mut decrypted_file, &dec_input).await?;
    }

    let round_tripped = fs::read(&decrypted_path)?;
    assert_eq!(round_tripped, plaintext, "round-trip plaintext must match");

    fs::remove_dir_all(&dir)?;
    println!("Success! Streaming encrypt/decrypt round trip completed.");
    Ok(())
}

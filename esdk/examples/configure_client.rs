// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sets every client and encrypt option the ESDK offers.
//!
//! A `Client` holds the settings that apply to every operation it starts:
//! the commitment policy and the most encrypted data keys a message may carry.
//! Each `encrypt` call can also pick its own algorithm suite and frame length.
//!
//! Runs offline.

use aws_esdk::keyring::RawAesKeyring;
use aws_esdk::types::{AesWrappingAlg, AlgorithmSuiteId, CommitmentPolicy, EncryptionContext};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let esdk = aws_esdk::Client::builder()
        .commitment_policy(CommitmentPolicy::RequireEncryptRequireDecrypt)
        // Encrypt and decrypt reject a message with more encrypted data keys than this.
        // Set it to the most keyrings you ever encrypt to, so a decrypt can't be made to try many keys.
        .max_encrypted_data_keys(1)
        .build()?;

    // For demonstration only.
    // A real application must load its wrapping key from a secure store, never hardcode it.
    let keyring = RawAesKeyring::builder()
        .key_namespace("my-key-namespace")
        .key_name("my-key-name")
        .wrapping_key(vec![0x01u8; 32])
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()?;

    let plaintext = vec![0x42u8; 10_000];

    let encryption_context = EncryptionContext::from([("purpose", "example")]);

    let encrypted = esdk
        .encrypt()
        .plaintext(&plaintext)
        .set_encryption_context(Some(encryption_context.clone()))
        .keyring(keyring.clone())
        .algorithm_suite_id(AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384)
        // 10,000 bytes in 1,024-byte frames makes a message with 10 frames.
        .frame_length(1024)
        .send()
        .await?;

    // Decrypt reads the algorithm suite and frame length from the message.
    let decrypted = esdk
        .decrypt()
        .ciphertext(encrypted.ciphertext())
        .set_encryption_context(Some(encryption_context))
        .keyring(keyring)
        .send()
        .await?;

    assert_eq!(
        decrypted.plaintext(),
        plaintext.as_slice(),
        "Decryption failed: plaintext mismatch"
    );
    println!(
        "Success! Encrypted with {:?} in 1024-byte frames.",
        encrypted.algorithm_suite_id()
    );
    Ok(())
}

// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Keeps chosen encryption context pairs out of the message with a required encryption context CMM.
//!
//! Runs offline.

use aws_esdk::Error;
use aws_esdk::cmm::{DefaultCmm, RequiredEncryptionContextCmm};
use aws_esdk::keyring::RawAesKeyring;
use aws_esdk::types::{AesWrappingAlg, EncryptionContext};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // For demonstration only.
    // A real application must load its wrapping key from a secure store, never hardcode it.
    let keyring = RawAesKeyring::builder()
        .key_namespace("my-key-namespace")
        .key_name("my-key-name")
        .wrapping_key(vec![0x01u8; 32])
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()?;

    // Encrypt fails unless the encryption context has every required key.
    // The message authenticates the required pairs but does not store them.
    let cmm = RequiredEncryptionContextCmm::builder()
        .underlying_cmm(DefaultCmm::new(keyring.clone()))
        .required_encryption_context_keys("tenant")
        .build()?;

    let plaintext = b"Hello World";

    // The encryption context is authenticated, not encrypted, and is bound to the message.
    let encryption_context =
        EncryptionContext::from([("purpose", "example"), ("tenant", "TenantA")]);

    let esdk = aws_esdk::Client::default();

    let encrypted = esdk
        .encrypt()
        .plaintext(plaintext)
        .set_encryption_context(Some(encryption_context))
        .cmm(cmm.clone())
        .send()
        .await?;

    // Decrypt fails unless the caller supplies the required pairs.
    let result = esdk
        .decrypt()
        .ciphertext(encrypted.ciphertext())
        .cmm(cmm.clone())
        .send()
        .await;
    assert!(
        matches!(result, Err(Error::EncryptionContextMismatch(_))),
        "decrypt without the required pair must fail, got {result:?}"
    );

    // The caller must supply a value for every required key, and may leave out the stored pairs.
    let reproduced_encryption_context = EncryptionContext::from([("tenant", "TenantA")]);

    let decrypted = esdk
        .decrypt()
        .ciphertext(encrypted.ciphertext())
        .set_encryption_context(Some(reproduced_encryption_context.clone()))
        .cmm(cmm)
        .send()
        .await?;
    assert_eq!(
        decrypted.plaintext(),
        plaintext,
        "Decryption failed: plaintext mismatch"
    );

    // Decrypt does not need the required encryption context CMM, but it still needs the pairs.
    // Without them, the raw AES keyring cannot unwrap the data key.
    let result = esdk
        .decrypt()
        .ciphertext(encrypted.ciphertext())
        .keyring(keyring.clone())
        .send()
        .await;
    assert!(
        matches!(result, Err(Error::Cryptographic(_))),
        "a keyring without the required pair must fail, got {result:?}"
    );

    let decrypted = esdk
        .decrypt()
        .ciphertext(encrypted.ciphertext())
        .set_encryption_context(Some(reproduced_encryption_context))
        .keyring(keyring)
        .send()
        .await?;
    assert_eq!(
        decrypted.plaintext(),
        plaintext,
        "Decryption failed: plaintext mismatch"
    );

    println!(
        "Success! Decrypt failed without the required encryption context and succeeded with it."
    );
    Ok(())
}

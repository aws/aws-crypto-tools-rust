// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines a custom cryptographic materials manager (CMM) by implementing the [`Cmm`] trait.
//!
//! `SigningSuiteOnlyCmm` wraps a [`DefaultCmm`] and rejects any algorithm suite without a signature,
//! so a caller cannot encrypt or decrypt an unsigned message through it.
//! A signature lets a decryptor verify that the message came from someone allowed to encrypt,
//! not just someone allowed to decrypt.
//!
//! Runs offline.

use aws_crypto_mpl::cmm::{
    DecryptMaterialsInput, DecryptMaterialsOutput, GetEncryptionMaterialsInput,
    GetEncryptionMaterialsOutput,
};
use aws_crypto_mpl::{AesGcm, Cmm, DefaultCmm, Keyring, RawAesKeyring};
use aws_esdk::error::Error;
use aws_esdk::{AlgorithmSuiteId, DecryptInput, EncryptInput, EncryptionContext, decrypt, encrypt};

/// Passes requests to a [`DefaultCmm`] and fails any that would use an algorithm suite without a signature.
#[derive(Clone)]
struct SigningSuiteOnlyCmm {
    inner: DefaultCmm,
}

impl SigningSuiteOnlyCmm {
    fn new(keyring: impl Keyring + 'static) -> Self {
        Self {
            inner: DefaultCmm::new(keyring),
        }
    }
}

#[async_trait::async_trait]
impl Cmm for SigningSuiteOnlyCmm {
    async fn get_encryption_materials(
        &self,
        input: GetEncryptionMaterialsInput,
    ) -> Result<GetEncryptionMaterialsOutput, Error> {
        // The caller may leave the suite unset and let the default CMM choose,
        // so check the suite on the materials it returns.
        let output = self.inner.get_encryption_materials(input).await?;
        let suite = output.encryption_materials().algorithm_suite();
        if suite.asymmetric_signature_algorithm().is_none() {
            return Err(Error::validation("algorithm suite must use signing"));
        }
        Ok(output)
    }

    async fn decrypt_materials(
        &self,
        input: DecryptMaterialsInput,
    ) -> Result<DecryptMaterialsOutput, Error> {
        if !input.algorithm_suite_id().has_asymmetric_signing() {
            return Err(Error::validation("algorithm suite must use signing"));
        }
        self.inner.decrypt_materials(input).await
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // For demonstration only.
    // A real application must load its wrapping key from a secure store, never hardcode it.
    let keyring = RawAesKeyring::builder()
        .key_namespace("my-key-namespace")
        .key_name("my-key-name")
        .wrapping_key(vec![0x01u8; 32])
        .wrapping_alg(AesGcm::Aes256Gcm)
        .build()?;
    let cmm = SigningSuiteOnlyCmm::new(keyring);

    let plaintext = b"Hello World";

    let mut encryption_context = EncryptionContext::new();
    encryption_context.insert("purpose", "example");

    // The default algorithm suite signs, so the CMM allows it.
    let encrypted = encrypt(
        &EncryptInput::builder()
            .plaintext(plaintext)
            .encryption_context(encryption_context.clone())
            .cmm(cmm.clone())
            .build()?,
    )
    .await?;

    let decrypted = decrypt(
        &DecryptInput::builder()
            .ciphertext(&encrypted.ciphertext)
            .encryption_context(encryption_context.clone())
            .cmm(cmm.clone())
            .build()?,
    )
    .await?;
    assert_eq!(
        decrypted.plaintext, plaintext,
        "Decryption failed: plaintext mismatch"
    );

    // A suite without a signature is rejected.
    let result = encrypt(
        &EncryptInput::builder()
            .plaintext(plaintext)
            .encryption_context(encryption_context)
            .cmm(cmm)
            .algorithm_suite_id(AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey)
            .build()?,
    )
    .await;
    assert!(
        matches!(result, Err(Error::Validation(_))),
        "a non-signing suite must be rejected, got {result:?}"
    );

    println!("Success! The CMM allowed a signing suite and rejected a non-signing one.");
    Ok(())
}

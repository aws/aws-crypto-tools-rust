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

use aws_crypto_mpl::async_trait;
use aws_crypto_mpl::cmm::{
    DecryptMaterialsInput, DecryptMaterialsOutput, GetEncryptionMaterialsInput,
    GetEncryptionMaterialsOutput,
};
use aws_crypto_mpl::{AesGcm, Cmm, DefaultCmm, Error as MplError, Keyring, RawAesKeyring};
use aws_esdk::Error;
use aws_esdk::{AlgorithmSuiteId, EncryptionContext};

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

#[async_trait]
impl Cmm for SigningSuiteOnlyCmm {
    async fn get_encryption_materials(
        &self,
        input: GetEncryptionMaterialsInput,
    ) -> Result<GetEncryptionMaterialsOutput, MplError> {
        // The caller may leave the suite unset and let the default CMM choose,
        // so check the suite on the materials it returns.
        let output = Cmm::get_encryption_materials(&self.inner, input).await?;
        let suite = output.encryption_materials().algorithm_suite();
        if suite.asymmetric_signature_algorithm().is_none() {
            return Err(MplError::validation("algorithm suite must use signing"));
        }
        Ok(output)
    }

    async fn decrypt_materials(
        &self,
        input: DecryptMaterialsInput,
    ) -> Result<DecryptMaterialsOutput, MplError> {
        if !input.algorithm_suite_id().has_asymmetric_signing() {
            return Err(MplError::validation("algorithm suite must use signing"));
        }
        Cmm::decrypt_materials(&self.inner, input).await
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

    let encryption_context = EncryptionContext::from([("purpose", "example")]);

    let esdk = aws_esdk::Client::default();

    // The default algorithm suite signs, so the CMM allows it.
    let encrypted = esdk
        .encrypt()
        .plaintext(plaintext)
        .set_encryption_context(Some(encryption_context.clone()))
        .cmm(cmm.clone())
        .send()
        .await?;

    let decrypted = esdk
        .decrypt()
        .ciphertext(encrypted.ciphertext())
        .set_encryption_context(Some(encryption_context.clone()))
        .cmm(cmm.clone())
        .send()
        .await?;
    assert_eq!(
        decrypted.plaintext(),
        plaintext,
        "Decryption failed: plaintext mismatch"
    );

    // A suite without a signature is rejected.
    let result = esdk
        .encrypt()
        .plaintext(plaintext)
        .set_encryption_context(Some(encryption_context))
        .cmm(cmm)
        .algorithm_suite_id(AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey)
        .send()
        .await;
    assert!(
        matches!(result, Err(Error::Validation(_))),
        "a non-signing suite must be rejected, got {result:?}"
    );

    println!("Success! The CMM allowed a signing suite and rejected a non-signing one.");
    Ok(())
}

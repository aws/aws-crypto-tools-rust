// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Encrypts a message with a raw RSA keyring that holds only a public key,
//! and decrypts it with one that holds only the matching private key.
//!
//! Runs offline.

use aws_esdk::Error;
use aws_esdk::keyring::RawRsaKeyring;
use aws_esdk::mpl::types::PaddingScheme;
use aws_esdk::types::EncryptionContext;
use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rsa::{KeySize, PrivateDecryptingKey};

/// Returns a new RSA key pair in the encodings that the raw RSA keyring takes:
/// the PEM-encoded X.509 public key and the PEM-encoded PKCS #8 private key.
fn generate_rsa_key_pair() -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    let private_key = PrivateDecryptingKey::generate(KeySize::Rsa4096)?;
    let public_der = private_key.public_key().as_der()?;
    let private_der = private_key.as_der()?;
    let public_pem = pem::encode(&pem::Pem::new("PUBLIC KEY", public_der.as_ref()));
    let private_pem = pem::encode(&pem::Pem::new("PRIVATE KEY", private_der.as_ref()));
    Ok((public_pem.into_bytes(), private_pem.into_bytes()))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // For demonstration only.
    // A real application must store and protect its private key,
    // preferably in a hardware security module (HSM) or key management system.
    let (public_key, private_key) = generate_rsa_key_pair()?;

    // The namespace and name identify this key pair.
    // A decrypting keyring tries only the encrypted data keys with its own namespace and name.
    // It must also use the padding scheme that encrypted the message.
    let template = RawRsaKeyring::builder()
        .key_namespace("my-key-namespace")
        .key_name("my-rsa-key-name")
        .padding_scheme(PaddingScheme::OaepSha256Mgf1);

    // A keyring with only a public key can encrypt but not decrypt.
    let encrypt_keyring = template.clone().public_key(public_key).build()?;
    // A keyring with only a private key can decrypt but not encrypt.
    // A keyring can hold both keys to encrypt and decrypt.
    // It does not check that they belong to the same key pair.
    let decrypt_keyring = template.clone().private_key(private_key).build()?;

    let plaintext = b"Hello World";

    // The encryption context is authenticated, not encrypted, and is bound to the message.
    let encryption_context =
        EncryptionContext::from([("purpose", "example"), ("is not", "secret")]);

    let esdk = aws_esdk::Client::default();

    let encrypted = esdk
        .encrypt()
        .plaintext(plaintext)
        .set_encryption_context(Some(encryption_context.clone()))
        .keyring(encrypt_keyring)
        .send()
        .await?;

    let decrypted = esdk
        .decrypt()
        .ciphertext(encrypted.ciphertext())
        .set_encryption_context(Some(encryption_context.clone()))
        .keyring(decrypt_keyring)
        .send()
        .await?;

    assert_eq!(
        decrypted.plaintext(),
        plaintext,
        "Decryption failed: plaintext mismatch"
    );

    // The private key of a different key pair cannot decrypt the message,
    // even under the same namespace and name.
    let (_, other_private_key) = generate_rsa_key_pair()?;
    let other_keyring = template.private_key(other_private_key).build()?;
    let result = esdk
        .decrypt()
        .ciphertext(encrypted.ciphertext())
        .set_encryption_context(Some(encryption_context))
        .keyring(other_keyring)
        .send()
        .await;
    assert!(
        matches!(result, Err(Error::Cryptographic(_))),
        "a different key pair must not decrypt the message, got {result:?}"
    );

    println!("Success! Only the matching private key decrypted the message.");
    Ok(())
}

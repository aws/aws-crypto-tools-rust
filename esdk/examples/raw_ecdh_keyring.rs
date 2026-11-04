// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Encrypts and decrypts messages with raw ECDH keyrings in each of their three key agreement schemes.
//!
//! Runs offline.

use aws_esdk::Error;
use aws_esdk::keyring::{
    EphemeralPrivateKeyToStaticPublicKeyInput, PublicKeyDiscoveryInput, RawEcdhKeyring,
    RawEcdhStaticConfigurations, RawPrivateKeyToStaticPublicKeyInput,
};
use aws_esdk::mpl::types::EcdhCurveSpec;
use aws_esdk::types::EncryptionContext;
use aws_lc_rs::agreement::{ECDH_P256, PrivateKey};
use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der, PublicKeyX509Der};

/// An ECC key pair on P-256, in the encodings that the raw ECDH keyring takes.
struct EccKeyPair {
    /// PEM-encoded PKCS #8.
    private_key: Vec<u8>,
    /// DER-encoded X.509 `SubjectPublicKeyInfo`.
    public_key: Vec<u8>,
}

fn generate_ecc_key_pair() -> Result<EccKeyPair, Box<dyn std::error::Error>> {
    let private_key = PrivateKey::generate(&ECDH_P256)?;
    let private_der: Pkcs8V1Der = private_key.as_der()?;
    let public_der: PublicKeyX509Der = private_key.compute_public_key()?.as_der()?;
    Ok(EccKeyPair {
        private_key: pem::encode(&pem::Pem::new("PRIVATE KEY", private_der.as_ref())).into_bytes(),
        public_key: public_der.as_ref().to_vec(),
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // For demonstration only.
    // A real application must load its private keys from a secure store, such as an HSM.
    let sender = generate_ecc_key_pair()?;
    let recipient = generate_ecc_key_pair()?;

    // The keyring supports P-256, P-384, and P-521.
    // Building the keyring fails for a key on another curve.
    let curve = EcdhCurveSpec::EccNistP256;

    // RawPrivateKeyToStaticPublicKey: the sender's private key and the recipient's public key.
    // It encrypts, and decrypts the messages that it encrypted.
    let sender_keyring = RawEcdhKeyring::builder()
        .curve_spec(curve)
        .key_agreement_scheme(RawEcdhStaticConfigurations::RawPrivateKeyToStaticPublicKey(
            RawPrivateKeyToStaticPublicKeyInput::builder()
                .sender_static_private_key(sender.private_key)
                .recipient_public_key(recipient.public_key.clone())
                .build()?,
        ))
        .build()?;

    // The recipient's private key with the sender's public key gives the same shared secret,
    // so the recipient can build the same scheme the other way round.
    let recipient_keyring = RawEcdhKeyring::builder()
        .curve_spec(curve)
        .key_agreement_scheme(RawEcdhStaticConfigurations::RawPrivateKeyToStaticPublicKey(
            RawPrivateKeyToStaticPublicKeyInput::builder()
                .sender_static_private_key(recipient.private_key.clone())
                .recipient_public_key(sender.public_key)
                .build()?,
        ))
        .build()?;

    // EphemeralPrivateKeyToStaticPublicKey: a new sender key pair for each message, and the recipient's public key.
    // It only encrypts, because it does not keep the ephemeral private key.
    let ephemeral_keyring = RawEcdhKeyring::builder()
        .curve_spec(curve)
        .key_agreement_scheme(
            RawEcdhStaticConfigurations::EphemeralPrivateKeyToStaticPublicKey(
                EphemeralPrivateKeyToStaticPublicKeyInput::builder()
                    .recipient_public_key(recipient.public_key)
                    .build()?,
            ),
        )
        .build()?;

    // PublicKeyDiscovery: only the recipient's private key.
    // It only decrypts, and only messages encrypted to the recipient's public key.
    // It reads the sender's public key from the message.
    let discovery_keyring = RawEcdhKeyring::builder()
        .curve_spec(curve)
        .key_agreement_scheme(RawEcdhStaticConfigurations::PublicKeyDiscovery(
            PublicKeyDiscoveryInput::builder()
                .recipient_static_private_key(recipient.private_key)
                .build()?,
        ))
        .build()?;

    let plaintext = b"Hello World";

    // The encryption context is authenticated, not encrypted, and is bound to the message.
    let encryption_context =
        EncryptionContext::from([("purpose", "example"), ("is not", "secret")]);

    let esdk = aws_esdk::Client::default();

    let static_encrypted = esdk
        .encrypt()
        .plaintext(plaintext)
        .set_encryption_context(Some(encryption_context.clone()))
        .keyring(sender_keyring.clone())
        .send()
        .await?;
    let ephemeral_encrypted = esdk
        .encrypt()
        .plaintext(plaintext)
        .set_encryption_context(Some(encryption_context.clone()))
        .keyring(ephemeral_keyring.clone())
        .send()
        .await?;

    for (encrypted, keyring) in [
        (&static_encrypted, sender_keyring),
        (&static_encrypted, recipient_keyring),
        (&static_encrypted, discovery_keyring.clone()),
        (&ephemeral_encrypted, discovery_keyring.clone()),
    ] {
        let decrypted = esdk
            .decrypt()
            .ciphertext(encrypted.ciphertext())
            .set_encryption_context(Some(encryption_context.clone()))
            .keyring(keyring)
            .send()
            .await?;
        assert_eq!(
            decrypted.plaintext(),
            plaintext,
            "Decryption failed: plaintext mismatch"
        );
    }

    // The ephemeral keyring cannot decrypt, not even a message that it encrypted.
    let result = esdk
        .decrypt()
        .ciphertext(ephemeral_encrypted.ciphertext())
        .set_encryption_context(Some(encryption_context.clone()))
        .keyring(ephemeral_keyring)
        .send()
        .await;
    assert!(
        matches!(result, Err(Error::Validation(_))),
        "an ephemeral keyring must not decrypt, got {result:?}"
    );

    // The discovery keyring cannot encrypt.
    let result = esdk
        .encrypt()
        .plaintext(plaintext)
        .set_encryption_context(Some(encryption_context))
        .keyring(discovery_keyring)
        .send()
        .await;
    assert!(
        matches!(result, Err(Error::Validation(_))),
        "a discovery keyring must not encrypt, got {result:?}"
    );

    println!("Success! Each raw ECDH key agreement scheme encrypted or decrypted as expected.");
    Ok(())
}

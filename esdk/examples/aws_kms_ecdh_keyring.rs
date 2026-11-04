// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Encrypts and decrypts a message with AWS KMS ECDH keyrings,
//! in the KmsPrivateKeyToStaticPublicKey and KmsPublicKeyDiscovery key agreement schemes.
//!
//! Requires AWS credentials and access to the AWS KMS keys below.

use aws_esdk::keyring::{
    AwsKmsEcdhKeyring, KmsEcdhStaticConfigurations, KmsPrivateKeyToStaticPublicKeyInput,
    KmsPublicKeyDiscoveryInput,
};
use aws_esdk::mpl::types::EcdhCurveSpec;
use aws_esdk::types::EncryptionContext;
use aws_esdk::{Error, aws_config, aws_sdk_kms};

// The AWS Crypto Tools CI test keys: ECC keys on P-256 with key usage KEY_AGREEMENT.
// Replace them with your own AWS KMS key ARNs.
const SENDER_KMS_KEY_ARN: &str =
    "arn:aws:kms:us-west-2:370957321024:key/eabdf483-6be2-4d2d-8ee4-8c2583d416e9";
const RECIPIENT_KMS_KEY_ARN: &str =
    "arn:aws:kms:us-west-2:370957321024:key/0265c8e9-5b6a-4055-8f70-63719e09fda5";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The AWS KMS client must be in the keys' region.
    let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new("us-west-2"))
        .load()
        .await;
    let kms = aws_sdk_kms::Client::new(&sdk_config);

    // The sender needs the recipient's DER-encoded X.509 public key.
    // Here it comes from AWS KMS GetPublicKey, which needs kms:GetPublicKey on the recipient's key.
    // The recipient's key does not have to be in AWS KMS: any public key on the same curve works.
    // A recipient outside AWS KMS decrypts with a raw ECDH keyring that holds its private key.
    let response = kms
        .get_public_key()
        .key_id(RECIPIENT_KMS_KEY_ARN)
        .send()
        .await?;
    let recipient_public_key = response
        .public_key()
        .ok_or("GetPublicKey returned no public key")?
        .as_ref()
        .to_vec();

    // The keyring supports P-256, P-384, and P-521.
    // Building the keyring fails for a key on another curve.
    let curve = EcdhCurveSpec::EccNistP256;

    // KmsPrivateKeyToStaticPublicKey: the sender's AWS KMS key and the recipient's public key.
    // It encrypts, and decrypts the messages that it encrypted.
    // Encrypt and decrypt call DeriveSharedSecret, which needs kms:DeriveSharedSecret on the sender's key.
    // Without `sender_public_key`, the build also calls GetPublicKey on the sender's key.
    let sender_keyring = AwsKmsEcdhKeyring::builder()
        .curve_spec(curve)
        .key_agreement_scheme(KmsEcdhStaticConfigurations::KmsPrivateKeyToStaticPublicKey(
            KmsPrivateKeyToStaticPublicKeyInput::builder()
                .sender_kms_identifier(SENDER_KMS_KEY_ARN)
                .recipient_public_key(recipient_public_key)
                .build()?,
        ))
        .kms_client(kms.clone())
        .build()
        .await?;

    // KmsPublicKeyDiscovery: only the recipient's AWS KMS key.
    // It only decrypts, and only messages encrypted to the recipient's public key.
    // It reads the sender's public key from the message.
    // The build calls GetPublicKey and decrypt calls DeriveSharedSecret,
    // so it needs kms:GetPublicKey and kms:DeriveSharedSecret on the recipient's key.
    let recipient_keyring = AwsKmsEcdhKeyring::builder()
        .curve_spec(curve)
        .key_agreement_scheme(KmsEcdhStaticConfigurations::KmsPublicKeyDiscovery(
            KmsPublicKeyDiscoveryInput::builder()
                .recipient_kms_identifier(RECIPIENT_KMS_KEY_ARN)
                .build()?,
        ))
        .kms_client(kms)
        .build()
        .await?;

    let plaintext = b"Hello World";

    // The encryption context is authenticated, not encrypted, and is bound to the message.
    let encryption_context =
        EncryptionContext::from([("purpose", "example"), ("is not", "secret")]);

    let esdk = aws_esdk::Client::default();

    let encrypted = esdk
        .encrypt()
        .plaintext(plaintext)
        .set_encryption_context(Some(encryption_context.clone()))
        .keyring(sender_keyring.clone())
        .send()
        .await?;

    for keyring in [sender_keyring, recipient_keyring.clone()] {
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

    // The discovery keyring cannot encrypt.
    let result = esdk
        .encrypt()
        .plaintext(plaintext)
        .set_encryption_context(Some(encryption_context))
        .keyring(recipient_keyring)
        .send()
        .await;
    assert!(
        matches!(result, Err(Error::Validation(_))),
        "a discovery keyring must not encrypt, got {result:?}"
    );

    println!("Success! The sender and the recipient both decrypted the message through AWS KMS.");
    Ok(())
}

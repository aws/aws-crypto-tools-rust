// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Encrypts a message with the public key of an AWS KMS RSA key, and decrypts it through AWS KMS.
//!
//! Requires AWS credentials and access to the AWS KMS key below.

use aws_esdk::aws_sdk_kms::types::EncryptionAlgorithmSpec;
use aws_esdk::keyring::AwsKmsRsaKeyring;
use aws_esdk::types::{AlgorithmSuiteId, EncryptionContext};
use aws_esdk::{aws_config, aws_sdk_kms};

// The AWS Crypto Tools CI test key, an RSA key with key usage ENCRYPT_DECRYPT.
// Replace it with your own AWS KMS RSA key ARN.
const KMS_RSA_KEY_ARN: &str =
    "arn:aws:kms:us-west-2:370957321024:key/mrk-63d386cb70614ea59b32ad65c9315297";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The AWS KMS client must be in the key's region.
    let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new("us-west-2"))
        .load()
        .await;
    let kms = aws_sdk_kms::Client::new(&sdk_config);

    // Getting the public key needs kms:GetPublicKey on the key.
    // The public key is not secret: an application that only encrypts can store it,
    // and then needs no AWS credentials.
    let response = kms.get_public_key().key_id(KMS_RSA_KEY_ARN).send().await?;
    let public_key_der = response
        .public_key()
        .ok_or("GetPublicKey returned no public key")?;
    let public_key = pem::encode(&pem::Pem::new("PUBLIC KEY", public_key_der.as_ref()));

    // The encryption algorithm must be one that the key supports.
    // Decrypt must use the one that encrypted the message.
    let encryption_algorithm = EncryptionAlgorithmSpec::RsaesOaepSha256;

    // With only the public key, the keyring encrypts without calling AWS KMS, and cannot decrypt.
    let encrypt_keyring = AwsKmsRsaKeyring::builder()
        .kms_key_id(KMS_RSA_KEY_ARN)
        .public_key(public_key)
        .encryption_algorithm(encryption_algorithm.clone())
        .build()
        .await?;

    // With only an AWS KMS client, the keyring decrypts through AWS KMS Decrypt, and cannot encrypt.
    // Decrypt needs kms:Decrypt on the key.
    let decrypt_keyring = AwsKmsRsaKeyring::builder()
        .kms_key_id(KMS_RSA_KEY_ARN)
        .encryption_algorithm(encryption_algorithm)
        .kms_client(kms)
        .build()
        .await?;

    let plaintext = b"Hello World";

    // The encryption context is authenticated, not encrypted, and is bound to the message.
    let encryption_context =
        EncryptionContext::from([("purpose", "example"), ("is not", "secret")]);

    let esdk = aws_esdk::Client::default();

    // The AWS KMS RSA keyring rejects algorithm suites that sign the message, and the default suite signs.
    let encrypted = esdk
        .encrypt()
        .plaintext(plaintext)
        .set_encryption_context(Some(encryption_context.clone()))
        .keyring(encrypt_keyring)
        .algorithm_suite_id(AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey)
        .send()
        .await?;

    let decrypted = esdk
        .decrypt()
        .ciphertext(encrypted.ciphertext())
        .set_encryption_context(Some(encryption_context))
        .keyring(decrypt_keyring)
        .send()
        .await?;

    assert_eq!(
        decrypted.plaintext(),
        plaintext,
        "Decryption failed: plaintext mismatch"
    );
    println!("Success! Encrypted with the RSA public key and decrypted through AWS KMS.");
    Ok(())
}

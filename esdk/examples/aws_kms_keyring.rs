// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Encrypts and decrypts a message with an AWS KMS keyring.
//!
//! Requires AWS credentials and access to the AWS KMS key below.

use aws_esdk::keyring::AwsKmsKeyring;
use aws_esdk::types::EncryptionContext;
use aws_esdk::{Error, aws_config, aws_sdk_kms};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The AWS Crypto Tools CI test key.
    // Replace it with your own KMS key ARN.
    let kms_key_arn = "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f";

    // The KMS client must be in the key's region.
    let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new("us-west-2"))
        .load()
        .await;
    let kms = aws_sdk_kms::Client::new(&sdk_config);

    // Encrypt calls GenerateDataKey and decrypt calls Decrypt on this key,
    // so the caller needs kms:GenerateDataKey and kms:Decrypt on it.
    let keyring = AwsKmsKeyring::builder()
        .kms_key_id(kms_key_arn)
        .kms_client(kms.clone())
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
        .keyring(keyring.clone())
        .send()
        .await?;

    // On decrypt, the keyring tries only the encrypted data keys that its own KMS key wrapped.
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

    // A keyring built with a key ID or an alias can encrypt, but it cannot decrypt.
    // Each encrypted data key records the ARN of its KMS key, and decrypt compares the keyring's key with it.
    let key_id_keyring = AwsKmsKeyring::builder()
        .kms_key_id("b3537ef1-d8dc-4780-9f5a-55776cbb2f7f")
        .kms_client(kms)
        .build()
        .await?;
    let result = esdk
        .decrypt()
        .ciphertext(encrypted.ciphertext())
        .set_encryption_context(Some(encryption_context))
        .keyring(key_id_keyring)
        .send()
        .await;
    assert!(
        matches!(result, Err(Error::Validation(_))),
        "a keyring with a key ID must not decrypt, got {result:?}"
    );

    println!("Success! Encryption and decryption completed successfully.");
    Ok(())
}

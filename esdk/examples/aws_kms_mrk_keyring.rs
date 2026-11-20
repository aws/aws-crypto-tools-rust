// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Encrypts with a multi-Region AWS KMS key in us-east-1 and decrypts with its replica in us-west-2.
//!
//! Requires AWS credentials and access to the AWS KMS keys below.

use aws_esdk::keyring::{AwsKmsKeyring, AwsKmsMrkKeyring};
use aws_esdk::types::EncryptionContext;
use aws_esdk::{Error, aws_config, aws_sdk_kms};

// The AWS Crypto Tools CI test multi-Region key, and its replica in us-west-2.
// Replace them with your own multi-Region key and a replica of it in another region.
const MRK_US_EAST_1: &str =
    "arn:aws:kms:us-east-1:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7";
const MRK_US_WEST_2: &str =
    "arn:aws:kms:us-west-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7";

/// A KMS client in `region`, with credentials from the default AWS config chain.
async fn kms_client(region: &'static str) -> aws_sdk_kms::Client {
    let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(region))
        .load()
        .await;
    aws_sdk_kms::Client::new(&sdk_config)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The KMS client must be in the key's region.
    let encrypt_keyring = AwsKmsMrkKeyring::builder()
        .kms_key_id(MRK_US_EAST_1)
        .kms_client(kms_client("us-east-1").await)
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
        .keyring(encrypt_keyring)
        .send()
        .await?;

    // An MRK keyring that names the replica decrypts a data key that the us-east-1 key wrapped.
    // It calls AWS KMS in us-west-2, so it needs kms:Decrypt on the replica only.
    let decrypt_keyring = AwsKmsMrkKeyring::builder()
        .kms_key_id(MRK_US_WEST_2)
        .kms_client(kms_client("us-west-2").await)
        .build()
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

    // An AWS KMS keyring decrypts only data keys wrapped by its exact key ARN, so the replica does not match.
    let kms_keyring = AwsKmsKeyring::builder()
        .kms_key_id(MRK_US_WEST_2)
        .kms_client(kms_client("us-west-2").await)
        .build()
        .await?;
    let result = esdk
        .decrypt()
        .ciphertext(encrypted.ciphertext())
        .set_encryption_context(Some(encryption_context))
        .keyring(kms_keyring)
        .send()
        .await;
    assert!(
        matches!(result, Err(Error::NoMatchingDataKey(_))),
        "an AWS KMS keyring must not decrypt with a replica, got {result:?}"
    );

    println!("Success! The replica in us-west-2 decrypted a message encrypted in us-east-1.");
    Ok(())
}

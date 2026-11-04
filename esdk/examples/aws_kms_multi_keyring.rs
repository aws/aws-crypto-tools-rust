// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Encrypts a message under two AWS KMS keys with an AWS KMS multi-keyring,
//! then decrypts it with a keyring for each key on its own.
//!
//! Requires AWS credentials and access to both AWS KMS keys below.

use aws_esdk::keyring::{AwsKmsKeyring, MultiKeyring};
use aws_esdk::types::EncryptionContext;
use aws_esdk::{aws_config, aws_sdk_kms};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The AWS Crypto Tools CI test keys.
    // Replace them with your own KMS key ARNs.
    let generator_key_arn =
        "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f";
    let other_key_arn =
        "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126";

    let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new("us-west-2"))
        .load()
        .await;

    // The generator key makes the data key and wraps it, so the caller needs kms:GenerateDataKey on it.
    // Each other key wraps the same data key, so the caller needs kms:Encrypt on each.
    // Any one of the keys can decrypt the message.
    let multi_keyring = MultiKeyring::aws_kms()
        .generator(generator_key_arn)
        .kms_key_ids(other_key_arn)
        // The keyring makes a KMS client in each key ARN's region from this configuration.
        .sdk_config(sdk_config.clone())
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
        .keyring(multi_keyring.clone())
        .send()
        .await?;

    // On decrypt, the multi-keyring tries its keys in order and stops at the first one that decrypts.
    let decrypted = esdk
        .decrypt()
        .ciphertext(encrypted.ciphertext())
        .set_encryption_context(Some(encryption_context.clone()))
        .keyring(multi_keyring)
        .send()
        .await?;
    assert_eq!(
        decrypted.plaintext(),
        plaintext,
        "Decryption failed: plaintext mismatch"
    );

    // A keyring with only one of the keys also decrypts the message.
    // Both keys are in us-west-2, the region of this client.
    let kms = aws_sdk_kms::Client::new(&sdk_config);
    for kms_key_arn in [generator_key_arn, other_key_arn] {
        let keyring = AwsKmsKeyring::builder()
            .kms_key_id(kms_key_arn)
            .kms_client(kms.clone())
            .build()
            .await?;
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

    println!("Success! Each key in the multi-keyring decrypted the message on its own.");
    Ok(())
}

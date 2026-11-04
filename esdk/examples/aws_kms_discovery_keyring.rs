// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Decrypts a message with an AWS KMS discovery keyring.
//!
//! Requires AWS credentials and access to the AWS KMS key below.

use aws_esdk::keyring::{AwsKmsDiscoveryKeyring, AwsKmsKeyring, DiscoveryFilter};
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

    // A discovery keyring names no KMS key, so it cannot encrypt.
    // Encrypt with an AWS KMS keyring instead.
    let encrypt_keyring = AwsKmsKeyring::builder()
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
        .keyring(encrypt_keyring)
        .send()
        .await?;

    // On decrypt, the keyring calls AWS KMS Decrypt with the KMS key that each encrypted data key names,
    // whoever owns that key.
    // The call succeeds only if the caller has kms:Decrypt on that key.
    // The filter limits the keyring to KMS keys in these accounts and this partition.
    let discovery_keyring = AwsKmsDiscoveryKeyring::builder()
        // The keyring decrypts only data keys wrapped by KMS keys in this client's region.
        .kms_client(kms.clone())
        .discovery_filter(
            DiscoveryFilter::builder()
                .partition("aws")
                .account_ids("658956600833")
                .build()?,
        )
        .build()
        .await?;

    let decrypted = esdk
        .decrypt()
        .ciphertext(encrypted.ciphertext())
        .set_encryption_context(Some(encryption_context.clone()))
        .keyring(discovery_keyring)
        .send()
        .await?;
    assert_eq!(
        decrypted.plaintext(),
        plaintext,
        "Decryption failed: plaintext mismatch"
    );

    // The message's KMS key is not in this filter's account, so this keyring does not try it.
    let other_account_keyring = AwsKmsDiscoveryKeyring::builder()
        .kms_client(kms)
        .discovery_filter(
            DiscoveryFilter::builder()
                .partition("aws")
                .account_ids("111122223333")
                .build()?,
        )
        .build()
        .await?;
    let result = esdk
        .decrypt()
        .ciphertext(encrypted.ciphertext())
        .set_encryption_context(Some(encryption_context))
        .keyring(other_account_keyring)
        .send()
        .await;
    assert!(
        matches!(result, Err(Error::NoMatchingDataKey(_))),
        "a filter for another account must not decrypt the message, got {result:?}"
    );

    println!("Success! The discovery keyring decrypted only with a filter for the key's account.");
    Ok(())
}

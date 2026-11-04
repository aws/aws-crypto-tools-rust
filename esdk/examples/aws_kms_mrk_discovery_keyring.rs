// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Encrypts under a multi-Region key in us-east-1 and decrypts with an MRK discovery keyring in us-west-2.
//!
//! Requires AWS credentials and access to the AWS KMS keys below.

use aws_esdk::keyring::{AwsKmsMrkDiscoveryKeyring, AwsKmsMrkKeyring, DiscoveryFilter};
use aws_esdk::types::EncryptionContext;
use aws_esdk::{Error, aws_config, aws_sdk_kms};

// The AWS Crypto Tools CI test multi-Region key, which has a replica in us-west-2.
// Replace it with your own multi-Region key and its account.
const MRK_US_EAST_1: &str =
    "arn:aws:kms:us-east-1:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7";
const MRK_ACCOUNT: &str = "658956600833";

/// A KMS client in `region`, with credentials from the default AWS config chain.
async fn kms_client(region: &'static str) -> aws_sdk_kms::Client {
    let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(region))
        .load()
        .await;
    aws_sdk_kms::Client::new(&sdk_config)
}

/// An MRK discovery keyring in us-west-2 that tries only AWS KMS keys in `account`.
async fn discovery_keyring(account: &str) -> Result<AwsKmsMrkDiscoveryKeyring, Error> {
    // The filter limits the keyring to data keys wrapped by AWS KMS keys in these accounts and partition.
    // Without one, the keyring asks AWS KMS to decrypt with any key named in the message.
    let filter = DiscoveryFilter::builder()
        .partition("aws")
        .account_ids(account)
        .build()?;
    // The keyring reads each key ARN from the message.
    // For a multi-Region key, it calls AWS KMS with the replica in its own region,
    // so it needs kms:Decrypt on that replica.
    // It skips a single-Region key in any other region.
    // The client must be in the keyring's region.
    let keyring = AwsKmsMrkDiscoveryKeyring::builder()
        .kms_client(kms_client("us-west-2").await)
        .region("us-west-2")
        .discovery_filter(filter)
        .build()
        .await?;
    Ok(keyring)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A discovery keyring cannot encrypt, so encrypt with an MRK keyring.
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

    let decrypted = esdk
        .decrypt()
        .ciphertext(encrypted.ciphertext())
        .set_encryption_context(Some(encryption_context.clone()))
        .keyring(discovery_keyring(MRK_ACCOUNT).await?)
        .send()
        .await?;

    assert_eq!(
        decrypted.plaintext(),
        plaintext,
        "Decryption failed: plaintext mismatch"
    );

    // A filter for another account skips the message's only data key, so decrypt fails.
    let result = esdk
        .decrypt()
        .ciphertext(encrypted.ciphertext())
        .set_encryption_context(Some(encryption_context))
        .keyring(discovery_keyring("111122223333").await?)
        .send()
        .await;
    assert!(
        matches!(result, Err(Error::NoMatchingDataKey(_))),
        "a filter for another account must not decrypt the message, got {result:?}"
    );

    println!(
        "Success! An MRK discovery keyring in us-west-2 decrypted a message encrypted in us-east-1."
    );
    Ok(())
}

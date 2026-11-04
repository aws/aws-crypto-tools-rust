// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Decrypts a message with an AWS KMS discovery multi-keyring: one discovery keyring per region.
//!
//! Requires AWS credentials and access to the AWS KMS key below.

use aws_esdk::keyring::{AwsKmsKeyring, DiscoveryFilter, MultiKeyring};
use aws_esdk::types::EncryptionContext;
use aws_esdk::{aws_config, aws_sdk_kms};

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

    // A discovery keyring names no KMS key, so it cannot encrypt.
    // Encrypt with an AWS KMS keyring instead.
    let encrypt_keyring = AwsKmsKeyring::builder()
        .kms_key_id(kms_key_arn)
        .kms_client(aws_sdk_kms::Client::new(&sdk_config))
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

    // Each discovery keyring has a KMS client in its own region,
    // so the multi-keyring decrypts data keys wrapped by KMS keys in any of its regions.
    // Every keyring uses the same filter: KMS keys in these accounts and this partition.
    let discovery_multi_keyring = MultiKeyring::aws_kms_discovery()
        .regions("us-west-2")
        .regions("us-east-1")
        .discovery_filter(
            DiscoveryFilter::builder()
                .partition("aws")
                .account_ids("658956600833")
                .build()?,
        )
        // The keyring makes each region's KMS client from this configuration.
        .sdk_config(sdk_config)
        .build()
        .await?;

    // On decrypt, the keyrings run in order and stop at the first one that decrypts a data key.
    // Each one tries the encrypted data keys that the filter allows,
    // calling AWS KMS Decrypt with the KMS key that each data key names.
    // The caller needs kms:Decrypt on that key.
    let decrypted = esdk
        .decrypt()
        .ciphertext(encrypted.ciphertext())
        .set_encryption_context(Some(encryption_context))
        .keyring(discovery_multi_keyring)
        .send()
        .await?;

    assert_eq!(
        decrypted.plaintext(),
        plaintext,
        "Decryption failed: plaintext mismatch"
    );
    println!("Success! The discovery multi-keyring decrypted the message.");
    Ok(())
}

// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Encrypts under a multi-Region key and decrypts with an MRK discovery multi-keyring that covers two regions.
//!
//! Requires AWS credentials and access to the AWS KMS keys below.

use aws_esdk::keyring::{AwsKmsMrkKeyring, DiscoveryFilter, MultiKeyring};
use aws_esdk::types::EncryptionContext;
use aws_esdk::{aws_config, aws_sdk_kms};

// The AWS Crypto Tools CI test multi-Region key, which has a replica in us-west-2.
// Replace it with your own multi-Region key and its account.
const MRK_US_EAST_1: &str =
    "arn:aws:kms:us-east-1:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7";
const MRK_ACCOUNT: &str = "658956600833";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;

    // A discovery keyring cannot encrypt, so encrypt with an MRK keyring.
    // Its KMS client must be in the key's region.
    let east_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new("us-east-1"))
        .load()
        .await;
    let encrypt_keyring = AwsKmsMrkKeyring::builder()
        .kms_key_id(MRK_US_EAST_1)
        .kms_client(aws_sdk_kms::Client::new(&east_config))
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

    // The multi-keyring holds one MRK discovery keyring per region, all with this filter.
    // Each one decrypts a multi-Region key's data key with the replica in its region,
    // so it needs kms:Decrypt on that replica.
    // It tries a single-Region key's data key only when that key is in its region.
    // They try in the order of the regions and stop at the first that decrypts: the us-west-2 replica here.
    let decrypt_keyring = MultiKeyring::aws_kms_mrk_discovery()
        // Each region's keyring gets a KMS client in that region, with credentials from this config.
        .sdk_config(sdk_config)
        .regions("us-west-2")
        .regions("us-east-1")
        // Try only data keys wrapped by AWS KMS keys in these accounts and partition.
        .discovery_filter(
            DiscoveryFilter::builder()
                .partition("aws")
                .account_ids(MRK_ACCOUNT)
                .build()?,
        )
        .build()
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
    println!("Success! An MRK discovery multi-keyring decrypted the message.");
    Ok(())
}

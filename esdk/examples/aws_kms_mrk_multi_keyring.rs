// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Encrypts with an MRK multi-keyring of a multi-Region key and a single-Region key,
//! then decrypts with the multi-keyring and with the multi-Region key's replica alone.
//!
//! Requires AWS credentials and access to the AWS KMS keys below.

use aws_esdk::keyring::{AwsKmsMrkKeyring, MultiKeyring};
use aws_esdk::types::EncryptionContext;
use aws_esdk::{aws_config, aws_sdk_kms};

// The AWS Crypto Tools CI test keys.
// Replace them with your own multi-Region key, a replica of it, and another KMS key.
const MRK_US_EAST_1: &str =
    "arn:aws:kms:us-east-1:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7";
const MRK_US_WEST_2: &str =
    "arn:aws:kms:us-west-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7";
const KEY_US_WEST_2: &str =
    "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;

    // The generator key makes the data key and wraps it; the other key also wraps it.
    // Either key can decrypt the message on its own.
    // Encrypt needs kms:GenerateDataKey on the generator and kms:Encrypt on the other key.
    let multi_keyring = MultiKeyring::aws_kms_mrk()
        // Each key gets a KMS client in its ARN's region, with credentials from this config.
        .sdk_config(sdk_config.clone())
        .generator(MRK_US_EAST_1)
        .kms_key_ids(KEY_US_WEST_2)
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

    // The multi-keyring tries its keys in order and stops at the first that decrypts: the generator here.
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

    // An MRK keyring that names the generator's replica in us-west-2 also decrypts the message.
    let west_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new("us-west-2"))
        .load()
        .await;
    let replica_keyring = AwsKmsMrkKeyring::builder()
        .kms_key_id(MRK_US_WEST_2)
        .kms_client(aws_sdk_kms::Client::new(&west_config))
        .build()
        .await?;

    let decrypted = esdk
        .decrypt()
        .ciphertext(encrypted.ciphertext())
        .set_encryption_context(Some(encryption_context))
        .keyring(replica_keyring)
        .send()
        .await?;
    assert_eq!(
        decrypted.plaintext(),
        plaintext,
        "Decryption failed: plaintext mismatch"
    );

    println!("Success! The multi-keyring and the replica alone each decrypted the message.");
    Ok(())
}

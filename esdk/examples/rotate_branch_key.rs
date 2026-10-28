// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Creates a branch key, then rotates it to a new version.
//!
//! Rotating a branch key makes a new version active.
//! Encrypt then uses the new version,
//! and decrypt still reads messages written under earlier versions.
//!
//! Requires AWS credentials and an existing key store.
//! Each run creates a new branch key in it.

use std::time::Duration;

use aws_esdk::key_store::types::KmsConfiguration;
use aws_esdk::keyring::HierarchicalKeyring;
use aws_esdk::types::EncryptionContext;
use aws_esdk::{aws_config, aws_sdk_dynamodb, aws_sdk_kms, key_store};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;

    // The AWS Crypto Tools CI test key store.
    // Replace these with your own key store's table, name, and KMS key ARN.
    let key_store = key_store::DynamoDbKeyStore::builder()
        .ddb_table_name("KeyStoreDdbTable")
        .logical_key_store_name("KeyStoreDdbTable")
        .kms_configuration(KmsConfiguration::KmsKeyArn(
            "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126".into(),
        ))
        .kms_client(aws_sdk_kms::Client::new(&sdk_config))
        .ddb_client(aws_sdk_dynamodb::Client::new(&sdk_config))
        .build()
        .await?;

    // The branch key's encryption context is bound to every version of it.
    let branch_key_context = EncryptionContext::from([("purpose", "example")]);
    let branch_key_id = key_store
        .create_key()
        .set_encryption_context(Some(branch_key_context))
        .send()
        .await?
        .into_branch_key_id();

    let make_keyring = async || {
        HierarchicalKeyring::builder()
            .key_store(key_store.clone())
            .ttl(Duration::from_secs(600))
            .branch_key_id(&branch_key_id)
            .build()
            .await
    };

    let plaintext = b"Hello World";
    let encryption_context = EncryptionContext::from([("purpose", "example")]);
    let esdk = aws_esdk::Client::default();
    let encrypt_with = async |keyring: HierarchicalKeyring| {
        esdk.encrypt()
            .plaintext(plaintext)
            .set_encryption_context(Some(encryption_context.clone()))
            .keyring(keyring)
            .send()
            .await
    };

    let before_rotation = encrypt_with(make_keyring().await?).await?;

    key_store
        .version_key()
        .branch_key_id(&branch_key_id)
        .send()
        .await?;

    // A keyring keeps using the version it cached until its TTL expires.
    // This keyring is new, so it fetches the version that is active now.
    let keyring = make_keyring().await?;
    let after_rotation = encrypt_with(keyring.clone()).await?;

    // Both messages decrypt: the first one under the earlier version, the new one under the active version.
    for encrypted in [before_rotation, after_rotation] {
        let decrypted = esdk
            .decrypt()
            .ciphertext(encrypted.ciphertext())
            .set_encryption_context(Some(encryption_context.clone()))
            .keyring(keyring.clone())
            .send()
            .await?;
        assert_eq!(
            decrypted.plaintext(),
            plaintext,
            "Decryption failed: plaintext mismatch"
        );
    }

    println!("Success! Rotated branch key {branch_key_id}; messages from both versions decrypt.");
    Ok(())
}

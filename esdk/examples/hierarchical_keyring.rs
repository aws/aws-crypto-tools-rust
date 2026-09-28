// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Encrypts and decrypts a message with a hierarchical keyring.
//!
//! Requires an existing key store with a provisioned branch key.
//! Unlike the other examples this one needs AWS credentials, a KMS key, and a DynamoDB table, and does not run offline.

use std::time::Duration;

use aws_crypto_mpl::keystore::{BranchKeyStore, KmsConfiguration};
use aws_crypto_mpl::{HierarchicalKeyring, aws_config, aws_sdk_dynamodb, aws_sdk_kms};
use aws_esdk::{DecryptInput, EncryptInput, EncryptionContext, decrypt, encrypt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // KMS and DynamoDB clients come from the standard AWS config chain (region and credentials).
    let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let kms_client = aws_sdk_kms::Client::new(&sdk_config);
    let ddb_client = aws_sdk_dynamodb::Client::new(&sdk_config);

    // The AWS Crypto Tools CI test key store.
    // Replace these with your own key store's table, name, and KMS key ARN.
    let key_store = BranchKeyStore::builder()
        .ddb_table_name("KeyStoreDdbTable")
        .logical_keystore_name("KeyStoreDdbTable")
        .kms_configuration(KmsConfiguration::KmsKeyArn(
            "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126"
                .to_string(),
        ))
        .kms_client(kms_client)
        .ddb_client(ddb_client)
        .build()
        .await?;

    let keyring = HierarchicalKeyring::builder()
        .key_store(key_store)
        // How long cached branch-key material may be reused.
        .ttl(Duration::from_secs(600))
        .branch_key_id("3f43a9af-08c5-4317-b694-3d3e883dcaef")
        .build()?;

    let plaintext = b"Hello World";

    // The encryption context is authenticated, not encrypted, and is bound to the message.
    let mut encryption_context = EncryptionContext::new();
    encryption_context.insert("purpose", "example");
    encryption_context.insert("is not", "secret");

    let encrypted = encrypt(
        &EncryptInput::builder()
            .plaintext(plaintext)
            .encryption_context(encryption_context.clone())
            .keyring(keyring.clone())
            .build()?,
    )
    .await?;

    // Decrypt fails unless the message's encryption context contains every pair given here.
    let decrypted = decrypt(
        &DecryptInput::builder()
            .ciphertext(&encrypted.ciphertext)
            .encryption_context(encryption_context)
            .keyring(keyring)
            .build()?,
    )
    .await?;

    assert_eq!(
        decrypted.plaintext, plaintext,
        "Decryption failed: plaintext mismatch"
    );
    println!("Success! Encryption and decryption completed successfully.");
    Ok(())
}

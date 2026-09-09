// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Encrypts and decrypts a message with a hierarchical keyring.
//!
//! Requires an existing key store with a provisioned branch key, so unlike the other
//! examples this one needs AWS credentials, a KMS key, and a DynamoDB table, and does not run offline.

use aws_esdk::{DecryptInput, EncryptInput, EncryptionContext, decrypt, encrypt, mpl};
use aws_mpl_legacy::dafny::aws_cryptography_keyStore::client::Client as KeystoreClient;
use aws_mpl_legacy::dafny::aws_cryptography_keyStore::types::KmsConfiguration;
use aws_mpl_legacy::dafny::aws_cryptography_keyStore::types::key_store_config::KeyStoreConfig;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // KMS and DynamoDB clients come from the standard AWS config chain (region and credentials).
    let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let kms_client = aws_sdk_kms::Client::new(&sdk_config);
    let ddb_client = aws_sdk_dynamodb::Client::new(&sdk_config);

    // The AWS Crypto Tools CI test key store.
    // Replace these with your own key store's table, name, and KMS key ARN.
    let key_store_config = KeyStoreConfig::builder()
        .kms_client(kms_client)
        .ddb_client(ddb_client)
        .ddb_table_name("KeyStoreDdbTable")
        .logical_key_store_name("KeyStoreDdbTable")
        .kms_configuration(KmsConfiguration::KmsKeyArn(
            "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126"
                .to_string(),
        ))
        .build()?;
    let key_store = KeystoreClient::from_conf(key_store_config)?;

    let keyring = mpl()
        .create_aws_kms_hierarchical_keyring()
        .key_store(key_store)
        .branch_key_id("3f43a9af-08c5-4317-b694-3d3e883dcaef")
        // ttl_seconds: how long cached branch-key material may be reused.
        .ttl_seconds(600)
        .send()
        .await?;

    let plaintext = b"Hello World";

    let encrypted = encrypt(&EncryptInput::with_legacy_keyring(
        plaintext,
        EncryptionContext::new(),
        keyring.clone(),
    ))
    .await?;

    let decrypted = decrypt(&DecryptInput::with_legacy_keyring(
        &encrypted.ciphertext,
        EncryptionContext::new(),
        keyring,
    ))
    .await?;

    assert_eq!(
        decrypted.plaintext, plaintext,
        "Decryption failed: plaintext mismatch"
    );
    println!("Success! Encryption and decryption completed successfully.");
    Ok(())
}

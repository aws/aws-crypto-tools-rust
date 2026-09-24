// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Encrypts and decrypts a message with a hierarchical keyring.
//!
//! Requires an existing key store with a provisioned branch key.
//! Unlike the other examples this one needs AWS credentials, a KMS key, and a DynamoDB table, and does not run offline.

use std::sync::Arc;

use aws_crypto_mpl::keystore::{BranchKeyStore, KeyStoreConfig, KmsConfiguration};
use aws_crypto_mpl::{HierarchicalKeyring, Keyring, aws_config, aws_sdk_dynamodb, aws_sdk_kms};
use aws_esdk::{DecryptInput, EncryptInput, EncryptionContext, decrypt, encrypt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // KMS and DynamoDB clients come from the standard AWS config chain (region and credentials).
    let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let kms_client = aws_sdk_kms::Client::new(&sdk_config);
    let ddb_client = aws_sdk_dynamodb::Client::new(&sdk_config);

    // The AWS Crypto Tools CI test key store.
    // Replace these with your own key store's table, name, and KMS key ARN.
    let key_store = BranchKeyStore::with_clients(KeyStoreConfig {
        ddb_table_name: "KeyStoreDdbTable".to_string(),
        logical_keystore_name: "KeyStoreDdbTable".to_string(),
        kms_configuration: KmsConfiguration::KmsKeyArn(
            "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126"
                .to_string(),
        ),
        id: None,
        grant_tokens: None,
        kms_client: Some(kms_client),
        ddb_client: Some(ddb_client),
    })?;

    let keyring: Arc<dyn Keyring> = Arc::new(HierarchicalKeyring::new(
        Arc::new(key_store),
        // ttl_seconds: how long cached branch-key material may be reused.
        600,
        Some("3f43a9af-08c5-4317-b694-3d3e883dcaef".to_string()),
        None, // branch_key_id_supplier
        None, // cache_type
        None, // partition_id
    )?);

    let plaintext = b"Hello World";

    let encrypted = encrypt(&EncryptInput::with_keyring(
        plaintext,
        EncryptionContext::new(),
        keyring.clone(),
    ))
    .await?;

    let decrypted = decrypt(&DecryptInput::with_keyring(
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

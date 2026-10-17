// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Encrypts and decrypts a message with a hierarchical keyring.
//!
//! Requires AWS credentials and an existing key store with a provisioned branch key.

use std::time::Duration;

use aws_esdk::error::{Resource, Service};
use aws_esdk::key_store::types::KmsConfiguration;
use aws_esdk::keyring::HierarchicalKeyring;
use aws_esdk::types::EncryptionContext;
use aws_esdk::{Error, aws_config, aws_sdk_dynamodb, aws_sdk_kms, key_store};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The clients take their region and credentials from the default AWS config chain.
    let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let kms = aws_sdk_kms::Client::new(&sdk_config);
    let ddb = aws_sdk_dynamodb::Client::new(&sdk_config);

    // The AWS Crypto Tools CI test key store.
    // Replace these with your own key store's table, name, and KMS key ARN.
    let key_store = key_store::DynamoDbKeyStore::builder()
        .ddb_table_name("KeyStoreDdbTable")
        .logical_key_store_name("KeyStoreDdbTable")
        .kms_configuration(KmsConfiguration::KmsKeyArn(
            "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126".into(),
        ))
        .kms_client(kms)
        .ddb_client(ddb)
        .build()
        .await?;

    let keyring = HierarchicalKeyring::builder()
        .key_store(key_store)
        // How long the keyring reuses cached branch key material.
        .ttl(Duration::from_secs(600))
        .branch_key_id("3f43a9af-08c5-4317-b694-3d3e883dcaef")
        .build()
        .await?;

    let plaintext = b"Hello World";

    // The encryption context is authenticated, not encrypted, and is bound to the message.
    let encryption_context =
        EncryptionContext::from([("purpose", "example"), ("is not", "secret")]);

    let esdk = aws_esdk::Client::default();

    let result = esdk
        .encrypt()
        .plaintext(plaintext)
        .encryption_context(encryption_context.clone())
        .keyring(keyring.clone())
        .send()
        .await;
    let encrypted = match result {
        Ok(output) => output,
        Err(e) => {
            match &e {
                Error::ResourceNotFound(not_found) => match not_found.resource() {
                    Some(Resource::BranchKey(branch_key)) => {
                        eprintln!("branch key {} is not in the key store", branch_key.id());
                    }
                    _ => eprintln!("an AWS resource does not exist: {e}"),
                },
                Error::AccessDenied(denied) => match denied.service() {
                    Some(Service::Kms) => eprintln!("AWS KMS denied access: {e}"),
                    Some(Service::DynamoDb) => eprintln!("DynamoDB denied access: {e}"),
                    _ => eprintln!("access denied: {e}"),
                },
                _ => eprintln!("encrypt failed: {e}"),
            }
            return Err(e.into());
        }
    };

    let decrypted = esdk
        .decrypt()
        .ciphertext(encrypted.ciphertext())
        .encryption_context(encryption_context)
        .keyring(keyring)
        .send()
        .await?;

    assert_eq!(
        decrypted.plaintext(),
        plaintext,
        "Decryption failed: plaintext mismatch"
    );
    println!("Success! Encryption and decryption completed successfully.");
    Ok(())
}

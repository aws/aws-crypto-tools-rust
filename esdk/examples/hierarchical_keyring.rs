// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Encrypt/decrypt with a hierarchical (branch-key) keyring.
//!
//! REQUIRES AWS credentials, a KMS key, and a DynamoDB-backed key store with a
//! provisioned branch key. Unlike the other examples, this one calls AWS and
//! does not run offline. The values below are AWS Crypto Tools test resources;
//! replace them with your own key store table, logical name, KMS key ARN, and
//! branch key id.

use aws_esdk::{DecryptInput, EncryptInput, EncryptionContext, decrypt, encrypt, mpl};
use aws_mpl_legacy::dafny::aws_cryptography_keyStore::client::Client as KeystoreClient;
use aws_mpl_legacy::dafny::aws_cryptography_keyStore::types::KmsConfiguration;
use aws_mpl_legacy::dafny::aws_cryptography_keyStore::types::key_store_config::KeyStoreConfig;

// AWS Crypto Tools test resources. Replace with your own.
const KEY_STORE_TABLE: &str = "KeyStoreDdbTable";
const LOGICAL_KEY_STORE_NAME: &str = "KeyStoreDdbTable";
const KMS_KEY_ARN: &str =
    "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126";
const BRANCH_KEY_ID: &str = "3f43a9af-08c5-4317-b694-3d3e883dcaef";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // KMS and DynamoDB clients come from the standard AWS config chain
    // (region and credentials).
    let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let kms_client = aws_sdk_kms::Client::new(&sdk_config);
    let ddb_client = aws_sdk_dynamodb::Client::new(&sdk_config);

    let key_store_config = KeyStoreConfig::builder()
        .kms_client(kms_client)
        .ddb_client(ddb_client)
        .ddb_table_name(KEY_STORE_TABLE)
        .logical_key_store_name(LOGICAL_KEY_STORE_NAME)
        .kms_configuration(KmsConfiguration::KmsKeyArn(KMS_KEY_ARN.to_string()))
        .build()?;
    let key_store = KeystoreClient::from_conf(key_store_config)?;

    // ttl_seconds bounds how long cached branch-key material may be reused.
    let keyring = mpl()
        .create_aws_kms_hierarchical_keyring()
        .key_store(key_store)
        .branch_key_id(BRANCH_KEY_ID)
        .ttl_seconds(600)
        .send()
        .await?;

    let plaintext = b"Hello World";

    let mut encryption_context = EncryptionContext::new();
    encryption_context.insert(
        "purpose".to_string(),
        "hierarchical-keyring-example".to_string(),
    );

    let encrypted = encrypt(&EncryptInput::with_legacy_keyring(
        plaintext,
        encryption_context.clone(),
        keyring.clone(),
    ))
    .await?;

    let decrypted = decrypt(&DecryptInput::with_legacy_keyring(
        &encrypted.ciphertext,
        encryption_context,
        keyring,
    ))
    .await?;

    assert_eq!(
        decrypted.plaintext, plaintext,
        "round-trip plaintext must match"
    );
    println!("Success! Hierarchical keyring encrypt/decrypt round trip completed.");
    Ok(())
}

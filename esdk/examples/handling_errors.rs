// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Handles the errors a hierarchical keyring returns: retries a decrypt that can succeed later,
//! and reports a branch key or key store table that does not exist.
//!
//! Requires AWS credentials and the key store in hierarchical_keyring.rs.

use std::time::Duration;

use aws_crypto_mpl::error_chain::aws_service_error_code;
use aws_crypto_mpl::keystore::{BranchKeyStore, KmsConfiguration};
use aws_crypto_mpl::{HierarchicalKeyring, aws_config, aws_sdk_dynamodb, aws_sdk_kms};
use aws_esdk::{
    DecryptInput, DecryptOutput, DisplayErrorContext, EncryptInput, ErrorKind, decrypt, encrypt,
};

// The AWS Crypto Tools CI test key store.
// Replace these with your own key store's table, name, KMS key ARN, and branch key ID.
const TABLE_NAME: &str = "KeyStoreDdbTable";
const LOGICAL_KEY_STORE_NAME: &str = "KeyStoreDdbTable";
const KMS_KEY_ARN: &str =
    "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126";
const BRANCH_KEY_ID: &str = "3f43a9af-08c5-4317-b694-3d3e883dcaef";

async fn hierarchical_keyring(
    table_name: &str,
    branch_key_id: &str,
) -> Result<HierarchicalKeyring, aws_crypto_mpl::Error> {
    let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    // Building the key store and keyring does no IO,
    // so a missing table or branch key shows up on the first encrypt or decrypt.
    let key_store = BranchKeyStore::builder()
        .ddb_table_name(table_name)
        .logical_keystore_name(LOGICAL_KEY_STORE_NAME)
        .kms_configuration(KmsConfiguration::KmsKeyArn(KMS_KEY_ARN.to_string()))
        .kms_client(aws_sdk_kms::Client::new(&sdk_config))
        .ddb_client(aws_sdk_dynamodb::Client::new(&sdk_config))
        .build()
        .await?;
    HierarchicalKeyring::builder()
        .key_store(key_store)
        .ttl(Duration::from_secs(600))
        .branch_key_id(branch_key_id)
        .build()
}

/// Decrypt, retrying a retryable failure with exponential backoff.
///
/// The KMS and DynamoDB clients already retry each call a few times.
/// This loop retries the whole decrypt once those retries are used up,
/// for example during a sustained throttle or a network outage.
async fn decrypt_with_retry(input: &DecryptInput<'_>) -> Result<DecryptOutput, aws_esdk::Error> {
    const MAX_ATTEMPTS: u32 = 4;
    let mut delay = Duration::from_millis(200);
    let mut attempt = 1;
    loop {
        match decrypt(input).await {
            Ok(output) => return Ok(output),
            // A retryable error might succeed if the same call is made again later.
            // Any other error fails the same way every time, so return it at once.
            Err(err) if err.is_retryable() && attempt < MAX_ATTEMPTS => {
                eprintln!(
                    "decrypt attempt {attempt} failed, retrying in {delay:?}: {}",
                    DisplayErrorContext(&err)
                );
                tokio::time::sleep(delay).await;
                delay *= 2;
                attempt += 1;
            }
            Err(err) => return Err(err),
        }
    }
}

/// Say what to do about an error that retrying cannot fix.
fn report(err: &aws_esdk::Error) {
    match err.kind() {
        ErrorKind::RemoteResourceNotFound => {
            // The AWS service error code says which resource is missing.
            // DynamoDB reports a missing table as ResourceNotFoundException.
            // A missing branch key has no code: DynamoDB found the table but no record for the ID.
            match aws_service_error_code(err) {
                Some("ResourceNotFoundException") => {
                    println!("the key store table does not exist; check the table name");
                }
                Some(code) => {
                    println!("an AWS resource does not exist ({code}); check the configuration")
                }
                None => println!(
                    "the branch key does not exist in the key store; check the branch key ID"
                ),
            }
        }
        // IAM usually allows only the key store's own table,
        // so a request for a table that does not exist is often denied before DynamoDB looks for it.
        ErrorKind::RemoteAccessDenied => {
            println!("access denied; check the IAM policy for the key store table and KMS key");
        }
        // Still failing after the retries, or not retryable at all, such as missing credentials.
        ErrorKind::RemoteTransport => {
            println!("could not reach AWS; check the credentials, region, and network");
        }
        ErrorKind::Validation => println!("invalid input or configuration; fix it and try again"),
        ErrorKind::Cryptographic
        | ErrorKind::NoMatchingDataKey
        | ErrorKind::Serialization
        | ErrorKind::EncryptionContextMismatch => println!("reject the message"),
        // ErrorKind is non-exhaustive, so a match needs a catch-all arm.
        _ => println!("failed"),
    }
    // The whole chain, for logs. Decide from the kind, never from this text.
    println!("  {}", DisplayErrorContext(err));
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let keyring = hierarchical_keyring(TABLE_NAME, BRANCH_KEY_ID).await?;
    let encrypted = encrypt(
        &EncryptInput::builder()
            .plaintext(b"Hello World")
            .keyring(keyring.clone())
            .build()?,
    )
    .await?;

    let input = DecryptInput::builder()
        .ciphertext(&encrypted.ciphertext)
        .keyring(keyring)
        .build()?;
    match decrypt_with_retry(&input).await {
        Ok(decrypted) => assert_eq!(decrypted.plaintext, b"Hello World"),
        Err(err) => {
            report(&err);
            return Err(err.into());
        }
    }
    println!("decrypted the message");

    // A branch key ID with no record in the key store.
    let missing_branch_key =
        hierarchical_keyring(TABLE_NAME, "branch-key-that-does-not-exist").await?;
    let err = encrypt(
        &EncryptInput::builder()
            .plaintext(b"Hello World")
            .keyring(missing_branch_key)
            .build()?,
    )
    .await
    .expect_err("a branch key that does not exist cannot encrypt");
    report(&err);

    // A key store table that does not exist.
    let missing_table = hierarchical_keyring("table-that-does-not-exist", BRANCH_KEY_ID).await?;
    let err = encrypt(
        &EncryptInput::builder()
            .plaintext(b"Hello World")
            .keyring(missing_table)
            .build()?,
    )
    .await
    .expect_err("a key store table that does not exist cannot encrypt");
    report(&err);

    Ok(())
}

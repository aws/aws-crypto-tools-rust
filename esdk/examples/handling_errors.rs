// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Handles the errors that the hierarchical keyring and its key store return.
//!
//! Every operation returns one `aws_esdk::Error`.
//! Decide from its fields, never from the message text, which can change in any release:
//! - `is_retryable()`: whether a retry can help
//! - the variant: the kind of failure
//! - `service()`: the AWS service involved
//! - `resource()`: the resource to act on
//!
//! The encrypt call handles errors from coarse to fine.
//! The decrypt call handles the failures only decrypt has,
//! and lists every failure when the keyring tried more than one encrypted data key.
//! The key store call handles a key store error with a reason.
//!
//! Requires AWS credentials and an existing key store with a provisioned branch key.

use std::time::Duration;

use aws_crypto_mpl::error::ConflictReason;
use aws_crypto_mpl::key_store::{KeyStoreClient, KmsConfiguration};
use aws_crypto_mpl::{HierarchicalKeyring, aws_config, aws_sdk_dynamodb, aws_sdk_kms};
use aws_esdk::EncryptionContext;
use aws_esdk::Error;
use aws_esdk::error::{Resource, Service};

// The AWS Crypto Tools CI test key store.
// Replace these with your own key store's table, name, KMS key ARN, and branch key ID.
const TABLE_NAME: &str = "KeyStoreDdbTable";
const LOGICAL_KEY_STORE_NAME: &str = "KeyStoreDdbTable";
const KMS_KEY_ARN: &str =
    "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126";
const BRANCH_KEY_ID: &str = "3f43a9af-08c5-4317-b694-3d3e883dcaef";

const PLAINTEXT: &[u8] = b"Hello World";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let key_store = KeyStoreClient::builder()
        .ddb_table_name(TABLE_NAME)
        .logical_key_store_name(LOGICAL_KEY_STORE_NAME)
        .kms_configuration(KmsConfiguration::KmsKeyArn(KMS_KEY_ARN.into()))
        .kms_client(aws_sdk_kms::Client::new(&sdk_config))
        .ddb_client(aws_sdk_dynamodb::Client::new(&sdk_config))
        .build()
        .await?;
    let keyring = HierarchicalKeyring::builder()
        .key_store(key_store.clone())
        .ttl(Duration::from_secs(600))
        .branch_key_id(BRANCH_KEY_ID)
        .build()
        .await?;

    // Encrypt, handling errors from coarse to fine.
    // The hierarchical keyring reads the branch key from DynamoDB and decrypts it with AWS KMS,
    // so encrypt can fail in either service.
    let esdk = aws_esdk::Client::default();
    let result = esdk
        .encrypt()
        .plaintext(PLAINTEXT)
        .keyring(keyring.clone())
        .send()
        .await;
    let encrypted = match result {
        Ok(output) => output,
        Err(e) => {
            match &e {
                // Checking `is_retryable()` first catches throttling, timeouts, etc. in one arm, whatever their variant.
                // The AWS SDK clients already retried these, so retry at a higher level.
                // `e.retry_kind()` says how to back off.
                _ if e.is_retryable() => {
                    eprintln!("retry later ({:?}): {e}", e.retry_kind());
                }

                // Many applications stop at the variant, for example `Error::AccessDenied(_) => alert_on_call()`.
                // `is_credentials()` means AWS rejected the credentials themselves, not a permission on a resource.
                Error::AccessDenied(denied) if denied.is_credentials() => {
                    eprintln!("the AWS credentials are expired or invalid");
                }

                // `service()` says which service denied access.
                // The fix differs per service: a KMS key policy or grant, or an IAM policy on the table.
                Error::AccessDenied(denied) => match denied.service() {
                    Some(Service::Kms) => match denied.resource() {
                        // `resource()` is the resource to act on.
                        Some(Resource::KmsKey(key)) => {
                            eprintln!("grant access to the KMS key {}", key.arn());
                        }
                        // `Resource` gains kinds in later releases, so end every match on it with a catch-all arm.
                        _ => eprintln!("AWS KMS denied access: {e}"),
                    },
                    Some(Service::DynamoDb) => match denied.resource() {
                        Some(Resource::DynamoDbTable(table)) => {
                            eprintln!("grant access to the key store table {}", table.name());
                        }
                        _ => eprintln!("DynamoDB denied access: {e}"),
                    },
                    // `Service` also gains values in later releases.
                    _ => eprintln!("access denied: {e}"),
                },

                // A missing resource: branch on the service, then on the resource, the same way.
                Error::ResourceNotFound(not_found) => match not_found.service() {
                    Some(Service::Kms) => match not_found.resource() {
                        Some(Resource::KmsKey(key)) => {
                            eprintln!("the KMS key {} does not exist", key.arn());
                        }
                        _ => eprintln!("an AWS KMS resource does not exist: {e}"),
                    },
                    // The key store keeps branch keys in DynamoDB,
                    // so both a missing branch key and a missing table are DynamoDB resources.
                    Some(Service::DynamoDb) => match not_found.resource() {
                        Some(Resource::BranchKey(branch_key)) => {
                            eprintln!("create the branch key {} in the key store", branch_key.id());
                        }
                        Some(Resource::DynamoDbTable(table)) => {
                            eprintln!("the key store table {} does not exist", table.name());
                        }
                        _ => eprintln!("a DynamoDB resource does not exist: {e}"),
                    },
                    _ => eprintln!("a resource does not exist: {e}"),
                },

                // `Error` gains variants in later releases, so the last arm handles every other failure.
                // `{e:#}` prints the error and every cause below it.
                _ => eprintln!("encrypt failed: {e:#}"),
            }
            return Err(e.into());
        }
    };

    // Decrypt, handling the failures only decrypt has.
    let result = esdk
        .decrypt()
        .ciphertext(encrypted.ciphertext())
        .keyring(keyring)
        .send()
        .await;
    let decrypted = match result {
        Ok(output) => output,
        Err(e) => {
            match &e {
                _ if e.is_retryable() => eprintln!("retry later: {e}"),

                // The branch key record in DynamoDB is malformed, for example a key of the wrong length.
                // `resource()` names the branch key to repair.
                Error::InvalidMaterials(invalid) => match invalid.resource() {
                    Some(Resource::BranchKey(branch_key)) => {
                        eprintln!("the record for branch key {} is malformed", branch_key.id());
                    }
                    _ => eprintln!("invalid materials: {e}"),
                },

                // None of the message's encrypted data keys belongs to this keyring.
                // `encrypted_data_keys()` lists which keys the message was encrypted for.
                Error::NoMatchingDataKey(no_match) => {
                    for key in no_match.encrypted_data_keys() {
                        eprintln!(
                            "the message was encrypted for key provider {}",
                            key.key_provider_id()
                        );
                    }
                }

                // The message is corrupt or was modified.
                // Retrying cannot help.
                Error::Cryptographic(_) | Error::Serialization(_) => {
                    eprintln!("the message is corrupt or was tampered with");
                }

                // The keyring tries each of the message's encrypted data keys.
                // When all fail, `e` is the most actionable failure,
                // and `failures()` returns every one, each a full `Error`.
                _ => {
                    for failure in e.failures() {
                        match &failure {
                            Error::AccessDenied(denied) => match denied.resource() {
                                Some(Resource::KmsKey(key)) => {
                                    eprintln!("one attempt was denied the KMS key {}", key.arn());
                                }
                                _ => eprintln!("one attempt was denied access: {failure}"),
                            },
                            Error::Throttling(_) => eprintln!("one attempt was throttled"),
                            _ => eprintln!("one attempt failed: {failure}"),
                        }
                    }
                }
            }
            return Err(e.into());
        }
    };
    assert_eq!(decrypted.plaintext(), PLAINTEXT);
    println!("decrypted the message");

    // Key store operations return `aws_crypto_mpl::Error`, with the same variants and accessors.
    // A `Conflict` says why through `reason()`:
    // - `AlreadyExists`: the branch key ID is already in use
    // - `ConcurrentModification`: another caller rotated the branch key at the same time
    // This call reuses the provisioned branch key's ID, so it reaches `AlreadyExists`.
    let branch_key_context = EncryptionContext::from([("purpose", "example")]);
    match key_store
        .create_key()
        .branch_key_id(BRANCH_KEY_ID)
        .encryption_context(branch_key_context)
        .send()
        .await
    {
        Ok(output) => println!("created branch key {}", output.branch_key_id()),
        Err(aws_crypto_mpl::Error::Conflict(conflict)) => match conflict.reason() {
            Some(ConflictReason::AlreadyExists) => {
                println!("branch key {BRANCH_KEY_ID} already exists; use it or pick another ID");
            }
            // `ConflictReason` gains values in later releases.
            _ => return Err(conflict.into()),
        },
        Err(e) => return Err(e.into()),
    }

    Ok(())
}

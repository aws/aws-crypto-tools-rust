// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shares one storm-tracking cache across two hierarchical keyrings.
//!
//! A hierarchical keyring caches branch key material so it does not call KMS on every message.
//! By default, each keyring gets its own cache.
//! Keyrings that share one cache reuse each other's entries
//! when they also have the same partition ID, logical key store name, and branch key ID.
//! Here the two keyrings use separate key store instances with the same logical name,
//! as two services reading one key store table would.
//! Never give two different key store tables the same logical name.
//!
//! A storm-tracking cache also keeps concurrent requests from all refreshing the same entry:
//! near expiry, one request refreshes the entry while the others keep using the cached value.
//!
//! Requires AWS credentials and an existing key store with a provisioned branch key.

use std::time::Duration;

use aws_crypto_mpl::key_store::{KeyStoreClient, KmsKeyArn};
use aws_crypto_mpl::{
    HierarchicalKeyring, StormTrackingCmc, aws_config, aws_sdk_dynamodb, aws_sdk_kms,
};
use aws_esdk::{DecryptInput, EncryptInput, EncryptionContext, decrypt, encrypt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The clients take their region and credentials from the default AWS config chain.
    let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;

    // The AWS Crypto Tools CI test key store.
    // Replace these with your own key store's table, name, and KMS key ARN.
    let make_key_store = || {
        KeyStoreClient::builder()
            .ddb_table_name("KeyStoreDdbTable")
            .logical_key_store_name("KeyStoreDdbTable")
            .kms_configuration(KmsKeyArn::new(
                "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126",
            ))
            .kms_client(aws_sdk_kms::Client::new(&sdk_config))
            .ddb_client(aws_sdk_dynamodb::Client::new(&sdk_config))
            .build()
    };
    let key_store_a = make_key_store().await?;
    let key_store_b = make_key_store().await?;

    // Every parameter is optional; each value set here is its default.
    let cache = StormTrackingCmc::builder()
        // Maximum number of entries the cache holds.
        .entry_capacity(1000)
        // Least-recently-used entries checked for expiry on each lookup.
        .entry_pruning_tail_size(1)
        // How long before expiry one request starts refreshing an entry.
        // Must be less than the keyring TTL.
        .grace_period(Duration::from_secs(10))
        // How long other requests wait before another one may try refreshing.
        .grace_interval(Duration::from_secs(1))
        // Maximum number of entries being refreshed at the same time.
        .fan_out(20)
        // How long a refresh may run before another request may retry it.
        .inflight_ttl(Duration::from_secs(10))
        // How long a waiting request sleeps before checking the cache again.
        .sleep(Duration::from_millis(20))
        .build()?;

    // Same cache, partition ID, logical key store name, and branch key ID,
    // so the keyrings reuse each other's entries.
    let make_keyring = |key_store: KeyStoreClient| {
        HierarchicalKeyring::builder()
            .key_store(key_store)
            .ttl(Duration::from_secs(600))
            .branch_key_id("3f43a9af-08c5-4317-b694-3d3e883dcaef")
            .cache(cache.clone())
            .partition_id("shared-partition")
            .build()
    };
    let keyring_a = make_keyring(key_store_a)?;
    let keyring_b = make_keyring(key_store_b)?;

    let plaintext = b"Hello World";

    // The encryption context is authenticated, not encrypted, and is bound to the message.
    let mut encryption_context = EncryptionContext::new();
    encryption_context.insert("purpose", "example");
    encryption_context.insert("is not", "secret");

    // Encrypt with A, decrypt with B: both go through the same cache.
    let encrypted = encrypt(
        &EncryptInput::builder()
            .plaintext(plaintext)
            .encryption_context(encryption_context.clone())
            .keyring(keyring_a)
            .build()?,
    )
    .await?;

    let decrypted = decrypt(
        &DecryptInput::builder()
            .ciphertext(&encrypted.ciphertext)
            .encryption_context(encryption_context)
            .keyring(keyring_b)
            .build()?,
    )
    .await?;

    assert_eq!(
        decrypted.plaintext, plaintext,
        "Decryption failed: plaintext mismatch"
    );
    println!("Success! Two keyrings shared one storm-tracking cache.");
    Ok(())
}

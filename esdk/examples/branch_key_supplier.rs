// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Picks a branch key per tenant with a [`BranchKeySupplier`].
//!
//! A multi-tenant application gives each tenant its own branch key,
//! so one tenant's branch key cannot decrypt another tenant's data.
//! One hierarchical keyring serves every tenant:
//! its supplier reads the tenant from the encryption context and returns that tenant's branch key ID.
//!
//! The example creates a branch key for each of two tenants,
//! encrypts a message for each through the supplier,
//! and shows that a keyring fixed to one tenant's branch key cannot decrypt the other tenant's message.
//!
//! Requires AWS credentials and an existing key store.
//! Each run creates two new branch keys in it.

use std::time::Duration;

use aws_crypto_mpl::Error as MplError;
use aws_crypto_mpl::async_trait;
use aws_crypto_mpl::key_store::{KeyStoreClient, KmsConfiguration};
use aws_crypto_mpl::{
    BranchKeySupplier, GetBranchKeyIdInput, GetBranchKeyIdOutput, HierarchicalKeyring, aws_config,
    aws_sdk_dynamodb, aws_sdk_kms,
};
use aws_esdk::Error;
use aws_esdk::types::EncryptionContext;

/// Maps the `tenant` value in the encryption context to that tenant's branch key ID.
struct TenantBranchKeySupplier {
    tenant_a: String,
    tenant_b: String,
}

#[async_trait]
impl BranchKeySupplier for TenantBranchKeySupplier {
    async fn get_branch_key_id(
        &self,
        input: GetBranchKeyIdInput,
    ) -> Result<GetBranchKeyIdOutput, MplError> {
        let branch_key_id = match input.encryption_context().get("tenant") {
            Some("TenantA") => &self.tenant_a,
            Some("TenantB") => &self.tenant_b,
            _ => {
                return Err(MplError::validation(
                    "the encryption context has no known tenant",
                ));
            }
        };
        Ok(branch_key_id.as_str().into())
    }
}

fn tenant_context(tenant: &str) -> EncryptionContext {
    EncryptionContext::from([("tenant", tenant), ("purpose", "example")])
}

async fn fixed_keyring(
    key_store: &KeyStoreClient,
    branch_key_id: &str,
) -> Result<HierarchicalKeyring, MplError> {
    HierarchicalKeyring::builder()
        .key_store(key_store.clone())
        .ttl(Duration::from_secs(600))
        .branch_key_id(branch_key_id)
        .build()
        .await
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;

    // The AWS Crypto Tools CI test key store.
    // Replace these with your own key store's table, name, and KMS key ARN.
    let key_store = KeyStoreClient::builder()
        .ddb_table_name("KeyStoreDdbTable")
        .logical_key_store_name("KeyStoreDdbTable")
        .kms_configuration(KmsConfiguration::KmsKeyArn(
            "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126".into(),
        ))
        .kms_client(aws_sdk_kms::Client::new(&sdk_config))
        .ddb_client(aws_sdk_dynamodb::Client::new(&sdk_config))
        .build()
        .await?;

    let branch_key_context = EncryptionContext::from([("purpose", "example")]);
    let create_branch_key = async || {
        key_store
            .create_key()
            .encryption_context(branch_key_context.clone())
            .send()
            .await
            .map(|output| output.into_branch_key_id())
    };
    let branch_key_a = create_branch_key().await?;
    let branch_key_b = create_branch_key().await?;

    let keyring = HierarchicalKeyring::builder()
        .key_store(key_store.clone())
        .ttl(Duration::from_secs(600))
        .branch_key_id_supplier(TenantBranchKeySupplier {
            tenant_a: branch_key_a.clone(),
            tenant_b: branch_key_b.clone(),
        })
        .build()
        .await?;

    let plaintext = b"Hello World";

    let esdk = aws_esdk::Client::default();

    let encrypted_a = esdk
        .encrypt()
        .plaintext(plaintext)
        .encryption_context(tenant_context("TenantA"))
        .keyring(keyring.clone())
        .send()
        .await?;
    let encrypted_b = esdk
        .encrypt()
        .plaintext(plaintext)
        .encryption_context(tenant_context("TenantB"))
        .keyring(keyring)
        .send()
        .await?;

    let keyring_a = fixed_keyring(&key_store, &branch_key_a).await?;
    let keyring_b = fixed_keyring(&key_store, &branch_key_b).await?;

    // Tenant B's branch key cannot decrypt tenant A's message.
    let result = esdk
        .decrypt()
        .ciphertext(encrypted_a.ciphertext())
        .encryption_context(tenant_context("TenantA"))
        .keyring(keyring_b.clone())
        .send()
        .await;
    assert!(
        matches!(result, Err(Error::NoMatchingDataKey(_))),
        "a different tenant's branch key must not decrypt the message, got {result:?}"
    );

    // Each tenant's branch key decrypts that tenant's message.
    for (encrypted, tenant, keyring) in [
        (&encrypted_a, "TenantA", keyring_a),
        (&encrypted_b, "TenantB", keyring_b),
    ] {
        let decrypted = esdk
            .decrypt()
            .ciphertext(encrypted.ciphertext())
            .encryption_context(tenant_context(tenant))
            .keyring(keyring)
            .send()
            .await?;
        assert_eq!(
            decrypted.plaintext(),
            plaintext,
            "Decryption failed: plaintext mismatch"
        );
    }

    println!("Success! Each tenant's message decrypts only under that tenant's branch key.");
    Ok(())
}

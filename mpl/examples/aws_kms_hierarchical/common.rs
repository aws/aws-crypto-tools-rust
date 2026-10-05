// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared helpers used by every demo in this example crate.
//!
//! Real AWS access is required to actually run these examples — each demo
//! exercises real KMS Decrypt and DynamoDB GetItem against the keystore
//! configured via the env vars listed in [`Config::from_env`]. The
//! examples compile without any AWS access; they only fail at the first
//! `.on_encrypt` / `.on_decrypt` if credentials or fixtures aren't
//! present. This mirrors the ESDK Rust hierarchical-keyring blueprint.

use std::sync::Arc;

use aws_config::{BehaviorVersion, Region};
use aws_sdk_dynamodb::Client as DynamoDbClient;
use aws_sdk_kms::Client as KmsClient;

use aws_crypto_mpl::aws_kms::hierarchical_keyring::HierarchicalKeyring;
use aws_crypto_mpl::keystore::{KeyStoreConfig, Keystore, KmsConfiguration};
use aws_crypto_mpl::structures::{
    AlgorithmSuiteId, DecryptionMaterials, EncryptionContext, EncryptionMaterials,
};
use aws_crypto_mpl::{Keyring, MaterialProviders};

/// Bag of fixture inputs the examples need. All fields are read from
/// environment variables on first use; missing vars cause a descriptive
/// error rather than a silent default.
pub struct Config {
    /// DynamoDB table backing the branch-key store.
    pub table_name: String,
    /// Logical keystore name cryptographically bound to the branch keys.
    pub logical_keystore_name: String,
    /// AWS Region for the KMS / DDB clients (e.g. `us-west-2`).
    pub region: String,
    /// KMS Key ARN governing branch-key encryption / decryption.
    pub kms_key_arn: String,
    /// Existing branch-key id used by single-tenant demos.
    pub branch_key_id: String,
    /// Existing branch-key id for tenant A in the supplier demo.
    pub branch_key_id_tenant_a: String,
    /// Existing branch-key id for tenant B in the supplier demo.
    pub branch_key_id_tenant_b: String,
}

impl Config {
    /// Read all required fixture inputs from environment variables.
    ///
    /// Required:
    /// - `MPL_EXAMPLE_KEY_STORE_TABLE` — DDB table name.
    /// - `MPL_EXAMPLE_LOGICAL_KEY_STORE_NAME` — logical keystore name.
    /// - `MPL_EXAMPLE_KMS_KEY_ARN` — KMS Key ARN.
    /// - `MPL_EXAMPLE_BRANCH_KEY_ID` — pre-existing branch key id.
    ///
    /// Optional (default to `MPL_EXAMPLE_BRANCH_KEY_ID`):
    /// - `MPL_EXAMPLE_BRANCH_KEY_ID_TENANT_A`
    /// - `MPL_EXAMPLE_BRANCH_KEY_ID_TENANT_B`
    ///
    /// Optional (defaults to `us-west-2`):
    /// - `MPL_EXAMPLE_REGION`
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        fn req(name: &str) -> Result<String, Box<dyn std::error::Error>> {
            std::env::var(name).map_err(|_| format!("required env var {name} is not set").into())
        }
        let branch_key_id = req("MPL_EXAMPLE_BRANCH_KEY_ID")?;
        Ok(Self {
            table_name: req("MPL_EXAMPLE_KEY_STORE_TABLE")?,
            logical_keystore_name: req("MPL_EXAMPLE_LOGICAL_KEY_STORE_NAME")?,
            region: std::env::var("MPL_EXAMPLE_REGION").unwrap_or_else(|_| "us-west-2".to_string()),
            kms_key_arn: req("MPL_EXAMPLE_KMS_KEY_ARN")?,
            branch_key_id_tenant_a: std::env::var("MPL_EXAMPLE_BRANCH_KEY_ID_TENANT_A")
                .unwrap_or_else(|_| branch_key_id.clone()),
            branch_key_id_tenant_b: std::env::var("MPL_EXAMPLE_BRANCH_KEY_ID_TENANT_B")
                .unwrap_or_else(|_| branch_key_id.clone()),
            branch_key_id,
        })
    }
}

/// Construct an AWS KMS client and an Amazon DynamoDB client pinned to
/// the configured region using the platform's default credential chain.
pub async fn build_clients(region: &str) -> (KmsClient, DynamoDbClient) {
    let cfg = aws_config::defaults(BehaviorVersion::latest())
        .region(Region::new(region.to_string()))
        .load()
        .await;
    (KmsClient::new(&cfg), DynamoDbClient::new(&cfg))
}

/// Build a `BranchKeyStore` through the MPL client's factory.
pub async fn build_keystore(
    mpl: &MaterialProviders,
    config: &Config,
) -> Result<Arc<dyn Keystore>, Box<dyn std::error::Error>> {
    let (kms_client, ddb_client) = build_clients(&config.region).await;
    let key_store_config = KeyStoreConfig {
        ddb_table_name: config.table_name.clone(),
        kms_configuration: KmsConfiguration::KmsKeyArn(config.kms_key_arn.clone()),
        logical_keystore_name: config.logical_keystore_name.clone(),
        id: None,
        grant_tokens: None,
        ddb_client: None,
        kms_client: None,
    };
    // The factory returns Arc<BranchKeyStore>; the unsized coercion to
    // Arc<dyn Keystore> happens implicitly when we type-annotate.
    let store = mpl
        .create_branch_key_store()
        .key_store_config(key_store_config)
        .kms_client(kms_client)
        .ddb_client(ddb_client)
        .send()
        .await?;
    Ok(store)
}

/// Choose a non-signing algorithm suite so signing-key invariants stay
/// out of the way of the demos. The hierarchical keyring is suite-agnostic.
pub fn example_suite() -> AlgorithmSuiteId {
    AlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf
}

/// Build empty [`EncryptionMaterials`] with the supplied encryption context.
pub fn empty_encryption_materials(
    encryption_context: EncryptionContext,
) -> Result<EncryptionMaterials, Box<dyn std::error::Error>> {
    Ok(EncryptionMaterials::new(
        example_suite(),
        Vec::new(),
        encryption_context,
        Default::default(),
        None,
        None,
        None,
    )?)
}

/// Build empty [`DecryptionMaterials`] with the supplied encryption context.
pub fn empty_decryption_materials(
    encryption_context: EncryptionContext,
) -> Result<DecryptionMaterials, Box<dyn std::error::Error>> {
    Ok(DecryptionMaterials::new(
        example_suite(),
        encryption_context,
        Default::default(),
        None,
        None,
        None,
    )?)
}

/// Run an encrypt → decrypt round trip through `keyring`. Returns a
/// descriptive error if the recovered plaintext data key does not match
/// the one produced by `on_encrypt`.
///
/// This is the contract every developer using the MPL keyring layer
/// cares about — a decrypt operation MUST recover the same data key
/// the encrypt operation produced, given the same encryption context.
pub async fn round_trip(
    keyring: &HierarchicalKeyring,
    encryption_context: EncryptionContext,
) -> Result<(), Box<dyn std::error::Error>> {
    let em_in = empty_encryption_materials(encryption_context.clone())?;
    let em_out = keyring.on_encrypt(em_in).await?;
    let pdk_encrypt = em_out
        .plaintext_data_key()
        .ok_or("on_encrypt did not produce a plaintext data key")?
        .as_bytes()
        .to_vec();
    let edks = em_out.encrypted_data_keys().to_vec();

    let dm_in = empty_decryption_materials(encryption_context)?;
    let dm_out = keyring.on_decrypt(dm_in, &edks).await?;
    let pdk_decrypt = dm_out
        .plaintext_data_key()
        .ok_or("on_decrypt did not produce a plaintext data key")?
        .as_bytes()
        .to_vec();

    if pdk_encrypt != pdk_decrypt {
        return Err("decrypted data key did not match encrypted data key".into());
    }
    Ok(())
}

/// Build a small, demo-shaped encryption context. Real workloads encode
/// caller / tenant / classification metadata; the values here are
/// intentionally illustrative.
pub fn demo_encryption_context(extra: &[(&str, &str)]) -> EncryptionContext {
    let mut ec = EncryptionContext::new();
    ec.insert(b"region".to_vec(), b"us-west-2".to_vec());
    ec.insert(b"purpose".to_vec(), b"mpl-example".to_vec());
    for (k, v) in extra {
        ec.insert(k.as_bytes().to_vec(), v.as_bytes().to_vec());
    }
    ec
}

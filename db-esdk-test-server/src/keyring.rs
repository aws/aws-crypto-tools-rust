// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Translate the modeled `Keyring` union into an MPL keyring.

use std::collections::HashMap;
use std::time::Duration;

use crate::error::ServerError;
use crate::model::{
    AesWrappingAlg, AwsKmsHierarchicalKeyringConfig, AwsKmsKeyringConfig,
    DdbKeyBranchKeyIdSupplier, Keyring, RawAesKeyringConfig,
};
use aws_db_esdk::aws_sdk_dynamodb::types::AttributeValue;
use aws_db_esdk::key_store::types::KmsConfiguration;
use aws_db_esdk::keyring::{
    AwsKmsKeyring, GetBranchKeyIdFromItemKeyInput, GetBranchKeyIdOutput, HierarchicalKeyring,
    ItemKeyBranchKeySupplier, ItemKeySupplier, RawAesKeyring, SharedKeyring,
};
use aws_db_esdk::types::AesWrappingAlg as MplAesWrappingAlg;
use aws_db_esdk::{async_trait, aws_config, aws_sdk_dynamodb, aws_sdk_kms, key_store, mpl};

/// Build the keyring a modeled `Keyring` names; exactly one variant must be set.
pub async fn keyring_for_config(keyring: &Keyring) -> Result<SharedKeyring, ServerError> {
    let set = usize::from(keyring.aws_kms.is_some())
        + usize::from(keyring.raw_aes.is_some())
        + usize::from(keyring.aws_kms_hierarchical.is_some())
        + keyring.other.len();
    if set != 1 {
        return Err(ServerError::generic(format!(
            "Keyring must set exactly one variant, found {set}"
        )));
    }
    if let Some(raw_aes) = &keyring.raw_aes {
        return build_raw_aes(raw_aes);
    }
    if let Some(aws_kms) = &keyring.aws_kms {
        return build_aws_kms(aws_kms).await;
    }
    if let Some(hierarchical) = &keyring.aws_kms_hierarchical {
        return build_hierarchical(hierarchical).await;
    }
    let name = keyring.other.keys().next().map_or("", String::as_str);
    Err(ServerError::generic(format!(
        "keyring variant {name} is not supported by the native Rust language server"
    )))
}

fn build_raw_aes(config: &RawAesKeyringConfig) -> Result<SharedKeyring, ServerError> {
    let alg = match config.wrapping_alg {
        AesWrappingAlg::Aes128 => MplAesWrappingAlg::AlgAes128GcmIv12Tag16,
        AesWrappingAlg::Aes192 => MplAesWrappingAlg::AlgAes192GcmIv12Tag16,
        AesWrappingAlg::Aes256 => MplAesWrappingAlg::AlgAes256GcmIv12Tag16,
    };
    let keyring = RawAesKeyring::builder()
        .key_namespace(config.key_namespace.as_str())
        .key_name(config.key_name.as_str())
        .wrapping_key(config.wrapping_key.clone())
        .wrapping_alg(alg)
        .build()
        .map_err(|e| ServerError::client(e.to_string()))?;
    Ok(SharedKeyring::new(keyring))
}

/// The region of a KMS key ARN, if it is one.
fn region_of(key_id: &str) -> Option<String> {
    let parts: Vec<&str> = key_id.split(':').collect();
    match parts.as_slice() {
        ["arn", _, "kms", region, _, _] if !region.is_empty() => Some((*region).to_owned()),
        _ => None,
    }
}

/// The ambient AWS configuration, in the region of `key_id` when it is a KMS key ARN.
async fn sdk_config_for(key_id: &str) -> aws_config::SdkConfig {
    // AWS KMS rejects an ARN whose region differs from the client's.
    let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
    if let Some(region) = region_of(key_id) {
        loader = loader.region(aws_config::Region::new(region));
    }
    loader.load().await
}

async fn build_aws_kms(config: &AwsKmsKeyringConfig) -> Result<SharedKeyring, ServerError> {
    let sdk_config = sdk_config_for(&config.kms_key_id).await;
    let keyring = AwsKmsKeyring::builder()
        .kms_key_id(config.kms_key_id.as_str())
        .kms_client(aws_sdk_kms::Client::new(&sdk_config))
        .set_grant_tokens(config.grant_tokens.clone())
        .build()
        .map_err(|e| ServerError::client(e.to_string()))?;
    Ok(SharedKeyring::new(keyring))
}

/// A hierarchical keyring over the DynamoDB branch key store the config names.
///
/// The key store's KMS and DynamoDB clients use the region of the KMS key ARN.
async fn build_hierarchical(
    config: &AwsKmsHierarchicalKeyringConfig,
) -> Result<SharedKeyring, ServerError> {
    let sdk_config = sdk_config_for(&config.kms_key_arn).await;
    let key_store = key_store::Client::builder()
        .ddb_table_name(config.key_store_table_name.as_str())
        .logical_key_store_name(config.logical_key_store_name.as_str())
        .kms_configuration(KmsConfiguration::KmsKeyArn(config.kms_key_arn.clone()))
        .kms_client(aws_sdk_kms::Client::new(&sdk_config))
        .ddb_client(aws_sdk_dynamodb::Client::new(&sdk_config))
        .build()
        .await
        .map_err(|e| ServerError::client(e.to_string()))?;
    let ttl_seconds = u64::try_from(config.ttl_seconds).map_err(|_| {
        ServerError::client(format!(
            "ttlSeconds must be non-negative, got {}",
            config.ttl_seconds
        ))
    })?;
    let builder = HierarchicalKeyring::builder()
        .key_store(key_store)
        .ttl(Duration::from_secs(ttl_seconds))
        .set_branch_key_id(config.branch_key_id.clone());
    let builder = match &config.branch_key_id_supplier {
        Some(supplier) => builder.branch_key_id_supplier(ItemKeyBranchKeySupplier::new(
            RoutingSupplier::from(supplier),
        )),
        None => builder,
    };
    let keyring = builder
        .build()
        .await
        .map_err(|e| ServerError::client(e.to_string()))?;
    Ok(SharedKeyring::new(keyring))
}

/// Routes each item to `routes[value]`, where `value` is the String value of the item key's
/// `route_attribute`.
struct RoutingSupplier {
    route_attribute: String,
    routes: HashMap<String, String>,
}

impl From<&DdbKeyBranchKeyIdSupplier> for RoutingSupplier {
    fn from(config: &DdbKeyBranchKeyIdSupplier) -> Self {
        Self {
            route_attribute: config.route_attribute.clone(),
            routes: config.routes.clone(),
        }
    }
}

#[async_trait]
impl ItemKeySupplier for RoutingSupplier {
    async fn get_branch_key_id(
        &self,
        input: GetBranchKeyIdFromItemKeyInput,
    ) -> Result<GetBranchKeyIdOutput, mpl::Error> {
        let Some(AttributeValue::S(value)) = input.item_key().get(&self.route_attribute) else {
            return Err(mpl::Error::validation(format!(
                "item key has no String attribute {}",
                self.route_attribute
            )));
        };
        let branch_key_id = self
            .routes
            .get(value)
            .ok_or_else(|| mpl::Error::validation(format!("no branch key route for {value}")))?;
        Ok(branch_key_id.as_str().into())
    }
}

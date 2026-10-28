// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Translate the modeled `Keyring` union into an MPL keyring.

use std::collections::HashMap;
use std::time::Duration;

use crate::error::ServerError;
use crate::model::{
    AesWrappingAlg, AwsKmsDiscoveryKeyringConfig, AwsKmsHierarchicalKeyringConfig,
    AwsKmsKeyringConfig, AwsKmsMrkDiscoveryKeyringConfig, AwsKmsMultiKeyringConfig,
    AwsKmsRsaKeyringConfig, DdbKeyBranchKeyIdSupplier, DiscoveryFilter as ModelDiscoveryFilter,
    Keyring, KmsRsaEncryptionAlgorithm, MultiKeyringConfig, PaddingScheme, RawAesKeyringConfig,
    RawRsaKeyringConfig,
};
use aws_db_esdk::aws_sdk_dynamodb::types::AttributeValue;
use aws_db_esdk::aws_sdk_kms::types::EncryptionAlgorithmSpec;
use aws_db_esdk::key_store::types::KmsConfiguration;
use aws_db_esdk::keyring::{
    AwsKmsDiscoveryKeyring, AwsKmsKeyring, AwsKmsMrkDiscoveryKeyring, AwsKmsMrkKeyring,
    AwsKmsRsaKeyring, DiscoveryFilter, GetBranchKeyIdFromItemKeyInput, GetBranchKeyIdOutput,
    HierarchicalKeyring, ItemKeyBranchKeySupplier, ItemKeySupplier, MultiKeyring, RawAesKeyring,
    RawRsaKeyring, SharedKeyring,
};
use aws_db_esdk::types::{AesWrappingAlg as MplAesWrappingAlg, PaddingScheme as MplPaddingScheme};
use aws_db_esdk::{async_trait, aws_config, aws_sdk_dynamodb, aws_sdk_kms, key_store, mpl};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

/// Build the keyring a modeled `Keyring` names; exactly one variant must be set.
pub async fn keyring_for_config(keyring: &Keyring) -> Result<SharedKeyring, ServerError> {
    let set = usize::from(keyring.aws_kms.is_some())
        + usize::from(keyring.raw_aes.is_some())
        + usize::from(keyring.raw_rsa.is_some())
        + usize::from(keyring.aws_kms_rsa.is_some())
        + usize::from(keyring.aws_kms_hierarchical.is_some())
        + usize::from(keyring.aws_kms_discovery.is_some())
        + usize::from(keyring.aws_kms_multi_keyring.is_some())
        + usize::from(keyring.aws_kms_mrk.is_some())
        + usize::from(keyring.aws_kms_mrk_discovery.is_some())
        + usize::from(keyring.aws_kms_mrk_multi_keyring.is_some())
        + usize::from(keyring.multi.is_some())
        + keyring.other.len();
    if set != 1 {
        return Err(ServerError::generic(format!(
            "Keyring must set exactly one variant, found {set}"
        )));
    }
    if let Some(raw_aes) = &keyring.raw_aes {
        return build_raw_aes(raw_aes);
    }
    if let Some(raw_rsa) = &keyring.raw_rsa {
        return build_raw_rsa(raw_rsa);
    }
    if let Some(aws_kms) = &keyring.aws_kms {
        return build_aws_kms(aws_kms).await;
    }
    if let Some(aws_kms_rsa) = &keyring.aws_kms_rsa {
        return build_aws_kms_rsa(aws_kms_rsa).await;
    }
    if let Some(hierarchical) = &keyring.aws_kms_hierarchical {
        return build_hierarchical(hierarchical).await;
    }
    if let Some(discovery) = &keyring.aws_kms_discovery {
        return build_aws_kms_discovery(discovery).await;
    }
    if let Some(aws_kms_multi) = &keyring.aws_kms_multi_keyring {
        return build_aws_kms_multi(aws_kms_multi).await;
    }
    if let Some(aws_kms_mrk) = &keyring.aws_kms_mrk {
        return build_aws_kms_mrk(aws_kms_mrk).await;
    }
    if let Some(mrk_discovery) = &keyring.aws_kms_mrk_discovery {
        return build_aws_kms_mrk_discovery(mrk_discovery).await;
    }
    if let Some(mrk_multi) = &keyring.aws_kms_mrk_multi_keyring {
        return build_aws_kms_mrk_multi(mrk_multi).await;
    }
    if let Some(multi) = &keyring.multi {
        return build_multi(multi).await;
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

fn build_raw_rsa(config: &RawRsaKeyringConfig) -> Result<SharedKeyring, ServerError> {
    let padding_scheme = match config.padding_scheme {
        PaddingScheme::Pkcs1 => MplPaddingScheme::Pkcs1,
        PaddingScheme::OaepSha1Mgf1 => MplPaddingScheme::OaepSha1Mgf1,
        PaddingScheme::OaepSha256Mgf1 => MplPaddingScheme::OaepSha256Mgf1,
        PaddingScheme::OaepSha384Mgf1 => MplPaddingScheme::OaepSha384Mgf1,
        PaddingScheme::OaepSha512Mgf1 => MplPaddingScheme::OaepSha512Mgf1,
    };
    let keyring = RawRsaKeyring::builder()
        .key_namespace(config.key_namespace.as_str())
        .key_name(config.key_name.as_str())
        .padding_scheme(padding_scheme)
        .set_public_key(config.public_key.clone())
        .set_private_key(config.private_key.clone())
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

/// An AWS KMS RSA keyring with a KMS client in its key's region.
///
/// Without a configured public key, the key's public key is fetched once with
/// KMS `GetPublicKey` (DER) and PEM-encoded. The encryption algorithm defaults
/// to RSAES-OAEP-SHA-256.
async fn build_aws_kms_rsa(config: &AwsKmsRsaKeyringConfig) -> Result<SharedKeyring, ServerError> {
    let sdk_config = sdk_config_for(&config.kms_key_id).await;
    let kms_client = aws_sdk_kms::Client::new(&sdk_config);
    let public_key = match &config.public_key {
        Some(key) => to_public_key_pem(key),
        None => {
            let response = kms_client
                .get_public_key()
                .key_id(config.kms_key_id.as_str())
                .send()
                .await
                .map_err(|e| {
                    ServerError::generic(format!(
                        "KMS GetPublicKey failed: {}",
                        aws_sdk_kms::error::DisplayErrorContext(&e)
                    ))
                })?;
            let der = response.public_key.ok_or_else(|| {
                ServerError::generic("KMS GetPublicKey returned no public key".to_owned())
            })?;
            to_public_key_pem(der.as_ref())
        }
    };
    let encryption_algorithm = match config.encryption_algorithm {
        Some(KmsRsaEncryptionAlgorithm::OaepSha1) => EncryptionAlgorithmSpec::RsaesOaepSha1,
        Some(KmsRsaEncryptionAlgorithm::OaepSha256) | None => {
            EncryptionAlgorithmSpec::RsaesOaepSha256
        }
    };
    let keyring = AwsKmsRsaKeyring::builder()
        .kms_key_id(config.kms_key_id.as_str())
        .public_key(public_key)
        .encryption_algorithm(encryption_algorithm)
        .kms_client(kms_client)
        .set_grant_tokens(config.grant_tokens.clone())
        .build()
        .map_err(|e| ServerError::client(e.to_string()))?;
    Ok(SharedKeyring::new(keyring))
}

/// A PEM `PUBLIC KEY` block of a DER X.509 `SubjectPublicKeyInfo`; PEM input passes through.
fn to_public_key_pem(key: &[u8]) -> Vec<u8> {
    if key.starts_with(b"-----BEGIN") {
        return key.to_vec();
    }
    let encoded = STANDARD.encode(key);
    let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
    for line in encoded.as_bytes().chunks(64) {
        pem.push_str(&String::from_utf8_lossy(line));
        pem.push('\n');
    }
    pem.push_str("-----END PUBLIC KEY-----\n");
    pem.into_bytes()
}

/// A discovery keyring with a KMS client in the ambient region.
async fn build_aws_kms_discovery(
    config: &AwsKmsDiscoveryKeyringConfig,
) -> Result<SharedKeyring, ServerError> {
    let discovery_filter = discovery_filter(config.discovery_filter.as_ref())?;
    let sdk_config = sdk_config_for("").await;
    let keyring = AwsKmsDiscoveryKeyring::builder()
        .kms_client(aws_sdk_kms::Client::new(&sdk_config))
        .set_discovery_filter(discovery_filter)
        .set_grant_tokens(config.grant_tokens.clone())
        .build()
        .map_err(|e| ServerError::client(e.to_string()))?;
    Ok(SharedKeyring::new(keyring))
}

/// The MPL discovery filter a modeled one names.
fn discovery_filter(
    filter: Option<&ModelDiscoveryFilter>,
) -> Result<Option<DiscoveryFilter>, ServerError> {
    filter
        .map(|filter| {
            DiscoveryFilter::builder()
                .partition(filter.partition.as_str())
                .set_account_ids(Some(filter.account_ids.clone()))
                .build()
        })
        .transpose()
        .map_err(|e| ServerError::client(e.to_string()))
}

/// An MRK keyring with a KMS client in its key's region.
async fn build_aws_kms_mrk(config: &AwsKmsKeyringConfig) -> Result<SharedKeyring, ServerError> {
    let sdk_config = sdk_config_for(&config.kms_key_id).await;
    let keyring = AwsKmsMrkKeyring::builder()
        .kms_key_id(config.kms_key_id.as_str())
        .kms_client(aws_sdk_kms::Client::new(&sdk_config))
        .set_grant_tokens(config.grant_tokens.clone())
        .build()
        .map_err(|e| ServerError::client(e.to_string()))?;
    Ok(SharedKeyring::new(keyring))
}

/// An MRK discovery keyring with a KMS client in the configured region.
async fn build_aws_kms_mrk_discovery(
    config: &AwsKmsMrkDiscoveryKeyringConfig,
) -> Result<SharedKeyring, ServerError> {
    let discovery_filter = discovery_filter(config.discovery_filter.as_ref())?;
    let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(config.region.clone()))
        .load()
        .await;
    let keyring = AwsKmsMrkDiscoveryKeyring::builder()
        .kms_client(aws_sdk_kms::Client::new(&sdk_config))
        .region(config.region.as_str())
        .set_discovery_filter(discovery_filter)
        .set_grant_tokens(config.grant_tokens.clone())
        .build()
        .map_err(|e| ServerError::client(e.to_string()))?;
    Ok(SharedKeyring::new(keyring))
}

/// A multi-keyring of MRK keyrings, each with a KMS client in its key's region.
async fn build_aws_kms_mrk_multi(
    config: &AwsKmsMultiKeyringConfig,
) -> Result<SharedKeyring, ServerError> {
    let keyring = MultiKeyring::aws_kms_mrk()
        .set_generator(config.generator.clone())
        .set_kms_key_ids(config.kms_key_ids.clone())
        .set_grant_tokens(config.grant_tokens.clone())
        .sdk_config(sdk_config_for("").await)
        .build()
        .await
        .map_err(|e| ServerError::client(e.to_string()))?;
    Ok(SharedKeyring::new(keyring))
}

/// A multi-keyring of AWS KMS keyrings, each with a KMS client in its key's region.
async fn build_aws_kms_multi(
    config: &AwsKmsMultiKeyringConfig,
) -> Result<SharedKeyring, ServerError> {
    let keyring = MultiKeyring::aws_kms()
        .set_generator(config.generator.clone())
        .set_kms_key_ids(config.kms_key_ids.clone())
        .set_grant_tokens(config.grant_tokens.clone())
        .sdk_config(sdk_config_for("").await)
        .build()
        .await
        .map_err(|e| ServerError::client(e.to_string()))?;
    Ok(SharedKeyring::new(keyring))
}

/// A multi-keyring of the modeled generator and child keyrings.
async fn build_multi(config: &MultiKeyringConfig) -> Result<SharedKeyring, ServerError> {
    let generator = match &config.generator {
        Some(generator) => Some(Box::pin(keyring_for_config(generator)).await?),
        None => None,
    };
    let mut child_keyrings = Vec::with_capacity(config.child_keyrings.len());
    for child in &config.child_keyrings {
        child_keyrings.push(Box::pin(keyring_for_config(child)).await?);
    }
    let keyring = MultiKeyring::builder()
        .set_generator(generator)
        .set_child_keyrings(Some(child_keyrings))
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

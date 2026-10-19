//! Translate the modeled CMM/Keyring configuration into an `aws-esdk`
//! [`SharedKeyring`](aws_esdk::keyring::SharedKeyring).
//!
//! Both keyrings are built from the MPL ([`aws_crypto_mpl`]):
//! - Raw AES via [`RawAesKeyring`].
//! - AWS KMS Hierarchical via [`HierarchicalKeyring`] over the key store [`KeyStoreClient::builder`](aws_crypto_mpl::key_store::Client::builder) builds.
//!
//! Enforces the "exactly one variant member set" invariant that the Smithy
//! tagged-union-via-optional-members shapes cannot express in the type system.

use std::time::Duration;

use crate::error::ServerError;
use crate::model::{
    AwsKmsHierarchicalKeyringConfig, CryptographicMaterialsManager, Keyring, RawAesKeyringConfig,
};
use aws_crypto_mpl::key_store::types::KmsConfiguration;
use aws_crypto_mpl::key_store::Client as KeyStoreClient;
use aws_crypto_mpl::keyring::{HierarchicalKeyring, RawAesKeyring};
use aws_esdk::keyring::SharedKeyring;

/// Resolve a CMM configuration to the keyring the ESDK client will use.
///
/// A `Default` CMM resolves to its inner keyring (the ESDK wraps a keyring in a
/// default CMM).
pub async fn keyring_for_cmm(
    cmm: &CryptographicMaterialsManager,
) -> Result<SharedKeyring, ServerError> {
    let set = [
        cmm.default_cmm.is_some(),
        cmm.required_encryption_context.is_some(),
        cmm.caching.is_some(),
    ]
    .iter()
    .filter(|present| **present)
    .count();
    if set != 1 {
        return Err(ServerError::generic(format!(
            "CryptographicMaterialsManager must set exactly one variant, found {set}"
        )));
    }

    if let Some(default_cmm) = &cmm.default_cmm {
        return keyring_for_config(&default_cmm.keyring).await;
    }
    Err(ServerError::generic(
        "only the Default CMM is wired in the Rust language server",
    ))
}

/// Build an `aws-esdk` [`SharedKeyring`](aws_esdk::keyring::SharedKeyring) from a modeled `Keyring`.
pub async fn keyring_for_config(keyring: &Keyring) -> Result<SharedKeyring, ServerError> {
    let set = [
        keyring.aws_kms.is_some(),
        keyring.aws_kms_mrk.is_some(),
        keyring.aws_kms_multi.is_some(),
        keyring.aws_kms_discovery.is_some(),
        keyring.aws_kms_rsa.is_some(),
        keyring.raw_aes.is_some(),
        keyring.raw_rsa.is_some(),
        keyring.aws_kms_hierarchical.is_some(),
        keyring.multi.is_some(),
    ]
    .iter()
    .filter(|present| **present)
    .count();
    if set != 1 {
        return Err(ServerError::generic(format!(
            "Keyring must set exactly one variant, found {set}"
        )));
    }

    if let Some(raw_aes) = &keyring.raw_aes {
        return build_raw_aes(raw_aes).await;
    }
    if let Some(hierarchical) = &keyring.aws_kms_hierarchical {
        return build_hierarchical(hierarchical).await;
    }
    Err(ServerError::generic(
        "only RawAes and AwsKmsHierarchical keyrings are wired in the Rust language server",
    ))
}

async fn build_raw_aes(config: &RawAesKeyringConfig) -> Result<SharedKeyring, ServerError> {
    let wrapping_alg = match config.wrapping_alg {
        crate::model::AesWrappingAlg::Alg128 => {
            aws_crypto_mpl::types::AesWrappingAlg::AlgAes128GcmIv12Tag16
        }
        crate::model::AesWrappingAlg::Alg192 => {
            aws_crypto_mpl::types::AesWrappingAlg::AlgAes192GcmIv12Tag16
        }
        crate::model::AesWrappingAlg::Alg256 => {
            aws_crypto_mpl::types::AesWrappingAlg::AlgAes256GcmIv12Tag16
        }
    };
    let keyring = RawAesKeyring::builder()
        .key_namespace(config.key_namespace.clone())
        .key_name(config.key_name.clone())
        .wrapping_key(config.wrapping_key.clone())
        .wrapping_alg(wrapping_alg)
        .build()
        .map_err(|e| ServerError::esdk(e.to_string()))?;
    Ok(SharedKeyring::new(keyring))
}

/// Build a hierarchical keyring over an MPL branch key store.
///
/// No KMS or DynamoDB client is supplied, so the key store builds its own from
/// the ambient AWS configuration, with the region taken from the KMS key ARN
/// (not `AWS_REGION`); branch-key retrieval reaches KMS and DynamoDB when the
/// client encrypts or decrypts.
async fn build_hierarchical(
    config: &AwsKmsHierarchicalKeyringConfig,
) -> Result<SharedKeyring, ServerError> {
    let key_store = KeyStoreClient::builder()
        .ddb_table_name(config.key_store_table_name.clone())
        .logical_key_store_name(config.logical_key_store_name.clone())
        .kms_configuration(KmsConfiguration::KmsKeyArn(config.kms_key_arn.clone()))
        .build()
        .await
        .map_err(|e| ServerError::esdk(e.to_string()))?;
    let ttl_seconds = u64::try_from(config.ttl_seconds).map_err(|_| {
        ServerError::generic(format!(
            "ttlSeconds must be non-negative, got {}",
            config.ttl_seconds
        ))
    })?;
    let keyring = HierarchicalKeyring::builder()
        .key_store(key_store)
        .ttl(Duration::from_secs(ttl_seconds))
        .branch_key_id(config.branch_key_id.clone())
        .build()
        .await
        .map_err(|e| ServerError::esdk(e.to_string()))?;
    Ok(SharedKeyring::new(keyring))
}

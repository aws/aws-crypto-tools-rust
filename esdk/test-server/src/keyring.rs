//! Translate the modeled CMM/Keyring configuration into an `aws-esdk`
//! [`Keyring`](aws_esdk::Keyring).
//!
//! Both keyrings resolve through the Dafny MPL reached via [`aws_esdk::mpl`],
//! yielding a [`Keyring::Legacy`](aws_esdk::Keyring::Legacy):
//! - Raw AES via `create_raw_aes_keyring`.
//! - AWS KMS Hierarchical via `create_aws_kms_hierarchical_keyring` over the
//!   Dafny MPL key store client.
//!
//! Enforces the "exactly one variant member set" invariant that the Smithy
//! tagged-union-via-optional-members shapes cannot express in the type system.

use crate::error::ServerError;
use crate::model::{
    AwsKmsHierarchicalKeyringConfig, CryptographicMaterialsManager, Keyring, RawAesKeyringConfig,
};
use aws_esdk::Keyring as EsdkKeyring;
use aws_mpl_legacy::dafny::deps::aws_cryptography_keyStore::client::Client as KeyStoreClient;
use aws_mpl_legacy::dafny::deps::aws_cryptography_keyStore::types::{
    KeyStoreConfig, KmsConfiguration,
};
use aws_mpl_legacy::dafny::types::AesWrappingAlg as MplAesWrappingAlg;

/// Resolve a CMM configuration to the keyring the ESDK client will use.
/// Failure here is a CreateClient-time configuration rejection.
pub async fn keyring_for_cmm(
    cmm: &CryptographicMaterialsManager,
) -> Result<EsdkKeyring, ServerError> {
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

/// Build an `aws-esdk` [`Keyring`](aws_esdk::Keyring) from a modeled `Keyring`.
pub async fn keyring_for_config(keyring: &Keyring) -> Result<EsdkKeyring, ServerError> {
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

async fn build_raw_aes(config: &RawAesKeyringConfig) -> Result<EsdkKeyring, ServerError> {
    let wrapping_alg = match config.wrapping_alg {
        crate::model::AesWrappingAlg::Alg128 => MplAesWrappingAlg::AlgAes128GcmIv12Tag16,
        crate::model::AesWrappingAlg::Alg192 => MplAesWrappingAlg::AlgAes192GcmIv12Tag16,
        crate::model::AesWrappingAlg::Alg256 => MplAesWrappingAlg::AlgAes256GcmIv12Tag16,
    };
    let keyring = aws_esdk::mpl()
        .create_raw_aes_keyring()
        .key_namespace(config.key_namespace.clone())
        .key_name(config.key_name.clone())
        .wrapping_key(aws_smithy_types::Blob::new(config.wrapping_key.clone()))
        .wrapping_alg(wrapping_alg)
        .send()
        .await
        .map_err(|e| ServerError::generic(e.to_string()))?;
    Ok(EsdkKeyring::Legacy(keyring))
}

/// Build a hierarchical keyring via the legacy (Dafny) MPL key store client.
///
/// The key store's DynamoDB and KMS clients are resolved from the ambient AWS
/// configuration (region via `AWS_REGION`); branch-key retrieval reaches KMS and
/// DynamoDB when the client encrypts or decrypts.
async fn build_hierarchical(
    config: &AwsKmsHierarchicalKeyringConfig,
) -> Result<EsdkKeyring, ServerError> {
    let key_store_config = KeyStoreConfig::builder()
        .ddb_table_name(config.key_store_table_name.clone())
        .logical_key_store_name(config.logical_key_store_name.clone())
        .kms_configuration(KmsConfiguration::KmsKeyArn(config.kms_key_arn.clone()))
        .build()
        .map_err(|e| ServerError::generic(e.to_string()))?;
    let key_store = KeyStoreClient::from_conf(key_store_config)
        .map_err(|e| ServerError::generic(e.to_string()))?;
    let keyring = aws_esdk::mpl()
        .create_aws_kms_hierarchical_keyring()
        .branch_key_id(config.branch_key_id.clone())
        .key_store(key_store)
        .ttl_seconds(config.ttl_seconds)
        .send()
        .await
        .map_err(|e| ServerError::generic(e.to_string()))?;
    Ok(EsdkKeyring::Legacy(keyring))
}

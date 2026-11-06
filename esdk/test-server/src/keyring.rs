// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Translate the modeled `CryptographicMaterialsManager` and `Keyring` into MPL
//! ([`aws_crypto_mpl`]) CMMs and keyrings.
//!
//! The CMMs are the [`DefaultCmm`] and the [`CachingCmm`]. The keyrings are:
//! - Raw AES via [`RawAesKeyring`].
//! - AWS KMS Hierarchical via [`HierarchicalKeyring`] over the key store [`DynamoDbKeyStore::builder`](aws_crypto_mpl::key_store::DynamoDbKeyStore::builder) builds.
//!
//! Enforces the "exactly one variant member set" invariant that the Smithy
//! tagged-union-via-optional-members shapes cannot express in the type system.
//! Errors here are `GenericServerError`: the commons suite treats them as
//! CreateClient rejections.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use crate::error::ServerError;
use crate::model::{
    AwsKmsHierarchicalKeyringConfig, CachingCmmConfig, CryptographicMaterialsManager, Keyring,
    RawAesKeyringConfig,
};
use aws_crypto_mpl::cmc::{DefaultCmc, SharedCmc};
use aws_crypto_mpl::cmm::{CachingCmm, DefaultCmm, SharedCmm};
use aws_crypto_mpl::key_store::types::KmsConfiguration;
use aws_crypto_mpl::key_store::DynamoDbKeyStore;
use aws_crypto_mpl::keyring::{HierarchicalKeyring, RawAesKeyring};
use aws_esdk::keyring::SharedKeyring;

/// How many entries each Caching CMM's materials cache holds.
const CACHE_ENTRY_CAPACITY: usize = 100;

/// The materials caches that Caching CMM configs name by `sharedCacheName`.
///
/// Clients whose configs name the same cache share it, so they reuse each other's cached materials.
#[derive(Default)]
pub struct SharedCaches(Mutex<HashMap<String, SharedCmc>>);

impl SharedCaches {
    /// The cache named `name`, created on first use.
    fn get_or_create(&self, name: &str) -> Result<SharedCmc, ServerError> {
        let mut caches = self.0.lock().expect("shared cache mutex");
        if let Some(cache) = caches.get(name) {
            return Ok(cache.clone());
        }
        let cache = new_cache()?;
        caches.insert(name.to_owned(), cache.clone());
        Ok(cache)
    }
}

fn new_cache() -> Result<SharedCmc, ServerError> {
    let cache = DefaultCmc::builder()
        .entry_capacity(CACHE_ENTRY_CAPACITY)
        .build()
        .map_err(generic)?;
    Ok(SharedCmc::new(cache))
}

fn generic(e: impl std::fmt::Display) -> ServerError {
    ServerError::generic(e.to_string())
}

/// Build the CMM a modeled `CryptographicMaterialsManager` names; exactly one variant must be set.
pub async fn cmm_for_config(
    cmm: &CryptographicMaterialsManager,
    caches: &SharedCaches,
) -> Result<SharedCmm, ServerError> {
    let set = usize::from(cmm.default_cmm.is_some())
        + usize::from(cmm.required_encryption_context.is_some())
        + usize::from(cmm.caching.is_some());
    if set != 1 {
        return Err(ServerError::generic(format!(
            "CryptographicMaterialsManager must set exactly one variant, found {set}"
        )));
    }
    if let Some(default_cmm) = &cmm.default_cmm {
        let keyring = keyring_for_config(&default_cmm.keyring).await?;
        return Ok(SharedCmm::new(DefaultCmm::new(keyring)));
    }
    if let Some(caching) = &cmm.caching {
        return build_caching(caching, caches).await;
    }
    Err(ServerError::generic(
        "only the Default and Caching CMMs are wired in the Rust language server",
    ))
}

/// A Caching CMM over the modeled underlying CMM.
///
/// With a `sharedCacheName`, the cache is the server-wide one of that name;
/// otherwise the CMM gets a cache of its own.
async fn build_caching(
    config: &CachingCmmConfig,
    caches: &SharedCaches,
) -> Result<SharedCmm, ServerError> {
    let underlying = Box::pin(cmm_for_config(&config.underlying_cmm, caches)).await?;
    let cache = match &config.shared_cache_name {
        Some(name) => caches.get_or_create(name)?,
        None => new_cache()?,
    };
    let ttl_seconds = non_negative(
        "cacheLimitTtlSeconds",
        config.cache_limit_ttl_seconds.into(),
    )?;
    let limit_bytes = config
        .limit_bytes
        .map(|v| non_negative("limitBytes", v))
        .transpose()?;
    let limit_messages = config
        .limit_messages
        .map(|v| non_negative("limitMessages", v))
        .transpose()?;
    let cmm = CachingCmm::builder()
        .underlying_cmm(underlying)
        .cache(cache)
        .cache_limit_ttl(Duration::from_secs(ttl_seconds))
        .set_partition_id(config.partition_id.clone())
        .set_limit_bytes(limit_bytes)
        .set_limit_messages(limit_messages)
        .build()
        .map_err(generic)?;
    Ok(SharedCmm::new(cmm))
}

fn non_negative(name: &str, value: i64) -> Result<u64, ServerError> {
    u64::try_from(value)
        .map_err(|_| ServerError::generic(format!("{name} must be non-negative, got {value}")))
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
        .map_err(|e| ServerError::generic(e.to_string()))?;
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
    let key_store = DynamoDbKeyStore::builder()
        .ddb_table_name(config.key_store_table_name.clone())
        .logical_key_store_name(config.logical_key_store_name.clone())
        .kms_configuration(KmsConfiguration::kms_key_arn(config.kms_key_arn.clone()))
        .build()
        .await
        .map_err(|e| ServerError::generic(e.to_string()))?;
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
        .map_err(|e| ServerError::generic(e.to_string()))?;
    Ok(SharedKeyring::new(keyring))
}

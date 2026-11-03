// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Translate the modeled `CryptographicMaterialsManager` and `Keyring` into MPL
//! ([`aws_crypto_mpl`]) CMMs and keyrings.
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
    AesWrappingAlg, AwsKmsDiscoveryKeyringConfig, AwsKmsEcdhKeyringConfig,
    AwsKmsHierarchicalKeyringConfig, AwsKmsKeyringConfig, AwsKmsMrkDiscoveryKeyringConfig,
    AwsKmsMrkKeyringConfig, AwsKmsMrkMultiKeyringConfig, AwsKmsMultiKeyringConfig,
    AwsKmsRsaKeyringConfig, CachingCmmConfig, CryptographicMaterialsManager,
    DiscoveryFilter as ModelDiscoveryFilter, EcdhCurveSpec, Keyring, KmsRsaEncryptionAlgorithm,
    MultiKeyringConfig, PaddingScheme, RawAesKeyringConfig, RawEcdhKeyringConfig,
    RawRsaKeyringConfig,
};
use aws_crypto_mpl::aws_sdk_kms::types::EncryptionAlgorithmSpec;
use aws_crypto_mpl::cmc::{DefaultCmc, SharedCmc};
use aws_crypto_mpl::cmm::{CachingCmm, DefaultCmm, RequiredEncryptionContextCmm, SharedCmm};
use aws_crypto_mpl::key_store::types::KmsConfiguration;
use aws_crypto_mpl::key_store::DynamoDbKeyStore;
use aws_crypto_mpl::keyring::{
    AwsKmsDiscoveryKeyring, AwsKmsEcdhKeyring, AwsKmsKeyring, AwsKmsMrkDiscoveryKeyring,
    AwsKmsMrkKeyring, AwsKmsRsaKeyring, DiscoveryFilter, EphemeralPrivateKeyToStaticPublicKeyInput,
    HierarchicalKeyring, KmsEcdhStaticConfigurations, KmsPrivateKeyToStaticPublicKeyInput,
    KmsPublicKeyDiscoveryInput, MultiKeyring, PublicKeyDiscoveryInput, RawAesKeyring,
    RawEcdhKeyring, RawEcdhStaticConfigurations, RawPrivateKeyToStaticPublicKeyInput,
    RawRsaKeyring, SharedKeyring,
};
use aws_crypto_mpl::types::{
    AesWrappingAlg as MplAesWrappingAlg, EcdhCurveSpec as MplEcdhCurveSpec,
    PaddingScheme as MplPaddingScheme,
};
use aws_crypto_mpl::{aws_config, aws_sdk_kms};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

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
    if let Some(required) = &cmm.required_encryption_context {
        let underlying = Box::pin(cmm_for_config(&required.underlying_cmm, caches)).await?;
        let cmm = RequiredEncryptionContextCmm::builder()
            .underlying_cmm(underlying)
            .set_required_encryption_context_keys(Some(
                required.required_encryption_context_keys.clone(),
            ))
            .build()
            .map_err(generic)?;
        return Ok(SharedCmm::new(cmm));
    }
    let Some(caching) = &cmm.caching else {
        unreachable!("exactly one variant is set");
    };
    build_caching(caching, caches).await
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

/// Build the keyring a modeled `Keyring` names; exactly one variant must be set.
pub async fn keyring_for_config(keyring: &Keyring) -> Result<SharedKeyring, ServerError> {
    let set = usize::from(keyring.aws_kms.is_some())
        + usize::from(keyring.aws_kms_mrk.is_some())
        + usize::from(keyring.aws_kms_multi.is_some())
        + usize::from(keyring.aws_kms_mrk_multi.is_some())
        + usize::from(keyring.aws_kms_discovery.is_some())
        + usize::from(keyring.aws_kms_mrk_discovery.is_some())
        + usize::from(keyring.aws_kms_rsa.is_some())
        + usize::from(keyring.aws_kms_ecdh.is_some())
        + usize::from(keyring.raw_aes.is_some())
        + usize::from(keyring.raw_rsa.is_some())
        + usize::from(keyring.raw_ecdh.is_some())
        + usize::from(keyring.aws_kms_hierarchical.is_some())
        + usize::from(keyring.multi.is_some());
    if set != 1 {
        return Err(ServerError::generic(format!(
            "Keyring must set exactly one variant, found {set}"
        )));
    }
    if let Some(config) = &keyring.aws_kms {
        return build_aws_kms(config).await;
    }
    if let Some(config) = &keyring.aws_kms_mrk {
        return build_aws_kms_mrk(config).await;
    }
    if let Some(config) = &keyring.aws_kms_multi {
        return build_aws_kms_multi(config).await;
    }
    if let Some(config) = &keyring.aws_kms_mrk_multi {
        return build_aws_kms_mrk_multi(config).await;
    }
    if let Some(config) = &keyring.aws_kms_discovery {
        return build_aws_kms_discovery(config).await;
    }
    if let Some(config) = &keyring.aws_kms_mrk_discovery {
        return build_aws_kms_mrk_discovery(config).await;
    }
    if let Some(config) = &keyring.aws_kms_rsa {
        return build_aws_kms_rsa(config).await;
    }
    if let Some(config) = &keyring.aws_kms_ecdh {
        return build_aws_kms_ecdh(config).await;
    }
    if let Some(config) = &keyring.raw_aes {
        return build_raw_aes(config);
    }
    if let Some(config) = &keyring.raw_rsa {
        return build_raw_rsa(config);
    }
    if let Some(config) = &keyring.raw_ecdh {
        return build_raw_ecdh(config);
    }
    if let Some(config) = &keyring.aws_kms_hierarchical {
        return build_hierarchical(config).await;
    }
    let Some(config) = &keyring.multi else {
        unreachable!("exactly one variant is set");
    };
    build_multi(config).await
}

fn build_raw_aes(config: &RawAesKeyringConfig) -> Result<SharedKeyring, ServerError> {
    let wrapping_alg = match config.wrapping_alg {
        AesWrappingAlg::Alg128 => MplAesWrappingAlg::AlgAes128GcmIv12Tag16,
        AesWrappingAlg::Alg192 => MplAesWrappingAlg::AlgAes192GcmIv12Tag16,
        AesWrappingAlg::Alg256 => MplAesWrappingAlg::AlgAes256GcmIv12Tag16,
    };
    let keyring = RawAesKeyring::builder()
        .key_namespace(config.key_namespace.clone())
        .key_name(config.key_name.clone())
        .wrapping_key(config.wrapping_key.clone())
        .wrapping_alg(wrapping_alg)
        .build()
        .map_err(generic)?;
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
        .key_namespace(config.key_namespace.clone())
        .key_name(config.key_name.clone())
        .padding_scheme(padding_scheme)
        .set_public_key(config.public_key.clone())
        .set_private_key(config.private_key.clone())
        .build()
        .map_err(generic)?;
    Ok(SharedKeyring::new(keyring))
}

/// The MPL curve a modeled curve names. The native MPL has no SM2.
fn curve(curve_spec: EcdhCurveSpec) -> Result<MplEcdhCurveSpec, ServerError> {
    match curve_spec {
        EcdhCurveSpec::EccNistP256 => Ok(MplEcdhCurveSpec::EccNistP256),
        EcdhCurveSpec::EccNistP384 => Ok(MplEcdhCurveSpec::EccNistP384),
        EcdhCurveSpec::EccNistP521 => Ok(MplEcdhCurveSpec::EccNistP521),
        EcdhCurveSpec::Sm2 => Err(ServerError::generic(
            "the SM2 curve is not supported by the native Rust MPL",
        )),
    }
}

fn build_raw_ecdh(config: &RawEcdhKeyringConfig) -> Result<SharedKeyring, ServerError> {
    let scheme = &config.key_agreement_scheme;
    let set = usize::from(scheme.raw_private_key_to_static_public_key.is_some())
        + usize::from(scheme.ephemeral_private_key_to_static_public_key.is_some())
        + usize::from(scheme.public_key_discovery.is_some());
    if set != 1 {
        return Err(ServerError::generic(format!(
            "RawEcdhKeyAgreementScheme must set exactly one variant, found {set}"
        )));
    }
    let scheme = if let Some(s) = &scheme.raw_private_key_to_static_public_key {
        RawEcdhStaticConfigurations::RawPrivateKeyToStaticPublicKey(
            RawPrivateKeyToStaticPublicKeyInput::builder()
                .sender_static_private_key(s.sender_static_private_key.clone())
                .recipient_public_key(s.recipient_public_key.clone())
                .build()
                .map_err(generic)?,
        )
    } else if let Some(s) = &scheme.ephemeral_private_key_to_static_public_key {
        RawEcdhStaticConfigurations::EphemeralPrivateKeyToStaticPublicKey(
            EphemeralPrivateKeyToStaticPublicKeyInput::builder()
                .recipient_public_key(s.recipient_public_key.clone())
                .build()
                .map_err(generic)?,
        )
    } else {
        let Some(s) = &scheme.public_key_discovery else {
            unreachable!("exactly one variant is set");
        };
        RawEcdhStaticConfigurations::PublicKeyDiscovery(
            PublicKeyDiscoveryInput::builder()
                .recipient_static_private_key(s.recipient_static_private_key.clone())
                .build()
                .map_err(generic)?,
        )
    };
    let keyring = RawEcdhKeyring::builder()
        .key_agreement_scheme(scheme)
        .curve_spec(curve(config.curve_spec)?)
        .build()
        .map_err(generic)?;
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

async fn kms_client_for(key_id: &str) -> aws_sdk_kms::Client {
    aws_sdk_kms::Client::new(&sdk_config_for(key_id).await)
}

async fn build_aws_kms(config: &AwsKmsKeyringConfig) -> Result<SharedKeyring, ServerError> {
    let keyring = AwsKmsKeyring::builder()
        .kms_key_id(config.kms_key_id.clone())
        .kms_client(kms_client_for(&config.kms_key_id).await)
        .set_grant_tokens(config.grant_tokens.clone())
        .build()
        .map_err(generic)?;
    Ok(SharedKeyring::new(keyring))
}

async fn build_aws_kms_mrk(config: &AwsKmsMrkKeyringConfig) -> Result<SharedKeyring, ServerError> {
    let keyring = AwsKmsMrkKeyring::builder()
        .kms_key_id(config.kms_key_id.clone())
        .kms_client(kms_client_for(&config.kms_key_id).await)
        .set_grant_tokens(config.grant_tokens.clone())
        .build()
        .map_err(generic)?;
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
        .map_err(generic)?;
    Ok(SharedKeyring::new(keyring))
}

/// A multi-keyring of MRK keyrings, each with a KMS client in its key's region.
async fn build_aws_kms_mrk_multi(
    config: &AwsKmsMrkMultiKeyringConfig,
) -> Result<SharedKeyring, ServerError> {
    let keyring = MultiKeyring::aws_kms_mrk()
        .set_generator(config.generator.clone())
        .set_kms_key_ids(config.kms_key_ids.clone())
        .set_grant_tokens(config.grant_tokens.clone())
        .sdk_config(sdk_config_for("").await)
        .build()
        .await
        .map_err(generic)?;
    Ok(SharedKeyring::new(keyring))
}

/// The MPL discovery filter a modeled one names.
fn discovery_filter(
    filter: Option<&ModelDiscoveryFilter>,
) -> Result<Option<DiscoveryFilter>, ServerError> {
    filter
        .map(|filter| {
            DiscoveryFilter::builder()
                .partition(filter.partition.clone())
                .set_account_ids(Some(filter.account_ids.clone()))
                .build()
        })
        .transpose()
        .map_err(generic)
}

/// A discovery keyring with a KMS client in the ambient region.
async fn build_aws_kms_discovery(
    config: &AwsKmsDiscoveryKeyringConfig,
) -> Result<SharedKeyring, ServerError> {
    let keyring = AwsKmsDiscoveryKeyring::builder()
        .kms_client(kms_client_for("").await)
        .set_discovery_filter(discovery_filter(config.discovery_filter.as_ref())?)
        .set_grant_tokens(config.grant_tokens.clone())
        .build()
        .map_err(generic)?;
    Ok(SharedKeyring::new(keyring))
}

/// An MRK discovery keyring with a KMS client in the configured region.
async fn build_aws_kms_mrk_discovery(
    config: &AwsKmsMrkDiscoveryKeyringConfig,
) -> Result<SharedKeyring, ServerError> {
    let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(config.region.clone()))
        .load()
        .await;
    let keyring = AwsKmsMrkDiscoveryKeyring::builder()
        .kms_client(aws_sdk_kms::Client::new(&sdk_config))
        .region(config.region.clone())
        .set_discovery_filter(discovery_filter(config.discovery_filter.as_ref())?)
        .set_grant_tokens(config.grant_tokens.clone())
        .build()
        .map_err(generic)?;
    Ok(SharedKeyring::new(keyring))
}

/// An AWS KMS RSA keyring with a KMS client in its key's region.
///
/// Without a configured public key, this fetches the key's public key once with KMS `GetPublicKey`.
/// The keyring takes the key PEM-encoded; a DER key is PEM-encoded first.
/// The encryption algorithm defaults to RSAES-OAEP-SHA-256.
async fn build_aws_kms_rsa(config: &AwsKmsRsaKeyringConfig) -> Result<SharedKeyring, ServerError> {
    let kms_client = kms_client_for(&config.kms_key_id).await;
    let public_key = match &config.public_key {
        Some(key) => to_public_key_pem(key),
        None => {
            let response = kms_client
                .get_public_key()
                .key_id(config.kms_key_id.clone())
                .send()
                .await
                .map_err(|e| {
                    ServerError::generic(format!(
                        "KMS GetPublicKey failed: {}",
                        aws_sdk_kms::error::DisplayErrorContext(&e)
                    ))
                })?;
            let der = response
                .public_key
                .ok_or_else(|| ServerError::generic("KMS GetPublicKey returned no public key"))?;
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
        .kms_key_id(config.kms_key_id.clone())
        .public_key(public_key)
        .encryption_algorithm(encryption_algorithm)
        .kms_client(kms_client)
        .set_grant_tokens(config.grant_tokens.clone())
        .build()
        .map_err(generic)?;
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

/// An AWS KMS ECDH keyring with a KMS client in the region of its KMS key.
async fn build_aws_kms_ecdh(
    config: &AwsKmsEcdhKeyringConfig,
) -> Result<SharedKeyring, ServerError> {
    let scheme = &config.key_agreement_scheme;
    let set = usize::from(scheme.kms_private_key_to_static_public_key.is_some())
        + usize::from(scheme.kms_public_key_discovery.is_some());
    if set != 1 {
        return Err(ServerError::generic(format!(
            "KmsEcdhKeyAgreementScheme must set exactly one variant, found {set}"
        )));
    }
    let (key_id, scheme) = if let Some(s) = &scheme.kms_private_key_to_static_public_key {
        let input = KmsPrivateKeyToStaticPublicKeyInput::builder()
            .sender_kms_identifier(s.sender_kms_identifier.clone())
            .set_sender_public_key(s.sender_public_key.clone())
            .recipient_public_key(s.recipient_public_key.clone())
            .build()
            .map_err(generic)?;
        (
            &s.sender_kms_identifier,
            KmsEcdhStaticConfigurations::KmsPrivateKeyToStaticPublicKey(input),
        )
    } else {
        let Some(s) = &scheme.kms_public_key_discovery else {
            unreachable!("exactly one variant is set");
        };
        let input = KmsPublicKeyDiscoveryInput::builder()
            .recipient_kms_identifier(s.recipient_kms_identifier.clone())
            .build()
            .map_err(generic)?;
        (
            &s.recipient_kms_identifier,
            KmsEcdhStaticConfigurations::KmsPublicKeyDiscovery(input),
        )
    };
    let keyring = AwsKmsEcdhKeyring::builder()
        .key_agreement_scheme(scheme)
        .curve_spec(curve(config.curve_spec)?)
        .kms_client(kms_client_for(key_id).await)
        .set_grant_tokens(config.grant_tokens.clone())
        .build()
        .await
        .map_err(generic)?;
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
        .kms_configuration(KmsConfiguration::KmsKeyArn(config.kms_key_arn.clone()))
        .build()
        .await
        .map_err(generic)?;
    let ttl_seconds = non_negative("ttlSeconds", config.ttl_seconds.into())?;
    let keyring = HierarchicalKeyring::builder()
        .key_store(key_store)
        .ttl(Duration::from_secs(ttl_seconds))
        .branch_key_id(config.branch_key_id.clone())
        .build()
        .await
        .map_err(generic)?;
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
        .map_err(generic)?;
    Ok(SharedKeyring::new(keyring))
}

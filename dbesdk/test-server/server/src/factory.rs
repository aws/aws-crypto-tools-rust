// Translates a wire `DbeClientConfig` into a real DBE `item_encryptor` client,
// building the keyring (or CMM) from the Material Providers Library. Mirrors the
// Java `ItemEncryptorFactory`, including its recursion over the Multi keyring and
// the Default / RequiredEncryptionContext CMMs.
//
// KMS keyrings are handed an `aws_sdk_kms::Client` in the key's region, exactly
// as the Java factory passes `kmsClientForKey(...)`. No KMS call happens at
// construction; the network is touched only on EncryptItem / DecryptItem.
//
// Deferred variants (AwsKmsRsa, AwsKmsHierarchical, Caching CMM) return a
// GenericServerError: the declared Feature_Catalog is [raw-aes, aws-kms] and the
// Java factory itself leaves the Caching CMM unwired. They are not reached by any
// current Test. Every other variant is fully wired.

use crate::error::ServerError;
use crate::model;
use aws_config::SdkConfig;
use aws_db_esdk::item_encryptor::client::Client as ItemEncryptor;
use aws_db_esdk::item_encryptor::types::dynamo_db_item_encryptor_config::DynamoDbItemEncryptorConfig;
use aws_db_esdk::material_providers::client::Client as MplClient;
use aws_db_esdk::material_providers::types::cryptographic_materials_manager::CryptographicMaterialsManagerRef;
use aws_db_esdk::material_providers::types::keyring::KeyringRef;
use aws_db_esdk::material_providers::types::AesWrappingAlg as MplAesWrappingAlg;
use aws_db_esdk::material_providers::types::DbeAlgorithmSuiteId as MplSuiteId;
use aws_db_esdk::material_providers::types::PaddingScheme as MplPaddingScheme;
use aws_db_esdk::CryptoAction as DbeCryptoAction;
use aws_sdk_dynamodb::primitives::Blob;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

/// Build a configured DBE item encryptor from the wire config. A construction
/// failure is a framework failure (GenericServerError) — matching the Java
/// CreateClient handler, which maps any build exception to GenericServerError.
pub async fn build_client(
    mpl: &MplClient,
    sdk_config: &SdkConfig,
    cfg: &model::DbeClientConfig,
) -> Result<ItemEncryptor, ServerError> {
    let mut builder = DynamoDbItemEncryptorConfig::builder()
        .logical_table_name(&cfg.logical_table_name)
        .partition_key_name(&cfg.partition_key_name)
        .attribute_actions_on_encrypt(crypto_actions(&cfg.attribute_actions_on_encrypt));

    if let Some(sort_key) = &cfg.sort_key_name {
        builder = builder.sort_key_name(sort_key);
    }
    if let Some(prefix) = &cfg.allowed_unsigned_attribute_prefix {
        builder = builder.allowed_unsigned_attribute_prefix(prefix);
    }
    if let Some(list) = &cfg.allowed_unsigned_attributes {
        if !list.is_empty() {
            builder = builder.allowed_unsigned_attributes(list.clone());
        }
    }
    if let Some(suite) = cfg.algorithm_suite_id {
        builder = builder.algorithm_suite_id(algorithm_suite(suite));
    }

    match (&cfg.keyring, &cfg.cmm) {
        (Some(keyring), None) => {
            builder = builder.keyring(build_keyring(mpl, sdk_config, keyring).await?);
        }
        (None, Some(cmm)) => {
            builder = builder.cmm(build_cmm(mpl, sdk_config, cmm).await?);
        }
        (Some(_), Some(_)) => {
            return Err(ServerError::Generic(
                "config set both keyring and cmm; exactly one is required".into(),
            ));
        }
        (None, None) => {
            return Err(ServerError::Generic(
                "config set neither keyring nor cmm; exactly one is required".into(),
            ));
        }
    }

    let dbe_config = builder.build().map_err(|e| {
        ServerError::Generic(format!("invalid DynamoDbItemEncryptorConfig: {e}"))
    })?;
    ItemEncryptor::from_conf(dbe_config)
        .map_err(|e| ServerError::Generic(format!("failed to build item encryptor: {e}")))
}

fn crypto_actions(
    modeled: &HashMap<String, model::CryptoAction>,
) -> HashMap<String, DbeCryptoAction> {
    modeled
        .iter()
        .map(|(name, action)| {
            let native = match action {
                model::CryptoAction::EncryptAndSign => DbeCryptoAction::EncryptAndSign,
                model::CryptoAction::SignOnly => DbeCryptoAction::SignOnly,
                model::CryptoAction::DoNothing => DbeCryptoAction::DoNothing,
            };
            (name.clone(), native)
        })
        .collect()
}

fn algorithm_suite(suite: model::DbeAlgorithmSuiteId) -> MplSuiteId {
    match suite {
        model::DbeAlgorithmSuiteId::Symsig => {
            MplSuiteId::AlgAes256GcmHkdfSha512CommitKeySymsigHmacSha384
        }
        model::DbeAlgorithmSuiteId::EcdsaSymsig => {
            MplSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384SymsigHmacSha384
        }
    }
}

fn aes_wrapping_alg(alg: model::AesWrappingAlg) -> MplAesWrappingAlg {
    match alg {
        model::AesWrappingAlg::Aes128 => MplAesWrappingAlg::AlgAes128GcmIv12Tag16,
        model::AesWrappingAlg::Aes192 => MplAesWrappingAlg::AlgAes192GcmIv12Tag16,
        model::AesWrappingAlg::Aes256 => MplAesWrappingAlg::AlgAes256GcmIv12Tag16,
    }
}

fn padding_scheme(scheme: model::PaddingScheme) -> MplPaddingScheme {
    match scheme {
        model::PaddingScheme::Pkcs1 => MplPaddingScheme::Pkcs1,
        model::PaddingScheme::OaepSha1Mgf1 => MplPaddingScheme::OaepSha1Mgf1,
        model::PaddingScheme::OaepSha256Mgf1 => MplPaddingScheme::OaepSha256Mgf1,
        model::PaddingScheme::OaepSha384Mgf1 => MplPaddingScheme::OaepSha384Mgf1,
        model::PaddingScheme::OaepSha512Mgf1 => MplPaddingScheme::OaepSha512Mgf1,
    }
}

/// An AWS KMS client in the key's own region (KMS rejects an ARN whose region
/// differs from the client's). Falls back to the ambient region for a bare key
/// id or alias. Mirrors the Java `kmsClientForKey`.
fn kms_client_for_key(sdk_config: &SdkConfig, key_id: &str) -> aws_sdk_kms::Client {
    let region = region_for_key(key_id);
    match region {
        Some(region) => {
            let conf = aws_sdk_kms::config::Builder::from(sdk_config)
                .region(aws_sdk_kms::config::Region::new(region))
                .build();
            aws_sdk_kms::Client::from_conf(conf)
        }
        None => aws_sdk_kms::Client::new(sdk_config),
    }
}

fn region_for_key(key_id: &str) -> Option<String> {
    if key_id.starts_with("arn:") {
        let parts: Vec<&str> = key_id.split(':').collect();
        if parts.len() > 3 && !parts[3].is_empty() {
            return Some(parts[3].to_string());
        }
    }
    None
}

/// Build a keyring from the wire union. Boxed so the Multi variant can recurse.
fn build_keyring<'a>(
    mpl: &'a MplClient,
    sdk_config: &'a SdkConfig,
    keyring: &'a model::Keyring,
) -> Pin<Box<dyn Future<Output = Result<KeyringRef, ServerError>> + Send + 'a>> {
    Box::pin(async move {
        if let Some(c) = &keyring.raw_aes {
            return mpl
                .create_raw_aes_keyring()
                .key_namespace(&c.key_namespace)
                .key_name(&c.key_name)
                .wrapping_key(Blob::new(c.wrapping_key.to_vec()))
                .wrapping_alg(aes_wrapping_alg(c.wrapping_alg))
                .send()
                .await
                .map_err(construction_error);
        }
        if let Some(c) = &keyring.aws_kms {
            let mut b = mpl
                .create_aws_kms_keyring()
                .kms_key_id(&c.kms_key_id)
                .kms_client(kms_client_for_key(sdk_config, &c.kms_key_id));
            if let Some(tokens) = non_empty(&c.grant_tokens) {
                b = b.grant_tokens(tokens);
            }
            return b.send().await.map_err(construction_error);
        }
        if let Some(c) = &keyring.aws_kms_mrk {
            let mut b = mpl
                .create_aws_kms_mrk_keyring()
                .kms_key_id(&c.kms_key_id)
                .kms_client(kms_client_for_key(sdk_config, &c.kms_key_id));
            if let Some(tokens) = non_empty(&c.grant_tokens) {
                b = b.grant_tokens(tokens);
            }
            return b.send().await.map_err(construction_error);
        }
        if let Some(c) = &keyring.aws_kms_multi {
            let mut b = mpl.create_aws_kms_multi_keyring();
            if let Some(gen) = &c.generator {
                b = b.generator(gen);
            }
            if let Some(ids) = non_empty(&c.kms_key_ids) {
                b = b.kms_key_ids(ids);
            }
            if let Some(tokens) = non_empty(&c.grant_tokens) {
                b = b.grant_tokens(tokens);
            }
            return b.send().await.map_err(construction_error);
        }
        if let Some(c) = &keyring.aws_kms_mrk_multi {
            let mut b = mpl.create_aws_kms_mrk_multi_keyring();
            if let Some(gen) = &c.generator {
                b = b.generator(gen);
            }
            if let Some(ids) = non_empty(&c.kms_key_ids) {
                b = b.kms_key_ids(ids);
            }
            if let Some(tokens) = non_empty(&c.grant_tokens) {
                b = b.grant_tokens(tokens);
            }
            return b.send().await.map_err(construction_error);
        }
        if let Some(c) = &keyring.aws_kms_discovery {
            let mut b = mpl
                .create_aws_kms_discovery_keyring()
                .kms_client(aws_sdk_kms::Client::new(sdk_config));
            if let Some(filter) = &c.discovery_filter {
                b = b.discovery_filter(discovery_filter(filter));
            }
            if let Some(tokens) = non_empty(&c.grant_tokens) {
                b = b.grant_tokens(tokens);
            }
            return b.send().await.map_err(construction_error);
        }
        if let Some(c) = &keyring.aws_kms_mrk_discovery {
            let conf = aws_sdk_kms::config::Builder::from(sdk_config)
                .region(aws_sdk_kms::config::Region::new(c.region.clone()))
                .build();
            let mut b = mpl
                .create_aws_kms_mrk_discovery_keyring()
                .kms_client(aws_sdk_kms::Client::from_conf(conf))
                .region(&c.region);
            if let Some(filter) = &c.discovery_filter {
                b = b.discovery_filter(discovery_filter(filter));
            }
            if let Some(tokens) = non_empty(&c.grant_tokens) {
                b = b.grant_tokens(tokens);
            }
            return b.send().await.map_err(construction_error);
        }
        if let Some(c) = &keyring.raw_rsa {
            let mut b = mpl
                .create_raw_rsa_keyring()
                .key_namespace(&c.key_namespace)
                .key_name(&c.key_name)
                .padding_scheme(padding_scheme(c.padding_scheme));
            if let Some(public_key) = &c.public_key {
                b = b.public_key(Blob::new(public_key.to_vec()));
            }
            if let Some(private_key) = &c.private_key {
                b = b.private_key(Blob::new(private_key.to_vec()));
            }
            return b.send().await.map_err(construction_error);
        }
        if let Some(c) = &keyring.multi {
            let mut b = mpl.create_multi_keyring();
            if let Some(gen) = &c.generator {
                b = b.generator(build_keyring(mpl, sdk_config, gen).await?);
            }
            let mut children = Vec::with_capacity(c.child_keyrings.len());
            for child in &c.child_keyrings {
                children.push(build_keyring(mpl, sdk_config, child).await?);
            }
            return b
                .child_keyrings(children)
                .send()
                .await
                .map_err(construction_error);
        }
        if keyring.aws_kms_rsa.is_some() {
            return Err(ServerError::Generic(
                "AwsKmsRsa keyring is not wired in this pass of the Rust TestServer".into(),
            ));
        }
        if keyring.aws_kms_hierarchical.is_some() {
            return Err(ServerError::Generic(
                "AwsKmsHierarchical keyring is not wired in this pass of the Rust TestServer"
                    .into(),
            ));
        }
        Err(ServerError::Generic(
            "Keyring had no variant member set".into(),
        ))
    })
}

/// Build a CMM from the wire union. Boxed so the wrapping variants can recurse.
fn build_cmm<'a>(
    mpl: &'a MplClient,
    sdk_config: &'a SdkConfig,
    cmm: &'a model::CryptographicMaterialsManager,
) -> Pin<Box<dyn Future<Output = Result<CryptographicMaterialsManagerRef, ServerError>> + Send + 'a>>
{
    Box::pin(async move {
        if let Some(c) = &cmm.default {
            let keyring = build_keyring(mpl, sdk_config, &c.keyring).await?;
            return mpl
                .create_default_cryptographic_materials_manager()
                .keyring(keyring)
                .send()
                .await
                .map_err(construction_error);
        }
        if let Some(c) = &cmm.required_encryption_context {
            let underlying = build_cmm(mpl, sdk_config, &c.underlying_cmm).await?;
            return mpl
                .create_required_encryption_context_cmm()
                .underlying_cmm(underlying)
                .required_encryption_context_keys(c.required_encryption_context_keys.clone())
                .send()
                .await
                .map_err(construction_error);
        }
        if cmm.caching.is_some() {
            return Err(ServerError::Generic(
                "Caching CMM is not wired in this pass of the Rust TestServer".into(),
            ));
        }
        Err(ServerError::Generic(
            "CryptographicMaterialsManager had no variant member set".into(),
        ))
    })
}

fn discovery_filter(
    filter: &model::DiscoveryFilter,
) -> aws_db_esdk::material_providers::types::DiscoveryFilter {
    aws_db_esdk::material_providers::types::DiscoveryFilter::builder()
        .partition(&filter.partition)
        .account_ids(filter.account_ids.clone())
        .build()
        .expect("DiscoveryFilter has all required fields set")
}

fn non_empty(tokens: &Option<Vec<String>>) -> Option<Vec<String>> {
    tokens.as_ref().filter(|t| !t.is_empty()).cloned()
}

fn construction_error<E: std::fmt::Display>(err: E) -> ServerError {
    ServerError::Generic(format!("keyring/CMM construction failed: {err}"))
}

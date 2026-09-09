// Translates a wire `DbeClientConfig` into a real DBE `item_encryptor` client,
// building the keyring (or CMM) from the Material Providers Library. Mirrors the
// Java `ItemEncryptorFactory`, including its recursion over the Multi keyring and
// the Default / RequiredEncryptionContext CMMs.
//
// KMS keyrings are handed an `aws_sdk_kms::Client` in the key's region, exactly
// as the Java factory passes `kmsClientForKey(...)`. No KMS call happens at
// construction; the network is touched only on EncryptItem / DecryptItem.
//
// Deferred variants (AwsKmsRsa, Caching CMM) return a GenericServerError: the
// Java factory itself leaves the Caching CMM unwired, and AwsKmsRsa needs an
// asymmetric KMS key. They are not reached by any current Test. Every other
// variant — including the AwsKmsHierarchical keyring (branch-key store) — is
// fully wired.

use crate::error::ServerError;
use crate::model;
use aws_config::SdkConfig;
use aws_db_esdk::dynamodb::types::DynamoDbTableEncryptionConfig;
use aws_db_esdk::dynamodb::types::{
    BeaconKeySource as DbeBeaconKeySource, BeaconVersion as DbeBeaconVersion,
    CompoundBeacon as DbeCompoundBeacon, Constructor as DbeConstructor,
    ConstructorPart as DbeConstructorPart, EncryptedPart as DbeEncryptedPart,
    SearchConfig as DbeSearchConfig, SignedPart as DbeSignedPart,
    SingleKeyStore as DbeSingleKeyStore, StandardBeacon as DbeStandardBeacon,
    VirtualField as DbeVirtualField, VirtualPart as DbeVirtualPart,
    VirtualTransform as DbeVirtualTransform, Upper as DbeUpper,
    GetPrefix as DbeGetPrefix, GetSuffix as DbeGetSuffix,
};
use aws_db_esdk::key_store::client::Client as KeyStoreClient;
use aws_db_esdk::key_store::types::key_store_config::KeyStoreConfig;
use aws_db_esdk::key_store::types::KmsConfiguration;
use aws_db_esdk::item_encryptor::client::Client as ItemEncryptor;
use aws_db_esdk::item_encryptor::types::dynamo_db_item_encryptor_config::DynamoDbItemEncryptorConfig;
use aws_db_esdk::material_providers::client::Client as MplClient;
use aws_db_esdk::material_providers::types::cryptographic_materials_manager::CryptographicMaterialsManagerRef;
use aws_db_esdk::material_providers::types::keyring::KeyringRef;
use aws_db_esdk::material_providers::types::AesWrappingAlg as MplAesWrappingAlg;
use aws_db_esdk::material_providers::types::DbeAlgorithmSuiteId as MplSuiteId;
use aws_db_esdk::material_providers::types::PaddingScheme as MplPaddingScheme;
use aws_db_esdk::Client as TransformsClient;
use aws_db_esdk::CryptoAction as DbeCryptoAction;
use aws_db_esdk::DynamoDbTablesEncryptionConfig;
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

/// Build a configured DBE DDB-SDK transforms client bound to one or more
/// physical tables. Reuses the item encryptor's recursive keyring/CMM
/// construction and Crypto Action mapping; only the target config type differs
/// (`DynamoDbTableEncryptionConfig` rather than `DynamoDbItemEncryptorConfig`).
/// Each table gets its own independent `DynamoDbTableEncryptionConfig`, so
/// per-table settings (notably `algorithm_suite_id`) do not leak across tables.
/// A construction failure is a framework failure (GenericServerError).
pub async fn build_transforms_client(
    mpl: &MplClient,
    sdk_config: &SdkConfig,
    cfg: &model::DbeClientConfig,
    table_name: &str,
    additional: &[model::TransformsTableConfig],
) -> Result<TransformsClient, ServerError> {
    let mut table_configs: HashMap<String, DynamoDbTableEncryptionConfig> = HashMap::new();
    table_configs.insert(
        table_name.to_string(),
        build_table_config(mpl, sdk_config, cfg).await?,
    );
    for extra in additional {
        table_configs.insert(
            extra.table_name.clone(),
            build_table_config(mpl, sdk_config, &extra.config).await?,
        );
    }

    let tables_config = DynamoDbTablesEncryptionConfig::builder()
        .table_encryption_configs(table_configs)
        .build()
        .map_err(|e| {
            ServerError::Generic(format!("invalid DynamoDbTablesEncryptionConfig: {e}"))
        })?;
    TransformsClient::from_conf(tables_config)
        .map_err(|e| ServerError::Generic(format!("failed to build transforms client: {e}")))
}

/// Build one table's `DynamoDbTableEncryptionConfig` from its wire config.
async fn build_table_config(
    mpl: &MplClient,
    sdk_config: &SdkConfig,
    cfg: &model::DbeClientConfig,
) -> Result<DynamoDbTableEncryptionConfig, ServerError> {
    let mut builder = DynamoDbTableEncryptionConfig::builder()
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

    if let Some(search) = &cfg.search {
        builder = builder.search(build_search_config(search)?);
    }

    builder.build().map_err(|e| {
        ServerError::Generic(format!("invalid DynamoDbTableEncryptionConfig: {e}"))
    })
}

/// Build a DBE SearchConfig (beacons) from the wire config. The beacon key
/// store's DynamoDB and KMS clients are derived from the KMS key ARN's region
/// (no explicit clients passed), so the keystore reaches KeyStoreDdbTable with
/// the ambient credentials.
fn build_search_config(search: &model::SearchConfig) -> Result<DbeSearchConfig, ServerError> {
    let mut versions = Vec::with_capacity(search.versions.len());
    for v in &search.versions {
        let key_store = KeyStoreClient::from_conf(
            KeyStoreConfig::builder()
                .ddb_table_name(&v.key_store.ddb_table_name)
                .logical_key_store_name(&v.key_store.logical_key_store_name)
                .kms_configuration(KmsConfiguration::KmsKeyArn(v.key_store.kms_key_arn.clone()))
                .build()
                .map_err(|e| ServerError::Generic(format!("invalid KeyStoreConfig: {e}")))?,
        )
        .map_err(|e| ServerError::Generic(format!("failed to build beacon key store: {e}")))?;

        let single = v.key_source.single.as_ref().ok_or_else(|| {
            ServerError::Generic("BeaconKeySource requires a single key store".into())
        })?;
        let key_source = DbeBeaconKeySource::Single(
            DbeSingleKeyStore::builder()
                .key_id(&single.key_id)
                .cache_ttl(single.cache_ttl_seconds)
                .build()
                .map_err(|e| ServerError::Generic(format!("invalid SingleKeyStore: {e}")))?,
        );

        let mut bv = DbeBeaconVersion::builder()
            .version(v.version)
            .key_store(key_store)
            .key_source(key_source);
        if let Some(beacons) = &v.standard_beacons {
            let mut standard = Vec::with_capacity(beacons.len());
            for b in beacons {
                let mut sb = DbeStandardBeacon::builder().name(&b.name).length(b.length);
                if let Some(loc) = &b.loc {
                    sb = sb.loc(loc);
                }
                if let Some(n) = b.number_of_partitions {
                    sb = sb.number_of_partitions(n);
                }
                standard.push(
                    sb.build()
                        .map_err(|e| ServerError::Generic(format!("invalid StandardBeacon: {e}")))?,
                );
            }
            bv = bv.standard_beacons(standard);
        }
        if let Some(fields) = &v.virtual_fields {
            bv = bv.virtual_fields(build_virtual_fields(fields)?);
        }
        if let Some(parts) = &v.encrypted_parts {
            bv = bv.encrypted_parts(build_encrypted_parts(parts)?);
        }
        if let Some(parts) = &v.signed_parts {
            bv = bv.signed_parts(build_signed_parts(parts)?);
        }
        if let Some(compound) = &v.compound_beacons {
            bv = bv.compound_beacons(build_compound_beacons(compound)?);
        }
        if let Some(max) = v.maximum_number_of_partitions {
            bv = bv.maximum_number_of_partitions(max);
        }
        if let Some(default) = v.default_number_of_partitions {
            bv = bv.default_number_of_partitions(default);
        }
        versions.push(
            bv.build()
                .map_err(|e| ServerError::Generic(format!("invalid BeaconVersion: {e}")))?,
        );
    }

    DbeSearchConfig::builder()
        .versions(versions)
        .write_version(search.write_version.unwrap_or(1))
        .build()
        .map_err(|e| ServerError::Generic(format!("invalid SearchConfig: {e}")))
}

fn build_virtual_fields(
    wire: &[model::VirtualField],
) -> Result<Vec<DbeVirtualField>, ServerError> {
    let mut out = Vec::with_capacity(wire.len());
    for f in wire {
        let mut parts = Vec::with_capacity(f.parts.len());
        for p in &f.parts {
            let mut pb = DbeVirtualPart::builder().loc(&p.loc);
            if let Some(trans) = &p.trans {
                pb = pb.set_trans(Some(build_virtual_transforms(trans)?));
            }
            parts.push(
                pb.build()
                    .map_err(|e| ServerError::Generic(format!("invalid VirtualPart: {e}")))?,
            );
        }
        out.push(
            DbeVirtualField::builder()
                .name(&f.name)
                .parts(parts)
                .build()
                .map_err(|e| ServerError::Generic(format!("invalid VirtualField: {e}")))?,
        );
    }
    Ok(out)
}

fn build_virtual_transforms(
    wire: &[model::VirtualTransform],
) -> Result<Vec<DbeVirtualTransform>, ServerError> {
    let mut out = Vec::with_capacity(wire.len());
    for t in wire {
        if t.upper.is_some() {
            out.push(DbeVirtualTransform::Upper(
                DbeUpper::builder()
                    .build()
                    .map_err(|e| ServerError::Generic(format!("invalid Upper: {e}")))?,
            ));
        } else if let Some(p) = &t.prefix {
            out.push(DbeVirtualTransform::Prefix(
                DbeGetPrefix::builder()
                    .length(p.length)
                    .build()
                    .map_err(|e| ServerError::Generic(format!("invalid GetPrefix: {e}")))?,
            ));
        } else if let Some(s) = &t.suffix {
            out.push(DbeVirtualTransform::Suffix(
                DbeGetSuffix::builder()
                    .length(s.length)
                    .build()
                    .map_err(|e| ServerError::Generic(format!("invalid GetSuffix: {e}")))?,
            ));
        } else {
            return Err(ServerError::Generic(
                "VirtualTransform had no member set".into(),
            ));
        }
    }
    Ok(out)
}

fn build_encrypted_parts(
    wire: &[model::EncryptedPart],
) -> Result<Vec<DbeEncryptedPart>, ServerError> {
    let mut out = Vec::with_capacity(wire.len());
    for p in wire {
        out.push(
            DbeEncryptedPart::builder()
                .name(&p.name)
                .prefix(&p.prefix)
                .build()
                .map_err(|e| ServerError::Generic(format!("invalid EncryptedPart: {e}")))?,
        );
    }
    Ok(out)
}

fn build_signed_parts(wire: &[model::SignedPart]) -> Result<Vec<DbeSignedPart>, ServerError> {
    let mut out = Vec::with_capacity(wire.len());
    for p in wire {
        let mut sp = DbeSignedPart::builder().name(&p.name).prefix(&p.prefix);
        if let Some(loc) = &p.loc {
            sp = sp.loc(loc);
        }
        out.push(
            sp.build()
                .map_err(|e| ServerError::Generic(format!("invalid SignedPart: {e}")))?,
        );
    }
    Ok(out)
}

fn build_compound_beacons(
    wire: &[model::CompoundBeacon],
) -> Result<Vec<DbeCompoundBeacon>, ServerError> {
    let mut out = Vec::with_capacity(wire.len());
    for c in wire {
        let mut cb = DbeCompoundBeacon::builder().name(&c.name).split(&c.split);
        if let Some(encrypted) = &c.encrypted {
            cb = cb.encrypted(build_encrypted_parts(encrypted)?);
        }
        if let Some(signed) = &c.signed {
            cb = cb.signed(build_signed_parts(signed)?);
        }
        if let Some(constructors) = &c.constructors {
            let mut ctors = Vec::with_capacity(constructors.len());
            for ctor in constructors {
                let mut parts = Vec::with_capacity(ctor.parts.len());
                for part in &ctor.parts {
                    parts.push(
                        DbeConstructorPart::builder()
                            .name(&part.name)
                            .required(part.required)
                            .build()
                            .map_err(|e| {
                                ServerError::Generic(format!("invalid ConstructorPart: {e}"))
                            })?,
                    );
                }
                ctors.push(
                    DbeConstructor::builder()
                        .parts(parts)
                        .build()
                        .map_err(|e| ServerError::Generic(format!("invalid Constructor: {e}")))?,
                );
            }
            cb = cb.constructors(ctors);
        }
        out.push(
            cb.build()
                .map_err(|e| ServerError::Generic(format!("invalid CompoundBeacon: {e}")))?,
        );
    }
    Ok(out)
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
                model::CryptoAction::SignAndIncludeInEncryptionContext =>
                    DbeCryptoAction::SignAndIncludeInEncryptionContext,
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
        if let Some(c) = &keyring.aws_kms_hierarchical {
            // Branch keys live in a DynamoDB key store and are wrapped by a KMS
            // key. The keystore's DDB/KMS clients are derived from the KMS key
            // ARN's region (no explicit clients), matching the beacon SearchConfig
            // keystore build. Branch-key retrieval reaches DynamoDB and KMS only
            // on EncryptItem / DecryptItem, not at construction.
            let key_store = KeyStoreClient::from_conf(
                KeyStoreConfig::builder()
                    .ddb_table_name(&c.key_store_table_name)
                    .logical_key_store_name(&c.logical_key_store_name)
                    .kms_configuration(KmsConfiguration::KmsKeyArn(c.kms_key_arn.clone()))
                    .build()
                    .map_err(|e| ServerError::Generic(format!("invalid KeyStoreConfig: {e}")))?,
            )
            .map_err(|e| ServerError::Generic(format!("failed to build key store: {e}")))?;
            return mpl
                .create_aws_kms_hierarchical_keyring()
                .key_store(key_store)
                .branch_key_id(&c.branch_key_id)
                .ttl_seconds(c.ttl_seconds)
                .send()
                .await
                .map_err(construction_error);
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

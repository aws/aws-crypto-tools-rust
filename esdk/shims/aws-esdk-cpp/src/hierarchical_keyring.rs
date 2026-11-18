// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The hierarchical keyring and everything it needs: the AWS SDK clients,
//! their configuration, the key store, and the caches.
//! `lib.rs` builds this module only with the `kms`, `ddb` and
//! `default-aws-sdk-clients` features.

use super::*;
use aws_config::{BehaviorVersion, FrameworkMetadata, Region, SdkConfig};
use aws_crypto_mpl::aws_config;
#[cfg(feature = "rt-tokio")]
use aws_crypto_mpl::cmc::{DefaultCmc, StormTrackingCmc, StormTrackingCmcBuilder};
use aws_crypto_mpl::cmc::{LocalCmc, SharedCmc};
use aws_crypto_mpl::key_store::DynamoDbKeyStore;
use aws_crypto_mpl::key_store::types::{Discovery, KmsConfiguration, MrDiscovery};
use aws_crypto_mpl::keyring::HierarchicalKeyring;
use aws_crypto_mpl::{aws_sdk_dynamodb, aws_sdk_kms};
use aws_sdk_kms::config::{IdentityCache, SharedCredentialsProvider, SharedHttpClient};
use aws_smithy_runtime::client::defaults::default_http_client_plugin_v2;
use aws_smithy_runtime_api::client::runtime_components::RuntimeComponentsBuilder;
use aws_smithy_runtime_api::client::runtime_plugin::RuntimePlugin;
use std::sync::LazyLock;
use std::time::{Duration, SystemTime};

pub(super) struct CryptographicMaterialsCache {
    pub(super) inner: SharedCmc,
}

impl ffi::OptCredentials {
    /// `Some(&value)` when `set` is true, else `None`.
    pub(super) fn as_option(&self) -> Option<&ffi::Credentials> {
        self.set.then_some(&self.value)
    }
}

/// An HTTP client, with its connection pool, that service clients can share.
pub(super) struct HttpClient {
    pub(super) inner: SharedHttpClient,
}

pub(super) struct MplKmsClient {
    pub(super) inner: aws_sdk_kms::Client,
}
pub(super) struct MplDdbClient {
    pub(super) inner: aws_sdk_dynamodb::Client,
}

pub(super) struct KeyStore {
    pub(super) inner: DynamoDbKeyStore,
}

// Create an ESDK Rust Key Store KmsConfiguration value from the given FFI KmsConfiguration value
pub(super) fn make_kms_config(
    kind: ffi::KmsConfigurationType,
    value: &str,
) -> Result<KmsConfiguration, String> {
    match kind {
        ffi::KmsConfigurationType::Unset => Err(shim_err(
            ffi::ShimErrorKind::Validation,
            "create_keystore",
            "kms_configuration_type is unset",
        )),
        //= spec/shim/esdk-shim.md#kms-configuration
        //# - The shim MUST translate a KMS key ARN configuration.
        ffi::KmsConfigurationType::KmsKeyArn => Ok(KmsConfiguration::kms_key_arn(value)),
        //= spec/shim/esdk-shim.md#kms-configuration
        //# - The shim MUST translate a KMS multi-Region-key ARN configuration.
        ffi::KmsConfigurationType::KmsMrKeyArn => Ok(KmsConfiguration::kms_mr_key_arn(value)),
        //= spec/shim/esdk-shim.md#kms-configuration
        //# - The shim MUST translate a discovery configuration.
        ffi::KmsConfigurationType::Discovery => Ok(KmsConfiguration::Discovery(
            Discovery::builder().build().map_err(core_err)?,
        )),
        //= spec/shim/esdk-shim.md#kms-configuration
        //# - The shim MUST translate a multi-Region-key discovery configuration.
        ffi::KmsConfigurationType::MrDiscovery => Ok(KmsConfiguration::MrDiscovery(
            MrDiscovery::builder()
                .region(value)
                .build()
                .map_err(core_err)?,
        )),
        //= spec/shim/esdk-shim.md#kms-configuration
        //# - The shim MUST return an error when the target KMS configuration type is not a
        //# supported value.
        _ => Err(shim_err(
            ffi::ShimErrorKind::Validation,
            "create_keystore",
            "unrecognized KMS configuration type",
        )),
    }
}

/// C++ to Rust for AWS SDK call retry config
pub(super) fn make_retry_config(
    config: &ffi::RetryConfig,
) -> Option<aws_config::retry::RetryConfig> {
    let max_attempts = config.max_attempts.to_option();
    if !config.mode_adaptive && max_attempts.is_none() {
        return None;
    }
    let mut out_config = if config.mode_adaptive {
        aws_config::retry::RetryConfig::adaptive()
    } else {
        aws_config::retry::RetryConfig::standard()
    };
    if let Some(max_attempts) = max_attempts {
        out_config = out_config.with_max_attempts(max_attempts);
    }
    Some(out_config)
}

// AWS SDK client configuration

// A library built on the AWS SDK for Rust identifies itself with FrameworkMetadata.
// The SDK renders it into the User-Agent as `lib/<name>/<version>`.
pub(super) const SHIM_FRAMEWORK_NAME: &str = "AwsEncryptionSdk-Shim-C++-Rust";

//= spec/shim/esdk-shim.md#service-client-configuration
//# - The shim MUST set a user-agent on each service client of the form
//# `AwsEncryptionSdk-Shim-<target-language>-<core-language>-<version>`, where
//# `<target-language>` is the target language, `<core-language>` is the core
//# ESDK's implementation language, and `<version>` is the shim's published version.
pub(super) fn shim_framework_metadata() -> FrameworkMetadata {
    FrameworkMetadata::new(SHIM_FRAMEWORK_NAME, Some(env!("CARGO_PKG_VERSION")))
        .expect("the shim framework metadata name and version are valid")
}

// Loaded once per process.
// Every client config derives from it, so clients without explicit credentials share one credential chain.
pub(super) static DEFAULT_SDK_CONFIG: LazyLock<Result<SdkConfig, String>> =
    LazyLock::new(load_default_sdk_config);

/// The AWS SDK's default HTTPS client.
pub(super) fn default_http_client() -> Option<SharedHttpClient> {
    default_http_client_plugin_v2(BehaviorVersion::latest())?
        .runtime_components(&RuntimeComponentsBuilder::new("aws-esdk-cpp"))
        .http_client()
}

pub(super) fn load_default_sdk_config() -> Result<SdkConfig, String> {
    let shared_config =
        TOKIO_RUNTIME.block_on(aws_config::defaults(BehaviorVersion::latest()).load());
    Ok(with_shim_user_agent(shared_config))
}

pub(super) fn with_shim_user_agent(loaded: SdkConfig) -> SdkConfig {
    //= spec/shim/esdk-shim.md#service-client-configuration
    //= type=implication
    //= reason=FrameworkMetadata is appended to the User-Agent and the shim sets no app name, so any user-agent already present in the loaded configuration is preserved.
    //# - The shim MUST preserve any user-agent already present in the loaded
    //# configuration, appending its own rather than replacing it.
    loaded
        .to_builder()
        .framework_metadata(shim_framework_metadata())
        .build()
}

/// Convert C++ static credentials to AWS SDK credentials.
pub(super) fn credentials_target_to_core(
    input: &ffi::Credentials,
    operation: &str,
) -> Result<aws_sdk_kms::config::Credentials, String> {
    // Messages name the empty field only; they never carry credential values.
    for (field, value) in [
        ("access key id", &input.access_key_id),
        ("secret access key", &input.secret_access_key),
    ] {
        if value.is_empty() {
            return Err(shim_err(
                ffi::ShimErrorKind::Validation,
                operation,
                format!("{field} must not be empty"),
            ));
        }
    }
    let expiration = match input.expiration.to_option() {
        None => None,
        Some(d) => {
            let since_epoch = from_ffi_duration(d, "credentials expiration", operation)?;
            let Some(expiration) = SystemTime::UNIX_EPOCH.checked_add(since_epoch) else {
                return Err(shim_err(
                    ffi::ShimErrorKind::Validation,
                    operation,
                    "credentials expiration is out of range",
                ));
            };
            Some(expiration)
        }
    };
    Ok(aws_sdk_kms::config::Credentials::new(
        input.access_key_id.as_str(),
        input.secret_access_key.as_str(),
        input.session_token.to_option(),
        expiration,
        "aws-esdk-cpp",
    ))
}

//= spec/shim/esdk-shim.md#service-client-configuration
//= type=implication
//= reason=create_kms_client and create_ddb_client each build their SdkConfig from the same MplAwsClientConfig, so one configuration can be applied to multiple clients.
//# - The shim SHOULD allow one client configuration to be applied to multiple
//# service clients.
pub(super) fn create_sdk_config(
    input: &ffi::MplAwsClientConfig,
    http_client: Option<&HttpClient>,
) -> Result<SdkConfig, String> {
    let mut builder = DEFAULT_SDK_CONFIG
        .as_ref()
        .map_err(Clone::clone)?
        .to_builder();
    // Without a shared HTTP client, each service client gets its own connection pool.
    // It is set on the config so clients derived with `with_credentials` reuse it.
    let http_client = match http_client {
        Some(shared) => Some(shared.inner.clone()),
        None => default_http_client(),
    };
    builder.set_http_client(http_client);
    if let Some(credentials) = input.credentials.as_option() {
        let credentials = credentials_target_to_core(credentials, "client configuration")?;
        // Static credentials need no cache.
        // A cached copy would take a slot in the identity cache that every client shares.
        builder = builder
            .credentials_provider(SharedCredentialsProvider::new(credentials))
            .identity_cache(IdentityCache::no_cache());
    }
    //= spec/shim/esdk-shim.md#service-client-configuration
    //# - If the target does not supply a retry configuration, the shim MUST defer to
    //# the core ESDK's default retry configuration and MUST NOT substitute its own.
    if let Some(retry_config) = make_retry_config(&input.retry) {
        //= spec/shim/esdk-shim.md#service-client-configuration
        //# - If the target supplies a retry configuration, the shim MUST apply it to each
        //# service client.
        builder = builder.retry_config(retry_config);
    }
    //= spec/shim/esdk-shim.md#service-client-configuration
    //# - If the target supplies a region, the shim MUST apply it to each service client.
    if let Some(region) = input.region.to_option() {
        builder = builder.region(Region::new(region));
    }
    Ok(builder.build())
}

//= spec/shim/esdk-shim.md#create-kms-client
//# - The shim MUST provide an operation that creates a KMS service client backed by
//# the core ESDK.
pub(super) fn create_kms_client(
    input: &ffi::MplAwsClientConfig,
) -> Result<Box<MplKmsClient>, String> {
    kms_client(input, None)
}

pub(super) fn create_kms_client_with_http_client(
    input: &ffi::MplAwsClientConfig,
    http_client: &HttpClient,
) -> Result<Box<MplKmsClient>, String> {
    kms_client(input, Some(http_client))
}

pub(super) fn kms_client(
    input: &ffi::MplAwsClientConfig,
    http_client: Option<&HttpClient>,
) -> Result<Box<MplKmsClient>, String> {
    //= spec/shim/esdk-shim.md#create-kms-client
    //# - Creating a KMS client MUST apply the target-supplied client configuration, as
    //# defined in [Service client configuration](#service-client-configuration).
    let sdk_config = create_sdk_config(input, http_client)?;
    Ok(Box::new(MplKmsClient {
        inner: aws_sdk_kms::Client::new(&sdk_config),
    }))
}

//= spec/shim/esdk-shim.md#create-dynamodb-client
//# - The shim MUST provide an operation that creates a DynamoDB service client
//# backed by the core ESDK.
pub(super) fn create_ddb_client(
    input: &ffi::MplAwsClientConfig,
) -> Result<Box<MplDdbClient>, String> {
    ddb_client(input, None)
}

pub(super) fn create_ddb_client_with_http_client(
    input: &ffi::MplAwsClientConfig,
    http_client: &HttpClient,
) -> Result<Box<MplDdbClient>, String> {
    ddb_client(input, Some(http_client))
}

pub(super) fn ddb_client(
    input: &ffi::MplAwsClientConfig,
    http_client: Option<&HttpClient>,
) -> Result<Box<MplDdbClient>, String> {
    //= spec/shim/esdk-shim.md#create-dynamodb-client
    //# - Creating a DynamoDB client MUST apply the target-supplied client configuration,
    //# as defined in [Service client configuration](#service-client-configuration).
    let sdk_config = create_sdk_config(input, http_client)?;
    let mut config = aws_sdk_dynamodb::config::Builder::from(&sdk_config);
    // The DynamoDB client ignores the SdkConfig's retry config and uses its own default.
    // Setting it on the client config makes the caller's retry config apply.
    if let Some(retry_config) = make_retry_config(&input.retry) {
        config = config.retry_config(retry_config);
    }
    Ok(Box::new(MplDdbClient {
        inner: aws_sdk_dynamodb::Client::from_conf(config.build()),
    }))
}

pub(super) fn create_http_client() -> Result<Box<HttpClient>, String> {
    // The shim always turns on aws-smithy-runtime's default-https-client feature.
    let inner = default_http_client().expect("default-https-client is on");
    Ok(Box::new(HttpClient { inner }))
}

// A derived client keeps the base client's configuration and HTTP client.
// See create_sdk_config for why static credentials skip the identity cache.

pub(super) fn kms_client_with_credentials(
    base: &MplKmsClient,
    credentials: &ffi::Credentials,
) -> Result<Box<MplKmsClient>, String> {
    let credentials = credentials_target_to_core(credentials, "KMS client with credentials")?;
    let config = base
        .inner
        .config()
        .to_builder()
        .credentials_provider(credentials)
        .identity_cache(IdentityCache::no_cache())
        .build();
    Ok(Box::new(MplKmsClient {
        inner: aws_sdk_kms::Client::from_conf(config),
    }))
}

pub(super) fn kms_client_with_headers(
    base: &MplKmsClient,
    headers: Vec<ffi::HttpHeader>,
) -> Result<Box<MplKmsClient>, String> {
    let invalid = |message: String| {
        shim_err(
            ffi::ShimErrorKind::Validation,
            "KMS client with headers",
            message,
        )
    };
    if headers.is_empty() {
        return Err(invalid("headers is empty".to_string()));
    }
    // try_insert applies the request's own name and value rules,
    // and returns the previous value for a repeated name.
    let mut checked = aws_sdk_kms::config::http::HttpRequest::empty();
    for header in &headers {
        if header.name.is_empty() || header.value.is_empty() {
            return Err(invalid(format!(
                "header {:?} has an empty name or value",
                header.name
            )));
        }
        match checked
            .headers_mut()
            .try_insert(header.name.clone(), header.value.clone())
        {
            Ok(None) => {}
            Ok(Some(_)) => return Err(invalid(format!("header {:?} is repeated", header.name))),
            Err(e) => return Err(invalid(format!("header {:?} is invalid: {e}", header.name))),
        }
    }
    let config = base
        .inner
        .config()
        .to_builder()
        .interceptor(RequestHeaders(
            headers.into_iter().map(|h| (h.name, h.value)).collect(),
        ))
        .build();
    Ok(Box::new(MplKmsClient {
        inner: aws_sdk_kms::Client::from_conf(config),
    }))
}

/// Adds fixed headers to every request.
#[derive(Debug)]
pub(super) struct RequestHeaders(pub(super) Vec<(String, String)>);

impl aws_sdk_kms::config::Intercept for RequestHeaders {
    fn name(&self) -> &'static str {
        "RequestHeaders"
    }

    // Before signing, so SigV4 signs the headers.
    fn modify_before_signing(
        &self,
        context: &mut aws_sdk_kms::config::interceptors::BeforeTransmitInterceptorContextMut<'_>,
        _runtime_components: &aws_sdk_kms::config::RuntimeComponents,
        _cfg: &mut aws_sdk_kms::config::ConfigBag,
    ) -> Result<(), aws_sdk_kms::error::BoxError> {
        let headers = context.request_mut().headers_mut();
        for (name, value) in &self.0 {
            headers.try_insert(name.clone(), value.clone())?;
        }
        Ok(())
    }
}

pub(super) fn ddb_client_with_credentials(
    base: &MplDdbClient,
    credentials: &ffi::Credentials,
) -> Result<Box<MplDdbClient>, String> {
    let credentials = credentials_target_to_core(credentials, "DynamoDB client with credentials")?;
    let config = base
        .inner
        .config()
        .to_builder()
        .credentials_provider(credentials)
        .identity_cache(IdentityCache::no_cache())
        .build();
    Ok(Box::new(MplDdbClient {
        inner: aws_sdk_dynamodb::Client::from_conf(config),
    }))
}

//= spec/shim/esdk-shim.md#create-key-store
//# - The shim MUST provide an operation that creates a key store backed by the core ESDK.
pub(super) fn create_keystore(input: &ffi::KeyStoreConfig) -> Result<Box<KeyStore>, String> {
    let builder = DynamoDbKeyStore::builder()
        //= spec/shim/esdk-shim.md#create-key-store
        //# - Creating a key store MUST provide the target-supplied table name and logical key
        //# store name to the core ESDK.
        .ddb_table_name(input.ddb_table_name.clone())
        .logical_key_store_name(input.logical_key_store_name.clone())
        //= spec/shim/esdk-shim.md#create-key-store
        //# - Creating a key store MUST provide the target-supplied KMS configuration to the
        //# core ESDK, converted as defined in [KMS configuration](#kms-configuration).
        .kms_configuration(make_kms_config(
            input.kms_configuration_type,
            &input.kms_configuration_value,
        )?)
        //= spec/shim/esdk-shim.md#create-key-store
        //# - Creating a key store MUST provide the target-supplied key store id and grant
        //# tokens to the core ESDK when present; an unset value is omitted.
        .set_id(input.id.to_option())
        .set_grant_tokens(non_empty(&input.grant_tokens))
        //= spec/shim/esdk-shim.md#create-key-store
        //# - Creating a key store MAY be supplied with a KMS client and a DynamoDB client,
        //# each checked as defined in
        //# [Shim Specification: Handles and lifetimes](./shim.md#handles-and-lifetimes); a
        //# supplied client MUST be provided to the core ESDK, and an absent one MUST be
        //# left for the core ESDK to default.
        //
        // A null handle means "not supplied", so the core builds its own default client.
        // SAFETY: a non-null handle is a valid client borrowed for this call.
        .set_kms_client(unsafe { input.kms_client.as_ref() }.map(|c| c.inner.clone()))
        .set_ddb_client(unsafe { input.ddb_client.as_ref() }.map(|c| c.inner.clone()));

    let inner = TOKIO_RUNTIME.block_on(builder.build()).map_err(core_err)?;
    Ok(Box::new(KeyStore { inner }))
}

/// An empty target list means no grant tokens were supplied.
pub(super) fn non_empty(tokens: &[String]) -> Option<Vec<String>> {
    (!tokens.is_empty()).then(|| tokens.to_vec())
}

//= spec/shim/esdk-shim.md#create-hierarchical-keyring
//# - The shim MUST provide an operation that creates a hierarchical keyring backed
//# by the core ESDK.
pub(super) fn create_hierarchical_keyring(
    input: &ffi::HierarchicalKeyringInput,
) -> Result<Box<Keyring>, String> {
    //= spec/shim/esdk-shim.md#create-hierarchical-keyring
    //# - Creating a hierarchical keyring MUST require a key store handle, checked as
    //# defined in
    //# [Shim Specification: Handles and lifetimes](./shim.md#handles-and-lifetimes),
    //# and MUST provide it to the core ESDK.
    let key_store = require_handle(input.key_store, "key_store", "create_hierarchical_keyring")?;

    //= spec/shim/esdk-shim.md#create-hierarchical-keyring
    //# - Creating a hierarchical keyring MAY be supplied with a
    //# [cryptographic materials cache](#create-cryptographic-materials-cache),
    //# checked as defined in
    //# [Shim Specification: Handles and lifetimes](./shim.md#handles-and-lifetimes).
    //
    // SAFETY: a non-null handle is a valid cache borrowed for this call.
    let cache = unsafe { input.cache.as_ref() }.map(|c| c.inner.clone());

    //= spec/shim/esdk-shim.md#create-hierarchical-keyring
    //# - Creating a hierarchical keyring MUST provide the target-supplied partition id to
    //# the core ESDK when present; an unset value is omitted.
    let partition_id = input.partition_id.to_option();

    let ttl = from_ffi_duration(input.ttl, "ttl", "create_hierarchical_keyring")?;

    let mut builder = HierarchicalKeyring::builder()
        .key_store(key_store.inner.clone())
        //= spec/shim/esdk-shim.md#create-hierarchical-keyring
        //# - Creating a hierarchical keyring MUST provide the target-supplied branch key id
        //# and time-to-live to the core ESDK.
        .ttl(ttl)
        .branch_key_id(input.branch_key_id.clone());
    //= spec/shim/esdk-shim.md#create-hierarchical-keyring
    //= reason=Without a cache the builder is left unset, and ESDK Rust builds its default cache
    //# - When no cache is supplied, creating a hierarchical keyring MUST defer to the
    //# core ESDK's default cache.
    if let Some(cache) = cache {
        //= spec/shim/esdk-shim.md#create-hierarchical-keyring
        //# - When a cache is supplied, creating a hierarchical keyring MUST reference that
        //# exact cache, so several keyrings given the same cache share it.
        builder = builder.cache(cache);
    }
    if let Some(partition_id) = partition_id {
        builder = builder.partition_id(partition_id);
    }
    let keyring = TOKIO_RUNTIME.block_on(builder.build()).map_err(core_err)?;

    Ok(Box::new(Keyring {
        inner: SharedKeyring::new(keyring),
    }))
}

/// Converts a bridge duration to a `Duration`.
pub(super) fn from_ffi_duration(
    d: ffi::Duration,
    field: &str,
    op: &str,
) -> Result<Duration, String> {
    Duration::from_secs(d.secs)
        .checked_add(Duration::from_nanos(u64::from(d.nanos)))
        .ok_or_else(|| {
            shim_err(
                ffi::ShimErrorKind::Validation,
                op,
                format!("{field} is out of range"),
            )
        })
}

pub(super) fn cache_count(field: &str, v: u32, op: &str) -> Result<usize, String> {
    i32::try_from(v)
        .ok()
        .and_then(|bounded| usize::try_from(bounded).ok())
        .ok_or_else(|| {
            shim_err(
                ffi::ShimErrorKind::Validation,
                op,
                format!("{field} {v} exceeds the bridge's supported maximum"),
            )
        })
}

/// Apply each set option to `builder`.
#[cfg(feature = "rt-tokio")]
pub(super) fn apply_storm_tracking_options(
    builder: StormTrackingCmcBuilder,
    options: &ffi::StormTrackingCmcOptions,
) -> Result<StormTrackingCmcBuilder, String> {
    let op = "create_storm_tracking_cmc";
    let count = |field: &str, v: Option<u32>| -> Result<Option<usize>, String> {
        v.map(|v| cache_count(field, v, op)).transpose()
    };
    let duration = |field: &str, d: Option<ffi::Duration>| -> Result<Option<Duration>, String> {
        d.map(|d| from_ffi_duration(d, field, op)).transpose()
    };
    Ok(builder
        .set_entry_capacity(count("entry_capacity", options.entry_capacity.to_option())?)
        .set_entry_pruning_tail_size(count(
            "entry_pruning_tail_size",
            options.entry_pruning_tail_size.to_option(),
        )?)
        .set_grace_period(duration("grace_period", options.grace_period.to_option())?)
        .set_grace_interval(duration(
            "grace_interval",
            options.grace_interval.to_option(),
        )?)
        .set_fan_out(count("fan_out", options.fan_out.to_option())?)
        .set_in_flight_ttl(duration(
            "in_flight_ttl",
            options.in_flight_ttl.to_option(),
        )?)
        .set_sleep(duration("sleep", options.sleep.to_option())?))
}

//= spec/shim/esdk-shim.md#create-cryptographic-materials-cache
//= reason=Each cache kind has its own create_* function, so the target selects a kind by calling that kind's function.
//# - The shim MUST provide an operation that creates a cryptographic materials
//# cache of a target-selected kind, backed by the core ESDK.
//
//= spec/shim/esdk-shim.md#create-cryptographic-materials-cache
//= type=implication
//= reason=The cache kinds are the create_* functions the bridge exports, so a kind the bridge does not export cannot be requested.
//# - The shim MUST return an error when the target cache kind is not a supported
//# value.
//
//= spec/shim/esdk-shim.md#create-cryptographic-materials-cache
//= type=exception
//= reason=Will be added in the future
//# - The shim MUST support creating a cache that performs no caching.
//
//= spec/shim/esdk-shim.md#create-cryptographic-materials-cache
//# - The shim MUST support creating a storm tracking cache.
#[cfg(feature = "rt-tokio")]
pub(super) fn create_storm_tracking_cmc(
    options: &ffi::StormTrackingCmcOptions,
) -> Result<Box<CryptographicMaterialsCache>, String> {
    //= spec/shim/esdk-shim.md#create-cryptographic-materials-cache
    //# - Creating a cryptographic materials cache MUST provide the target-supplied
    //# cache type, with its values, to the core ESDK.
    let cache = apply_storm_tracking_options(StormTrackingCmc::builder(), options)?
        .build()
        .map_err(core_err)?;
    Ok(Box::new(CryptographicMaterialsCache {
        inner: SharedCmc::new(cache),
    }))
}

//= spec/shim/esdk-shim.md#create-cryptographic-materials-cache
//# - The shim MUST support creating a default cache.
#[cfg(feature = "rt-tokio")]
pub(super) fn create_default_cmc(
    entry_capacity: u32,
) -> Result<Box<CryptographicMaterialsCache>, String> {
    let op = "create_default_cmc";
    let cache = DefaultCmc::builder()
        .entry_capacity(cache_count("entry_capacity", entry_capacity, op)?)
        .build()
        .map_err(core_err)?;
    Ok(Box::new(CryptographicMaterialsCache {
        inner: SharedCmc::new(cache),
    }))
}

pub(super) fn create_local_cmc(
    entry_capacity: u32,
) -> Result<Box<CryptographicMaterialsCache>, String> {
    let op = "create_local_cmc";
    let cache = LocalCmc::builder()
        .entry_capacity(cache_count("entry_capacity", entry_capacity, op)?)
        .build()
        .map_err(core_err)?;
    Ok(Box::new(CryptographicMaterialsCache {
        inner: SharedCmc::new(cache),
    }))
}

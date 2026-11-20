// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Builders for multi-keyrings made of AWS KMS keyrings, one KMS client per region.

use std::collections::HashMap;

use aws_sdk_kms::Client as KmsClient;
use aws_types::SdkConfig;
use aws_types::region::Region;

use crate::Error;
use crate::aws_kms::aws_kms_keyring::{AwsKmsKeyring, parse_kms_identifier, valid_grant_tokens};
use crate::aws_kms::discovery_keyring::{AwsKmsDiscoveryKeyring, DiscoveryFilter};
use crate::aws_kms::mrk_discovery_keyring::AwsKmsMrkDiscoveryKeyring;
use crate::aws_kms::mrk_keyring::AwsKmsMrkKeyring;
use crate::keyring::{MultiKeyring, SharedKeyring};

impl MultiKeyring {
    /// Start a builder for a multi-keyring of [`AwsKmsKeyring`]s: a generator key and other keys.
    #[must_use]
    pub fn aws_kms() -> AwsKmsMultiKeyringBuilder {
        AwsKmsMultiKeyringBuilder::default()
    }

    /// Start a builder for a multi-keyring of [`AwsKmsDiscoveryKeyring`]s, one per region.
    #[must_use]
    pub fn aws_kms_discovery() -> AwsKmsDiscoveryMultiKeyringBuilder {
        AwsKmsDiscoveryMultiKeyringBuilder::default()
    }

    /// Start a builder for a multi-keyring of [`AwsKmsMrkKeyring`]s: a generator key and other keys.
    #[must_use]
    pub fn aws_kms_mrk() -> AwsKmsMrkMultiKeyringBuilder {
        AwsKmsMrkMultiKeyringBuilder::default()
    }

    /// Start a builder for a multi-keyring of [`AwsKmsMrkDiscoveryKeyring`]s, one per region.
    #[must_use]
    pub fn aws_kms_mrk_discovery() -> AwsKmsMrkDiscoveryMultiKeyringBuilder {
        AwsKmsMrkDiscoveryMultiKeyringBuilder::default()
    }
}

/// Makes one AWS KMS client per region from an AWS SDK configuration.
struct RegionalClients {
    sdk_config: SdkConfig,
    clients: HashMap<Option<String>, KmsClient>,
}

impl RegionalClients {
    async fn new(sdk_config: Option<SdkConfig>) -> Result<Self, Error> {
        let sdk_config = match sdk_config {
            Some(sdk_config) => sdk_config,
            #[cfg(feature = "default-aws-sdk-clients")]
            None => aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await,
            #[cfg(not(feature = "default-aws-sdk-clients"))]
            None => {
                return Err(Error::validation(
                    "sdk_config is required without the `default-aws-sdk-clients` feature",
                ));
            }
        };
        Ok(Self {
            sdk_config,
            clients: HashMap::new(),
        })
    }

    /// The client for `region`, or for the configuration's own region when `None`.
    fn client(&mut self, region: Option<String>) -> KmsClient {
        let sdk_config = &self.sdk_config;
        self.clients
            .entry(region)
            .or_insert_with_key(|region| {
                let mut config = aws_sdk_kms::config::Builder::from(sdk_config);
                if let Some(region) = region {
                    config = config.region(Region::new(region.clone()));
                }
                KmsClient::from_conf(config.build())
            })
            .clone()
    }
}

/// The region of an AWS KMS key ARN; `None` for a key ID or alias name.
async fn aws_kms_keyring(
    kms_key_id: String,
    kms_client: KmsClient,
    grant_tokens: &[String],
) -> Result<SharedKeyring, Error> {
    let keyring = AwsKmsKeyring::builder()
        .kms_key_id(kms_key_id)
        .kms_client(kms_client)
        .set_grant_tokens(Some(grant_tokens.to_vec()))
        .build()
        .await?;
    Ok(SharedKeyring::new(keyring))
}

async fn aws_kms_mrk_keyring(
    kms_key_id: String,
    kms_client: KmsClient,
    grant_tokens: &[String],
) -> Result<SharedKeyring, Error> {
    let keyring = AwsKmsMrkKeyring::builder()
        .kms_key_id(kms_key_id)
        .kms_client(kms_client)
        .set_grant_tokens(Some(grant_tokens.to_vec()))
        .build()
        .await?;
    Ok(SharedKeyring::new(keyring))
}

fn region_of(kms_key_id: &str) -> Option<String> {
    let parts: Vec<&str> = kms_key_id.split(':').collect();
    match parts.as_slice() {
        ["arn", _, _, region, _, _] => Some((*region).to_owned()),
        _ => None,
    }
}

/// Builder for a [`MultiKeyring`] of [`AwsKmsKeyring`]s.
/// Start it with [`MultiKeyring::aws_kms`].
///
/// The generator key makes and wraps the data key; each other key also wraps it.
/// Each keyring gets a KMS client in its key's region.
///
/// ```no_run
/// use aws_crypto_mpl::keyring::MultiKeyring;
///
/// # async fn example() -> Result<(), aws_crypto_mpl::Error> {
/// let keyring = MultiKeyring::aws_kms()
///     .generator("arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab")
///     .kms_key_ids("arn:aws:kms:eu-west-1:111122223333:key/0987dcba-09fe-87dc-65ba-ab0987654321")
///     .build()
///     .await?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct AwsKmsMultiKeyringBuilder {
    generator: Option<String>,
    kms_key_ids: Option<Vec<String>>,
    grant_tokens: Option<Vec<String>>,
    sdk_config: Option<SdkConfig>,
}

impl AwsKmsMultiKeyringBuilder {
    /// The AWS KMS key that makes the data key.
    /// Optional, but the keyring cannot make a data key without one.
    #[must_use]
    pub fn generator(mut self, generator: impl Into<String>) -> Self {
        self.generator = Some(generator.into());
        self
    }

    /// The generator key. See [`Self::generator`].
    #[must_use]
    pub fn set_generator(mut self, generator: Option<String>) -> Self {
        self.generator = generator;
        self
    }

    /// Add an AWS KMS key that also wraps the data key.
    #[must_use]
    pub fn kms_key_ids(mut self, kms_key_id: impl Into<String>) -> Self {
        self.kms_key_ids
            .get_or_insert_with(Vec::new)
            .push(kms_key_id.into());
        self
    }

    /// Replace the other AWS KMS keys. See [`Self::kms_key_ids`].
    #[must_use]
    pub fn set_kms_key_ids(mut self, kms_key_ids: Option<Vec<String>>) -> Self {
        self.kms_key_ids = kms_key_ids;
        self
    }

    /// Add a grant token, sent with every AWS KMS request.
    #[must_use]
    pub fn grant_tokens(mut self, grant_token: impl Into<String>) -> Self {
        self.grant_tokens
            .get_or_insert_with(Vec::new)
            .push(grant_token.into());
        self
    }

    /// Replace the grant tokens. See [`Self::grant_tokens`].
    #[must_use]
    pub fn set_grant_tokens(mut self, grant_tokens: Option<Vec<String>>) -> Self {
        self.grant_tokens = grant_tokens;
        self
    }

    /// The AWS SDK configuration to make each KMS client from.
    /// The client for a key ARN uses the ARN's region; the client for any other key uses this configuration's region.
    /// Optional with the `default-aws-sdk-clients` feature: the default uses your AWS credentials and region.
    #[must_use]
    pub fn sdk_config(mut self, sdk_config: SdkConfig) -> Self {
        self.sdk_config = Some(sdk_config);
        self
    }

    /// The AWS SDK configuration. See [`Self::sdk_config`].
    #[must_use]
    pub fn set_sdk_config(mut self, sdk_config: Option<SdkConfig>) -> Self {
        self.sdk_config = sdk_config;
        self
    }

    /// Build the keyring.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): no generator and no other key,
    ///   a malformed key identifier,
    ///   a grant token list that is too long or has a token of the wrong length,
    ///   or no `sdk_config` without the `default-aws-sdk-clients` feature.
    pub async fn build(self) -> Result<MultiKeyring, Error> {
        let grant_tokens = valid_grant_tokens(self.grant_tokens)?;
        let kms_key_ids = self.kms_key_ids.unwrap_or_default();
        for kms_key_id in self.generator.iter().chain(&kms_key_ids) {
            parse_kms_identifier(kms_key_id).map_err(Error::validation)?;
        }
        let mut clients = RegionalClients::new(self.sdk_config).await?;
        let mut generator = None;
        if let Some(kms_key_id) = self.generator {
            let client = clients.client(region_of(&kms_key_id));
            generator = Some(aws_kms_keyring(kms_key_id, client, &grant_tokens).await?);
        }
        let mut child_keyrings = Vec::with_capacity(kms_key_ids.len());
        for kms_key_id in kms_key_ids {
            let client = clients.client(region_of(&kms_key_id));
            child_keyrings.push(aws_kms_keyring(kms_key_id, client, &grant_tokens).await?);
        }
        if generator.is_none() && child_keyrings.is_empty() {
            return Err(Error::validation(
                "generatorKeyring or child Keryings needed to create a multi keyring",
            ));
        }
        MultiKeyring::from_parts(generator, child_keyrings)
    }
}

/// Builder for a [`MultiKeyring`] of [`AwsKmsDiscoveryKeyring`]s.
/// Start it with [`MultiKeyring::aws_kms_discovery`].
///
/// Each region gets a discovery keyring with a KMS client in that region,
/// so the multi-keyring decrypts data keys wrapped by AWS KMS keys in any of those regions.
///
/// ```no_run
/// use aws_crypto_mpl::keyring::{DiscoveryFilter, MultiKeyring};
///
/// # async fn example() -> Result<(), aws_crypto_mpl::Error> {
/// let keyring = MultiKeyring::aws_kms_discovery()
///     .regions("us-west-2")
///     .regions("eu-west-1")
///     .discovery_filter(
///         DiscoveryFilter::builder()
///             .partition("aws")
///             .account_ids("111122223333")
///             .build()?,
///     )
///     .build()
///     .await?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct AwsKmsDiscoveryMultiKeyringBuilder {
    regions: Option<Vec<String>>,
    discovery_filter: Option<DiscoveryFilter>,
    grant_tokens: Option<Vec<String>>,
    sdk_config: Option<SdkConfig>,
}

impl AwsKmsDiscoveryMultiKeyringBuilder {
    /// Add an AWS region.
    /// At least one is required.
    #[must_use]
    pub fn regions(mut self, region: impl Into<String>) -> Self {
        self.regions
            .get_or_insert_with(Vec::new)
            .push(region.into());
        self
    }

    /// Replace the regions. See [`Self::regions`].
    #[must_use]
    pub fn set_regions(mut self, regions: Option<Vec<String>>) -> Self {
        self.regions = regions;
        self
    }

    /// Use only the AWS KMS keys that this filter allows.
    /// Optional: with no filter, the keyring tries any AWS KMS key.
    #[must_use]
    pub fn discovery_filter(mut self, discovery_filter: DiscoveryFilter) -> Self {
        self.discovery_filter = Some(discovery_filter);
        self
    }

    /// The discovery filter. See [`Self::discovery_filter`].
    #[must_use]
    pub fn set_discovery_filter(mut self, discovery_filter: Option<DiscoveryFilter>) -> Self {
        self.discovery_filter = discovery_filter;
        self
    }

    /// Add a grant token, sent with every AWS KMS request.
    #[must_use]
    pub fn grant_tokens(mut self, grant_token: impl Into<String>) -> Self {
        self.grant_tokens
            .get_or_insert_with(Vec::new)
            .push(grant_token.into());
        self
    }

    /// Replace the grant tokens. See [`Self::grant_tokens`].
    #[must_use]
    pub fn set_grant_tokens(mut self, grant_tokens: Option<Vec<String>>) -> Self {
        self.grant_tokens = grant_tokens;
        self
    }

    /// The AWS SDK configuration to make each KMS client from.
    /// Each client uses one of the configured regions.
    /// Optional with the `default-aws-sdk-clients` feature: the default uses your AWS credentials.
    #[must_use]
    pub fn sdk_config(mut self, sdk_config: SdkConfig) -> Self {
        self.sdk_config = Some(sdk_config);
        self
    }

    /// The AWS SDK configuration. See [`Self::sdk_config`].
    #[must_use]
    pub fn set_sdk_config(mut self, sdk_config: Option<SdkConfig>) -> Self {
        self.sdk_config = sdk_config;
        self
    }

    /// Build the keyring.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): no region,
    ///   a blank region,
    ///   a grant token list that is too long or has a token of the wrong length,
    ///   or no `sdk_config` without the `default-aws-sdk-clients` feature.
    pub async fn build(self) -> Result<MultiKeyring, Error> {
        let grant_tokens = valid_grant_tokens(self.grant_tokens)?;
        let regions = self.regions.unwrap_or_default();
        if regions.is_empty() {
            return Err(Error::validation("No regions passed."));
        }
        if regions.iter().any(String::is_empty) {
            return Err(Error::validation("Empty string is not a valid region."));
        }
        let mut clients = RegionalClients::new(self.sdk_config).await?;
        let mut child_keyrings = Vec::with_capacity(regions.len());
        for region in regions {
            let keyring = AwsKmsDiscoveryKeyring::builder()
                .kms_client(clients.client(Some(region)))
                .set_discovery_filter(self.discovery_filter.clone())
                .set_grant_tokens(Some(grant_tokens.clone()))
                .build()
                .await?;
            child_keyrings.push(SharedKeyring::new(keyring));
        }
        MultiKeyring::from_parts(None, child_keyrings)
    }
}

/// The key ID of a multi-Region AWS KMS key identifier (`mrk-...`), or `None` for any other key.
fn mrk_key_id(kms_key_id: &str) -> Option<&str> {
    let resource = match kms_key_id.split(':').collect::<Vec<_>>().as_slice() {
        ["arn", _, _, _, _, resource] => *resource,
        _ => kms_key_id,
    };
    let key_id = resource.strip_prefix("key/").unwrap_or(resource);
    (key_id.starts_with("mrk-") && !resource.starts_with("alias/")).then_some(key_id)
}

/// Fail when two of `kms_key_ids` name the same multi-Region key, in the same or different regions.
fn mrks_are_unique<'a>(kms_key_ids: impl Iterator<Item = &'a String> + Clone) -> Result<(), Error> {
    let mut seen = std::collections::HashSet::new();
    let duplicated: std::collections::HashSet<&str> = kms_key_ids
        .clone()
        .filter_map(|id| mrk_key_id(id))
        .filter(|key_id| !seen.insert(*key_id))
        .collect();
    if duplicated.is_empty() {
        return Ok(());
    }
    let duplicates: Vec<&str> = kms_key_ids
        .filter(|id| mrk_key_id(id).is_some_and(|key_id| duplicated.contains(key_id)))
        .map(String::as_str)
        .collect();
    Err(Error::validation(format!(
        "Related multi-Region keys: {}are not allowed.",
        duplicates.join(",")
    )))
}

/// Builder for a [`MultiKeyring`] of [`AwsKmsMrkKeyring`]s.
/// Start it with [`MultiKeyring::aws_kms_mrk`].
///
/// The generator key makes and wraps the data key; each other key also wraps it.
/// Each keyring gets a KMS client in its key's region.
/// On decrypt, each keyring also accepts data keys wrapped by a replica of its multi-Region key.
/// No two keys may be the same multi-Region key.
///
/// ```no_run
/// use aws_crypto_mpl::keyring::MultiKeyring;
///
/// # async fn example() -> Result<(), aws_crypto_mpl::Error> {
/// let keyring = MultiKeyring::aws_kms_mrk()
///     .generator("arn:aws:kms:us-west-2:111122223333:key/mrk-1234abcd12ab34cd56ef1234567890ab")
///     .kms_key_ids("arn:aws:kms:eu-west-1:111122223333:key/0987dcba-09fe-87dc-65ba-ab0987654321")
///     .build()
///     .await?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct AwsKmsMrkMultiKeyringBuilder {
    generator: Option<String>,
    kms_key_ids: Option<Vec<String>>,
    grant_tokens: Option<Vec<String>>,
    sdk_config: Option<SdkConfig>,
}

impl AwsKmsMrkMultiKeyringBuilder {
    /// The AWS KMS key that makes the data key.
    /// Optional, but the keyring cannot make a data key without one.
    #[must_use]
    pub fn generator(mut self, generator: impl Into<String>) -> Self {
        self.generator = Some(generator.into());
        self
    }

    /// The generator key. See [`Self::generator`].
    #[must_use]
    pub fn set_generator(mut self, generator: Option<String>) -> Self {
        self.generator = generator;
        self
    }

    /// Add an AWS KMS key that also wraps the data key.
    #[must_use]
    pub fn kms_key_ids(mut self, kms_key_id: impl Into<String>) -> Self {
        self.kms_key_ids
            .get_or_insert_with(Vec::new)
            .push(kms_key_id.into());
        self
    }

    /// Replace the other AWS KMS keys. See [`Self::kms_key_ids`].
    #[must_use]
    pub fn set_kms_key_ids(mut self, kms_key_ids: Option<Vec<String>>) -> Self {
        self.kms_key_ids = kms_key_ids;
        self
    }

    /// Add a grant token, sent with every AWS KMS request.
    #[must_use]
    pub fn grant_tokens(mut self, grant_token: impl Into<String>) -> Self {
        self.grant_tokens
            .get_or_insert_with(Vec::new)
            .push(grant_token.into());
        self
    }

    /// Replace the grant tokens. See [`Self::grant_tokens`].
    #[must_use]
    pub fn set_grant_tokens(mut self, grant_tokens: Option<Vec<String>>) -> Self {
        self.grant_tokens = grant_tokens;
        self
    }

    /// The AWS SDK configuration to make each KMS client from.
    /// The client for a key ARN uses the ARN's region; the client for any other key uses this configuration's region.
    /// Optional with the `default-aws-sdk-clients` feature: the default uses your AWS credentials and region.
    #[must_use]
    pub fn sdk_config(mut self, sdk_config: SdkConfig) -> Self {
        self.sdk_config = Some(sdk_config);
        self
    }

    /// The AWS SDK configuration. See [`Self::sdk_config`].
    #[must_use]
    pub fn set_sdk_config(mut self, sdk_config: Option<SdkConfig>) -> Self {
        self.sdk_config = sdk_config;
        self
    }

    /// Build the keyring.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): no generator and no other key,
    ///   a malformed key identifier,
    ///   two keys that are the same multi-Region key,
    ///   a grant token list that is too long or has a token of the wrong length,
    ///   or no `sdk_config` without the `default-aws-sdk-clients` feature.
    pub async fn build(self) -> Result<MultiKeyring, Error> {
        let grant_tokens = valid_grant_tokens(self.grant_tokens)?;
        let kms_key_ids = self.kms_key_ids.unwrap_or_default();
        for kms_key_id in self.generator.iter().chain(&kms_key_ids) {
            parse_kms_identifier(kms_key_id).map_err(Error::validation)?;
        }
        mrks_are_unique(self.generator.iter().chain(&kms_key_ids))?;
        let mut clients = RegionalClients::new(self.sdk_config).await?;
        let mut generator = None;
        if let Some(kms_key_id) = self.generator {
            let client = clients.client(region_of(&kms_key_id));
            generator = Some(aws_kms_mrk_keyring(kms_key_id, client, &grant_tokens).await?);
        }
        let mut child_keyrings = Vec::with_capacity(kms_key_ids.len());
        for kms_key_id in kms_key_ids {
            let client = clients.client(region_of(&kms_key_id));
            child_keyrings.push(aws_kms_mrk_keyring(kms_key_id, client, &grant_tokens).await?);
        }
        if generator.is_none() && child_keyrings.is_empty() {
            return Err(Error::validation(
                "generatorKeyring or child Keyrings needed to create a multi keyring",
            ));
        }
        MultiKeyring::from_parts(generator, child_keyrings)
    }
}

/// Builder for a [`MultiKeyring`] of [`AwsKmsMrkDiscoveryKeyring`]s.
/// Start it with [`MultiKeyring::aws_kms_mrk_discovery`].
///
/// Each region gets an MRK discovery keyring with a KMS client in that region,
/// so the multi-keyring decrypts data keys wrapped by AWS KMS keys in any of those regions,
/// and by multi-Region keys that have a replica in any of them.
///
/// ```no_run
/// use aws_crypto_mpl::keyring::{DiscoveryFilter, MultiKeyring};
///
/// # async fn example() -> Result<(), aws_crypto_mpl::Error> {
/// let keyring = MultiKeyring::aws_kms_mrk_discovery()
///     .regions("us-west-2")
///     .regions("eu-west-1")
///     .discovery_filter(
///         DiscoveryFilter::builder()
///             .partition("aws")
///             .account_ids("111122223333")
///             .build()?,
///     )
///     .build()
///     .await?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct AwsKmsMrkDiscoveryMultiKeyringBuilder {
    regions: Option<Vec<String>>,
    discovery_filter: Option<DiscoveryFilter>,
    grant_tokens: Option<Vec<String>>,
    sdk_config: Option<SdkConfig>,
}

impl AwsKmsMrkDiscoveryMultiKeyringBuilder {
    /// Add an AWS region.
    /// At least one is required.
    #[must_use]
    pub fn regions(mut self, region: impl Into<String>) -> Self {
        self.regions
            .get_or_insert_with(Vec::new)
            .push(region.into());
        self
    }

    /// Replace the regions. See [`Self::regions`].
    #[must_use]
    pub fn set_regions(mut self, regions: Option<Vec<String>>) -> Self {
        self.regions = regions;
        self
    }

    /// Use only the AWS KMS keys that this filter allows.
    /// Optional: with no filter, the keyring tries any AWS KMS key.
    #[must_use]
    pub fn discovery_filter(mut self, discovery_filter: DiscoveryFilter) -> Self {
        self.discovery_filter = Some(discovery_filter);
        self
    }

    /// The discovery filter. See [`Self::discovery_filter`].
    #[must_use]
    pub fn set_discovery_filter(mut self, discovery_filter: Option<DiscoveryFilter>) -> Self {
        self.discovery_filter = discovery_filter;
        self
    }

    /// Add a grant token, sent with every AWS KMS request.
    #[must_use]
    pub fn grant_tokens(mut self, grant_token: impl Into<String>) -> Self {
        self.grant_tokens
            .get_or_insert_with(Vec::new)
            .push(grant_token.into());
        self
    }

    /// Replace the grant tokens. See [`Self::grant_tokens`].
    #[must_use]
    pub fn set_grant_tokens(mut self, grant_tokens: Option<Vec<String>>) -> Self {
        self.grant_tokens = grant_tokens;
        self
    }

    /// The AWS SDK configuration to make each KMS client from.
    /// Each client uses one of the configured regions.
    /// Optional with the `default-aws-sdk-clients` feature: the default uses your AWS credentials.
    #[must_use]
    pub fn sdk_config(mut self, sdk_config: SdkConfig) -> Self {
        self.sdk_config = Some(sdk_config);
        self
    }

    /// The AWS SDK configuration. See [`Self::sdk_config`].
    #[must_use]
    pub fn set_sdk_config(mut self, sdk_config: Option<SdkConfig>) -> Self {
        self.sdk_config = sdk_config;
        self
    }

    /// Build the keyring.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): no region,
    ///   a blank region,
    ///   a grant token list that is too long or has a token of the wrong length,
    ///   or no `sdk_config` without the `default-aws-sdk-clients` feature.
    pub async fn build(self) -> Result<MultiKeyring, Error> {
        let grant_tokens = valid_grant_tokens(self.grant_tokens)?;
        let regions = self.regions.unwrap_or_default();
        if regions.is_empty() {
            return Err(Error::validation("No regions passed."));
        }
        if regions.iter().any(String::is_empty) {
            return Err(Error::validation("Empty string is not a valid region."));
        }
        let mut clients = RegionalClients::new(self.sdk_config).await?;
        let mut child_keyrings = Vec::with_capacity(regions.len());
        for region in regions {
            let keyring = AwsKmsMrkDiscoveryKeyring::builder()
                .kms_client(clients.client(Some(region.clone())))
                .region(region)
                .set_discovery_filter(self.discovery_filter.clone())
                .set_grant_tokens(Some(grant_tokens.clone()))
                .build()
                .await?;
            child_keyrings.push(SharedKeyring::new(keyring));
        }
        MultiKeyring::from_parts(None, child_keyrings)
    }
}

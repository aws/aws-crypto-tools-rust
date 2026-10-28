// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The AWS KMS discovery keyring: unwraps data keys with whichever AWS KMS key wrapped them.

use std::borrow::Cow;
use std::sync::Arc;

use async_trait::async_trait;
use aws_sdk_kms::Client as KmsClient;

use crate::Error;
use crate::aws_kms::aws_kms_keyring::{
    PROVIDER_ID, decrypt_edk, kms_encryption_context, parse_kms_arn, valid_grant_tokens,
};
use crate::builder::required;
use crate::error::{DataKeyInfo, Kind};
use crate::keyring::{Keyring, OnDecryptInput, OnDecryptOutput, OnEncryptInput, OnEncryptOutput};
use crate::structures::EncryptedDataKey;

/// Limits a discovery keyring to the AWS KMS keys of some AWS accounts in one partition.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct DiscoveryFilter {
    partition: String,
    account_ids: Vec<String>,
}

impl DiscoveryFilter {
    /// Start a builder.
    #[must_use]
    pub fn builder() -> DiscoveryFilterBuilder {
        DiscoveryFilterBuilder::default()
    }

    /// The AWS partition, such as `aws`.
    #[must_use]
    pub fn partition(&self) -> &str {
        &self.partition
    }

    /// The AWS accounts whose keys the keyring may use.
    #[must_use]
    pub fn account_ids(&self) -> &[String] {
        &self.account_ids
    }

    /// Whether the AWS KMS key ARN with this partition and account passes the filter.
    fn allows(&self, partition: &str, account: &str) -> bool {
        self.partition == partition && self.account_ids.iter().any(|a| a == account)
    }
}

/// Builder for [`DiscoveryFilter`].
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct DiscoveryFilterBuilder {
    partition: Option<String>,
    account_ids: Option<Vec<String>>,
}

impl DiscoveryFilterBuilder {
    /// The AWS partition, such as `aws`. Required.
    #[must_use]
    pub fn partition(mut self, partition: impl Into<String>) -> Self {
        self.partition = Some(partition.into());
        self
    }

    /// The AWS partition. See [`Self::partition`].
    #[must_use]
    pub fn set_partition(mut self, partition: Option<String>) -> Self {
        self.partition = partition;
        self
    }

    /// Add an AWS account whose keys the keyring may use. At least one is required.
    #[must_use]
    pub fn account_ids(mut self, account_id: impl Into<String>) -> Self {
        self.account_ids
            .get_or_insert_with(Vec::new)
            .push(account_id.into());
        self
    }

    /// Replace the AWS accounts. See [`Self::account_ids`].
    #[must_use]
    pub fn set_account_ids(mut self, account_ids: Option<Vec<String>>) -> Self {
        self.account_ids = account_ids;
        self
    }

    /// Build the filter.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): the partition is unset or blank,
    ///   or there is no account ID, or an account ID is blank.
    pub fn build(self) -> Result<DiscoveryFilter, Error> {
        let partition = required(self.partition, "partition")?;
        let account_ids = self.account_ids.unwrap_or_default();
        if account_ids.is_empty() {
            return Err(Error::validation(
                "Discovery filter must have at least one account ID",
            ));
        }
        if account_ids.iter().any(String::is_empty) {
            return Err(Error::validation(
                "Discovery filter account IDs cannot be blank",
            ));
        }
        if partition.is_empty() {
            return Err(Error::validation(
                "Discovery filter partition cannot be blank",
            ));
        }
        Ok(DiscoveryFilter {
            partition,
            account_ids,
        })
    }
}

/// A keyring that decrypts with the AWS KMS key named in each encrypted data key.
///
/// It cannot encrypt. On decrypt it tries every `aws-kms` encrypted data key the
/// [`DiscoveryFilter`] allows, calling AWS KMS `Decrypt` with the key ARN the data key names.
/// The KMS client must be in that key's region.
///
/// ```no_run
/// use aws_crypto_mpl::keyring::{AwsKmsDiscoveryKeyring, DiscoveryFilter};
///
/// # async fn example() -> Result<(), aws_crypto_mpl::Error> {
/// let sdk_config = aws_crypto_mpl::aws_config::load_defaults(aws_crypto_mpl::aws_config::BehaviorVersion::latest()).await;
/// let keyring = AwsKmsDiscoveryKeyring::builder()
///     .kms_client(aws_crypto_mpl::aws_sdk_kms::Client::new(&sdk_config))
///     .discovery_filter(
///         DiscoveryFilter::builder()
///             .partition("aws")
///             .account_ids("111122223333")
///             .build()?,
///     )
///     .build()?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct AwsKmsDiscoveryKeyring {
    inner: Arc<AwsKmsDiscoveryKeyringInner>,
}

struct AwsKmsDiscoveryKeyringInner {
    client: KmsClient,
    discovery_filter: Option<DiscoveryFilter>,
    grant_tokens: Vec<String>,
}

impl std::fmt::Debug for AwsKmsDiscoveryKeyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsKmsDiscoveryKeyring")
            .field("discovery_filter", &self.inner.discovery_filter)
            .finish_non_exhaustive()
    }
}

impl AwsKmsDiscoveryKeyring {
    /// `aws-kms-discovery`, which errors show.
    #[must_use]
    pub fn name(&self) -> Cow<'_, str> {
        Cow::Borrowed("aws-kms-discovery")
    }

    /// Start a builder.
    #[must_use]
    pub fn builder() -> AwsKmsDiscoveryKeyringBuilder {
        AwsKmsDiscoveryKeyringBuilder::default()
    }

    /// The filter on the AWS KMS keys this keyring uses, if any.
    #[must_use]
    pub fn discovery_filter(&self) -> Option<&DiscoveryFilter> {
        self.inner.discovery_filter.as_ref()
    }

    /// The grant tokens sent with every AWS KMS request.
    #[must_use]
    pub fn grant_tokens(&self) -> &[String] {
        &self.inner.grant_tokens
    }

    /// The key ARN of `edk` when this keyring should try it.
    fn key_arn<'a>(&self, edk: &'a EncryptedDataKey) -> Result<Option<&'a str>, Error> {
        if edk.key_provider_id() != PROVIDER_ID {
            return Ok(None);
        }
        let key_id = std::str::from_utf8(edk.key_provider_info()).map_err(|_| {
            Error::new(
                Kind::Cryptographic,
                "Invalid AWS KMS encoding, provider info is not UTF8.",
            )
        })?;
        let arn = parse_kms_arn(key_id).map_err(|e| Error::new(Kind::Cryptographic, e))?;
        if arn.resource_type != "key" {
            return Err(Error::new(
                Kind::Cryptographic,
                "Only AWS KMS Keys supported",
            ));
        }
        // A parsed ARN has six `:`-separated parts: arn:partition:kms:region:account:resource.
        let parts: Vec<&str> = key_id.split(':').collect();
        let allowed = self
            .inner
            .discovery_filter
            .as_ref()
            .is_none_or(|filter| filter.allows(parts[1], parts[4]));
        Ok(allowed.then_some(key_id))
    }
}

/// Builder for [`AwsKmsDiscoveryKeyring`].
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct AwsKmsDiscoveryKeyringBuilder {
    kms_client: Option<KmsClient>,
    discovery_filter: Option<DiscoveryFilter>,
    grant_tokens: Option<Vec<String>>,
}

impl AwsKmsDiscoveryKeyringBuilder {
    /// The AWS KMS client. Required.
    #[must_use]
    pub fn kms_client(mut self, kms_client: KmsClient) -> Self {
        self.kms_client = Some(kms_client);
        self
    }

    /// The AWS KMS client. See [`Self::kms_client`].
    #[must_use]
    pub fn set_kms_client(mut self, kms_client: Option<KmsClient>) -> Self {
        self.kms_client = kms_client;
        self
    }

    /// Use only the AWS KMS keys this filter allows. Optional: without one, any key.
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

    /// Build the keyring.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): no client, more than 10 grant tokens,
    ///   or a grant token of the wrong length.
    pub fn build(self) -> Result<AwsKmsDiscoveryKeyring, Error> {
        let client = required(self.kms_client, "kms_client")?;
        let grant_tokens = valid_grant_tokens(self.grant_tokens)?;
        Ok(AwsKmsDiscoveryKeyring {
            inner: Arc::new(AwsKmsDiscoveryKeyringInner {
                client,
                discovery_filter: self.discovery_filter,
                grant_tokens,
            }),
        })
    }
}

#[async_trait]
impl Keyring for crate::shared::Builtin<AwsKmsDiscoveryKeyring> {
    fn name(&self) -> Cow<'_, str> {
        self.0.name()
    }

    async fn on_encrypt(&self, _input: OnEncryptInput) -> Result<OnEncryptOutput, Error> {
        Err(Error::validation(
            "Encryption is not supported with a Discovery Keyring.",
        ))
    }

    async fn on_decrypt(&self, input: OnDecryptInput) -> Result<OnDecryptOutput, Error> {
        let (materials, encrypted_data_keys) = input.into_parts();
        if materials.plaintext_data_key().is_some() {
            return Err(Error::new(
                Kind::InvalidMaterials,
                "Keyring received decryption materials that already contain a plaintext data key.",
            ));
        }
        let mut to_attempt = Vec::new();
        for edk in &encrypted_data_keys {
            if let Some(key_arn) = self.key_arn(edk)? {
                to_attempt.push((key_arn, edk));
            }
        }
        if to_attempt.is_empty() {
            return Err(Error::no_matching_data_key(
                "no encrypted data key was written by an AWS KMS key the discovery filter allows",
            )
            .with_encrypted_data_keys(encrypted_data_keys.iter().map(DataKeyInfo::from)));
        }
        let ec = kms_encryption_context(materials.encryption_context());
        let aad = materials
            .encryption_context()
            .serialize()
            .map_err(|e| Error::wrap("failed to serialize the encryption context", e))?;
        let mut errors = Vec::new();
        for (key_arn, edk) in to_attempt {
            let attempt = decrypt_edk(
                &self.inner.client,
                key_arn,
                &self.inner.grant_tokens,
                &materials,
                &ec,
                &aad,
                edk,
            )
            .await;
            match attempt {
                Ok(materials) => return OnDecryptOutput::builder().materials(materials).build(),
                Err(e) => errors.push(e),
            }
        }
        Err(Error::all_failed(
            "No Configured KMS Key was able to decrypt the Data Key.",
            errors,
        ))
    }
}

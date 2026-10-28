// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The AWS KMS multi-Region key (MRK) discovery keyring: unwraps data keys with
//! whichever AWS KMS key wrapped them, using the replica in its own region for a
//! multi-Region key.

use std::borrow::Cow;
use std::sync::Arc;

use async_trait::async_trait;
use aws_sdk_kms::Client as KmsClient;

use crate::Error;
use crate::aws_kms::aws_kms_keyring::{
    PROVIDER_ID, decrypt_edk, kms_encryption_context, parse_kms_arn, valid_grant_tokens,
};
use crate::aws_kms::discovery_keyring::DiscoveryFilter;
use crate::builder::required;
use crate::error::{DataKeyInfo, Kind};
use crate::keyring::{Keyring, OnDecryptInput, OnDecryptOutput, OnEncryptInput, OnEncryptOutput};
use crate::structures::EncryptedDataKey;

/// A keyring that decrypts with the AWS KMS key named in each encrypted data key,
/// in its own region.
///
/// It cannot encrypt. On decrypt it tries every `aws-kms` encrypted data key the
/// [`DiscoveryFilter`] allows whose key is in this keyring's region, or is a
/// multi-Region key in any region. For a multi-Region key it calls AWS KMS `Decrypt`
/// with the key ARN rewritten to this keyring's region, so it decrypts with the local replica.
/// The KMS client must be in the keyring's region.
///
/// ```no_run
/// use aws_crypto_mpl::keyring::{AwsKmsMrkDiscoveryKeyring, DiscoveryFilter};
///
/// # async fn example() -> Result<(), aws_crypto_mpl::Error> {
/// let sdk_config = aws_crypto_mpl::aws_config::load_defaults(aws_crypto_mpl::aws_config::BehaviorVersion::latest()).await;
/// let keyring = AwsKmsMrkDiscoveryKeyring::builder()
///     .kms_client(aws_crypto_mpl::aws_sdk_kms::Client::new(&sdk_config))
///     .region("us-east-1")
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
pub struct AwsKmsMrkDiscoveryKeyring {
    inner: Arc<AwsKmsMrkDiscoveryKeyringInner>,
}

struct AwsKmsMrkDiscoveryKeyringInner {
    client: KmsClient,
    region: String,
    discovery_filter: Option<DiscoveryFilter>,
    grant_tokens: Vec<String>,
}

impl std::fmt::Debug for AwsKmsMrkDiscoveryKeyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsKmsMrkDiscoveryKeyring")
            .field("region", &self.inner.region)
            .field("discovery_filter", &self.inner.discovery_filter)
            .finish_non_exhaustive()
    }
}

impl AwsKmsMrkDiscoveryKeyring {
    /// `aws-kms-mrk-discovery` and the region, which errors show.
    #[must_use]
    pub fn name(&self) -> Cow<'_, str> {
        Cow::Owned(format!("aws-kms-mrk-discovery {}", self.inner.region))
    }

    /// Start a builder.
    #[must_use]
    pub fn builder() -> AwsKmsMrkDiscoveryKeyringBuilder {
        AwsKmsMrkDiscoveryKeyringBuilder::default()
    }

    /// The region this keyring decrypts in.
    #[must_use]
    pub fn region(&self) -> &str {
        &self.inner.region
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

    /// The key ARN to call AWS KMS `Decrypt` with for `edk`, when this keyring should try it.
    fn key_arn(&self, edk: &EncryptedDataKey) -> Result<Option<String>, Error> {
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
        let mut parts: Vec<&str> = key_id.split(':').collect();
        let is_mrk = parts[5].starts_with("key/mrk-");
        let filter_allows = self
            .inner
            .discovery_filter
            .as_ref()
            .is_none_or(|filter| filter.allows(parts[1], parts[4]));
        if !filter_allows || (!is_mrk && parts[3] != self.inner.region) {
            return Ok(None);
        }
        if is_mrk {
            parts[3] = &self.inner.region;
        }
        Ok(Some(parts.join(":")))
    }
}

/// Builder for [`AwsKmsMrkDiscoveryKeyring`].
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct AwsKmsMrkDiscoveryKeyringBuilder {
    kms_client: Option<KmsClient>,
    region: Option<String>,
    discovery_filter: Option<DiscoveryFilter>,
    grant_tokens: Option<Vec<String>>,
}

impl AwsKmsMrkDiscoveryKeyringBuilder {
    /// The AWS KMS client, in [`Self::region`]. Required.
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

    /// The region this keyring decrypts in. Required.
    #[must_use]
    pub fn region(mut self, region: impl Into<String>) -> Self {
        self.region = Some(region.into());
        self
    }

    /// The region. See [`Self::region`].
    #[must_use]
    pub fn set_region(mut self, region: Option<String>) -> Self {
        self.region = region;
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
    /// - [`Validation`](crate::Error::Validation): no client or region, a client whose
    ///   region is not the keyring's region, more than 10 grant tokens,
    ///   or a grant token of the wrong length.
    pub fn build(self) -> Result<AwsKmsMrkDiscoveryKeyring, Error> {
        let client = required(self.kms_client, "kms_client")?;
        let region = required(self.region, "region")?;
        if client
            .config()
            .region()
            .is_some_and(|client_region| client_region.as_ref() != region)
        {
            return Err(Error::validation("Provided client and region do not match"));
        }
        let grant_tokens = valid_grant_tokens(self.grant_tokens)?;
        Ok(AwsKmsMrkDiscoveryKeyring {
            inner: Arc::new(AwsKmsMrkDiscoveryKeyringInner {
                client,
                region,
                discovery_filter: self.discovery_filter,
                grant_tokens,
            }),
        })
    }
}

#[async_trait]
impl Keyring for crate::shared::Builtin<AwsKmsMrkDiscoveryKeyring> {
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
            return Err(Error::no_matching_data_key(format!(
                "no encrypted data key was written by an AWS KMS key the discovery filter allows \
                 in region {}",
                self.inner.region
            ))
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
                &key_arn,
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

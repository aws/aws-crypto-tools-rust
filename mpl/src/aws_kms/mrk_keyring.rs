// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The AWS KMS multi-Region key (MRK) keyring.
//! It works like the AWS KMS keyring,
//! and also decrypts data keys wrapped by a replica of its multi-Region key in another region.

use std::borrow::Cow;

use async_trait::async_trait;
use aws_sdk_kms::Client as KmsClient;

use crate::Error;
use crate::aws_kms::aws_kms_keyring::AwsKmsKeyring;
use crate::aws_kms::mrk_match::aws_kms_mrk_match_for_decrypt;
use crate::keyring::{Keyring, OnDecryptInput, OnDecryptOutput, OnEncryptInput, OnEncryptOutput};

/// A keyring that protects each data key with one AWS KMS key.
/// When that key is a multi-Region key, decrypting also accepts a data key wrapped by any replica of it.
///
/// It encrypts exactly like [`AwsKmsKeyring`].
/// On decrypt, it tries each `aws-kms` encrypted data key whose key ARN is this keyring's key,
/// or a multi-Region key that differs from this keyring's key only in region.
/// It calls AWS KMS `Decrypt` with this keyring's own key, so the KMS client must be in that key's region.
///
/// ```no_run
/// use aws_crypto_mpl::keyring::AwsKmsMrkKeyring;
///
/// # async fn example() -> Result<(), aws_crypto_mpl::Error> {
/// let sdk_config = aws_crypto_mpl::aws_config::load_defaults(aws_crypto_mpl::aws_config::BehaviorVersion::latest()).await;
/// let keyring = AwsKmsMrkKeyring::builder()
///     .kms_key_id("arn:aws:kms:us-west-2:111122223333:key/mrk-1234abcd12ab34cd56ef1234567890ab")
///     .kms_client(aws_crypto_mpl::aws_sdk_kms::Client::new(&sdk_config))
///     .build()?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct AwsKmsMrkKeyring {
    inner: AwsKmsKeyring,
}

impl std::fmt::Debug for AwsKmsMrkKeyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsKmsMrkKeyring")
            .field("kms_key_id", &self.inner.kms_key_id())
            .finish_non_exhaustive()
    }
}

impl AwsKmsMrkKeyring {
    /// The name that error messages show for this keyring: `aws-kms-mrk` and the KMS key identifier.
    #[must_use]
    pub fn name(&self) -> Cow<'_, str> {
        Cow::Owned(format!("aws-kms-mrk {}", self.inner.kms_key_id()))
    }

    /// Start a builder.
    #[must_use]
    pub fn builder() -> AwsKmsMrkKeyringBuilder {
        AwsKmsMrkKeyringBuilder::default()
    }

    /// The AWS KMS key identifier that this keyring uses.
    #[must_use]
    pub fn kms_key_id(&self) -> &str {
        self.inner.kms_key_id()
    }

    /// The grant tokens that this keyring sends with every AWS KMS request.
    #[must_use]
    pub fn grant_tokens(&self) -> &[String] {
        self.inner.grant_tokens()
    }
}

/// Builder for [`AwsKmsMrkKeyring`].
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct AwsKmsMrkKeyringBuilder {
    kms_key_id: Option<String>,
    kms_client: Option<KmsClient>,
    grant_tokens: Option<Vec<String>>,
}

impl AwsKmsMrkKeyringBuilder {
    /// The AWS KMS key: a key ARN, key ID, alias name, or alias ARN.
    /// Required.
    ///
    /// Decrypting needs a key ARN.
    #[must_use]
    pub fn kms_key_id(mut self, kms_key_id: impl Into<String>) -> Self {
        self.kms_key_id = Some(kms_key_id.into());
        self
    }

    /// The AWS KMS key. See [`Self::kms_key_id`].
    #[must_use]
    pub fn set_kms_key_id(mut self, kms_key_id: Option<String>) -> Self {
        self.kms_key_id = kms_key_id;
        self
    }

    /// The AWS KMS client, in the key's region.
    /// Required.
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
    /// - [`Validation`](crate::Error::Validation): no key or client,
    ///   a malformed key identifier,
    ///   more than 10 grant tokens,
    ///   or a grant token of the wrong length.
    pub fn build(self) -> Result<AwsKmsMrkKeyring, Error> {
        let inner = AwsKmsKeyring::builder()
            .set_kms_key_id(self.kms_key_id)
            .set_kms_client(self.kms_client)
            .set_grant_tokens(self.grant_tokens)
            .build()?;
        Ok(AwsKmsMrkKeyring { inner })
    }
}

#[async_trait]
impl Keyring for crate::shared::Builtin<AwsKmsMrkKeyring> {
    fn name(&self) -> Cow<'_, str> {
        self.0.name()
    }

    async fn on_encrypt(&self, input: OnEncryptInput) -> Result<OnEncryptOutput, Error> {
        let materials = self.0.inner.wrap_materials(input.into_materials()).await?;
        OnEncryptOutput::builder().materials(materials).build()
    }

    async fn on_decrypt(&self, input: OnDecryptInput) -> Result<OnDecryptOutput, Error> {
        self.0
            .inner
            .unwrap_materials(input, aws_kms_mrk_match_for_decrypt)
            .await
    }
}

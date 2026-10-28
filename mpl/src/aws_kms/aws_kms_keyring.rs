// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The AWS KMS keyring: wraps and unwraps data keys with a single AWS KMS key.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use aws_mpl_primitives::generate_random_bytes;
use aws_sdk_kms::Client as KmsClient;
use aws_sdk_kms::primitives::Blob;

use crate::Error;
use crate::aws_kms::user_agent::user_agent_override;
use crate::builder::required;
use crate::error::{DataKeyInfo, Kind, KmsKey, Resource, Service};
use crate::keyring::edk_wrapping;
use crate::keyring::{Keyring, OnDecryptInput, OnDecryptOutput, OnEncryptInput, OnEncryptOutput};
use crate::structures::{
    AlgorithmSuite, DecryptionMaterials, EdkWrapping, EncryptedDataKey, EncryptionContext,
    PlaintextDataKey,
};

/// The key provider ID of every encrypted data key this keyring writes.
pub(crate) const PROVIDER_ID: &str = "aws-kms";
/// The longest AWS KMS key identifier.
const MAX_AWS_KMS_IDENTIFIER_LENGTH: usize = 2048;
/// AWS KMS ciphertexts are 1 to 6144 bytes.
const MAX_CIPHERTEXT_LENGTH: usize = 6144;
/// AWS KMS accepts at most this many grant tokens.
const MAX_GRANT_TOKENS: usize = 10;
const MAX_GRANT_TOKEN_LENGTH: usize = 8192;
const UINT16_LIMIT: usize = 65_536;

/// A parsed AWS KMS key identifier: an ARN or a raw key ID or alias.
pub(crate) struct KmsIdentifier {
    is_arn: bool,
    pub(crate) resource_type: String,
}

/// Parse `resource` as `key/<id>` or `alias/<name>`.
fn parse_kms_resource(resource: &str) -> Result<String, String> {
    let Some((resource_type, value)) = resource.split_once('/') else {
        return Err(format!("Malformed resource: {resource}"));
    };
    if value.is_empty() || (resource_type != "key" && resource_type != "alias") {
        return Err(format!("Malformed resource: {resource}"));
    }
    Ok(resource_type.to_owned())
}

/// Parse an AWS KMS key ARN: `arn:<partition>:kms:<region>:<account>:<key|alias>/<id>`.
pub(crate) fn parse_kms_arn(identifier: &str) -> Result<KmsIdentifier, String> {
    let components: Vec<&str> = identifier.split(':').collect();
    let [literal, partition, service, region, account, resource] = components.as_slice() else {
        return Err(format!("Malformed arn: {identifier}"));
    };
    let resource_type = parse_kms_resource(resource)?;
    if *literal != "arn"
        || partition.is_empty()
        || *service != "kms"
        || region.is_empty()
        || account.is_empty()
    {
        return Err(format!("Malformed Arn:{identifier}"));
    }
    Ok(KmsIdentifier {
        is_arn: true,
        resource_type,
    })
}

/// Parse a KMS key identifier: an ARN, an alias (`alias/<name>`), or a key ID.
pub(crate) fn parse_kms_identifier(identifier: &str) -> Result<KmsIdentifier, String> {
    if identifier.starts_with("arn:") {
        return parse_kms_arn(identifier);
    }
    if identifier.split('/').next() == Some("key") {
        return Err(format!("Malformed raw key id: {identifier}"));
    }
    let resource_type = if identifier.contains('/') {
        parse_kms_resource(identifier)?
    } else {
        parse_kms_resource(&format!("key/{identifier}"))?
    };
    Ok(KmsIdentifier {
        is_arn: false,
        resource_type,
    })
}

/// A keyring that protects each data key with one AWS KMS key.
///
/// On encrypt it calls AWS KMS `GenerateDataKey` (or `Encrypt` when the materials already
/// have a data key). On decrypt it tries only the encrypted data keys this KMS key wrote,
/// so decrypting needs the key's ARN, not an alias.
///
/// ```no_run
/// use aws_crypto_mpl::keyring::AwsKmsKeyring;
///
/// # async fn example() -> Result<(), aws_crypto_mpl::Error> {
/// let sdk_config = aws_crypto_mpl::aws_config::load_defaults(aws_crypto_mpl::aws_config::BehaviorVersion::latest()).await;
/// let keyring = AwsKmsKeyring::builder()
///     .kms_key_id("arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab")
///     .kms_client(aws_crypto_mpl::aws_sdk_kms::Client::new(&sdk_config))
///     .build()?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct AwsKmsKeyring {
    inner: Arc<AwsKmsKeyringInner>,
}

struct AwsKmsKeyringInner {
    kms_key_id: String,
    is_arn: bool,
    resource_type: String,
    client: KmsClient,
    grant_tokens: Vec<String>,
}

impl std::fmt::Debug for AwsKmsKeyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsKmsKeyring")
            .field("kms_key_id", &self.inner.kms_key_id)
            .finish_non_exhaustive()
    }
}

impl AwsKmsKeyring {
    /// `aws-kms` and the KMS key, which errors show.
    #[must_use]
    pub fn name(&self) -> Cow<'_, str> {
        Cow::Owned(format!("aws-kms {}", self.inner.kms_key_id))
    }

    /// Start a builder.
    #[must_use]
    pub fn builder() -> AwsKmsKeyringBuilder {
        AwsKmsKeyringBuilder::default()
    }

    /// The AWS KMS key identifier this keyring uses.
    #[must_use]
    pub fn kms_key_id(&self) -> &str {
        &self.inner.kms_key_id
    }

    /// The grant tokens sent with every AWS KMS request.
    #[must_use]
    pub fn grant_tokens(&self) -> &[String] {
        &self.inner.grant_tokens
    }

    fn resource(&self) -> Option<Resource> {
        Some(Resource::KmsKey(KmsKey::new(self.inner.kms_key_id.clone())))
    }

    fn service_err(&self, message: impl Into<String>) -> Error {
        service_err(&self.inner.kms_key_id, message)
    }

    /// `GenerateDataKey` of `len` bytes: the plaintext, the ciphertext, and the key ARN.
    async fn generate_data_key(
        &self,
        ec: &HashMap<String, String>,
        len: usize,
    ) -> Result<(PlaintextDataKey, Vec<u8>, String), Error> {
        let number_of_bytes = i32::try_from(len)
            .map_err(|_| Error::new(Kind::InvalidMaterials, "data key length too large"))?;
        let response = self
            .inner
            .client
            .generate_data_key()
            .key_id(&self.inner.kms_key_id)
            .number_of_bytes(number_of_bytes)
            .set_encryption_context(Some(ec.clone()))
            .set_grant_tokens(Some(self.inner.grant_tokens.clone()))
            .customize()
            .config_override(user_agent_override())
            .send()
            .await
            .map_err(|e| {
                Error::from_sdk(Service::Kms, "AWS KMS GenerateDataKey", self.resource(), e)
            })?;
        let key_id = response
            .key_id
            .filter(|id| parse_kms_identifier(id).is_ok())
            .ok_or_else(|| {
                self.service_err("Invalid response from KMS GenerateDataKey:: Invalid Key Id")
            })?;
        let plaintext = response
            .plaintext
            .map(Blob::into_inner)
            .filter(|p| p.len() == len)
            .ok_or_else(|| {
                self.service_err("Invalid response from AWS KMS GenerateDataKey: Invalid data key")
            })?;
        let ciphertext = response
            .ciphertext_blob
            .map(Blob::into_inner)
            .filter(|c| valid_ciphertext(c))
            .ok_or_else(|| {
                self.service_err(
                    "Invalid response from AWS KMS GeneratedDataKey: Invalid ciphertext",
                )
            })?;
        if response.ciphertext_for_recipient.is_some() {
            return Err(self.service_err(
                "Invalid response from AWS KMS GeneratedDataKey: Invalid CiphertextForRecipient",
            ));
        }
        Ok((PlaintextDataKey::new(plaintext), ciphertext, key_id))
    }

    /// `Encrypt` of `plaintext`: the ciphertext and the key ARN.
    async fn encrypt(
        &self,
        ec: &HashMap<String, String>,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, String), Error> {
        if plaintext.is_empty() || plaintext.len() > 4096 {
            return Err(Error::new(
                Kind::InvalidMaterials,
                "Invalid Plaintext on KMS Encrypt",
            ));
        }
        let response = self
            .inner
            .client
            .encrypt()
            .key_id(&self.inner.kms_key_id)
            .plaintext(Blob::new(plaintext))
            .set_encryption_context(Some(ec.clone()))
            .set_grant_tokens(Some(self.inner.grant_tokens.clone()))
            .customize()
            .config_override(user_agent_override())
            .send()
            .await
            .map_err(|e| Error::from_sdk(Service::Kms, "AWS KMS Encrypt", self.resource(), e))?;
        let key_id = response
            .key_id
            .filter(|id| parse_kms_identifier(id).is_ok())
            .ok_or_else(|| {
                self.service_err("Invalid response from AWS KMS Encrypt:: Invalid Key Id")
            })?;
        let ciphertext = response
            .ciphertext_blob
            .map(Blob::into_inner)
            .ok_or_else(|| {
                self.service_err("Invalid response from AWS KMS Encrypt: Invalid Ciphertext Blob")
            })?;
        Ok((ciphertext, key_id))
    }

    /// Whether `edk` was written by this keyring's KMS key.
    fn wrote(&self, edk: &EncryptedDataKey) -> Result<bool, Error> {
        if edk.key_provider_id() != PROVIDER_ID {
            return Ok(false);
        }
        let key_id = std::str::from_utf8(edk.key_provider_info()).map_err(|_| {
            Error::new(
                Kind::Cryptographic,
                "Invalid AWS KMS encoding, provider info is not UTF8.",
            )
        })?;
        parse_kms_arn(key_id).map_err(|e| Error::new(Kind::Cryptographic, e))?;
        Ok(self.inner.kms_key_id == key_id)
    }
}

/// A `Service` error about the AWS KMS key `key_id`.
fn service_err(key_id: &str, message: impl Into<String>) -> Error {
    Error::new(Kind::Service, message).about(
        Some(Service::Kms),
        Some(Resource::KmsKey(KmsKey::new(key_id.to_owned()))),
    )
}

/// `Decrypt` of `ciphertext` with the AWS KMS key `key_id`: the plaintext, of `len` bytes.
///
/// The response must name `key_id`.
async fn kms_decrypt(
    client: &KmsClient,
    key_id: &str,
    grant_tokens: &[String],
    ec: &HashMap<String, String>,
    ciphertext: &[u8],
    len: usize,
) -> Result<Vec<u8>, Error> {
    if !valid_ciphertext(ciphertext) {
        return Err(Error::new(Kind::Cryptographic, "Ciphertext length invalid"));
    }
    let resource = Some(Resource::KmsKey(KmsKey::new(key_id.to_owned())));
    let response = client
        .decrypt()
        .key_id(key_id)
        .ciphertext_blob(Blob::new(ciphertext))
        .set_encryption_context(Some(ec.clone()))
        .set_grant_tokens(Some(grant_tokens.to_vec()))
        .customize()
        .config_override(user_agent_override())
        .send()
        .await
        .map_err(|e| Error::from_sdk(Service::Kms, "AWS KMS Decrypt", resource, e))?;
    if response.key_id.as_deref() != Some(key_id) {
        return Err(service_err(key_id, "Invalid response from KMS Decrypt"));
    }
    response
        .plaintext
        .map(Blob::into_inner)
        .filter(|p| p.len() == len)
        .ok_or_else(|| service_err(key_id, "Invalid response from KMS Decrypt"))
}

/// Unwrap `edk` with the AWS KMS key `key_id` into the decryption materials.
pub(crate) async fn decrypt_edk(
    client: &KmsClient,
    key_id: &str,
    grant_tokens: &[String],
    materials: &DecryptionMaterials,
    ec: &HashMap<String, String>,
    aad: &[u8],
    edk: &EncryptedDataKey,
) -> Result<DecryptionMaterials, Error> {
    let suite = materials.algorithm_suite();
    let len = suite.encryption_key_length();
    match suite.edk_wrapping() {
        EdkWrapping::IntermediateKeyWrapping(_) => {
            let (encrypted_pdk, wrapped) = edk_wrapping::split(&suite, edk.ciphertext())?;
            let ikm = zeroize::Zeroizing::new(
                kms_decrypt(client, key_id, grant_tokens, ec, wrapped, len).await?,
            );
            let (pdk, signing_key) = edk_wrapping::decrypt_pdk(&suite, &ikm, aad, encrypted_pdk)?;
            materials
                .clone()
                .add_data_key_with_symmetric_signing_key(pdk, signing_key)
        }
        _ => {
            let pdk = kms_decrypt(client, key_id, grant_tokens, ec, edk.ciphertext(), len).await?;
            materials.clone().add_data_key(PlaintextDataKey::new(pdk))
        }
    }
}

/// The grant tokens, checked: at most 10, each 1 to 8192 characters.
pub(crate) fn valid_grant_tokens(grant_tokens: Option<Vec<String>>) -> Result<Vec<String>, Error> {
    let grant_tokens = grant_tokens.unwrap_or_default();
    if grant_tokens.len() > MAX_GRANT_TOKENS {
        return Err(Error::new(
            Kind::Validation,
            "Grant token list can have no more than 10 tokens",
        ));
    }
    if grant_tokens
        .iter()
        .any(|t| t.is_empty() || t.len() > MAX_GRANT_TOKEN_LENGTH)
    {
        return Err(Error::new(
            Kind::Validation,
            "Grant token list contains a grant token with invalid length",
        ));
    }
    Ok(grant_tokens)
}

fn valid_ciphertext(c: &[u8]) -> bool {
    (1..=MAX_CIPHERTEXT_LENGTH).contains(&c.len())
}

pub(crate) fn kms_encryption_context(ec: &EncryptionContext) -> HashMap<String, String> {
    ec.iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect()
}

fn random_key(suite: &AlgorithmSuite) -> Result<PlaintextDataKey, Error> {
    let mut bytes = vec![0u8; suite.encryption_key_length()];
    generate_random_bytes(&mut bytes).map_err(|e| {
        Error::with_cause(
            Kind::Cryptographic,
            "failed to obtain entropy for the plaintext data key",
            e,
        )
    })?;
    Ok(PlaintextDataKey::new(bytes))
}

fn kms_edk(key_id: String, ciphertext: Vec<u8>) -> Result<EncryptedDataKey, Error> {
    if key_id.len() >= UINT16_LIMIT {
        return Err(Error::new(
            Kind::Service,
            "Invalid response from AWS KMS GenerateDataKey: Key ID too long.",
        ));
    }
    EncryptedDataKey::builder()
        .key_provider_id(PROVIDER_ID)
        .key_provider_info(key_id.into_bytes())
        .ciphertext(ciphertext)
        .build()
}

/// Builder for [`AwsKmsKeyring`].
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct AwsKmsKeyringBuilder {
    kms_key_id: Option<String>,
    kms_client: Option<KmsClient>,
    grant_tokens: Option<Vec<String>>,
}

impl AwsKmsKeyringBuilder {
    /// The AWS KMS key: a key ARN, key ID, alias name, or alias ARN. Required.
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

    /// The AWS KMS client, in the key's region. Required.
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
    /// - [`Validation`](crate::Error::Validation): no key or client, a malformed key identifier,
    ///   or more than 10 grant tokens, or a grant token of the wrong length.
    pub fn build(self) -> Result<AwsKmsKeyring, Error> {
        let kms_key_id = required(self.kms_key_id, "kms_key_id")?;
        let client = required(self.kms_client, "kms_client")?;
        let parsed =
            parse_kms_identifier(&kms_key_id).map_err(|e| Error::new(Kind::Validation, e))?;
        if !kms_key_id.is_ascii() {
            return Err(Error::new(Kind::Validation, "Key identifier is not ASCII"));
        }
        if kms_key_id.is_empty() || kms_key_id.len() > MAX_AWS_KMS_IDENTIFIER_LENGTH {
            return Err(Error::new(Kind::Validation, "Key identifier is too long"));
        }
        let grant_tokens = valid_grant_tokens(self.grant_tokens)?;
        Ok(AwsKmsKeyring {
            inner: Arc::new(AwsKmsKeyringInner {
                kms_key_id,
                is_arn: parsed.is_arn,
                resource_type: parsed.resource_type,
                client,
                grant_tokens,
            }),
        })
    }
}

#[async_trait]
impl Keyring for crate::shared::Builtin<AwsKmsKeyring> {
    fn name(&self) -> Cow<'_, str> {
        self.0.name()
    }

    async fn on_encrypt(&self, input: OnEncryptInput) -> Result<OnEncryptOutput, Error> {
        let materials = input.into_materials();
        let suite = materials.algorithm_suite();
        let ec = kms_encryption_context(materials.encryption_context());
        let materials = match (suite.edk_wrapping(), materials.plaintext_data_key()) {
            (EdkWrapping::IntermediateKeyWrapping(_), existing) => {
                let aad = materials
                    .encryption_context()
                    .serialize()
                    .map_err(|e| Error::wrap("failed to serialize the encryption context", e))?;
                let (pdk, generated) = match existing {
                    Some(key) => (key.clone(), false),
                    None => (random_key(&suite)?, true),
                };
                let (ikm, wrapped, key_id) = self
                    .generate_data_key(&ec, suite.encryption_key_length())
                    .await?;
                let (mut ciphertext, signing_key) =
                    edk_wrapping::encrypt_pdk(&suite, ikm.as_bytes(), &aad, &pdk)?;
                ciphertext.extend_from_slice(&wrapped);
                let edk = kms_edk(key_id, ciphertext)?;
                if generated {
                    materials.add_data_key_with_symmetric_signing_key(pdk, edk, signing_key)?
                } else {
                    materials.add_encrypted_data_key_with_symmetric_signing_key(edk, signing_key)?
                }
            }
            (_, Some(pdk)) => {
                let (ciphertext, key_id) = self.encrypt(&ec, pdk.as_bytes()).await?;
                let edk = kms_edk(key_id, ciphertext)?;
                materials.add_encrypted_data_key(edk)?
            }
            (_, None) => {
                let (pdk, ciphertext, key_id) = self
                    .generate_data_key(&ec, suite.encryption_key_length())
                    .await?;
                let edk = kms_edk(key_id, ciphertext)?;
                materials.add_data_key(pdk, edk)?
            }
        };
        OnEncryptOutput::builder().materials(materials).build()
    }

    async fn on_decrypt(&self, input: OnDecryptInput) -> Result<OnDecryptOutput, Error> {
        let (materials, encrypted_data_keys) = input.into_parts();
        if materials.plaintext_data_key().is_some() {
            return Err(Error::new(
                Kind::InvalidMaterials,
                "Keyring received decryption materials that already contain a plaintext data key.",
            ));
        }
        if !self.inner.is_arn {
            return Err(Error::new(
                Kind::Validation,
                format!(
                    "KeyID cannot be used for Decrypt : {}",
                    self.inner.kms_key_id
                ),
            ));
        }
        if self.inner.resource_type != "key" {
            return Err(Error::new(
                Kind::Validation,
                format!(
                    "Alias cannot be used for Decrypt : {}",
                    self.inner.kms_key_id
                ),
            ));
        }
        let mut to_attempt = Vec::new();
        for edk in &encrypted_data_keys {
            if self.wrote(edk)? {
                to_attempt.push(edk);
            }
        }
        if to_attempt.is_empty() {
            return Err(Error::no_matching_data_key(format!(
                "no encrypted data key was written by AWS KMS key {}",
                self.inner.kms_key_id
            ))
            .with_encrypted_data_keys(encrypted_data_keys.iter().map(DataKeyInfo::from)));
        }
        let ec = kms_encryption_context(materials.encryption_context());
        let aad = materials
            .encryption_context()
            .serialize()
            .map_err(|e| Error::wrap("failed to serialize the encryption context", e))?;
        let mut errors = Vec::new();
        for edk in to_attempt {
            match decrypt_edk(
                &self.inner.client,
                &self.inner.kms_key_id,
                &self.inner.grant_tokens,
                &materials,
                &ec,
                &aad,
                edk,
            )
            .await
            {
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

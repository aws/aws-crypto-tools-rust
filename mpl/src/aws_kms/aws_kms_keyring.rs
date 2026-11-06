// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The AWS KMS keyring: wraps and unwraps data keys with a single AWS KMS key.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use aws_sdk_kms::Client as KmsClient;
use aws_sdk_kms::primitives::Blob;

use crate::Error;
use crate::aws_kms::user_agent::user_agent_override;
use crate::builder::required;
use crate::error::{DataKeyInfo, Kind, KmsKey, Resource, Service};
use crate::keyring::{Keyring, OnDecryptInput, OnDecryptOutput, OnEncryptInput, OnEncryptOutput};
use crate::structures::{
    DecryptionMaterials, EncryptedDataKey, EncryptionContext, EncryptionMaterials, PlaintextDataKey,
};

/// The key provider ID of every encrypted data key that this keyring writes.
const PROVIDER_ID: &str = "aws-kms";
/// The maximum length of an AWS KMS key identifier.
const MAX_AWS_KMS_IDENTIFIER_LENGTH: usize = 2048;
/// AWS KMS ciphertexts are 1 to 6144 bytes.
const MAX_CIPHERTEXT_LENGTH: usize = 6144;
/// AWS KMS accepts at most this many grant tokens.
const MAX_GRANT_TOKENS: usize = 10;
const MAX_GRANT_TOKEN_LENGTH: usize = 8192;
const UINT16_LIMIT: usize = 65_536;

/// A parsed AWS KMS key identifier: an ARN or a raw key ID or alias.
struct KmsIdentifier {
    is_arn: bool,
    resource_type: String,
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
fn parse_kms_arn(identifier: &str) -> Result<KmsIdentifier, String> {
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
fn parse_kms_identifier(identifier: &str) -> Result<KmsIdentifier, String> {
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
/// On encrypt, it calls AWS KMS `GenerateDataKey`,
/// or `Encrypt` when the materials already have a data key.
/// On decrypt, it tries only the encrypted data keys that this KMS key wrote.
/// Decrypting needs a key ARN: a keyring built with a key ID or an alias fails on decrypt.
///
/// ```no_run
/// use aws_crypto_mpl::keyring::AwsKmsKeyring;
///
/// # async fn example() -> Result<(), aws_crypto_mpl::Error> {
/// let sdk_config = aws_crypto_mpl::aws_config::load_defaults(aws_crypto_mpl::aws_config::BehaviorVersion::latest()).await;
/// let keyring = AwsKmsKeyring::builder()
///     .kms_key_id("arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab")
///     .kms_client(aws_crypto_mpl::aws_sdk_kms::Client::new(&sdk_config))
///     .build()
///     .await?;
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
    /// The name that error messages show for this keyring: `aws-kms` and the KMS key identifier.
    #[must_use]
    pub fn name(&self) -> Cow<'_, str> {
        Cow::Owned(format!("aws-kms {}", self.inner.kms_key_id))
    }

    /// Start a builder.
    #[must_use]
    pub fn builder() -> AwsKmsKeyringBuilder {
        AwsKmsKeyringBuilder::default()
    }

    /// The AWS KMS key identifier that this keyring uses.
    #[must_use]
    pub fn kms_key_id(&self) -> &str {
        &self.inner.kms_key_id
    }

    /// The grant tokens that this keyring sends with every AWS KMS request.
    #[must_use]
    pub fn grant_tokens(&self) -> &[String] {
        &self.inner.grant_tokens
    }

    fn resource(&self) -> KmsKey {
        KmsKey::new(self.inner.kms_key_id.clone())
    }

    fn service_err(&self, message: impl Into<String>) -> Error {
        service_err(&self.inner.kms_key_id, message)
    }

    /// Call AWS KMS `GenerateDataKey` for a data key of `len` bytes.
    /// Returns the plaintext, the ciphertext, and the ARN of the KMS key.
    async fn generate_data_key(
        &self,
        ec: &HashMap<String, String>,
        len: usize,
    ) -> Result<(PlaintextDataKey, Vec<u8>, String), Error> {
        let number_of_bytes = i32::try_from(len)
            .map_err(|_| Error::new(Kind::InvalidMaterials, "data key length too large"))?;
        //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
        //# The keyring MUST call AWS KMS GenerateDataKeys with a request constructed as follows:
        let response = self
            .inner
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //# If the keyring calls AWS KMS GenerateDataKeys, it MUST use the configured AWS KMS client to make the call.
            .client
            .generate_data_key()
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //# - `KeyId` MUST be the keyring's KMS key identifier.
            .key_id(&self.inner.kms_key_id)
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //# - `NumberOfBytes` MUST be the [key derivation input length](../algorithm-suites.md#key-derivation-input-length)
            //# specified by the [algorithm suite](../algorithm-suites.md) included in the input [encryption materials](../structures.md#encryption-materials).
            .number_of_bytes(number_of_bytes)
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //# - `EncryptionContext` MUST be the [encryption context](../structures.md#encryption-context)
            //# included in the input [encryption materials](../structures.md#encryption-materials).
            .set_encryption_context(Some(ec.clone()))
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //# - `GrantTokens` MUST be this keyring's [grant tokens](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#grant_token).
            .set_grant_tokens(Some(self.inner.grant_tokens.clone()))
            .customize()
            .config_override(user_agent_override())
            .send()
            .await
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //# If the call to [AWS KMS GenerateDataKey](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html) does not succeed,
            //# OnEncrypt MUST NOT modify the [encryption materials](../structures.md#encryption-materials) and MUST fail.
            .map_err(|e| {
                Error::from_sdk(Service::Kms, "AWS KMS GenerateDataKey", e)
                    .with_resource(self.resource())
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
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //# If the Generate Data Key call succeeds, OnEncrypt MUST verify that the response `Plaintext` length matches
            //# the specification of the [algorithm suite](../algorithm-suites.md)'s Key Derivation Input Length field.
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

    /// Call AWS KMS `Encrypt` on `plaintext`.
    /// Returns the ciphertext and the ARN of the KMS key.
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
        //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
        //# The keyring MUST AWS KMS Encrypt call with a request constructed as follows:
        let response = self
            .inner
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //# The keyring MUST call [AWS KMS Encrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html) using the configured AWS KMS client.
            .client
            .encrypt()
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //# - `KeyId` MUST be the configured AWS KMS key identifier.
            .key_id(&self.inner.kms_key_id)
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //# - `PlaintextDataKey` MUST be the plaintext data key in the [encryption materials](../structures.md#encryption-materials).
            .plaintext(Blob::new(plaintext))
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //# - `EncryptionContext` MUST be the [encryption context](../structures.md#encryption-context)
            //# included in the input [encryption materials](../structures.md#encryption-materials).
            .set_encryption_context(Some(ec.clone()))
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //# - `GrantTokens` MUST be this keyring's [grant tokens](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#grant_token).
            .set_grant_tokens(Some(self.inner.grant_tokens.clone()))
            .customize()
            .config_override(user_agent_override())
            .send()
            .await
            //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
            //# If the call to [AWS KMS Encrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html) does not succeed, OnEncrypt MUST fail.
            .map_err(|e| {
                Error::from_sdk(Service::Kms, "AWS KMS Encrypt", e).with_resource(self.resource())
            })?;
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

    /// Wrap the data key in `materials` with this keyring's AWS KMS key and add the encrypted data key.
    /// Generates the data key first when `materials` has none.
    async fn wrap_materials(
        &self,
        materials: EncryptionMaterials,
    ) -> Result<EncryptionMaterials, Error> {
        let ec = kms_encryption_context(materials.encryption_context());
        Ok(match materials.plaintext_data_key() {
            Some(pdk) => {
                //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
                //# If the input [encryption materials](../structures.md#encryption-materials) do contain a plaintext data key,
                //# OnEncrypt MUST attempt to encrypt the plaintext data key using the configured AWS KMS key identifier.
                let (ciphertext, key_id) = self.encrypt(&ec, pdk.as_bytes()).await?;
                let edk = kms_edk(key_id, ciphertext)?;
                //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
                //# If verified, OnEncrypt MUST append a new [encrypted data key](../structures.md#encrypted-data-key) to the encrypted data key list in the [encryption materials](../structures.md#encryption-materials), constructed as follows:
                materials.add_encrypted_data_key(edk)?
            }
            None => {
                let len = materials.algorithm_suite().encryption_key_length();
                //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
                //# If the input [encryption materials](../structures.md#encryption-materials) do not contain a plaintext data key
                //# OnEncrypt MUST attempt to generate a new plaintext data key
                //# by calling [AWS KMS GenerateDataKey](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html).
                let (pdk, ciphertext, key_id) = self.generate_data_key(&ec, len).await?;
                let edk = kms_edk(key_id, ciphertext)?;
                //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
                //# - MUST set the plaintext data key on the [encryption materials](../structures.md#encryption-materials) as the response `Plaintext`.
                //
                //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
                //# - MUST append a new [encrypted data key](../structures.md#encrypted-data-key) to the encrypted data key list in the [encryption materials](../structures.md#encryption-materials), constructed as follows:
                materials.add_data_key(pdk, edk)?
            }
        })
    }

    /// Try each encrypted data key that this keyring's AWS KMS key wrote,
    /// and return the first one that AWS KMS `Decrypt` unwraps.
    async fn unwrap_materials(&self, input: OnDecryptInput) -> Result<OnDecryptOutput, Error> {
        let (materials, encrypted_data_keys) = input.into_parts();
        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //# If the [decryption materials](../structures.md#decryption-materials) already contained a valid plaintext data key
        //# OnDecrypt MUST return an error.
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
        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //# The set of encrypted data keys MUST first be filtered to match this keyring’s configuration.
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
        let mut errors = Vec::new();
        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //# For each encrypted data key in the filtered set, one at a time, the OnDecrypt MUST attempt to decrypt the data key.
        for edk in to_attempt {
            match decrypt_edk(
                &self.inner.client,
                &self.inner.kms_key_id,
                &self.inner.grant_tokens,
                &materials,
                &ec,
                edk,
            )
            .await
            {
                //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
                //# - MUST immediately return the modified [decryption materials](../structures.md#decryption-materials).
                Ok(materials) => return OnDecryptOutput::builder().materials(materials).build(),
                //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
                //# If this attempt results in an error, then these errors MUST be collected.
                //
                //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
                //# If the response does not satisfies these requirements then an error MUST be collected
                //# and the next encrypted data key in the filtered set MUST be attempted.
                Err(e) => errors.push(e),
            }
        }
        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //# If OnDecrypt fails to successfully decrypt any [encrypted data key](../structures.md#encrypted-data-key),
        //# then it MUST yield an error that includes all the collected errors.
        Err(Error::all_failed(
            "No Configured KMS Key was able to decrypt the Data Key.",
            errors,
        ))
    }

    /// Whether `edk` names this keyring's AWS KMS key.
    fn wrote(&self, edk: &EncryptedDataKey) -> Result<bool, Error> {
        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //# - Its provider ID MUST exactly match the value “aws-kms”.
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
        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //# - The provider info MUST match the configured AWS KMS key identifier.
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

/// Call AWS KMS `Decrypt` on `ciphertext` with the AWS KMS key `key_id`.
/// Returns the plaintext, which must be `len` bytes.
///
/// Fails unless the response names `key_id`.
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
    let resource = KmsKey::new(key_id.to_owned());
    //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
    //# To attempt to decrypt a particular [encrypted data key](../structures.md#encrypted-data-key),
    //# OnDecrypt MUST call [AWS KMS Decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html) with the configured AWS KMS client.
    //
    //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
    //# When calling [AWS KMS Decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html), the keyring MUST call with a request constructed as follows:
    let response = client
        .decrypt()
        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //# - `KeyId` MUST be the configured AWS KMS key identifier.
        .key_id(key_id)
        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //# - `CiphertextBlob` MUST be the [encrypted data key ciphertext](../structures.md#ciphertext).
        .ciphertext_blob(Blob::new(ciphertext))
        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //# - `EncryptionContext` MUST be the [encryption context](../structures.md#encryption-context) included in the input [decryption materials](../structures.md#decryption-materials).
        .set_encryption_context(Some(ec.clone()))
        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //# - `GrantTokens` MUST be this keyring's [grant tokens](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#grant_token).
        .set_grant_tokens(Some(grant_tokens.to_vec()))
        .customize()
        .config_override(user_agent_override())
        .send()
        .await
        .map_err(|e| Error::from_sdk(Service::Kms, "AWS KMS Decrypt", e).with_resource(resource))?;
    //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
    //# - The `KeyId` field in the response MUST equal the configured AWS KMS key identifier.
    if response.key_id.as_deref() != Some(key_id) {
        return Err(service_err(key_id, "Invalid response from KMS Decrypt"));
    }
    response
        .plaintext
        .map(Blob::into_inner)
        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //# - The length of the response’s `Plaintext` MUST equal the [key derivation input length](../algorithm-suites.md#key-derivation-input-length)
        //# specified by the [algorithm suite](../algorithm-suites.md) included in the input [decryption materials](../structures.md#decryption-materials).
        .filter(|p| p.len() == len)
        .ok_or_else(|| service_err(key_id, "Invalid response from KMS Decrypt"))
}

/// Unwrap `edk` with the AWS KMS key `key_id`.
/// Returns a copy of `materials` with the plaintext data key added.
async fn decrypt_edk(
    client: &KmsClient,
    key_id: &str,
    grant_tokens: &[String],
    materials: &DecryptionMaterials,
    ec: &HashMap<String, String>,
    edk: &EncryptedDataKey,
) -> Result<DecryptionMaterials, Error> {
    let len = materials.algorithm_suite().encryption_key_length();
    let pdk = kms_decrypt(client, key_id, grant_tokens, ec, edk.ciphertext(), len).await?;
    //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
    //# - MUST set the plaintext data key on the [decryption materials](../structures.md#decryption-materials) as the response `Plaintext`.
    materials.clone().add_data_key(PlaintextDataKey::new(pdk))
}

/// Check `grant_tokens`: at most 10, each 1 to 8192 characters.
/// Returns an empty list for `None`.
fn valid_grant_tokens(grant_tokens: Option<Vec<String>>) -> Result<Vec<String>, Error> {
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

fn kms_encryption_context(ec: &EncryptionContext) -> HashMap<String, String> {
    ec.iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect()
}

fn kms_edk(key_id: String, ciphertext: Vec<u8>) -> Result<EncryptedDataKey, Error> {
    if key_id.len() >= UINT16_LIMIT {
        return Err(Error::new(
            Kind::Service,
            "Invalid response from AWS KMS GenerateDataKey: Key ID too long.",
        ));
    }
    EncryptedDataKey::builder()
        //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
        //# - the [key provider id](../structures.md#key-provider-id) MUST be "aws-kms".
        //
        //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
        //# - The [key provider id](../structures.md#key-provider-id) MUST be "aws-kms".
        .key_provider_id(PROVIDER_ID)
        //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
        //# - the [key provider information](../structures.md#key-provider-information) MUST be the response `KeyId`.
        //
        //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
        //# - The [key provider information](../structures.md#key-provider-information) MUST be the response `KeyId`.
        .key_provider_info(key_id.into_bytes())
        //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
        //# - the [ciphertext](../structures.md#ciphertext) MUST be the response `CiphertextBlob`.
        //
        //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
        //# - The [ciphertext](../structures.md#ciphertext) MUST be the response `CiphertextBlob`.
        .ciphertext(ciphertext)
        .build()
}

/// Builder for [`AwsKmsKeyring`].
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct AwsKmsKeyringBuilder {
    kms_key_id: Option<String>,
    kms_client: Option<KmsClient>,
    grant_tokens: Option<Vec<String>>,
}

impl AwsKmsKeyringBuilder {
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
    pub fn kms_client(mut self, kms_client: impl Into<KmsClient>) -> Self {
        self.kms_client = Some(kms_client.into());
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
    pub async fn build(self) -> Result<AwsKmsKeyring, Error> {
        //= spec/framework/aws-kms/aws-kms-keyring.md#initialization
        //# - MUST provide an AWS KMS key identifier
        let kms_key_id = required(self.kms_key_id, "kms_key_id")?;
        //= spec/framework/aws-kms/aws-kms-keyring.md#initialization
        //# - MUST provide an AWS KMS SDK client
        //
        //= spec/framework/aws-kms/aws-kms-keyring.md#initialization
        //# The AWS KMS SDK client MUST NOT be null.
        let client = required(self.kms_client, "kms_client")?;
        //= spec/framework/aws-kms/aws-kms-keyring.md#initialization
        //# The AWS KMS key identifier MUST be [a valid identifier](aws-kms-key-arn.md#a-valid-aws-kms-identifier).
        let parsed =
            parse_kms_identifier(&kms_key_id).map_err(|e| Error::new(Kind::Validation, e))?;
        if !kms_key_id.is_ascii() {
            return Err(Error::new(Kind::Validation, "Key identifier is not ASCII"));
        }
        //= spec/framework/aws-kms/aws-kms-keyring.md#initialization
        //# The AWS KMS key identifier MUST NOT be null or empty.
        if kms_key_id.is_empty() || kms_key_id.len() > MAX_AWS_KMS_IDENTIFIER_LENGTH {
            return Err(Error::new(Kind::Validation, "Key identifier is too long"));
        }
        //= spec/framework/aws-kms/aws-kms-keyring.md#initialization
        //# - MAY provide a list of Grant Tokens
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

//= spec/framework/aws-kms/aws-kms-keyring.md#interface
//= type=implication
//# MUST implement the [AWS Encryption SDK Keyring interface](../keyring-interface.md#interface)
#[async_trait]
impl Keyring for crate::shared::Builtin<AwsKmsKeyring> {
    fn name(&self) -> Cow<'_, str> {
        self.0.name()
    }

    //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
    //= type=implication
    //# OnEncrypt MUST take [encryption materials](../structures.md#encryption-materials) as input.
    async fn on_encrypt(&self, input: OnEncryptInput) -> Result<OnEncryptOutput, Error> {
        let materials = self.0.wrap_materials(input.into_materials()).await?;
        //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
        //# - MUST output the modified [encryption materials](../structures.md#encryption-materials)
        //
        //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
        //# If all Encrypt calls succeed, OnEncrypt MUST output the modified [encryption materials](../structures.md#encryption-materials).
        OnEncryptOutput::builder().materials(materials).build()
    }

    //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
    //= type=implication
    //# OnDecrypt MUST take [decryption materials](../structures.md#decryption-materials) and
    //# a list of [encrypted data keys](../structures.md#encrypted-data-key) as input.
    async fn on_decrypt(&self, input: OnDecryptInput) -> Result<OnDecryptOutput, Error> {
        self.0.unwrap_materials(input).await
    }
}

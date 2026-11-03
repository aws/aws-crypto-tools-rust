// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The AWS KMS RSA keyring.
//! It wraps data keys locally with the public key of an asymmetric AWS KMS RSA key,
//! and unwraps them with AWS KMS `Decrypt`.

use std::borrow::Cow;
use std::sync::Arc;

use async_trait::async_trait;
use aws_mpl_primitives::{
    DigestAlg, RsaPadding, constant_time_equal, digest, generate_random_bytes, rsa_encrypt,
    rsa_modulus_length_bits,
};
use aws_sdk_kms::Client as KmsClient;
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::EncryptionAlgorithmSpec;
use zeroize::Zeroizing;

use crate::Error;
use crate::aws_kms::aws_kms_keyring::{
    MAX_AWS_KMS_IDENTIFIER_LENGTH, parse_kms_arn, service_err, valid_ciphertext, valid_grant_tokens,
};
use crate::aws_kms::mrk_match::aws_kms_mrk_match_for_decrypt;
use crate::aws_kms::user_agent::user_agent_override;
use crate::builder::required;
use crate::error::{DataKeyInfo, Kind, KmsKey, Resource, Service};
use crate::keyring::edk_wrapping;
use crate::keyring::{Keyring, OnDecryptInput, OnDecryptOutput, OnEncryptInput, OnEncryptOutput};
use crate::structures::{
    AlgorithmSuite, DecryptionMaterials, EdkWrapping, EncryptedDataKey, EncryptionContext,
    PlaintextDataKey,
};

/// The key provider ID of every encrypted data key that this keyring writes.
pub(crate) const RSA_PROVIDER_ID: &str = "aws-kms-rsa";
/// The shortest RSA key, in bits, that AWS KMS supports.
const MIN_KMS_RSA_KEY_LEN: u32 = 2048;

/// A keyring that protects each data key with an asymmetric AWS KMS RSA key.
///
/// On encrypt, it RSA-encrypts the data key locally with the key's public key.
/// Encrypting needs no AWS KMS call.
/// On decrypt, it calls AWS KMS `Decrypt` with the key.
/// AWS KMS RSA keys take no encryption context.
/// To bind the encryption context, the keyring encrypts its SHA-384 digest together with the data key.
///
/// Use it with an algorithm suite without asymmetric signing.
///
/// ```no_run
/// use aws_crypto_mpl::aws_sdk_kms::types::EncryptionAlgorithmSpec;
/// use aws_crypto_mpl::keyring::AwsKmsRsaKeyring;
///
/// # async fn example(public_key_pem: Vec<u8>) -> Result<(), aws_crypto_mpl::Error> {
/// let sdk_config = aws_crypto_mpl::aws_config::load_defaults(aws_crypto_mpl::aws_config::BehaviorVersion::latest()).await;
/// let keyring = AwsKmsRsaKeyring::builder()
///     .kms_key_id("arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab")
///     .public_key(public_key_pem)
///     .encryption_algorithm(EncryptionAlgorithmSpec::RsaesOaepSha256)
///     .kms_client(aws_crypto_mpl::aws_sdk_kms::Client::new(&sdk_config))
///     .build()?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct AwsKmsRsaKeyring {
    inner: Arc<AwsKmsRsaKeyringInner>,
}

struct AwsKmsRsaKeyringInner {
    kms_key_id: String,
    resource_type: String,
    public_key: Option<Vec<u8>>,
    encryption_algorithm: EncryptionAlgorithmSpec,
    padding: RsaPadding,
    client: Option<KmsClient>,
    grant_tokens: Vec<String>,
}

impl std::fmt::Debug for AwsKmsRsaKeyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsKmsRsaKeyring")
            .field("kms_key_id", &self.inner.kms_key_id)
            .field("encryption_algorithm", &self.inner.encryption_algorithm)
            .field("has_public_key", &self.inner.public_key.is_some())
            .field("has_kms_client", &self.inner.client.is_some())
            .finish_non_exhaustive()
    }
}

impl AwsKmsRsaKeyring {
    /// The name that error messages show for this keyring: `aws-kms-rsa` and the KMS key ARN.
    #[must_use]
    pub fn name(&self) -> Cow<'_, str> {
        Cow::Owned(format!("{RSA_PROVIDER_ID} {}", self.inner.kms_key_id))
    }

    /// Start a builder.
    #[must_use]
    pub fn builder() -> AwsKmsRsaKeyringBuilder {
        AwsKmsRsaKeyringBuilder::default()
    }

    /// The AWS KMS key ARN that this keyring uses.
    #[must_use]
    pub fn kms_key_id(&self) -> &str {
        &self.inner.kms_key_id
    }

    /// The PEM-encoded public key of the AWS KMS key, if configured.
    #[must_use]
    pub fn public_key(&self) -> Option<&[u8]> {
        self.inner.public_key.as_deref()
    }

    /// The RSA encryption algorithm.
    #[must_use]
    pub fn encryption_algorithm(&self) -> &EncryptionAlgorithmSpec {
        &self.inner.encryption_algorithm
    }

    /// The grant tokens that this keyring sends with every AWS KMS request.
    #[must_use]
    pub fn grant_tokens(&self) -> &[String] {
        &self.inner.grant_tokens
    }

    /// RSA-encrypt the SHA-384 digest of `ec`, followed by `material`, under `public_key`.
    fn wrap(
        &self,
        public_key: &[u8],
        ec: &EncryptionContext,
        material: &PlaintextDataKey,
    ) -> Result<Vec<u8>, Error> {
        let mut plaintext = Zeroizing::new(encryption_context_digest(ec)?);
        plaintext.extend_from_slice(material.as_bytes());
        rsa_encrypt(self.inner.padding, public_key, &plaintext).map_err(|e| {
            Error::with_cause(
                Kind::Cryptographic,
                "RSA encryption of the data key failed",
                e,
            )
        })
    }

    /// Call AWS KMS `Decrypt` on `wrapped`.
    /// Returns the material that follows the encryption context digest in the plaintext.
    ///
    /// Fails unless the response names this keyring's key and the plaintext begins with `ec_digest`.
    async fn unwrap(
        &self,
        client: &KmsClient,
        suite: &AlgorithmSuite,
        ec_digest: &[u8],
        wrapped: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let key_id = self.inner.kms_key_id.as_str();
        if !valid_ciphertext(wrapped) {
            return Err(Error::new(Kind::Cryptographic, "Ciphertext length invalid"));
        }
        let resource = Some(Resource::KmsKey(KmsKey::new(key_id.to_owned())));
        // AWS KMS RSA keys take no encryption context, so this request sends none.
        // The digest at the start of the plaintext binds the encryption context.
        let response = client
            .decrypt()
            .key_id(key_id)
            .ciphertext_blob(Blob::new(wrapped))
            .set_grant_tokens(Some(self.inner.grant_tokens.clone()))
            .encryption_algorithm(self.inner.encryption_algorithm.clone())
            .customize()
            .config_override(user_agent_override())
            .send()
            .await
            .map_err(|e| Error::from_sdk(Service::Kms, "AWS KMS Decrypt", resource, e))?;
        if response.key_id.as_deref() != Some(key_id) {
            return Err(service_err(key_id, "Invalid response from KMS Decrypt"));
        }
        let plaintext = Zeroizing::new(
            response
                .plaintext
                .map(Blob::into_inner)
                .ok_or_else(|| service_err(key_id, "Invalid response from KMS Decrypt"))?,
        );
        if plaintext.len() != ec_digest.len() + suite.encryption_key_length()
            || !constant_time_equal(&plaintext[..ec_digest.len()], ec_digest)
        {
            return Err(Error::new(
                Kind::Cryptographic,
                "Encryption context digest does not match expected value.",
            ));
        }
        Ok(Zeroizing::new(plaintext[ec_digest.len()..].to_vec()))
    }

    /// Whether `edk` names an AWS KMS RSA key that is this keyring's key or a multi-Region replica of it.
    fn wrote(&self, edk: &EncryptedDataKey) -> Result<bool, Error> {
        if edk.key_provider_id() != RSA_PROVIDER_ID {
            return Ok(false);
        }
        let key_id = std::str::from_utf8(edk.key_provider_info()).map_err(|_| {
            Error::new(
                Kind::Cryptographic,
                "Invalid AWS KMS encoding, provider info is not UTF8.",
            )
        })?;
        parse_kms_arn(key_id).map_err(|e| Error::new(Kind::Cryptographic, e))?;
        Ok(aws_kms_mrk_match_for_decrypt(
            &self.inner.kms_key_id,
            key_id,
        ))
    }

    /// Unwrap `edk`.
    /// Returns a copy of `materials` with the plaintext data key added.
    async fn decrypt_edk(
        &self,
        client: &KmsClient,
        materials: &DecryptionMaterials,
        ec_digest: &[u8],
        aad: &[u8],
        edk: &EncryptedDataKey,
    ) -> Result<DecryptionMaterials, Error> {
        let suite = materials.algorithm_suite();
        match suite.edk_wrapping() {
            EdkWrapping::IntermediateKeyWrapping(_) => {
                let (encrypted_pdk, wrapped_ikm) = edk_wrapping::split(&suite, edk.ciphertext())
                    .map_err(|e| Error::wrap("Invalid material for Intermediate Unwrapping", e))?;
                let ikm = self.unwrap(client, &suite, ec_digest, wrapped_ikm).await?;
                let (pdk, signing_key) =
                    edk_wrapping::decrypt_pdk(&suite, &ikm, aad, encrypted_pdk)?;
                materials
                    .clone()
                    .add_data_key_with_symmetric_signing_key(pdk, signing_key)
            }
            _ => {
                let pdk = self
                    .unwrap(client, &suite, ec_digest, edk.ciphertext())
                    .await?;
                materials
                    .clone()
                    .add_data_key(PlaintextDataKey::new(pdk.to_vec()))
            }
        }
    }
}

/// The SHA-384 digest of the canonical serialization of `ec`.
fn encryption_context_digest(ec: &EncryptionContext) -> Result<Vec<u8>, Error> {
    let canonical = ec
        .serialize()
        .map_err(|e| Error::wrap("failed to serialize the encryption context", e))?;
    let mut out = vec![0u8; DigestAlg::Sha384.output_len()];
    digest(DigestAlg::Sha384, &canonical, &mut out).map_err(|e| {
        Error::with_cause(
            Kind::Cryptographic,
            "failed to digest the encryption context",
            e,
        )
    })?;
    Ok(out)
}

/// Fail when `suite` uses asymmetric signing, which this keyring supports on neither encrypt nor decrypt.
fn reject_asymmetric_signing(suite: &AlgorithmSuite) -> Result<(), Error> {
    if suite.asymmetric_signature_algorithm().is_some() {
        return Err(Error::new(
            Kind::Validation,
            "AwsKmsRsaKeyring cannot be used with an Algorithm Suite with asymmetric signing. \
             Please specify an algorithm suite without asymmetric signing.",
        ));
    }
    Ok(())
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

/// Builder for [`AwsKmsRsaKeyring`].
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct AwsKmsRsaKeyringBuilder {
    kms_key_id: Option<String>,
    public_key: Option<Vec<u8>>,
    encryption_algorithm: Option<EncryptionAlgorithmSpec>,
    kms_client: Option<KmsClient>,
    grant_tokens: Option<Vec<String>>,
}

impl AwsKmsRsaKeyringBuilder {
    /// The AWS KMS RSA key ARN.
    /// Required.
    #[must_use]
    pub fn kms_key_id(mut self, kms_key_id: impl Into<String>) -> Self {
        self.kms_key_id = Some(kms_key_id.into());
        self
    }

    /// The AWS KMS RSA key ARN. See [`Self::kms_key_id`].
    #[must_use]
    pub fn set_kms_key_id(mut self, kms_key_id: Option<String>) -> Self {
        self.kms_key_id = kms_key_id;
        self
    }

    /// The key ARN, if set.
    #[must_use]
    pub const fn get_kms_key_id(&self) -> &Option<String> {
        &self.kms_key_id
    }

    /// The public key of the AWS KMS key: a PEM-encoded X.509 `SubjectPublicKeyInfo` of at least 2048 bits.
    /// This is the key that AWS KMS `GetPublicKey` returns, PEM-encoded.
    /// Needed to encrypt.
    /// Set this, the AWS KMS client, or both.
    #[must_use]
    pub fn public_key(mut self, public_key: impl Into<Vec<u8>>) -> Self {
        self.public_key = Some(public_key.into());
        self
    }

    /// The public key. See [`Self::public_key`].
    #[must_use]
    pub fn set_public_key(mut self, public_key: Option<Vec<u8>>) -> Self {
        self.public_key = public_key;
        self
    }

    /// The public key, if set.
    #[must_use]
    pub const fn get_public_key(&self) -> &Option<Vec<u8>> {
        &self.public_key
    }

    /// The RSA encryption algorithm: `RsaesOaepSha1` or `RsaesOaepSha256`.
    /// Required.
    #[must_use]
    pub fn encryption_algorithm(mut self, encryption_algorithm: EncryptionAlgorithmSpec) -> Self {
        self.encryption_algorithm = Some(encryption_algorithm);
        self
    }

    /// The RSA encryption algorithm. See [`Self::encryption_algorithm`].
    #[must_use]
    pub fn set_encryption_algorithm(
        mut self,
        encryption_algorithm: Option<EncryptionAlgorithmSpec>,
    ) -> Self {
        self.encryption_algorithm = encryption_algorithm;
        self
    }

    /// The RSA encryption algorithm, if set.
    #[must_use]
    pub const fn get_encryption_algorithm(&self) -> &Option<EncryptionAlgorithmSpec> {
        &self.encryption_algorithm
    }

    /// The AWS KMS client, in the key's region.
    /// Needed to decrypt.
    /// Set this, the public key, or both.
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

    /// The AWS KMS client, if set.
    #[must_use]
    pub const fn get_kms_client(&self) -> &Option<KmsClient> {
        &self.kms_client
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

    /// The grant tokens, if set.
    #[must_use]
    pub const fn get_grant_tokens(&self) -> &Option<Vec<String>> {
        &self.grant_tokens
    }

    /// Build the keyring.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): no key ARN or encryption algorithm,
    ///   neither a public key nor an AWS KMS client,
    ///   an encryption algorithm other than RSAES-OAEP,
    ///   a key identifier that is not an AWS KMS key ARN,
    ///   a public key that is not a PEM RSA public key of at least 2048 bits,
    ///   or invalid grant tokens.
    pub fn build(self) -> Result<AwsKmsRsaKeyring, Error> {
        let kms_key_id = required(self.kms_key_id, "kms_key_id")?;
        let encryption_algorithm = required(self.encryption_algorithm, "encryption_algorithm")?;
        // Treat an empty public key as unset.
        let public_key = self.public_key.filter(|key| !key.is_empty());
        if public_key.is_none() && self.kms_client.is_none() {
            return Err(Error::new(
                Kind::Validation,
                "A publicKey or a kmsClient is required",
            ));
        }
        let padding = match encryption_algorithm {
            EncryptionAlgorithmSpec::RsaesOaepSha1 => RsaPadding::OaepSha1,
            EncryptionAlgorithmSpec::RsaesOaepSha256 => RsaPadding::OaepSha256,
            _ => {
                return Err(Error::new(
                    Kind::Validation,
                    "Unsupported EncryptionAlgorithmSpec",
                ));
            }
        };
        if kms_key_id.is_empty() || kms_key_id.len() > MAX_AWS_KMS_IDENTIFIER_LENGTH {
            return Err(Error::new(
                Kind::Validation,
                "Kms Key ID must be a KMS Key ARN",
            ));
        }
        let parsed = parse_kms_arn(&kms_key_id)
            .map_err(|_| Error::new(Kind::Validation, "Kms Key ID must be a KMS Key ARN"))?;
        let grant_tokens = valid_grant_tokens(self.grant_tokens)?;
        if let Some(public_key) = &public_key {
            let bits = rsa_modulus_length_bits(public_key)
                .map_err(|e| Error::with_cause(Kind::Validation, "Invalid public key", e))?;
            if bits < MIN_KMS_RSA_KEY_LEN {
                return Err(Error::new(Kind::Validation, "Invalid public key length"));
            }
        }
        Ok(AwsKmsRsaKeyring {
            inner: Arc::new(AwsKmsRsaKeyringInner {
                kms_key_id,
                resource_type: parsed.resource_type,
                public_key,
                encryption_algorithm,
                padding,
                client: self.kms_client,
                grant_tokens,
            }),
        })
    }
}

#[async_trait]
impl Keyring for crate::shared::Builtin<AwsKmsRsaKeyring> {
    fn name(&self) -> Cow<'_, str> {
        self.0.name()
    }

    async fn on_encrypt(&self, input: OnEncryptInput) -> Result<OnEncryptOutput, Error> {
        let Some(public_key) = self.inner.public_key.as_deref() else {
            return Err(Error::new(
                Kind::Validation,
                "A AwsKmsRsaKeyring without a public key cannot provide OnEncrypt",
            ));
        };
        let materials = input.into_materials();
        let suite = materials.algorithm_suite();
        reject_asymmetric_signing(&suite)?;
        let ec = materials.encryption_context().clone();
        let edk = |ciphertext: Vec<u8>| {
            EncryptedDataKey::builder()
                .key_provider_id(RSA_PROVIDER_ID)
                .key_provider_info(self.inner.kms_key_id.as_bytes().to_vec())
                .ciphertext(ciphertext)
                .build()
        };

        let materials = match (suite.edk_wrapping(), materials.plaintext_data_key()) {
            (EdkWrapping::IntermediateKeyWrapping(_), existing) => {
                // Wrap a fresh intermediate key.
                // Keys derived from it encrypt the plaintext data key and sign the message.
                let aad = ec
                    .serialize()
                    .map_err(|e| Error::wrap("failed to serialize the encryption context", e))?;
                let (pdk, generated) = match existing {
                    Some(key) => (key.clone(), false),
                    None => (random_key(&suite)?, true),
                };
                let ikm = random_key(&suite)?;
                let wrapped_ikm = self.0.wrap(public_key, &ec, &ikm)?;
                let (mut ciphertext, signing_key) =
                    edk_wrapping::encrypt_pdk(&suite, ikm.as_bytes(), &aad, &pdk)?;
                ciphertext.extend_from_slice(&wrapped_ikm);
                let edk = edk(ciphertext)?;
                if generated {
                    materials.add_data_key_with_symmetric_signing_key(pdk, edk, signing_key)?
                } else {
                    materials.add_encrypted_data_key_with_symmetric_signing_key(edk, signing_key)?
                }
            }
            (_, Some(pdk)) => {
                let edk = edk(self.0.wrap(public_key, &ec, pdk)?)?;
                materials.add_encrypted_data_key(edk)?
            }
            (_, None) => {
                let pdk = random_key(&suite)?;
                let edk = edk(self.0.wrap(public_key, &ec, &pdk)?)?;
                materials.add_data_key(pdk, edk)?
            }
        };
        OnEncryptOutput::builder().materials(materials).build()
    }

    async fn on_decrypt(&self, input: OnDecryptInput) -> Result<OnDecryptOutput, Error> {
        let Some(client) = self.inner.client.as_ref() else {
            return Err(Error::new(
                Kind::Validation,
                "An AwsKmsRsaKeyring without an AWS KMS client cannot provide OnDecrypt",
            ));
        };
        let (materials, encrypted_data_keys) = input.into_parts();
        if materials.plaintext_data_key().is_some() {
            return Err(Error::new(
                Kind::InvalidMaterials,
                "Keyring received decryption materials that already contain a plaintext data key.",
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
        let suite = materials.algorithm_suite();
        reject_asymmetric_signing(&suite)?;

        let mut to_attempt = Vec::new();
        for edk in &encrypted_data_keys {
            if self.0.wrote(edk)? {
                to_attempt.push(edk);
            }
        }
        if to_attempt.is_empty() {
            return Err(Error::no_matching_data_key(format!(
                "no encrypted data key was written by AWS KMS RSA key {}",
                self.inner.kms_key_id
            ))
            .with_encrypted_data_keys(encrypted_data_keys.iter().map(DataKeyInfo::from)));
        }

        let ec_digest = encryption_context_digest(materials.encryption_context())?;
        let aad = materials
            .encryption_context()
            .serialize()
            .map_err(|e| Error::wrap("failed to serialize the encryption context", e))?;
        let mut errors = Vec::new();
        for edk in to_attempt {
            match self
                .0
                .decrypt_edk(client, &materials, &ec_digest, &aad, edk)
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

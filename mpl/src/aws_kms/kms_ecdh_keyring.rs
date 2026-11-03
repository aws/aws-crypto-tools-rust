// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The AWS KMS ECDH keyring. Ported from the Dafny `AwsKmsEcdhKeyring.dfy`,
//! `GetEcdhPublicKey` in `AwsKmsUtils.dfy`,
//! and `CreateAwsKmsEcdhKeyring` in `AwsCryptographyMaterialProvidersOperations.dfy`.
//!
//! AWS KMS `DeriveSharedSecret` agrees on the shared secret with an AWS KMS ECC key,
//! and the keyring wraps data keys with it as the raw ECDH keyring does.

use std::borrow::Cow;
use std::sync::Arc;

use async_trait::async_trait;
use aws_mpl_primitives::{
    ecdh_compress_public_key, ecdh_decompress_public_key, ecdh_validate_public_key,
};
use aws_sdk_kms::Client as KmsClient;
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::{KeyAgreementAlgorithmSpec, KeyUsageType};
use zeroize::Zeroizing;

use crate::Error;
use crate::aws_kms::aws_kms_keyring::{
    MAX_AWS_KMS_IDENTIFIER_LENGTH, parse_kms_identifier, service_err, valid_grant_tokens,
};
use crate::aws_kms::user_agent::user_agent_override;
use crate::builder::required;
use crate::error::{DataKeyInfo, Kind, KmsKey, Service};
use crate::keyring::ecdh_wrapping::{self, KMS_ECDH_PROVIDER_ID};
use crate::keyring::{Keyring, OnDecryptInput, OnDecryptOutput, OnEncryptInput, OnEncryptOutput};
use crate::structures::{DecryptionMaterials, EcdhCurveSpec, EncryptedDataKey};

/// AWS KMS public keys are 1 to 8192 bytes.
const MAX_PUBLIC_KEY_LENGTH: usize = 8192;

fn valid_public_key_length(key: &[u8]) -> bool {
    (1..=MAX_PUBLIC_KEY_LENGTH).contains(&key.len())
}

/// Map a primitives error to an MPL error of `kind`.
fn prim_err(kind: Kind, message: &'static str) -> impl FnOnce(aws_mpl_primitives::Error) -> Error {
    move |e| Error::with_cause(kind, message, e)
}

/// Check that `key_id` is an AWS KMS key ARN, alias, or key ID of 1 to 2048 ASCII characters.
fn validate_kms_key_id(key_id: &str) -> Result<(), Error> {
    parse_kms_identifier(key_id).map_err(|e| Error::new(Kind::Validation, e))?;
    if !key_id.is_ascii() {
        return Err(Error::new(Kind::Validation, "Key identifier is not ASCII"));
    }
    if key_id.is_empty() || key_id.len() > MAX_AWS_KMS_IDENTIFIER_LENGTH {
        return Err(Error::new(Kind::Validation, "Key identifier is too long"));
    }
    Ok(())
}

/// The sender's AWS KMS ECC key and the recipient's public key.
/// Encrypts and decrypts.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct KmsPrivateKeyToStaticPublicKeyInput {
    sender_kms_identifier: String,
    sender_public_key: Option<Vec<u8>>,
    recipient_public_key: Vec<u8>,
}

impl KmsPrivateKeyToStaticPublicKeyInput {
    /// Start a builder.
    #[must_use]
    pub fn builder() -> KmsPrivateKeyToStaticPublicKeyInputBuilder {
        KmsPrivateKeyToStaticPublicKeyInputBuilder::default()
    }

    /// The sender's AWS KMS ECC key.
    #[must_use]
    pub fn sender_kms_identifier(&self) -> &str {
        &self.sender_kms_identifier
    }

    /// The sender's DER-encoded X.509 `SubjectPublicKeyInfo` public key, if configured.
    #[must_use]
    pub fn sender_public_key(&self) -> Option<&[u8]> {
        self.sender_public_key.as_deref()
    }

    /// The recipient's DER-encoded X.509 `SubjectPublicKeyInfo` public key.
    #[must_use]
    pub fn recipient_public_key(&self) -> &[u8] {
        &self.recipient_public_key
    }
}

/// Builder for [`KmsPrivateKeyToStaticPublicKeyInput`].
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct KmsPrivateKeyToStaticPublicKeyInputBuilder {
    sender_kms_identifier: Option<String>,
    sender_public_key: Option<Vec<u8>>,
    recipient_public_key: Option<Vec<u8>>,
}

impl KmsPrivateKeyToStaticPublicKeyInputBuilder {
    /// The sender's AWS KMS ECC key with key usage `KEY_AGREEMENT`: a key ARN, alias, or key ID.
    /// Required.
    #[must_use]
    pub fn sender_kms_identifier(mut self, key_id: impl Into<String>) -> Self {
        self.sender_kms_identifier = Some(key_id.into());
        self
    }

    /// The sender's AWS KMS key. See [`Self::sender_kms_identifier`].
    #[must_use]
    pub fn set_sender_kms_identifier(mut self, key_id: Option<String>) -> Self {
        self.sender_kms_identifier = key_id;
        self
    }

    /// The sender's AWS KMS key, if set.
    #[must_use]
    pub fn get_sender_kms_identifier(&self) -> &Option<String> {
        &self.sender_kms_identifier
    }

    /// The sender's DER-encoded X.509 `SubjectPublicKeyInfo` public key.
    /// Optional: without it, building the keyring calls AWS KMS `GetPublicKey` on the sender's key.
    #[must_use]
    pub fn sender_public_key(mut self, key: impl Into<Vec<u8>>) -> Self {
        self.sender_public_key = Some(key.into());
        self
    }

    /// The sender's public key. See [`Self::sender_public_key`].
    #[must_use]
    pub fn set_sender_public_key(mut self, key: Option<Vec<u8>>) -> Self {
        self.sender_public_key = key;
        self
    }

    /// The sender's public key, if set.
    #[must_use]
    pub fn get_sender_public_key(&self) -> &Option<Vec<u8>> {
        &self.sender_public_key
    }

    /// The recipient's DER-encoded X.509 `SubjectPublicKeyInfo` public key.
    /// Required.
    #[must_use]
    pub fn recipient_public_key(mut self, key: impl Into<Vec<u8>>) -> Self {
        self.recipient_public_key = Some(key.into());
        self
    }

    /// The recipient's public key. See [`Self::recipient_public_key`].
    #[must_use]
    pub fn set_recipient_public_key(mut self, key: Option<Vec<u8>>) -> Self {
        self.recipient_public_key = key;
        self
    }

    /// The recipient's public key, if set.
    #[must_use]
    pub fn get_recipient_public_key(&self) -> &Option<Vec<u8>> {
        &self.recipient_public_key
    }

    /// Build the key agreement scheme.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): the sender's key or the recipient's public key is unset.
    pub fn build(self) -> Result<KmsPrivateKeyToStaticPublicKeyInput, Error> {
        Ok(KmsPrivateKeyToStaticPublicKeyInput {
            sender_kms_identifier: required(self.sender_kms_identifier, "sender_kms_identifier")?,
            sender_public_key: self.sender_public_key,
            recipient_public_key: required(self.recipient_public_key, "recipient_public_key")?,
        })
    }
}

/// The recipient's AWS KMS ECC key.
/// Decrypts only: the sender's public key comes from each encrypted data key.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct KmsPublicKeyDiscoveryInput {
    recipient_kms_identifier: String,
}

impl KmsPublicKeyDiscoveryInput {
    /// Start a builder.
    #[must_use]
    pub fn builder() -> KmsPublicKeyDiscoveryInputBuilder {
        KmsPublicKeyDiscoveryInputBuilder::default()
    }

    /// The recipient's AWS KMS ECC key.
    #[must_use]
    pub fn recipient_kms_identifier(&self) -> &str {
        &self.recipient_kms_identifier
    }
}

/// Builder for [`KmsPublicKeyDiscoveryInput`].
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct KmsPublicKeyDiscoveryInputBuilder {
    recipient_kms_identifier: Option<String>,
}

impl KmsPublicKeyDiscoveryInputBuilder {
    /// The recipient's AWS KMS ECC key with key usage `KEY_AGREEMENT`: a key ARN, alias, or key ID.
    /// Required.
    #[must_use]
    pub fn recipient_kms_identifier(mut self, key_id: impl Into<String>) -> Self {
        self.recipient_kms_identifier = Some(key_id.into());
        self
    }

    /// The recipient's AWS KMS key. See [`Self::recipient_kms_identifier`].
    #[must_use]
    pub fn set_recipient_kms_identifier(mut self, key_id: Option<String>) -> Self {
        self.recipient_kms_identifier = key_id;
        self
    }

    /// The recipient's AWS KMS key, if set.
    #[must_use]
    pub fn get_recipient_kms_identifier(&self) -> &Option<String> {
        &self.recipient_kms_identifier
    }

    /// Build the key agreement scheme.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): the recipient's key is unset.
    pub fn build(self) -> Result<KmsPublicKeyDiscoveryInput, Error> {
        Ok(KmsPublicKeyDiscoveryInput {
            recipient_kms_identifier: required(
                self.recipient_kms_identifier,
                "recipient_kms_identifier",
            )?,
        })
    }
}

/// How an [`AwsKmsEcdhKeyring`] gets the two keys of its key agreement.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum KmsEcdhStaticConfigurations {
    /// The sender's AWS KMS ECC key and the recipient's public key.
    KmsPrivateKeyToStaticPublicKey(KmsPrivateKeyToStaticPublicKeyInput),
    /// The recipient's AWS KMS ECC key. Decrypts only.
    KmsPublicKeyDiscovery(KmsPublicKeyDiscoveryInput),
}

/// A keyring that wraps data keys with a key derived from an AWS KMS `DeriveSharedSecret` result.
///
/// Construct with [`AwsKmsEcdhKeyring::builder`].
/// Its messages decrypt with a raw ECDH keyring that holds the other party's private key,
/// and the other way round.
///
/// ```no_run
/// use aws_crypto_mpl::keyring::{
///     AwsKmsEcdhKeyring, KmsEcdhStaticConfigurations, KmsPublicKeyDiscoveryInput,
/// };
/// use aws_crypto_mpl::types::EcdhCurveSpec;
///
/// # async fn example() -> Result<(), aws_crypto_mpl::Error> {
/// let sdk_config = aws_crypto_mpl::aws_config::load_defaults(aws_crypto_mpl::aws_config::BehaviorVersion::latest()).await;
/// let keyring = AwsKmsEcdhKeyring::builder()
///     .curve_spec(EcdhCurveSpec::EccNistP256)
///     .key_agreement_scheme(KmsEcdhStaticConfigurations::KmsPublicKeyDiscovery(
///         KmsPublicKeyDiscoveryInput::builder()
///             .recipient_kms_identifier("arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab")
///             .build()?,
///     ))
///     .kms_client(aws_crypto_mpl::aws_sdk_kms::Client::new(&sdk_config))
///     .build()
///     .await?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct AwsKmsEcdhKeyring {
    inner: Arc<AwsKmsEcdhKeyringInner>,
}

struct AwsKmsEcdhKeyringInner {
    key_agreement_scheme: KmsEcdhStaticConfigurations,
    curve_spec: EcdhCurveSpec,
    client: KmsClient,
    grant_tokens: Vec<String>,
    /// The AWS KMS key that encrypt derives the shared secret with.
    /// `None` for discovery.
    sender_kms_key_id: Option<String>,
    /// Empty for discovery.
    compressed_sender_public_key: Vec<u8>,
    recipient_public_key: Vec<u8>,
    compressed_recipient_public_key: Vec<u8>,
}

impl std::fmt::Debug for AwsKmsEcdhKeyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsKmsEcdhKeyring")
            .field("key_agreement_scheme", &self.inner.key_agreement_scheme)
            .field("curve_spec", &self.inner.curve_spec)
            .finish_non_exhaustive()
    }
}

impl AwsKmsEcdhKeyring {
    /// The name that error messages show for this keyring: `aws-kms-ecdh` and its AWS KMS key.
    #[must_use]
    pub fn name(&self) -> Cow<'_, str> {
        Cow::Owned(format!("{KMS_ECDH_PROVIDER_ID} {}", self.kms_key_id()))
    }

    /// Start a builder.
    #[must_use]
    pub fn builder() -> AwsKmsEcdhKeyringBuilder {
        AwsKmsEcdhKeyringBuilder::default()
    }

    /// The curve of the keyring's keys.
    #[must_use]
    pub fn curve_spec(&self) -> EcdhCurveSpec {
        self.inner.curve_spec
    }

    /// The key agreement scheme.
    #[must_use]
    pub fn key_agreement_scheme(&self) -> &KmsEcdhStaticConfigurations {
        &self.inner.key_agreement_scheme
    }

    /// The grant tokens that this keyring sends with every AWS KMS request.
    #[must_use]
    pub fn grant_tokens(&self) -> &[String] {
        &self.inner.grant_tokens
    }

    /// The AWS KMS key this keyring derives shared secrets with.
    fn kms_key_id(&self) -> &str {
        match &self.inner.key_agreement_scheme {
            KmsEcdhStaticConfigurations::KmsPrivateKeyToStaticPublicKey(config) => {
                &config.sender_kms_identifier
            }
            KmsEcdhStaticConfigurations::KmsPublicKeyDiscovery(config) => {
                &config.recipient_kms_identifier
            }
        }
    }

    /// Decrypt one encrypted data key that [`ecdh_wrapping::should_decrypt`] matched.
    async fn decrypt_edk(
        &self,
        materials: &DecryptionMaterials,
        edk: &EncryptedDataKey,
    ) -> Result<DecryptionMaterials, Error> {
        let curve = self.inner.curve_spec.primitive();
        let info = ecdh_wrapping::parse_provider_info(edk.key_provider_info())?;
        let sender_public_key = ecdh_decompress_public_key(curve, info.sender_public_key).map_err(
            prim_err(Kind::Cryptographic, "invalid sender public key in the EDK"),
        )?;
        let recipient_public_key = ecdh_decompress_public_key(curve, info.recipient_public_key)
            .map_err(prim_err(
                Kind::Cryptographic,
                "invalid recipient public key in the EDK",
            ))?;
        ecdh_validate_public_key(curve, &sender_public_key).map_err(prim_err(
            Kind::Cryptographic,
            "invalid sender public key in the EDK",
        ))?;
        ecdh_validate_public_key(curve, &recipient_public_key).map_err(prim_err(
            Kind::Cryptographic,
            "invalid recipient public key in the EDK",
        ))?;
        if !valid_public_key_length(&sender_public_key)
            || !valid_public_key_length(&self.inner.recipient_public_key)
        {
            return Err(Error::new(
                Kind::Cryptographic,
                "Received serialized sender public key of incorrect length",
            ));
        }

        let (kms_key_id, public_key) = match &self.inner.key_agreement_scheme {
            KmsEcdhStaticConfigurations::KmsPublicKeyDiscovery(config) => {
                (config.recipient_kms_identifier.as_str(), sender_public_key)
            }
            KmsEcdhStaticConfigurations::KmsPrivateKeyToStaticPublicKey(config) => {
                // This keyring may be either party of the message.
                let public_key = if config.recipient_public_key == recipient_public_key {
                    recipient_public_key
                } else {
                    sender_public_key
                };
                (config.sender_kms_identifier.as_str(), public_key)
            }
        };
        let shared_secret = derive_shared_secret(
            &self.inner.client,
            kms_key_id,
            &public_key,
            &self.inner.grant_tokens,
        )
        .await?;
        let canonical_ec = materials
            .encryption_context()
            .to_bytes()
            .map_err(|e| Error::wrap("failed to serialize the encryption context", e))?;
        let fixed_info = ecdh_wrapping::fixed_info(
            self.inner.curve_spec,
            info.sender_public_key,
            info.recipient_public_key,
            &canonical_ec,
        );
        ecdh_wrapping::decrypt_encrypted_data_key(
            materials,
            &shared_secret,
            &fixed_info,
            edk.ciphertext(),
        )
    }
}

/// Call AWS KMS `DeriveSharedSecret` with the AWS KMS key `key_id` and the other party's `public_key`.
///
/// Fails unless the response names `key_id` and the ECDH algorithm and has a shared secret.
async fn derive_shared_secret(
    client: &KmsClient,
    key_id: &str,
    public_key: &[u8],
    grant_tokens: &[String],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let resource = KmsKey::new(key_id.to_owned());
    let response = client
        .derive_shared_secret()
        .key_id(key_id)
        .key_agreement_algorithm(KeyAgreementAlgorithmSpec::Ecdh)
        .public_key(Blob::new(public_key))
        .set_grant_tokens(Some(grant_tokens.to_vec()))
        .customize()
        .config_override(user_agent_override())
        .send()
        .await
        .map_err(|e| {
            Error::from_sdk(Service::Kms, "AWS KMS DeriveSharedSecret", e).with_resource(resource)
        })?;
    if response.key_id.as_deref() != Some(key_id)
        || response.key_agreement_algorithm != Some(KeyAgreementAlgorithmSpec::Ecdh)
    {
        return Err(service_err(
            key_id,
            "Invalid response from KMS DeriveSharedSecret",
        ));
    }
    response
        .shared_secret
        .map(|secret| Zeroizing::new(secret.into_inner()))
        .ok_or_else(|| service_err(key_id, "Invalid response from KMS DeriveSharedSecret"))
}

/// Call AWS KMS `GetPublicKey` on `key_id`.
/// Returns the DER-encoded X.509 `SubjectPublicKeyInfo` public key.
///
/// Fails unless the response names `key_id` and key usage `KEY_AGREEMENT` and has a public key.
async fn get_ecdh_public_key(client: &KmsClient, key_id: &str) -> Result<Vec<u8>, Error> {
    let resource = KmsKey::new(key_id.to_owned());
    let response = client
        .get_public_key()
        .key_id(key_id)
        .customize()
        .config_override(user_agent_override())
        .send()
        .await
        .map_err(|e| {
            Error::from_sdk(Service::Kms, "AWS KMS GetPublicKey", e).with_resource(resource)
        })?;
    if response.key_id.as_deref() != Some(key_id)
        || response.key_usage != Some(KeyUsageType::KeyAgreement)
    {
        return Err(service_err(
            key_id,
            "Invalid response from KMS GetPublicKey",
        ));
    }
    response
        .public_key
        .map(Blob::into_inner)
        .ok_or_else(|| service_err(key_id, "Invalid response from KMS GetPublicKey"))
}

/// Builder for [`AwsKmsEcdhKeyring`].
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct AwsKmsEcdhKeyringBuilder {
    key_agreement_scheme: Option<KmsEcdhStaticConfigurations>,
    curve_spec: Option<EcdhCurveSpec>,
    kms_client: Option<KmsClient>,
    grant_tokens: Option<Vec<String>>,
}

impl AwsKmsEcdhKeyringBuilder {
    /// How the keyring gets the keys of its key agreement.
    /// Required.
    #[must_use]
    pub fn key_agreement_scheme(mut self, scheme: KmsEcdhStaticConfigurations) -> Self {
        self.key_agreement_scheme = Some(scheme);
        self
    }

    /// The key agreement scheme. See [`Self::key_agreement_scheme`].
    #[must_use]
    pub fn set_key_agreement_scheme(mut self, scheme: Option<KmsEcdhStaticConfigurations>) -> Self {
        self.key_agreement_scheme = scheme;
        self
    }

    /// The key agreement scheme, if set.
    #[must_use]
    pub fn get_key_agreement_scheme(&self) -> &Option<KmsEcdhStaticConfigurations> {
        &self.key_agreement_scheme
    }

    /// The curve of every key the keyring uses.
    /// Required.
    #[must_use]
    pub fn curve_spec(mut self, curve_spec: EcdhCurveSpec) -> Self {
        self.curve_spec = Some(curve_spec);
        self
    }

    /// The curve. See [`Self::curve_spec`].
    #[must_use]
    pub fn set_curve_spec(mut self, curve_spec: Option<EcdhCurveSpec>) -> Self {
        self.curve_spec = curve_spec;
        self
    }

    /// The curve, if set.
    #[must_use]
    pub fn get_curve_spec(&self) -> &Option<EcdhCurveSpec> {
        &self.curve_spec
    }

    /// The AWS KMS client, in the AWS KMS key's region.
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

    /// The AWS KMS client, if set.
    #[must_use]
    pub fn get_kms_client(&self) -> &Option<KmsClient> {
        &self.kms_client
    }

    /// Add a grant token, sent with every AWS KMS `DeriveSharedSecret` request.
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
    pub fn get_grant_tokens(&self) -> &Option<Vec<String>> {
        &self.grant_tokens
    }

    /// Build the keyring.
    ///
    /// Calls AWS KMS `GetPublicKey` for the recipient's key with `KmsPublicKeyDiscovery`,
    /// and for the sender's key with `KmsPrivateKeyToStaticPublicKey` without a sender public key.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): the key agreement scheme, curve, or client is unset,
    ///   a malformed AWS KMS key identifier,
    ///   a public key that is not a valid key on the curve,
    ///   or invalid grant tokens.
    /// - A `GetPublicKey` failure, or a response for a key that is not a key agreement key.
    pub async fn build(self) -> Result<AwsKmsEcdhKeyring, Error> {
        let key_agreement_scheme = required(self.key_agreement_scheme, "key_agreement_scheme")?;
        let curve_spec = required(self.curve_spec, "curve_spec")?;
        let client = required(self.kms_client, "kms_client")?;
        let grant_tokens = valid_grant_tokens(self.grant_tokens)?;
        let curve = curve_spec.primitive();

        let (recipient_public_key, sender) = match &key_agreement_scheme {
            KmsEcdhStaticConfigurations::KmsPublicKeyDiscovery(config) => {
                validate_kms_key_id(&config.recipient_kms_identifier)?;
                let recipient_public_key =
                    get_ecdh_public_key(&client, &config.recipient_kms_identifier).await?;
                (recipient_public_key, None)
            }
            KmsEcdhStaticConfigurations::KmsPrivateKeyToStaticPublicKey(config) => {
                validate_kms_key_id(&config.sender_kms_identifier)?;
                let sender_public_key = match &config.sender_public_key {
                    Some(key) => {
                        if !valid_public_key_length(key) {
                            return Err(Error::validation("Invalid SenderPublicKey length."));
                        }
                        key.clone()
                    }
                    None => get_ecdh_public_key(&client, &config.sender_kms_identifier).await?,
                };
                if !valid_public_key_length(&config.recipient_public_key) {
                    return Err(Error::validation("Invalid RecipientPublicKey length."));
                }
                (
                    config.recipient_public_key.clone(),
                    Some((config.sender_kms_identifier.clone(), sender_public_key)),
                )
            }
        };

        ecdh_validate_public_key(curve, &recipient_public_key)
            .map_err(prim_err(Kind::Validation, "invalid recipient public key"))?;
        let compressed_recipient_public_key =
            ecdh_compress_public_key(curve, &recipient_public_key)
                .map_err(prim_err(Kind::Validation, "invalid recipient public key"))?;
        let (sender_kms_key_id, compressed_sender_public_key) = match sender {
            Some((key_id, public_key)) => {
                ecdh_validate_public_key(curve, &public_key)
                    .map_err(prim_err(Kind::Validation, "invalid sender public key"))?;
                let compressed = ecdh_compress_public_key(curve, &public_key)
                    .map_err(prim_err(Kind::Validation, "invalid sender public key"))?;
                (Some(key_id), compressed)
            }
            None => (None, Vec::new()),
        };

        Ok(AwsKmsEcdhKeyring {
            inner: Arc::new(AwsKmsEcdhKeyringInner {
                key_agreement_scheme,
                curve_spec,
                client,
                grant_tokens,
                sender_kms_key_id,
                compressed_sender_public_key,
                recipient_public_key,
                compressed_recipient_public_key,
            }),
        })
    }
}

#[async_trait]
impl Keyring for crate::shared::Builtin<AwsKmsEcdhKeyring> {
    fn name(&self) -> Cow<'_, str> {
        self.0.name()
    }

    async fn on_encrypt(&self, input: OnEncryptInput) -> Result<OnEncryptOutput, Error> {
        let Some(sender_kms_key_id) = self.inner.sender_kms_key_id.as_deref() else {
            return Err(Error::new(
                Kind::Validation,
                "KmsPublicKeyDiscovery Key Agreement Scheme is forbidden on encrypt.",
            ));
        };
        let materials = input.into_materials();
        let shared_secret = derive_shared_secret(
            &self.inner.client,
            sender_kms_key_id,
            &self.inner.recipient_public_key,
            &self.inner.grant_tokens,
        )
        .await?;
        let canonical_ec = materials
            .encryption_context()
            .to_bytes()
            .map_err(|e| Error::wrap("failed to serialize the encryption context", e))?;
        let fixed_info = ecdh_wrapping::fixed_info(
            self.inner.curve_spec,
            &self.inner.compressed_sender_public_key,
            &self.inner.compressed_recipient_public_key,
            &canonical_ec,
        );
        let provider_info = ecdh_wrapping::serialize_provider_info(
            &self.inner.compressed_sender_public_key,
            &self.inner.compressed_recipient_public_key,
        )?;
        let materials = ecdh_wrapping::add_encrypted_data_key(
            materials,
            &shared_secret,
            &fixed_info,
            KMS_ECDH_PROVIDER_ID,
            provider_info,
        )?;
        OnEncryptOutput::builder().materials(materials).build()
    }

    async fn on_decrypt(&self, input: OnDecryptInput) -> Result<OnDecryptOutput, Error> {
        let discovery = matches!(
            self.inner.key_agreement_scheme,
            KmsEcdhStaticConfigurations::KmsPublicKeyDiscovery(_)
        );
        let (materials, encrypted_data_keys) = input.into_parts();
        if materials.plaintext_data_key().is_some() {
            return Err(Error::new(
                Kind::InvalidMaterials,
                "Keyring received decryption materials that already contain a plaintext data key.",
            ));
        }

        let mut to_attempt = Vec::new();
        for edk in &encrypted_data_keys {
            if ecdh_wrapping::should_decrypt(
                edk,
                discovery,
                &self.inner.compressed_sender_public_key,
                &self.inner.compressed_recipient_public_key,
            )? {
                to_attempt.push(edk);
            }
        }
        if to_attempt.is_empty() {
            return Err(Error::no_matching_data_key(format!(
                "no encrypted data key matches the public keys of the AWS KMS ECDH keyring for {}",
                self.0.kms_key_id()
            ))
            .with_encrypted_data_keys(encrypted_data_keys.iter().map(DataKeyInfo::from)));
        }

        let mut errors = Vec::new();
        for edk in to_attempt {
            match self.0.decrypt_edk(&materials, edk).await {
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

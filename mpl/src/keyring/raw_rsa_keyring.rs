// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Raw RSA keyring.

use crate::Error;
use crate::builder::required;
use crate::error::{DataKeyInfo, Kind};
use std::borrow::Cow;
use std::sync::Arc;

use crate::keyring::edk_wrapping;
use crate::structures::{EdkWrapping, PaddingScheme};
use async_trait::async_trait;
use aws_mpl_primitives::{generate_random_bytes, rsa_decrypt, rsa_encrypt};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::keyring::Keyring;
use crate::keyring::{OnDecryptInput, OnDecryptOutput, OnEncryptInput, OnEncryptOutput};
use crate::structures::{AlgorithmSuite, EncryptedDataKey, PlaintextDataKey};

/// Key namespace prefix reserved for the AWS KMS keyrings.
/// The key namespace becomes the EDK's key provider ID,
/// and that ID must not claim to come from an AWS KMS keyring.
const RESERVED_KEY_NAMESPACE_PREFIX: &str = "aws-kms";

/// A keyring that wraps data keys with a local RSA public key
/// and unwraps them with the matching RSA private key.
///
/// Construct with [`RawRsaKeyring::builder`].
/// A keyring with only a public key can only encrypt;
/// a keyring with only a private key can only decrypt.
#[derive(Clone)]
pub struct RawRsaKeyring {
    inner: Arc<RawRsaKeyringInner>,
}

struct RawRsaKeyringInner {
    /// `{key_namespace}/{key_name}`, which `name()` returns.
    name: String,
    key_namespace: String,
    key_name: String,
    padding_scheme: PaddingScheme,
    public_key: Option<Vec<u8>>,
    private_key: Option<Vec<u8>>,
}

impl Drop for RawRsaKeyringInner {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

impl ZeroizeOnDrop for RawRsaKeyringInner {}

impl std::fmt::Debug for RawRsaKeyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawRsaKeyring")
            .field("key_namespace", &self.inner.key_namespace)
            .field("key_name", &self.inner.key_name)
            .field("padding_scheme", &self.inner.padding_scheme)
            .field("has_public_key", &self.inner.public_key.is_some())
            .field("has_private_key", &self.inner.private_key.is_some())
            .finish()
    }
}

impl RawRsaKeyring {
    /// `{key_namespace}/{key_name}`.
    #[must_use]
    pub fn name(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.inner.name)
    }

    /// Start a builder for `RawRsaKeyring`.
    #[must_use]
    pub fn builder() -> RawRsaKeyringBuilder {
        RawRsaKeyringBuilder::default()
    }

    /// The key namespace, used as the key provider ID of EDKs this keyring produces.
    #[must_use]
    pub fn key_namespace(&self) -> &str {
        &self.inner.key_namespace
    }

    /// The key name, used as the key provider information of EDKs this keyring produces.
    #[must_use]
    pub fn key_name(&self) -> &str {
        &self.inner.key_name
    }

    /// The configured padding scheme.
    #[must_use]
    pub fn padding_scheme(&self) -> PaddingScheme {
        self.inner.padding_scheme
    }

    /// The PEM-encoded public key, if configured.
    #[must_use]
    pub fn public_key(&self) -> Option<&[u8]> {
        self.inner.public_key.as_deref()
    }

    /// RSA-encrypt `material` under the public key.
    fn wrap(&self, public_key: &[u8], material: &PlaintextDataKey) -> Result<Vec<u8>, Error> {
        rsa_encrypt(
            self.inner.padding_scheme.primitive(),
            public_key,
            material.as_bytes(),
        )
        .map_err(|e| {
            Error::with_cause(
                Kind::Cryptographic,
                "RSA encryption of the data key failed",
                e,
            )
        })
    }

    /// RSA-decrypt `wrapped` under the private key,
    /// and check that the result has the encryption key length of `suite`.
    fn unwrap(
        &self,
        private_key: &[u8],
        suite: &AlgorithmSuite,
        wrapped: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let material = Zeroizing::new(
            rsa_decrypt(self.inner.padding_scheme.primitive(), private_key, wrapped).map_err(
                |e| {
                    Error::with_cause(
                        Kind::Cryptographic,
                        "RSA decryption of the data key failed",
                        e,
                    )
                },
            )?,
        );
        if material.len() != suite.encryption_key_length() {
            return Err(Error::new(Kind::Cryptographic, "Invalid plaintext length."));
        }
        Ok(material)
    }

    /// Whether this keyring should attempt to decrypt `edk`:
    /// its key provider ID and information match, and its ciphertext is not empty.
    fn should_decrypt(&self, edk: &EncryptedDataKey) -> bool {
        edk.key_provider_id() == self.inner.key_namespace
            && edk.key_provider_info() == self.inner.key_name.as_bytes()
            && !edk.ciphertext().is_empty()
    }
}

/// Builder for [`RawRsaKeyring`].
#[derive(Default)]
pub struct RawRsaKeyringBuilder {
    key_namespace: Option<String>,
    key_name: Option<String>,
    padding_scheme: Option<PaddingScheme>,
    public_key: Option<Vec<u8>>,
    private_key: Option<Vec<u8>>,
}

impl Drop for RawRsaKeyringBuilder {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

impl ZeroizeOnDrop for RawRsaKeyringBuilder {}

impl std::fmt::Debug for RawRsaKeyringBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawRsaKeyringBuilder")
            .field("key_namespace", &self.key_namespace)
            .field("key_name", &self.key_name)
            .field("padding_scheme", &self.padding_scheme)
            .field("has_public_key", &self.public_key.is_some())
            .field("has_private_key", &self.private_key.is_some())
            .finish_non_exhaustive()
    }
}

impl RawRsaKeyringBuilder {
    /// Set the key namespace, which becomes the key provider ID of each EDK this keyring produces.
    /// Required, and must not be or start with `aws-kms`.
    #[must_use]
    pub fn key_namespace(mut self, key_namespace: impl Into<String>) -> Self {
        self.key_namespace = Some(key_namespace.into());
        self
    }

    /// Set or clear the key namespace from an `Option`.
    /// To set a value, use [`Self::key_namespace`].
    #[must_use]
    pub fn set_key_namespace(mut self, key_namespace: Option<String>) -> Self {
        self.key_namespace = key_namespace;
        self
    }

    /// The key namespace, if set.
    #[must_use]
    pub const fn get_key_namespace(&self) -> &Option<String> {
        &self.key_namespace
    }

    /// Set the key name, which becomes the key provider information of each EDK this keyring produces.
    /// Required.
    #[must_use]
    pub fn key_name(mut self, key_name: impl Into<String>) -> Self {
        self.key_name = Some(key_name.into());
        self
    }

    /// Set or clear the key name from an `Option`.
    /// To set a value, use [`Self::key_name`].
    #[must_use]
    pub fn set_key_name(mut self, key_name: Option<String>) -> Self {
        self.key_name = key_name;
        self
    }

    /// The key name, if set.
    #[must_use]
    pub const fn get_key_name(&self) -> &Option<String> {
        &self.key_name
    }

    /// Set the padding scheme.
    /// Required.
    #[must_use]
    pub const fn padding_scheme(mut self, padding_scheme: PaddingScheme) -> Self {
        self.padding_scheme = Some(padding_scheme);
        self
    }

    /// Set or clear the padding scheme from an `Option`.
    /// To set a value, use [`Self::padding_scheme`].
    #[must_use]
    pub const fn set_padding_scheme(mut self, padding_scheme: Option<PaddingScheme>) -> Self {
        self.padding_scheme = padding_scheme;
        self
    }

    /// The padding scheme, if set.
    #[must_use]
    pub const fn get_padding_scheme(&self) -> &Option<PaddingScheme> {
        &self.padding_scheme
    }

    /// Set the PEM-encoded X.509 `SubjectPublicKeyInfo` RSA public key, used to encrypt.
    /// Set this, the private key, or both.
    #[must_use]
    pub fn public_key(mut self, public_key: impl Into<Vec<u8>>) -> Self {
        self.public_key = Some(public_key.into());
        self
    }

    /// Set or clear the public key from an `Option`.
    /// To set a value, use [`Self::public_key`].
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

    /// Set the PEM-encoded PKCS #8 RSA private key, used to decrypt.
    /// Set this, the public key, or both.
    #[must_use]
    pub fn private_key(mut self, private_key: impl Into<Vec<u8>>) -> Self {
        self.private_key = Some(private_key.into());
        self
    }

    /// Set or clear the private key from an `Option`.
    /// To set a value, use [`Self::private_key`].
    #[must_use]
    pub fn set_private_key(mut self, private_key: Option<Vec<u8>>) -> Self {
        self.private_key = private_key;
        self
    }

    /// The private key, if set.
    #[must_use]
    pub const fn get_private_key(&self) -> &Option<Vec<u8>> {
        &self.private_key
    }

    /// Build the `RawRsaKeyring`.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): the key namespace, key name or padding scheme is unset,
    ///   neither key is set,
    ///   or the key namespace is or starts with `aws-kms`.
    pub fn build(mut self) -> Result<RawRsaKeyring, Error> {
        let key_namespace = required(self.key_namespace.take(), "key_namespace")?;
        let key_name = required(self.key_name.take(), "key_name")?;
        let padding_scheme = required(self.padding_scheme.take(), "padding_scheme")?;
        // Treat an empty key as unset.
        let public_key = self.public_key.take().filter(|key| !key.is_empty());
        let private_key = self.private_key.take().filter(|key| !key.is_empty());

        if key_namespace.starts_with(RESERVED_KEY_NAMESPACE_PREFIX) {
            return Err(Error::new(
                Kind::Validation,
                format!(
                    "key namespace must not be or start with `{RESERVED_KEY_NAMESPACE_PREFIX}`, got `{key_namespace}`"
                ),
            ));
        }
        if public_key.is_none() && private_key.is_none() {
            return Err(Error::new(
                Kind::Validation,
                "A publicKey or a privateKey is required",
            ));
        }

        Ok(RawRsaKeyring {
            inner: Arc::new(RawRsaKeyringInner {
                name: format!("{key_namespace}/{key_name}"),
                key_namespace,
                key_name,
                padding_scheme,
                public_key,
                private_key,
            }),
        })
    }
}

#[async_trait]
impl Keyring for crate::shared::Builtin<RawRsaKeyring> {
    fn name(&self) -> Cow<'_, str> {
        self.0.name()
    }

    async fn on_encrypt(&self, input: OnEncryptInput) -> Result<OnEncryptOutput, Error> {
        let Some(public_key) = self.inner.public_key.as_deref() else {
            return Err(Error::new(
                Kind::Validation,
                "A RawRSAKeyring without a public key cannot provide OnEncrypt",
            ));
        };
        let materials = input.materials;
        let suite = materials.algorithm_suite();
        let key_provider = |ciphertext: Vec<u8>| {
            EncryptedDataKey::builder()
                .key_provider_id(self.inner.key_namespace.as_str())
                .key_provider_info(self.inner.key_name.as_bytes().to_vec())
                .ciphertext(ciphertext)
                .build()
        };

        let materials = match (suite.edk_wrapping(), materials.plaintext_data_key()) {
            (EdkWrapping::IntermediateKeyWrapping(_), existing) => {
                // Wrap a fresh intermediate key.
                // Keys derived from it encrypt the plaintext data key and sign the message.
                let aad = materials
                    .encryption_context()
                    .serialize()
                    .map_err(|e| Error::wrap("failed to serialize the encryption context", e))?;
                let (plaintext_dk, generated) = match existing {
                    Some(key) => (key.clone(), false),
                    None => (generate_random_data_key(suite)?, true),
                };
                let ikm = generate_random_data_key(suite)?;
                let wrapped_ikm = self.wrap(public_key, &ikm)?;
                let (mut ciphertext, signing_key) =
                    edk_wrapping::encrypt_pdk(&suite, ikm.as_bytes(), &aad, &plaintext_dk)?;
                ciphertext.extend_from_slice(&wrapped_ikm);
                let edk = key_provider(ciphertext)?;
                if generated {
                    materials.add_data_key_with_symmetric_signing_key(
                        plaintext_dk,
                        edk,
                        signing_key,
                    )?
                } else {
                    materials.add_encrypted_data_key_with_symmetric_signing_key(edk, signing_key)?
                }
            }
            (_, Some(plaintext_dk)) => {
                let edk = key_provider(self.wrap(public_key, plaintext_dk)?)?;
                materials.add_encrypted_data_key(edk)?
            }
            (_, None) => {
                let plaintext_dk = generate_random_data_key(suite)?;
                let edk = key_provider(self.wrap(public_key, &plaintext_dk)?)?;
                materials.add_data_key(plaintext_dk, edk)?
            }
        };
        OnEncryptOutput::builder().materials(materials).build()
    }

    async fn on_decrypt(&self, input: OnDecryptInput) -> Result<OnDecryptOutput, Error> {
        let Some(private_key) = self.inner.private_key.as_deref() else {
            return Err(Error::new(
                Kind::Validation,
                "A RawRSAKeyring without a private key cannot provide OnDecrypt",
            ));
        };
        let OnDecryptInput {
            materials,
            encrypted_data_keys,
        } = input;
        if materials.plaintext_data_key().is_some() {
            return Err(Error::new(
                Kind::InvalidMaterials,
                "Keyring received decryption materials that already contain a plaintext data key.",
            ));
        }

        let suite = materials.algorithm_suite();
        let intermediate = matches!(
            suite.edk_wrapping(),
            EdkWrapping::IntermediateKeyWrapping(_)
        );
        let aad = if intermediate {
            Some(
                materials
                    .encryption_context()
                    .serialize()
                    .map_err(|e| Error::wrap("failed to serialize the encryption context", e))?,
            )
        } else {
            None
        };

        let mut collected_errors: Vec<Error> = Vec::new();
        let mut attempted_decryption = false;
        for (index, edk) in encrypted_data_keys.iter().enumerate() {
            if !self.should_decrypt(edk) {
                collected_errors.push(
                    Error::new(Kind::NoMatchingDataKey, format!(
                        "encrypted data key {index} did not match the RSAKeyring, expected key provider id {}",
                        self.inner.key_namespace,
                    ))
                    .with_encrypted_data_keys(encrypted_data_keys.iter().map(DataKeyInfo::from)),
                );
                continue;
            }
            attempted_decryption = true;

            let result = match &aad {
                Some(aad) => edk_wrapping::split(&suite, edk.ciphertext())
                    .map_err(|e| Error::wrap("Invalid material for Intermediate Unwrapping", e))
                    .and_then(|(encrypted_pdk, wrapped_ikm)| {
                        let ikm = self.0.unwrap(private_key, &suite, wrapped_ikm)?;
                        edk_wrapping::decrypt_pdk(&suite, &ikm, aad, encrypted_pdk)
                    })
                    .and_then(|(pdk, signing_key)| {
                        materials
                            .clone()
                            .add_data_key_with_symmetric_signing_key(pdk, signing_key)
                    }),
                None => self
                    .0
                    .unwrap(private_key, &suite, edk.ciphertext())
                    .and_then(|pdk| {
                        materials
                            .clone()
                            .add_data_key(PlaintextDataKey::new(pdk.to_vec()))
                    }),
            };
            match result {
                Ok(materials) => return OnDecryptOutput::builder().materials(materials).build(),
                Err(e) => collected_errors.push(Error::wrap(
                    format!("encrypted data key {index} did not decrypt"),
                    e,
                )),
            }
        }

        if !attempted_decryption {
            return Err(if collected_errors.is_empty() {
                Error::new(
                    Kind::NoMatchingDataKey,
                    "no encrypted data key was supplied",
                )
            } else {
                Error::all_failed(
                    "no encrypted data key matched this keyring",
                    collected_errors,
                )
            });
        }

        Err(Error::all_failed(
            "Raw RSA Key was unable to decrypt any encrypted data key.",
            collected_errors,
        ))
    }
}

/// Generate a random key of the algorithm suite's encryption key length.
fn generate_random_data_key(suite: AlgorithmSuite) -> Result<PlaintextDataKey, Error> {
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

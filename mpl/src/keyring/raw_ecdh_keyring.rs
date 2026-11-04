// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Raw ECDH keyring. Ported from the Dafny `RawECDHKeyring.dfy`
//! and `CreateRawEcdhKeyring` in `AwsCryptographyMaterialProvidersOperations.dfy`.

use std::borrow::Cow;
use std::sync::Arc;

use async_trait::async_trait;
use aws_mpl_primitives::{
    ecdh_compress_public_key, ecdh_decompress_public_key, ecdh_derive_shared_secret,
    ecdh_generate_key_pair, ecdh_public_key_from_private_key, ecdh_validate_public_key,
};
use zeroize::Zeroizing;

use crate::Error;
use crate::builder::required;
use crate::error::{DataKeyInfo, Kind};
use crate::keyring::ecdh_wrapping::{self, RAW_ECDH_PROVIDER_ID};
use crate::keyring::{Keyring, OnDecryptInput, OnDecryptOutput, OnEncryptInput, OnEncryptOutput};
use crate::structures::{DecryptionMaterials, EcdhCurveSpec, EncryptedDataKey};

/// Map a primitives error to an MPL error of `kind`.
fn prim_err(kind: Kind, message: &'static str) -> impl FnOnce(aws_mpl_primitives::Error) -> Error {
    move |e| Error::with_cause(kind, message, e)
}

/// Whether `key` has the length of a DER X.509 public key on one of the supported curves.
fn valid_public_key_length(key: &[u8]) -> bool {
    [
        EcdhCurveSpec::EccNistP256,
        EcdhCurveSpec::EccNistP384,
        EcdhCurveSpec::EccNistP521,
    ]
    .iter()
    .any(|curve| curve.primitive().public_key_der_len() == key.len())
}

/// The sender's static private key and the recipient's public key.
/// Encrypts and decrypts.
#[derive(Clone)]
#[non_exhaustive]
pub struct RawPrivateKeyToStaticPublicKeyInput {
    sender_static_private_key: Zeroizing<Vec<u8>>,
    recipient_public_key: Vec<u8>,
}

impl std::fmt::Debug for RawPrivateKeyToStaticPublicKeyInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawPrivateKeyToStaticPublicKeyInput")
            .field("recipient_public_key", &self.recipient_public_key)
            .finish_non_exhaustive()
    }
}

impl RawPrivateKeyToStaticPublicKeyInput {
    /// Start a builder.
    #[must_use]
    pub fn builder() -> RawPrivateKeyToStaticPublicKeyInputBuilder {
        RawPrivateKeyToStaticPublicKeyInputBuilder::default()
    }

    /// The recipient's DER-encoded X.509 `SubjectPublicKeyInfo` public key.
    #[must_use]
    pub fn recipient_public_key(&self) -> &[u8] {
        &self.recipient_public_key
    }
}

/// Builder for [`RawPrivateKeyToStaticPublicKeyInput`].
#[derive(Clone, Default)]
#[non_exhaustive]
pub struct RawPrivateKeyToStaticPublicKeyInputBuilder {
    sender_static_private_key: Option<Zeroizing<Vec<u8>>>,
    recipient_public_key: Option<Vec<u8>>,
}

impl std::fmt::Debug for RawPrivateKeyToStaticPublicKeyInputBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawPrivateKeyToStaticPublicKeyInputBuilder")
            .field(
                "has_sender_static_private_key",
                &self.sender_static_private_key.is_some(),
            )
            .field("recipient_public_key", &self.recipient_public_key)
            .finish_non_exhaustive()
    }
}

impl RawPrivateKeyToStaticPublicKeyInputBuilder {
    /// The sender's PEM-encoded PKCS #8 private key.
    /// Required.
    #[must_use]
    pub fn sender_static_private_key(mut self, key: impl Into<Vec<u8>>) -> Self {
        self.sender_static_private_key = Some(Zeroizing::new(key.into()));
        self
    }

    /// The sender's private key. See [`Self::sender_static_private_key`].
    #[must_use]
    pub fn set_sender_static_private_key(mut self, key: Option<Vec<u8>>) -> Self {
        self.sender_static_private_key = key.map(Zeroizing::new);
        self
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
    /// - [`Validation`](crate::Error::Validation): either key is unset.
    pub fn build(self) -> Result<RawPrivateKeyToStaticPublicKeyInput, Error> {
        Ok(RawPrivateKeyToStaticPublicKeyInput {
            sender_static_private_key: required(
                self.sender_static_private_key,
                "sender_static_private_key",
            )?,
            recipient_public_key: required(self.recipient_public_key, "recipient_public_key")?,
        })
    }
}

/// A fresh ephemeral key pair for each message, and the recipient's public key.
/// Encrypts only.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct EphemeralPrivateKeyToStaticPublicKeyInput {
    recipient_public_key: Vec<u8>,
}

impl EphemeralPrivateKeyToStaticPublicKeyInput {
    /// Start a builder.
    #[must_use]
    pub fn builder() -> EphemeralPrivateKeyToStaticPublicKeyInputBuilder {
        EphemeralPrivateKeyToStaticPublicKeyInputBuilder::default()
    }

    /// The recipient's DER-encoded X.509 `SubjectPublicKeyInfo` public key.
    #[must_use]
    pub fn recipient_public_key(&self) -> &[u8] {
        &self.recipient_public_key
    }
}

/// Builder for [`EphemeralPrivateKeyToStaticPublicKeyInput`].
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct EphemeralPrivateKeyToStaticPublicKeyInputBuilder {
    recipient_public_key: Option<Vec<u8>>,
}

impl EphemeralPrivateKeyToStaticPublicKeyInputBuilder {
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
    /// - [`Validation`](crate::Error::Validation): the recipient's public key is unset.
    pub fn build(self) -> Result<EphemeralPrivateKeyToStaticPublicKeyInput, Error> {
        Ok(EphemeralPrivateKeyToStaticPublicKeyInput {
            recipient_public_key: required(self.recipient_public_key, "recipient_public_key")?,
        })
    }
}

/// The recipient's static private key.
/// Decrypts only: the sender's public key comes from each encrypted data key.
#[derive(Clone)]
#[non_exhaustive]
pub struct PublicKeyDiscoveryInput {
    recipient_static_private_key: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for PublicKeyDiscoveryInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicKeyDiscoveryInput")
            .finish_non_exhaustive()
    }
}

impl PublicKeyDiscoveryInput {
    /// Start a builder.
    #[must_use]
    pub fn builder() -> PublicKeyDiscoveryInputBuilder {
        PublicKeyDiscoveryInputBuilder::default()
    }
}

/// Builder for [`PublicKeyDiscoveryInput`].
#[derive(Clone, Default)]
#[non_exhaustive]
pub struct PublicKeyDiscoveryInputBuilder {
    recipient_static_private_key: Option<Zeroizing<Vec<u8>>>,
}

impl std::fmt::Debug for PublicKeyDiscoveryInputBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicKeyDiscoveryInputBuilder")
            .field(
                "has_recipient_static_private_key",
                &self.recipient_static_private_key.is_some(),
            )
            .finish()
    }
}

impl PublicKeyDiscoveryInputBuilder {
    /// The recipient's PEM-encoded PKCS #8 private key.
    /// Required.
    #[must_use]
    pub fn recipient_static_private_key(mut self, key: impl Into<Vec<u8>>) -> Self {
        self.recipient_static_private_key = Some(Zeroizing::new(key.into()));
        self
    }

    /// The recipient's private key. See [`Self::recipient_static_private_key`].
    #[must_use]
    pub fn set_recipient_static_private_key(mut self, key: Option<Vec<u8>>) -> Self {
        self.recipient_static_private_key = key.map(Zeroizing::new);
        self
    }

    /// Build the key agreement scheme.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): the recipient's private key is unset.
    pub fn build(self) -> Result<PublicKeyDiscoveryInput, Error> {
        Ok(PublicKeyDiscoveryInput {
            recipient_static_private_key: required(
                self.recipient_static_private_key,
                "recipient_static_private_key",
            )?,
        })
    }
}

/// How a [`RawEcdhKeyring`] gets the two keys of its key agreement.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum RawEcdhStaticConfigurations {
    /// The sender's static private key and the recipient's public key.
    RawPrivateKeyToStaticPublicKey(RawPrivateKeyToStaticPublicKeyInput),
    /// A fresh ephemeral sender key pair and the recipient's public key. Encrypts only.
    EphemeralPrivateKeyToStaticPublicKey(EphemeralPrivateKeyToStaticPublicKeyInput),
    /// The recipient's static private key. Decrypts only.
    PublicKeyDiscovery(PublicKeyDiscoveryInput),
}

/// A keyring that wraps data keys with a key that it derives by ECDH key agreement.
///
/// Construct with [`RawEcdhKeyring::builder`].
/// The [`RawEcdhStaticConfigurations`] decides which keys the agreement uses
/// and whether the keyring can encrypt, decrypt, or both.
///
/// ```
/// use aws_crypto_mpl::keyring::{RawEcdhKeyring, RawEcdhStaticConfigurations, EphemeralPrivateKeyToStaticPublicKeyInput};
/// use aws_crypto_mpl::types::EcdhCurveSpec;
///
/// # fn main() -> Result<(), aws_crypto_mpl::Error> {
/// # let recipient_public_key = aws_mpl_primitives::ecdh_generate_key_pair(aws_mpl_primitives::EcdhCurveSpec::EccNistP256).unwrap().public_key.clone();
/// let keyring = RawEcdhKeyring::builder()
///     .curve_spec(EcdhCurveSpec::EccNistP256)
///     .key_agreement_scheme(RawEcdhStaticConfigurations::EphemeralPrivateKeyToStaticPublicKey(
///         EphemeralPrivateKeyToStaticPublicKeyInput::builder()
///             .recipient_public_key(recipient_public_key)
///             .build()?,
///     ))
///     .build()?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct RawEcdhKeyring {
    inner: Arc<RawEcdhKeyringInner>,
}

struct RawEcdhKeyringInner {
    key_agreement_scheme: RawEcdhStaticConfigurations,
    curve_spec: EcdhCurveSpec,
    recipient_public_key: Vec<u8>,
    /// Empty unless the scheme is `RawPrivateKeyToStaticPublicKey`.
    compressed_sender_public_key: Vec<u8>,
    compressed_recipient_public_key: Vec<u8>,
}

impl std::fmt::Debug for RawEcdhKeyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawEcdhKeyring")
            .field("key_agreement_scheme", &self.inner.key_agreement_scheme)
            .field("curve_spec", &self.inner.curve_spec)
            .finish_non_exhaustive()
    }
}

impl RawEcdhKeyring {
    /// `raw-ecdh`.
    #[must_use]
    pub fn name(&self) -> Cow<'_, str> {
        Cow::Borrowed(RAW_ECDH_PROVIDER_ID)
    }

    /// Start a builder.
    #[must_use]
    pub fn builder() -> RawEcdhKeyringBuilder {
        RawEcdhKeyringBuilder::default()
    }

    /// The curve of the keyring's keys.
    #[must_use]
    pub fn curve_spec(&self) -> EcdhCurveSpec {
        self.inner.curve_spec
    }

    /// The recipient's DER-encoded X.509 `SubjectPublicKeyInfo` public key.
    #[must_use]
    pub fn recipient_public_key(&self) -> &[u8] {
        &self.inner.recipient_public_key
    }

    /// Decrypt one encrypted data key that [`ecdh_wrapping::should_decrypt`] matched.
    fn decrypt_edk(
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

        let (private_key, public_key) = match &self.inner.key_agreement_scheme {
            RawEcdhStaticConfigurations::PublicKeyDiscovery(discovery) => (
                discovery.recipient_static_private_key.as_slice(),
                sender_public_key,
            ),
            RawEcdhStaticConfigurations::RawPrivateKeyToStaticPublicKey(config) => {
                // This keyring may be either party of the message.
                let public_key = if config.recipient_public_key == recipient_public_key {
                    recipient_public_key
                } else {
                    sender_public_key
                };
                (config.sender_static_private_key.as_slice(), public_key)
            }
            RawEcdhStaticConfigurations::EphemeralPrivateKeyToStaticPublicKey(_) => {
                return Err(Error::new(
                    Kind::Validation,
                    "EphemeralPrivateKeyToStaticPublicKey Not allowed on decrypt",
                ));
            }
        };
        let shared_secret = Zeroizing::new(
            ecdh_derive_shared_secret(curve, private_key, &public_key)
                .map_err(prim_err(Kind::Cryptographic, "ECDH key agreement failed"))?,
        );
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

/// Builder for [`RawEcdhKeyring`].
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct RawEcdhKeyringBuilder {
    key_agreement_scheme: Option<RawEcdhStaticConfigurations>,
    curve_spec: Option<EcdhCurveSpec>,
}

impl RawEcdhKeyringBuilder {
    /// How the keyring gets the keys of its key agreement.
    /// Required.
    #[must_use]
    pub fn key_agreement_scheme(mut self, scheme: RawEcdhStaticConfigurations) -> Self {
        self.key_agreement_scheme = Some(scheme);
        self
    }

    /// The key agreement scheme. See [`Self::key_agreement_scheme`].
    #[must_use]
    pub fn set_key_agreement_scheme(mut self, scheme: Option<RawEcdhStaticConfigurations>) -> Self {
        self.key_agreement_scheme = scheme;
        self
    }

    /// The key agreement scheme, if set.
    #[must_use]
    pub fn get_key_agreement_scheme(&self) -> &Option<RawEcdhStaticConfigurations> {
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

    /// Build the keyring.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): the key agreement scheme or curve is unset,
    ///   or a key is not a valid key on the curve.
    pub fn build(self) -> Result<RawEcdhKeyring, Error> {
        let key_agreement_scheme = required(self.key_agreement_scheme, "key_agreement_scheme")?;
        let curve_spec = required(self.curve_spec, "curve_spec")?;
        let curve = curve_spec.primitive();

        let (recipient_public_key, sender_public_key) = match &key_agreement_scheme {
            RawEcdhStaticConfigurations::RawPrivateKeyToStaticPublicKey(config) => {
                let sender_public_key =
                    ecdh_public_key_from_private_key(curve, &config.sender_static_private_key)
                        .map_err(prim_err(Kind::Validation, "invalid sender private key"))?;
                (config.recipient_public_key.clone(), Some(sender_public_key))
            }
            RawEcdhStaticConfigurations::EphemeralPrivateKeyToStaticPublicKey(config) => {
                (config.recipient_public_key.clone(), None)
            }
            RawEcdhStaticConfigurations::PublicKeyDiscovery(config) => {
                let recipient_public_key =
                    ecdh_public_key_from_private_key(curve, &config.recipient_static_private_key)
                        .map_err(prim_err(Kind::Validation, "invalid recipient private key"))?;
                (recipient_public_key, None)
            }
        };

        let compressed_recipient_public_key =
            ecdh_compress_public_key(curve, &recipient_public_key)
                .map_err(prim_err(Kind::Validation, "invalid recipient public key"))?;
        ecdh_validate_public_key(curve, &recipient_public_key)
            .map_err(prim_err(Kind::Validation, "invalid recipient public key"))?;

        let compressed_sender_public_key = match &sender_public_key {
            Some(sender_public_key) => {
                ecdh_validate_public_key(curve, sender_public_key)
                    .map_err(prim_err(Kind::Validation, "invalid sender public key"))?;
                if !valid_public_key_length(sender_public_key) {
                    return Err(Error::validation("Invalid sender public key length"));
                }
                ecdh_compress_public_key(curve, sender_public_key)
                    .map_err(prim_err(Kind::Validation, "invalid sender public key"))?
            }
            None => Vec::new(),
        };
        if !valid_public_key_length(&recipient_public_key) {
            return Err(Error::validation("Invalid recipient public key length"));
        }

        Ok(RawEcdhKeyring {
            inner: Arc::new(RawEcdhKeyringInner {
                key_agreement_scheme,
                curve_spec,
                recipient_public_key,
                compressed_sender_public_key,
                compressed_recipient_public_key,
            }),
        })
    }
}

#[async_trait]
impl Keyring for crate::shared::Builtin<RawEcdhKeyring> {
    fn name(&self) -> Cow<'_, str> {
        self.0.name()
    }

    async fn on_encrypt(&self, input: OnEncryptInput) -> Result<OnEncryptOutput, Error> {
        let curve = self.inner.curve_spec.primitive();
        // The ephemeral key pair lives only for this call.
        let ephemeral;
        let (sender_private_key, compressed_sender_public_key) =
            match &self.inner.key_agreement_scheme {
                RawEcdhStaticConfigurations::PublicKeyDiscovery(_) => {
                    return Err(Error::new(
                        Kind::Validation,
                        "PublicKeyDiscovery Key Agreement Scheme is forbidden on encrypt.",
                    ));
                }
                RawEcdhStaticConfigurations::EphemeralPrivateKeyToStaticPublicKey(_) => {
                    ephemeral = ecdh_generate_key_pair(curve).map_err(prim_err(
                        Kind::Cryptographic,
                        "ephemeral ECC key generation failed",
                    ))?;
                    let compressed = ecdh_compress_public_key(curve, &ephemeral.public_key)
                        .map_err(prim_err(
                            Kind::Cryptographic,
                            "compressing the ephemeral public key failed",
                        ))?;
                    (ephemeral.private_key.as_slice(), Cow::Owned(compressed))
                }
                RawEcdhStaticConfigurations::RawPrivateKeyToStaticPublicKey(config) => (
                    config.sender_static_private_key.as_slice(),
                    Cow::Borrowed(self.inner.compressed_sender_public_key.as_slice()),
                ),
            };

        let materials = input.into_materials();
        let shared_secret = Zeroizing::new(
            ecdh_derive_shared_secret(curve, sender_private_key, &self.inner.recipient_public_key)
                .map_err(prim_err(Kind::Cryptographic, "ECDH key agreement failed"))?,
        );
        let canonical_ec = materials
            .encryption_context()
            .to_bytes()
            .map_err(|e| Error::wrap("failed to serialize the encryption context", e))?;
        let fixed_info = ecdh_wrapping::fixed_info(
            self.inner.curve_spec,
            &compressed_sender_public_key,
            &self.inner.compressed_recipient_public_key,
            &canonical_ec,
        );
        let provider_info = ecdh_wrapping::serialize_provider_info(
            &compressed_sender_public_key,
            &self.inner.compressed_recipient_public_key,
        )?;
        let materials = ecdh_wrapping::add_encrypted_data_key(
            materials,
            &shared_secret,
            &fixed_info,
            RAW_ECDH_PROVIDER_ID,
            provider_info,
        )?;
        OnEncryptOutput::builder().materials(materials).build()
    }

    async fn on_decrypt(&self, input: OnDecryptInput) -> Result<OnDecryptOutput, Error> {
        let discovery = match &self.inner.key_agreement_scheme {
            RawEcdhStaticConfigurations::EphemeralPrivateKeyToStaticPublicKey(_) => {
                return Err(Error::new(
                    Kind::Validation,
                    "EphemeralPrivateKeyToStaticPublicKey Key Agreement Scheme is forbidden on decrypt.",
                ));
            }
            RawEcdhStaticConfigurations::PublicKeyDiscovery(_) => true,
            RawEcdhStaticConfigurations::RawPrivateKeyToStaticPublicKey(_) => false,
        };
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
            return Err(Error::no_matching_data_key(
                "no encrypted data key matches this raw ECDH keyring's public keys",
            )
            .with_encrypted_data_keys(encrypted_data_keys.iter().map(DataKeyInfo::from)));
        }

        let mut errors = Vec::new();
        for edk in to_attempt {
            match self.0.decrypt_edk(&materials, edk) {
                Ok(materials) => return OnDecryptOutput::builder().materials(materials).build(),
                Err(e) => errors.push(e),
            }
        }
        Err(Error::all_failed(
            "No Configured Key was able to decrypt the Data Key.",
            errors,
        ))
    }
}

// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The multi-keyring: combines keyrings so each data key is wrapped by all of them.

use std::borrow::Cow;
use std::sync::Arc;

use async_trait::async_trait;

use super::SharedKeyring;
use super::{Keyring, OnDecryptInput, OnDecryptOutput, OnEncryptInput, OnEncryptOutput};
use crate::Error;
use crate::error::Kind;
use crate::shared::IntoShared;

/// A keyring made of other keyrings.
///
/// On encrypt, the generator keyring makes the data key, then every child keyring wraps it,
/// so the message has one encrypted data key from each. Without a generator, the materials
/// must already have a data key.
///
/// On decrypt, it tries the generator, then each child in order, and returns the first success.
///
/// ```
/// use aws_crypto_mpl::keyring::{MultiKeyring, RawAesKeyring};
/// use aws_crypto_mpl::types::AesWrappingAlg;
///
/// # fn example() -> Result<(), aws_crypto_mpl::Error> {
/// let raw_aes = |name: &str| {
///     RawAesKeyring::builder()
///         .key_namespace("my-namespace")
///         .key_name(name)
///         .wrapping_key(vec![7u8; 32])
///         .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
///         .build()
/// };
/// let keyring = MultiKeyring::builder()
///     .generator(raw_aes("primary")?)
///     .child_keyrings(raw_aes("backup")?)
///     .build()?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct MultiKeyring {
    inner: Arc<MultiKeyringInner>,
}

struct MultiKeyringInner {
    generator: Option<SharedKeyring>,
    child_keyrings: Vec<SharedKeyring>,
}

impl std::fmt::Debug for MultiKeyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiKeyring")
            .field(
                "generator",
                &self.inner.generator.as_ref().map(SharedKeyring::name),
            )
            .field(
                "child_keyrings",
                &self
                    .inner
                    .child_keyrings
                    .iter()
                    .map(SharedKeyring::name)
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl MultiKeyring {
    /// `multi`, which errors show.
    #[must_use]
    pub fn name(&self) -> Cow<'_, str> {
        Cow::Borrowed("multi")
    }

    /// Start a builder.
    #[must_use]
    pub fn builder() -> MultiKeyringBuilder {
        MultiKeyringBuilder::default()
    }

    /// The keyring that makes the data key, if any.
    #[must_use]
    pub fn generator(&self) -> Option<&SharedKeyring> {
        self.inner.generator.as_ref()
    }

    /// The keyrings that wrap the data key the generator made.
    #[must_use]
    pub fn child_keyrings(&self) -> &[SharedKeyring] {
        &self.inner.child_keyrings
    }

    pub(crate) fn from_parts(
        generator: Option<SharedKeyring>,
        child_keyrings: Vec<SharedKeyring>,
    ) -> Result<Self, Error> {
        if generator.is_none() && child_keyrings.is_empty() {
            return Err(Error::validation(
                "Must include a generator keyring and/or at least one child keyring",
            ));
        }
        Ok(Self {
            inner: Arc::new(MultiKeyringInner {
                generator,
                child_keyrings,
            }),
        })
    }
}

/// Builder for [`MultiKeyring`].
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct MultiKeyringBuilder {
    generator: Option<SharedKeyring>,
    child_keyrings: Option<Vec<SharedKeyring>>,
}

impl MultiKeyringBuilder {
    /// The keyring that makes the data key.
    /// Optional, but a multi-keyring without one cannot make a data key.
    #[must_use]
    pub fn generator(mut self, generator: impl IntoShared<SharedKeyring>) -> Self {
        self.generator = Some(generator.into_shared());
        self
    }

    /// The generator keyring. See [`Self::generator`].
    #[must_use]
    pub fn set_generator(mut self, generator: Option<SharedKeyring>) -> Self {
        self.generator = generator;
        self
    }

    /// Add a keyring that wraps the data key.
    #[must_use]
    pub fn child_keyrings(mut self, child_keyring: impl IntoShared<SharedKeyring>) -> Self {
        self.child_keyrings
            .get_or_insert_with(Vec::new)
            .push(child_keyring.into_shared());
        self
    }

    /// Replace the child keyrings. See [`Self::child_keyrings`].
    #[must_use]
    pub fn set_child_keyrings(mut self, child_keyrings: Option<Vec<SharedKeyring>>) -> Self {
        self.child_keyrings = child_keyrings;
        self
    }

    /// Build the keyring.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): neither a generator nor a child keyring is set.
    pub fn build(self) -> Result<MultiKeyring, Error> {
        MultiKeyring::from_parts(self.generator, self.child_keyrings.unwrap_or_default())
    }
}

#[async_trait]
impl Keyring for crate::shared::Builtin<MultiKeyring> {
    fn name(&self) -> Cow<'_, str> {
        self.0.name()
    }

    async fn on_encrypt(&self, input: OnEncryptInput) -> Result<OnEncryptOutput, Error> {
        let mut materials = input.into_materials();
        match &self.inner.generator {
            None if materials.plaintext_data_key().is_none() => {
                return Err(Error::new(
                    Kind::InvalidMaterials,
                    "Need either a generator keyring or input encryption materials which contain a plaintext data key",
                ));
            }
            None => {}
            Some(_) if materials.plaintext_data_key().is_some() => {
                return Err(Error::new(
                    Kind::InvalidMaterials,
                    "This multi keyring has a generator but provided Encryption Materials already contain plaintext data key",
                ));
            }
            Some(generator) => {
                materials = generator
                    .on_encrypt()
                    .materials(materials)
                    .send()
                    .await?
                    .into_materials();
                if materials.plaintext_data_key().is_none() {
                    return Err(Error::new(
                        Kind::InvalidMaterials,
                        "Could not retrieve materials required for encryption",
                    ));
                }
            }
        }
        for child in &self.inner.child_keyrings {
            materials = child
                .on_encrypt()
                .materials(materials)
                .send()
                .await?
                .into_materials();
            if materials.plaintext_data_key().is_none() {
                return Err(Error::new(
                    Kind::InvalidMaterials,
                    "Could not retrieve materials required for encryption",
                ));
            }
        }
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
        let mut errors = Vec::new();
        for keyring in self
            .inner
            .generator
            .iter()
            .chain(&self.inner.child_keyrings)
        {
            let attempt = keyring
                .on_decrypt()
                .materials(materials.clone())
                .encrypted_data_keys(encrypted_data_keys.clone())
                .send()
                .await;
            match attempt {
                Ok(output) if output.materials().plaintext_data_key().is_some() => {
                    return Ok(output);
                }
                Ok(_) => errors.push(Error::new(
                    Kind::InvalidMaterials,
                    "Keyring performed invalid material transition",
                )),
                Err(e) => errors.push(e),
            }
        }
        Err(Error::all_failed(
            "No Configured Keyring was able to decrypt the Data Key.",
            errors,
        ))
    }
}

// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Required encryption context CMM: a CMM that makes the caller supply
//! some encryption context keys again on every decrypt, so the message never stores them.

use crate::Error;
use crate::builder::required;
use crate::error::Kind;
use std::borrow::Cow;
use std::collections::BTreeSet;

use async_trait::async_trait;

use super::{
    Cmm, DecryptMaterialsInput, DecryptMaterialsOutput, GetEncryptionMaterialsInput,
    GetEncryptionMaterialsOutput, SharedCmm,
};
use crate::shared::IntoShared;

/// A CMM that wraps another CMM and requires some encryption context keys.
///
/// On encrypt, the encryption context must have every required key;
/// the underlying CMM marks them required, so the message does not store them.
/// On decrypt, the reproduced encryption context must supply every required key.
///
/// ```
/// use aws_crypto_mpl::cmm::{DefaultCmm, RequiredEncryptionContextCmm};
/// use aws_crypto_mpl::keyring::RawAesKeyring;
/// use aws_crypto_mpl::types::AesWrappingAlg;
///
/// # fn main() -> Result<(), aws_crypto_mpl::Error> {
/// let keyring = RawAesKeyring::builder()
///     .key_namespace("ns")
///     .key_name("name")
///     .wrapping_key(vec![1u8; 32])
///     .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
///     .build()?;
/// let cmm = RequiredEncryptionContextCmm::builder()
///     .underlying_cmm(DefaultCmm::new(keyring))
///     .required_encryption_context_keys("tenant")
///     .build()?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct RequiredEncryptionContextCmm {
    underlying_cmm: SharedCmm,
    required_encryption_context_keys: BTreeSet<String>,
}

impl RequiredEncryptionContextCmm {
    /// `"required encryption context"`.
    #[must_use]
    pub fn name(&self) -> Cow<'_, str> {
        Cow::Borrowed("required encryption context")
    }

    /// Start a builder.
    #[must_use]
    pub fn builder() -> RequiredEncryptionContextCmmBuilder {
        RequiredEncryptionContextCmmBuilder::default()
    }

    /// The encryption context keys every call must supply.
    #[must_use]
    pub const fn required_encryption_context_keys(&self) -> &BTreeSet<String> {
        &self.required_encryption_context_keys
    }
}

/// Builder for [`RequiredEncryptionContextCmm`].
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct RequiredEncryptionContextCmmBuilder {
    underlying_cmm: Option<SharedCmm>,
    required_encryption_context_keys: Option<BTreeSet<String>>,
}

impl RequiredEncryptionContextCmmBuilder {
    /// The CMM that supplies the materials. Required.
    #[must_use]
    pub fn underlying_cmm(mut self, cmm: impl IntoShared<SharedCmm>) -> Self {
        self.underlying_cmm = Some(cmm.into_shared());
        self
    }

    /// The CMM that supplies the materials. See [`Self::underlying_cmm`].
    #[must_use]
    pub fn set_underlying_cmm(mut self, cmm: Option<SharedCmm>) -> Self {
        self.underlying_cmm = cmm;
        self
    }

    /// Add an encryption context key that every call must supply. At least one is required.
    #[must_use]
    pub fn required_encryption_context_keys(mut self, key: impl Into<String>) -> Self {
        self.required_encryption_context_keys
            .get_or_insert_with(BTreeSet::new)
            .insert(key.into());
        self
    }

    /// Replace the required encryption context keys. See [`Self::required_encryption_context_keys`].
    #[must_use]
    pub fn set_required_encryption_context_keys(
        mut self,
        keys: Option<impl IntoIterator<Item = impl Into<String>>>,
    ) -> Self {
        self.required_encryption_context_keys =
            keys.map(|k| k.into_iter().map(Into::into).collect());
        self
    }

    /// Build the CMM.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): no underlying CMM, or no required key.
    pub fn build(self) -> Result<RequiredEncryptionContextCmm, Error> {
        let underlying_cmm = required(self.underlying_cmm, "underlying_cmm")?;
        let required_encryption_context_keys =
            self.required_encryption_context_keys.unwrap_or_default();
        if required_encryption_context_keys.is_empty() {
            return Err(Error::new(
                Kind::Validation,
                "RequiredEncryptionContextCMM needs at least one requiredEncryptionContextKey.",
            ));
        }
        Ok(RequiredEncryptionContextCmm {
            underlying_cmm,
            required_encryption_context_keys,
        })
    }
}

#[async_trait]
impl Cmm for crate::shared::Builtin<RequiredEncryptionContextCmm> {
    fn name(&self) -> Cow<'_, str> {
        self.0.name()
    }

    async fn get_encryption_materials(
        &self,
        mut input: GetEncryptionMaterialsInput,
    ) -> Result<GetEncryptionMaterialsOutput, Error> {
        let keys = &self.required_encryption_context_keys;
        if !keys
            .iter()
            .all(|k| input.encryption_context.contains_key(k))
        {
            return Err(Error::new(
                Kind::EncryptionContextMismatch,
                "Encryption context does not contain required keys.",
            ));
        }
        let caller_keys = input
            .required_encryption_context_keys
            .clone()
            .unwrap_or_default();
        let mut all_keys = caller_keys.clone();
        all_keys.extend(keys.iter().cloned());
        input.required_encryption_context_keys = Some(all_keys);

        let result = Cmm::get_encryption_materials(&*self.underlying_cmm.0, input).await?;
        let materials = result.encryption_materials();
        let returned = materials.required_encryption_context_keys();
        if !keys.iter().all(|k| returned.contains(k)) {
            return Err(Error::new(
                Kind::InvalidMaterials,
                "Expected encryption context keys do not exist in keys to only authenticate.",
            ));
        }
        if materials.plaintext_data_key().is_none() {
            return Err(Error::new(
                Kind::InvalidMaterials,
                "Could not retrieve materials required for encryption",
            ));
        }
        if !caller_keys.iter().all(|k| returned.contains(k)) {
            return Err(Error::new(
                Kind::InvalidMaterials,
                "Keyring returned an invalid response",
            ));
        }
        Ok(result)
    }

    async fn decrypt_materials(
        &self,
        input: DecryptMaterialsInput,
    ) -> Result<DecryptMaterialsOutput, Error> {
        let Some(reproduced) = input.reproduced_encryption_context.clone() else {
            return Err(Error::new(
                Kind::EncryptionContextMismatch,
                "No reproduced encryption context on decrypt.",
            ));
        };
        if reproduced.iter().any(|(k, v)| {
            input
                .encryption_context
                .get(k)
                .is_some_and(|stored| stored != v)
        }) {
            return Err(Error::new(
                Kind::EncryptionContextMismatch,
                "Encryption context does not match reproduced encryption context.",
            ));
        }
        let keys = &self.required_encryption_context_keys;
        if !keys.iter().all(|k| reproduced.contains_key(k)) {
            return Err(Error::new(
                Kind::EncryptionContextMismatch,
                "Reproduced encryption context missing required keys.",
            ));
        }

        let result = Cmm::decrypt_materials(&*self.underlying_cmm.0, input).await?;
        let materials = result.decryption_materials();
        let ec = materials.encryption_context();
        if !keys.iter().all(|k| ec.contains_key(k)) {
            return Err(Error::new(
                Kind::InvalidMaterials,
                "Final encryption context missing required keys.",
            ));
        }
        if reproduced.iter().any(|(k, v)| ec.get(k) != Some(v)) {
            return Err(Error::new(
                Kind::InvalidMaterials,
                "Reproduced encryption context missing from encryption context.",
            ));
        }
        if materials.plaintext_data_key().is_none() {
            return Err(Error::new(
                Kind::InvalidMaterials,
                "Keyring.OnDecrypt failed to decrypt the plaintext data key.",
            ));
        }
        Ok(result)
    }
}

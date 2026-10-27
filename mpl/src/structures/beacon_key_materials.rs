// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Beacon key materials structure.

use std::collections::BTreeMap;

use super::encryption_context::EncryptionContext;
use crate::Error;
use crate::builder::required;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Materials used in structured encryption containing HMAC keys derived from a beacon key.
///
/// Construct with [`BeaconKeyMaterials::builder`].
#[non_exhaustive]
pub struct BeaconKeyMaterials {
    beacon_key_id: String,
    encryption_context: EncryptionContext,
    beacon_key: Option<Vec<u8>>,
    hmac_keys: Option<BTreeMap<String, Vec<u8>>>,
}

impl BeaconKeyMaterials {
    /// Start a builder for `BeaconKeyMaterials`.
    #[must_use]
    pub fn builder() -> BeaconKeyMaterialsBuilder {
        BeaconKeyMaterialsBuilder::default()
    }

    /// The beacon key identifier.
    #[must_use]
    pub fn beacon_key_id(&self) -> &str {
        &self.beacon_key_id
    }

    /// The custom encryption context of the beacon key.
    #[must_use]
    pub const fn encryption_context(&self) -> &EncryptionContext {
        &self.encryption_context
    }

    /// The plaintext beacon key, if present.
    #[must_use]
    pub fn beacon_key(&self) -> Option<&[u8]> {
        self.beacon_key.as_deref()
    }

    /// The HMAC keys derived from the beacon key, by name, if present.
    #[must_use]
    pub const fn hmac_keys(&self) -> Option<&BTreeMap<String, Vec<u8>>> {
        self.hmac_keys.as_ref()
    }
}

impl std::fmt::Debug for BeaconKeyMaterials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BeaconKeyMaterials")
            .field("beacon_key_id", &self.beacon_key_id)
            .field("encryption_context", &self.encryption_context)
            .field("beacon_key", &redact_key(self.beacon_key.as_deref()))
            .field("hmac_keys", &redact_keys(self.hmac_keys.as_ref()))
            .finish()
    }
}

/// Builder for [`BeaconKeyMaterials`].
#[derive(Default)]
pub struct BeaconKeyMaterialsBuilder {
    beacon_key_id: Option<String>,
    encryption_context: Option<EncryptionContext>,
    beacon_key: Option<Vec<u8>>,
    hmac_keys: Option<BTreeMap<String, Vec<u8>>>,
}

impl BeaconKeyMaterialsBuilder {
    /// Set the beacon key identifier.
    /// Required, and must not be empty.
    #[must_use]
    pub fn beacon_key_id(mut self, beacon_key_id: impl Into<String>) -> Self {
        self.beacon_key_id = Some(beacon_key_id.into());
        self
    }

    /// Set or clear the beacon key identifier from an `Option`.
    /// To set a value, use [`Self::beacon_key_id`].
    #[must_use]
    pub fn set_beacon_key_id(mut self, beacon_key_id: Option<String>) -> Self {
        self.beacon_key_id = beacon_key_id;
        self
    }

    /// The beacon key ID, if set.
    #[must_use]
    pub const fn get_beacon_key_id(&self) -> &Option<String> {
        &self.beacon_key_id
    }

    /// Adds a key-value pair to the custom encryption context of the beacon key.
    ///
    /// To override the contents of this collection use [`set_encryption_context`](Self::set_encryption_context).
    /// Required.
    #[must_use]
    pub fn encryption_context(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.encryption_context
            .get_or_insert_with(Default::default)
            .insert(k, v);
        self
    }

    /// Set or clear the encryption context from an `Option`.
    /// To add one entry, use [`Self::encryption_context`].
    #[must_use]
    pub fn set_encryption_context(mut self, encryption_context: Option<EncryptionContext>) -> Self {
        self.encryption_context = encryption_context;
        self
    }

    /// The encryption context, if set.
    #[must_use]
    pub const fn get_encryption_context(&self) -> &Option<EncryptionContext> {
        &self.encryption_context
    }

    /// Set the plaintext beacon key.
    #[must_use]
    pub fn beacon_key(mut self, beacon_key: impl Into<Vec<u8>>) -> Self {
        self.beacon_key = Some(beacon_key.into());
        self
    }

    /// Set or clear the beacon key from an `Option`.
    /// To set a value, use [`Self::beacon_key`].
    #[must_use]
    pub fn set_beacon_key(mut self, beacon_key: Option<Vec<u8>>) -> Self {
        self.beacon_key = beacon_key;
        self
    }

    /// The beacon key, if set.
    #[must_use]
    pub const fn get_beacon_key(&self) -> &Option<Vec<u8>> {
        &self.beacon_key
    }

    /// Adds a key-value pair to the HMAC keys derived from the beacon key, by name.
    ///
    /// To override the contents of this collection use [`set_hmac_keys`](Self::set_hmac_keys).
    #[must_use]
    pub fn hmac_keys(mut self, k: impl Into<String>, v: impl Into<Vec<u8>>) -> Self {
        self.hmac_keys
            .get_or_insert_with(Default::default)
            .insert(k.into(), v.into());
        self
    }

    /// Set or clear the HMAC keys from an `Option`.
    /// To add one entry, use [`Self::hmac_keys`].
    #[must_use]
    pub fn set_hmac_keys(mut self, hmac_keys: Option<BTreeMap<String, Vec<u8>>>) -> Self {
        self.hmac_keys = hmac_keys;
        self
    }

    /// The HMAC keys, if set.
    #[must_use]
    pub const fn get_hmac_keys(&self) -> &Option<BTreeMap<String, Vec<u8>>> {
        &self.hmac_keys
    }

    /// Build the `BeaconKeyMaterials`.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): `beacon_key_id` or `encryption_context` is unset, or `beacon_key_id` is empty.
    pub fn build(mut self) -> Result<BeaconKeyMaterials, Error> {
        let beacon_key_id = required(self.beacon_key_id.take(), "beacon_key_id")?;
        if beacon_key_id.is_empty() {
            return Err(Error::validation("beacon_key_id must not be empty"));
        }
        Ok(BeaconKeyMaterials {
            beacon_key_id,
            encryption_context: required(self.encryption_context.take(), "encryption_context")?,
            beacon_key: self.beacon_key.take(),
            hmac_keys: self.hmac_keys.take(),
        })
    }
}

impl std::fmt::Debug for BeaconKeyMaterialsBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BeaconKeyMaterialsBuilder")
            .field("beacon_key_id", &self.beacon_key_id)
            .field("encryption_context", &self.encryption_context)
            .field("beacon_key", &redact_key(self.beacon_key.as_deref()))
            .field("hmac_keys", &redact_keys(self.hmac_keys.as_ref()))
            .finish()
    }
}

fn redact_key(key: Option<&[u8]>) -> Option<String> {
    key.map(|k| format!("[REDACTED; {} bytes]", k.len()))
}

fn redact_keys(keys: Option<&BTreeMap<String, Vec<u8>>>) -> Option<String> {
    keys.map(|m| format!("[{} keys; REDACTED]", m.len()))
}

/// Zero beacon and HMAC key bytes.
fn zeroize_keys(
    beacon_key: &mut Option<Vec<u8>>,
    hmac_keys: &mut Option<BTreeMap<String, Vec<u8>>>,
) {
    beacon_key.zeroize();
    if let Some(keys) = hmac_keys {
        keys.values_mut().for_each(Zeroize::zeroize);
    }
}

impl Drop for BeaconKeyMaterials {
    fn drop(&mut self) {
        zeroize_keys(&mut self.beacon_key, &mut self.hmac_keys);
    }
}

impl ZeroizeOnDrop for BeaconKeyMaterials {}

impl Drop for BeaconKeyMaterialsBuilder {
    fn drop(&mut self) {
        zeroize_keys(&mut self.beacon_key, &mut self.hmac_keys);
    }
}

impl ZeroizeOnDrop for BeaconKeyMaterialsBuilder {}

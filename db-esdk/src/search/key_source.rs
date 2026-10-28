// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Beacon keys: fetched from the key store, cached, and expanded into one HMAC key per beacon.

use std::collections::BTreeMap;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime};

#[cfg(feature = "rt-tokio")]
use aws_crypto_mpl::cmc::DefaultCmc;
use aws_crypto_mpl::cmc::SharedCmc;
use aws_crypto_mpl::key_store;
#[cfg(feature = "rt-tokio")]
use aws_crypto_mpl::shared::IntoShared;
use aws_crypto_mpl::types::{BeaconKeyMaterials, CacheEntry, CachedMaterials};
use aws_mpl_primitives::{DigestAlg, digest, generate_random_bytes, hkdf_no_salt};

use crate::error::{Error, crypt_err, materials_err, val_err};
use crate::search::beacon::{MaybeKeyId, MaybeKeyMap};

/// The cache identifier's resource id: the hierarchical keyring's.
const RESOURCE_ID_HIERARCHICAL_KEYRING: u8 = 0x02;
/// The cache identifier's scope id: searchable encryption.
const SCOPE_ID_SEARCHABLE_ENCRYPTION: u8 = 0x03;
const NULL_BYTE: u8 = 0x00;
/// The HKDF info prefix of a beacon's HMAC key.
const BEACON_KEY_INFO: &[u8] = b"AWS_DBE_SCAN_BEACON";
/// The length of a beacon's HMAC key.
const HMAC_KEY_LEN: usize = 64;

/// Where an item's beacon key id comes from.
#[derive(Clone, Debug)]
pub(crate) enum KeyLocation {
    /// The same key for every item.
    Single { key_id: String },
    /// The value of an item attribute or virtual field.
    Multi {
        key_field_name: String,
        /// Whether the key field is removed from an item before it is written.
        delete_key: bool,
    },
}

/// The beacon keys of a beacon version.
#[derive(Debug)]
pub(crate) struct KeySource {
    store: key_store::Client,
    pub(crate) location: KeyLocation,
    cache: SharedCmc,
    ttl: Duration,
    partition_id: Vec<u8>,
    /// The key store's logical name, read from the key store on first use.
    logical_key_store_name: OnceLock<String>,
}

/// The cache a key source uses: the configured one, or a new default holding `capacity` entries.
fn cache_or_default(cache: Option<SharedCmc>, capacity: usize) -> Result<SharedCmc, Error> {
    if let Some(cache) = cache {
        return Ok(cache);
    }
    #[cfg(feature = "rt-tokio")]
    {
        Ok(DefaultCmc::builder()
            .entry_capacity(capacity)
            .build()?
            .into_shared())
    }
    #[cfg(not(feature = "rt-tokio"))]
    {
        let _ = capacity;
        Err(val_err(
            "a beacon key cache is required without the `rt-tokio` feature",
        ))
    }
}

/// The 16 bytes of a random version-4 UUID.
fn random_partition_id() -> Result<Vec<u8>, Error> {
    let mut bytes = [0u8; 16];
    generate_random_bytes(&mut bytes)?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(bytes.to_vec())
}

impl KeySource {
    /// A key source reading keys from `store`.
    ///
    /// `capacity` is the default cache's size: 1 for a single key, 1000 for many.
    pub(crate) fn new(
        store: key_store::Client,
        location: KeyLocation,
        cache: Option<SharedCmc>,
        capacity: usize,
        ttl: Duration,
        partition_id: Option<&str>,
    ) -> Result<Self, Error> {
        if ttl.as_secs() == 0 {
            return Err(val_err("Beacon Cache TTL must be at least 1."));
        }
        let partition_id = match partition_id {
            Some(id) => id.as_bytes().to_vec(),
            None => random_partition_id()?,
        };
        Ok(Self {
            store,
            location,
            cache: cache_or_default(cache, capacity)?,
            ttl,
            partition_id,
            logical_key_store_name: OnceLock::new(),
        })
    }

    /// The key store's logical name.
    async fn logical_key_store_name(&self) -> Result<&str, Error> {
        if let Some(name) = self.logical_key_store_name.get() {
            return Ok(name);
        }
        let info = self.store.get_key_store_info().send().await?;
        Ok(self
            .logical_key_store_name
            .get_or_init(|| info.logical_key_store_name().to_owned()))
    }

    /// The SHA-384 cache identifier of beacon key `key_id`.
    async fn cache_identifier(&self, key_id: &str) -> Result<Vec<u8>, Error> {
        let logical_name = self.logical_key_store_name().await?;
        let mut id = vec![
            RESOURCE_ID_HIERARCHICAL_KEYRING,
            NULL_BYTE,
            SCOPE_ID_SEARCHABLE_ENCRYPTION,
            NULL_BYTE,
        ];
        id.extend_from_slice(&self.partition_id);
        id.push(NULL_BYTE);
        id.extend_from_slice(logical_name.as_bytes());
        id.push(NULL_BYTE);
        id.extend_from_slice(key_id.as_bytes());
        let mut out = vec![0u8; DigestAlg::Sha384.output_len()];
        digest(DigestAlg::Sha384, &id, &mut out)?;
        Ok(out)
    }

    /// The HMAC keys of `std_names`, for the beacon key `key_id` selects.
    ///
    /// # Errors
    ///
    /// A `Validation` error when `key_id` does not fit the key source:
    /// a single key store takes no key id, and a multi key store needs one.
    pub(crate) async fn get_key_map(
        &self,
        std_names: &[String],
        key_id: &MaybeKeyId,
    ) -> Result<MaybeKeyMap, Error> {
        match (&self.location, key_id) {
            (KeyLocation::Single { key_id: id }, MaybeKeyId::DontUse) => {
                Ok(MaybeKeyMap::Keys(self.hmac_keys(std_names, id).await?))
            }
            (KeyLocation::Single { .. }, _) => Err(val_err(
                "KeyID should not be supplied with a SingleKeyStore",
            )),
            (KeyLocation::Multi { .. }, MaybeKeyId::DontUse) => Err(val_err(
                "Fixed KeyID must not be supplied with a MultiKeyStore",
            )),
            (KeyLocation::Multi { .. }, MaybeKeyId::ShouldHave) => Ok(MaybeKeyMap::ShouldHaveKeys),
            (KeyLocation::Multi { .. }, MaybeKeyId::Id(id)) => {
                Ok(MaybeKeyMap::Keys(self.hmac_keys(std_names, id).await?))
            }
        }
    }

    /// The HMAC key of each of `beacon_names` under beacon key `key_id`.
    ///
    /// The keys come from the cache when its entry is younger than the TTL,
    /// otherwise from the key store, and are then cached.
    async fn hmac_keys(
        &self,
        beacon_names: &[String],
        key_id: &str,
    ) -> Result<BTreeMap<String, Vec<u8>>, Error> {
        let identifier = self.cache_identifier(key_id).await?;
        let cached = self
            .cache
            .get_cache_entry()
            .identifier(identifier.clone())
            .send()
            .await?
            .into_entry();
        if let Some(entry) = cached
            && self.within_ttl(&entry)
        {
            return cached_hmac_keys(&entry, key_id);
        }

        let materials = self
            .store
            .get_beacon_key()
            .branch_key_id(key_id)
            .send()
            .await?
            .into_beacon_key_materials();
        let beacon_key = materials
            .beacon_key()
            .ok_or_else(|| materials_err("beacon key unexpectedly empty"))?;
        let keys = derive_hmac_keys(beacon_names, beacon_key)?;
        let to_cache = BeaconKeyMaterials::builder()
            .beacon_key_id(materials.beacon_key_id())
            .encryption_context(materials.encryption_context().clone())
            .hmac_keys(keys.clone())
            .build()?;
        let now = SystemTime::now();
        let entry = CacheEntry::builder()
            .materials(CachedMaterials::BeaconKey(to_cache))
            .creation_time(now)
            .expiry_time(now + self.ttl)
            .build()?;
        self.cache
            .put_cache_entry()
            .identifier(identifier)
            .entry(entry)
            .send()
            .await?;
        Ok(keys)
    }

    /// Whether `entry` is no older than this key source's TTL.
    ///
    /// A shared cache may hold an entry written by a key source with a longer TTL.
    fn within_ttl(&self, entry: &CacheEntry) -> bool {
        // An entry created after now (clock skew) counts as fresh.
        SystemTime::now()
            .duration_since(entry.creation_time())
            .map_or(true, |age| age <= self.ttl)
    }
}

/// The HMAC keys of a cached beacon key entry.
fn cached_hmac_keys(entry: &CacheEntry, key_id: &str) -> Result<BTreeMap<String, Vec<u8>>, Error> {
    match entry.materials() {
        CachedMaterials::BeaconKey(m) if m.beacon_key_id() == key_id => m
            .hmac_keys()
            .cloned()
            .ok_or_else(|| materials_err("Invalid Material Type.")),
        _ => Err(materials_err("Invalid Material Type.")),
    }
}

/// Each beacon's HMAC key: HKDF-SHA-512 of the beacon key, with no salt and
/// info `AWS_DBE_SCAN_BEACON` followed by the beacon's name.
fn derive_hmac_keys(
    beacon_names: &[String],
    beacon_key: &[u8],
) -> Result<BTreeMap<String, Vec<u8>>, Error> {
    beacon_names
        .iter()
        .map(|name| {
            let mut key = vec![0u8; HMAC_KEY_LEN];
            hkdf_no_salt(
                DigestAlg::Sha512,
                beacon_key,
                &[BEACON_KEY_INFO, name.as_bytes()],
                &mut key,
            )
            .map_err(|e| {
                crypt_err(format!(
                    "could not derive the HMAC key of beacon {name}: {e}"
                ))
            })?;
            Ok((name.clone(), key))
        })
        .collect()
}

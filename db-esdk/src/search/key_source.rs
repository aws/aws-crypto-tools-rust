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
//= spec/searchable-encryption/search-config.md#resource-suffix
//# - MUST be the Resource ID for the Hierarchical Keyring (0x02)
const RESOURCE_ID_HIERARCHICAL_KEYRING: u8 = 0x02;

/// The cache identifier's scope id: searchable encryption.
//= spec/searchable-encryption/search-config.md#resource-suffix
//# - MUST be the Scope ID for Searchable Encryption (0x03)
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
        /// Whether the client removes the key field from an item before writing it.
        delete_key: bool,
    },
}

/// The beacon keys of a beacon version.
#[derive(Debug)]
pub(crate) struct KeySource {
    store: key_store::SharedKeyStore,
    pub(crate) location: KeyLocation,
    cache: SharedCmc,
    ttl: Duration,
    //= spec/searchable-encryption/search-config.md#partition-id
    //= type=implication
    //= reason=private field with no setter; KeySource methods take &self
    //# The Partition ID MUST NOT be changed after initialization.
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
        store: key_store::SharedKeyStore,
        location: KeyLocation,
        cache: Option<SharedCmc>,
        capacity: usize,
        ttl: Duration,
        partition_id: Option<&str>,
    ) -> Result<Self, Error> {
        if ttl.as_secs() == 0 {
            return Err(val_err(
                "the beacon key cache TTL must be at least 1 second",
            ));
        }

        //= spec/searchable-encryption/search-config.md#partition-id-1
        //# It can either be a String provided by the user, which MUST be interpreted as the bytes of
        //# UTF-8 Encoding of the String, or a v4 UUID, which SHOULD be interpreted as the 16 byte representation of the UUID.
        let partition_id = match partition_id {
            //= spec/searchable-encryption/search-config.md#partition-id
            //# If provided, it MUST be interpreted as UTF8 bytes.
            Some(id) => id.as_bytes().to_vec(),
            //= spec/searchable-encryption/search-config.md#partition-id
            //# If the PartitionId is NOT provided by the user, it MUST be set to the 16 byte representation of a v4 UUID.
            //
            //= spec/searchable-encryption/search-config.md#key-store-cache
            //= reason=a random partition id per key source keeps its identifiers apart from every other source
            //# In either case, Cache Identifiers MUST be unique across all key sources.
            None => random_partition_id()?,
        };
        Ok(Self {
            store,
            location,
            //= spec/searchable-encryption/search-config.md#key-store-cache
            //# For a Beacon Key Source a [CMC](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/cryptographic-materials-cache.md)
            //# MUST be created.
            cache: cache_or_default(cache, capacity)?,
            ttl,
            //= spec/searchable-encryption/search-config.md#partition-id-1
            //# The constructor of the [Beacon Key Source](#beacon-key-source) MUST record these bytes at construction time.
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

        //= spec/searchable-encryption/search-config.md#resource-suffix
        //# When the [Beacon Key Source](#beacon-key-source) receives a `getKeyMap` request,
        //# the cache entry identifier MUST be calculated as the
        //# SHA-384 hash of the following byte strings, in the order listed:
        let mut id = vec![
            RESOURCE_ID_HIERARCHICAL_KEYRING,
            NULL_BYTE,
            SCOPE_ID_SEARCHABLE_ENCRYPTION,
            NULL_BYTE,
        ];

        //= spec/searchable-encryption/search-config.md#resource-suffix
        //# - MUST be the Partition ID for the [Beacon Key Source](#beacon-key-source)
        //
        //= spec/searchable-encryption/search-config.md#partition-id-2
        //= reason=the identifier depends only on partition id, logical key store name, and key id
        //# - If the Partition ID is set by the user and is the same for two [Beacon Key Sources](#beacon-key-source) (or another Material Provider),
        //# they MAY share the same cache entries in the cache.
        id.extend_from_slice(&self.partition_id);
        id.push(NULL_BYTE);

        //= spec/searchable-encryption/search-config.md#resource-suffix
        //# - MUST be the UTF8 encoded Logical Key Store Name of the keystore for the [beacon versions](#beacon-version-initialization)
        //
        //= spec/searchable-encryption/search-config.md#logical-key-store-name
        //# Logical Key Store Name MUST be converted to UTF8 Bytes to be used in
        //# the cache identifiers.
        id.extend_from_slice(logical_name.as_bytes());
        id.push(NULL_BYTE);

        //= spec/searchable-encryption/search-config.md#resource-suffix
        //# - MUST be the UTF8 encoded branch-key-id
        id.extend_from_slice(key_id.as_bytes());
        let mut out = vec![0u8; DigestAlg::Sha384.output_len()];

        //= spec/searchable-encryption/search-config.md#resource-suffix
        //# The aforementioned 4 definitions ([Resource Identifier](#resource-identifier),
        //# [Scope Identifier](#scope-identifier), [Partition ID](#partition-id-1), and
        //# [Resource Suffix](#resource-suffix)) MUST be appended together with the null byte, 0x00,
        //# and the SHA384 of the result should be taken as the final cache identifier.
        digest(DigestAlg::Sha384, &id, &mut out)?;
        Ok(out)
    }

    /// The HMAC keys of `std_names`, for the beacon key that `key_id` selects.
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
            //= spec/searchable-encryption/search-config.md#get-beacon-key-after-encrypt
            //# If the [Beacon Key Source](#beacon-key-source) is a [Single Key Store](#single-key-store-initialization)
            //# then `beacon key id` MUST be the configured [beacon key id](#beacon-key-id)
            //
            //= spec/searchable-encryption/search-config.md#get-beacon-key-for-query
            //# If the [Beacon Key Source](#beacon-key-source) is a [Single Key Store](#single-key-store-initialization)
            //# then `beacon key id` MUST be the configured [beacon key id](#beacon-key-id)
            (KeyLocation::Single { key_id: id }, MaybeKeyId::DontUse)
            | (KeyLocation::Multi { .. }, MaybeKeyId::Id(id)) => {
                Ok(MaybeKeyMap::Keys(self.hmac_keys(std_names, id).await?))
            }
            (KeyLocation::Single { .. }, _) => Err(val_err(
                "KeyID should not be supplied with a SingleKeyStore",
            )),
            (KeyLocation::Multi { .. }, MaybeKeyId::DontUse) => Err(val_err(
                "Fixed KeyID must not be supplied with a MultiKeyStore",
            )),
            (KeyLocation::Multi { .. }, MaybeKeyId::ShouldHave) => Ok(MaybeKeyMap::ShouldHaveKeys),
        }
    }

    /// The HMAC key of each of `beacon_names` under beacon key `key_id`.
    ///
    /// Reads the keys from the cache when its entry is younger than the TTL.
    /// Otherwise reads them from the key store and caches them.
    async fn hmac_keys(
        &self,
        beacon_names: &[String],
        key_id: &str,
    ) -> Result<BTreeMap<String, Vec<u8>>, Error> {
        //= spec/searchable-encryption/search-config.md#key-store-cache
        //# Cache Identifiers for Searchable Encryption MUST be set as per the section [Searchable Encryption Cache Identifier](#searchable-encryption-cache-identifier).
        //
        //= spec/searchable-encryption/search-config.md#searchable-encryption-cache-identifier
        //# When accessing the underlying cryptographic materials cache,
        //# Searchable Encryption MUST use the formulas specified in this section
        //# in order to compute the [cache entry identifier](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/cryptographic-materials-cache.md#cache-identifier).
        let identifier = self.cache_identifier(key_id).await?;

        //= spec/searchable-encryption/search-config.md#get-beacon-key-materials
        //# Get beacon key MUST Call the associated [Key Store Cache](#key-store-cache)
        //# [Get Cache Entry](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/local-cryptographic-materials-cache.md#get-cache-entry)
        //# with the cache identifier defined in the [Searchable Encryption Cache Identifier](#searchable-encryption-cache-identifier) section.
        let cached = self
            .cache
            .get_cache_entry()
            .identifier(identifier.clone())
            .send()
            .await?
            .into_entry();

        //= spec/searchable-encryption/search-config.md#get-beacon-key-materials
        //# If this is NOT true, then we MUST treat the cache entry as expired.
        if let Some(entry) = cached
            && self.within_ttl(&entry)
        {
            //= spec/searchable-encryption/search-config.md#get-beacon-key-materials
            //# If a [cache entry](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/cryptographic-materials-cache.md#cache-entry)
            //# exists, get beacon key MUST return the [entry materials](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/cryptographic-materials-cache.md#materials).
            return cached_hmac_keys(&entry, key_id);
        }

        //= spec/searchable-encryption/search-config.md#get-beacon-key-materials
        //# The `beacon key id` MUST be passed to the configured `KeyStore`'s `GetBeaconKey` operation.
        //
        //= spec/searchable-encryption/search-config.md#get-beacon-key-materials
        //# If `GetBeaconKey` fails get beacon key MUST fail.
        let materials = self
            .store
            .get_beacon_key()
            .branch_key_id(key_id)
            .send()
            .await?
            .into_beacon_key_materials();
        let beacon_key = materials.beacon_key().ok_or_else(|| {
            materials_err("the key store returned beacon key materials with no beacon key")
        })?;

        //= spec/searchable-encryption/search-config.md#get-beacon-key-materials
        //# For every [standard beacons](beacons.md#standard-beacon-initialization), an HMAC key
        //# MUST be generated in accordance with [HMAC Key Generation](#hmac-key-generation).
        let keys = derive_hmac_keys(beacon_names, beacon_key)?;

        //= spec/searchable-encryption/search-config.md#get-beacon-key-materials
        //# [Beacon Key Materials](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/structures.md#beacon-key-materials) MUST be generated
        //# with the [beacon key id](#beacon-key-id) equal to the `beacon key id`
        //# and the [HMAC Keys](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/structures.md#hmac-keys) equal to a map
        //# of every [standard beacons](beacons.md#standard-beacon-initialization) name to its generated HMAC key.
        let to_cache = BeaconKeyMaterials::builder()
            .beacon_key_id(key_id)
            .set_encryption_context(Some(materials.encryption_context().clone()))
            .set_hmac_keys(Some(keys.clone()))
            .build()?;
        let now = SystemTime::now();

        //= spec/searchable-encryption/search-config.md#get-beacon-key-materials
        //# These materials MUST be put into the associated [Key Store Cache](#key-store-cache)
        //# with an [Expiry Time](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/cryptographic-materials-cache.md#expiry-time)
        //# equal to now + configured [cacheTTL](#cachettl).
        let entry = CacheEntry::builder()
            .materials(CachedMaterials::BeaconKey(to_cache))
            .creation_time(now)
            .expiry_time(now + self.ttl)
            .build()?;

        //= spec/searchable-encryption/search-config.md#get-beacon-key-materials
        //# The Searchable Encryption cache identifier
        //# used to [Put Cache Entry](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/local-cryptographic-materials-cache.md#put-cache-entry)
        //# MUST be the same
        //# as the identifier that was used to attempt [Get Cache Entry](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/local-cryptographic-materials-cache.md#get-cache-entry).
        self.cache
            .put_cache_entry()
            .identifier(identifier)
            .entry(entry)
            .send()
            .await?;

        //= spec/searchable-encryption/search-config.md#get-beacon-key-materials
        //# These cached materials MUST be returned.
        Ok(keys)
    }

    /// Whether `entry` is no older than this key source's TTL.
    ///
    /// A shared cache may hold an entry written by a key source with a longer TTL.
    /// An entry created after now (clock skew) counts as fresh.
    fn within_ttl(&self, entry: &CacheEntry) -> bool {
        //= spec/searchable-encryption/search-config.md#get-beacon-key-materials
        //# There MUST be a check (cacheEntryWithinLimits) to make sure that for the cache entry found, who's TTL has NOT expired,
        //# `time.now() - cacheEntryCreationTime <= ttlSeconds` is true and
        //# valid for TTL of the [Beacon Key Source](#beacon-key-source) getting the cache entry.
        SystemTime::now()
            .duration_since(entry.creation_time())
            .map_or(true, |age| age <= self.ttl)
    }
}

/// The HMAC keys of a cached beacon key entry.
fn cached_hmac_keys(entry: &CacheEntry, key_id: &str) -> Result<BTreeMap<String, Vec<u8>>, Error> {
    match entry.materials() {
        CachedMaterials::BeaconKey(m) if m.beacon_key_id() == key_id => {
            m.hmac_keys().cloned().ok_or_else(|| {
                materials_err(
                    "the cache entry for this beacon key does not hold its beacon key materials",
                )
            })
        }
        _ => Err(materials_err(
            "the cache entry for this beacon key does not hold its beacon key materials",
        )),
    }
}

/// Each beacon's HMAC key: HKDF-SHA-512 of the beacon key,
/// with no salt and with info `AWS_DBE_SCAN_BEACON` followed by the beacon's name.
fn derive_hmac_keys(
    beacon_names: &[String],
    beacon_key: &[u8],
) -> Result<BTreeMap<String, Vec<u8>>, Error> {
    beacon_names
        .iter()
        .map(|name| {
            //= spec/searchable-encryption/search-config.md#hmac-key-generation
            //# The `expectedLength` MUST be 64 bytes.
            let mut key = vec![0u8; HMAC_KEY_LEN];

            //= spec/searchable-encryption/search-config.md#hmac-key-generation
            //# For each beacon HKDF-SHA512 MUST be used
            //# to calculate the key for individual beacon,
            //# using the beacon key retrieved above as the initial key material with no salt.
            //
            //= spec/searchable-encryption/search-config.md#hmac-key-generation
            //# The `info` MUST be the concatenation of "AWS_DBE_SCAN_BEACON" encoded as UTF8
            //# and the beacon name.
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

#[cfg(test)]
#[path = "key_source_tests.rs"]
mod tests;

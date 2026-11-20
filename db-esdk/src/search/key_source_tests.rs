// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests of beacon key lookup and caching, with in-memory key stores.
//! They include the shared-cache tests from the reference implementation's `Beacon.dfy`.

use super::*;
use crate::search::test_fixtures::{BEACON_KEY, FakeKeyStore, hmac_keys};

const KEY_ID: &str = "040a32a8-3737-4f16-a3ba-bd4449556d73";

fn names() -> Vec<String> {
    vec!["Name".to_owned(), "std2".to_owned()]
}

fn single(store: &FakeKeyStore, cache: Option<SharedCmc>, partition_id: Option<&str>) -> KeySource {
    KeySource::new(
        store.client(),
        KeyLocation::Single {
            key_id: KEY_ID.to_owned(),
        },
        cache,
        1,
        Duration::from_secs(42),
        partition_id,
    )
    .unwrap()
}

fn multi(store: &FakeKeyStore, cache: Option<SharedCmc>, partition_id: Option<&str>) -> KeySource {
    KeySource::new(
        store.client(),
        KeyLocation::Multi {
            key_field_name: "TheKeyField".to_owned(),
            delete_key: false,
        },
        cache,
        1000,
        Duration::from_secs(42),
        partition_id,
    )
    .unwrap()
}

fn shared_cache() -> SharedCmc {
    DefaultCmc::builder()
        .entry_capacity(100)
        .build()
        .unwrap()
        .into_shared()
}

fn keys_of(map: MaybeKeyMap) -> BTreeMap<String, Vec<u8>> {
    match map {
        MaybeKeyMap::Keys(k) => k,
        other => panic!("expected keys, got {other:?}"),
    }
}

/// Assert that the failing fixture store was asked for the key, so the cache did not serve it.
fn assert_store_failed(r: Result<MaybeKeyMap, Error>) {
    match r {
        Err(e @ Error::Validation(_)) => {
            let source = e.find_source::<aws_crypto_mpl::Error>();
            assert_eq!(
                source.map(aws_crypto_mpl::Error::message),
                Some("bad key store")
            );
        }
        other => panic!("expected the key store's error, got {other:?}"),
    }
}

fn val_msg(err: &Error) -> String {
    assert!(matches!(err, Error::Validation(_)), "{err:?}");
    err.message().to_owned()
}

#[test]
fn zero_ttl_is_rejected() {
    // search-config.md#cachettl has no requirement for this: a key source rejects a TTL under 1 s.
    let err = KeySource::new(
        FakeKeyStore::new("ks").client(),
        KeyLocation::Single {
            key_id: "k".to_owned(),
        },
        None,
        1,
        Duration::from_millis(999),
        None,
    )
    .unwrap_err();
    assert_eq!(
        val_msg(&err),
        "the beacon key cache TTL must be at least 1 second"
    );
}

#[test]
fn derive_hmac_keys_matches_the_spec_derivation() {
    let derived = derive_hmac_keys(&names(), &BEACON_KEY).unwrap();
    assert_eq!(derived, hmac_keys(&["Name", "std2"], &BEACON_KEY));

    //= spec/searchable-encryption/search-config.md#hmac-key-generation
    //= type=test
    //# The `expectedLength` MUST be 64 bytes.
    assert!(derived.values().all(|k| k.len() == 64));
    assert_ne!(derived["Name"], derived["std2"]);
}

#[test]
fn random_partition_id_is_a_v4_uuid() {
    let a = random_partition_id().unwrap();
    let b = random_partition_id().unwrap();

    //= spec/searchable-encryption/search-config.md#partition-id
    //= type=test
    //# If the PartitionId is NOT provided by the user, it MUST be set to the 16 byte representation of a v4 UUID.
    assert_eq!(a.len(), 16);
    // UUID version nibble = 4
    assert_eq!(a[6] >> 4, 4);
    // RFC 4122 variant bits = 10
    assert_eq!(a[8] & 0xc0, 0x80);
    assert_ne!(a, b);
}

#[tokio::test]
async fn single_key_store_derives_keys_and_caches_them() {
    let store = FakeKeyStore::new("KeyStoreDdbTable");
    let src = single(&store, None, None);
    let keys = keys_of(
        src.get_key_map(&names(), &MaybeKeyId::DontUse)
            .await
            .unwrap(),
    );
    assert_eq!(keys, hmac_keys(&["Name", "std2"], &BEACON_KEY));
    // The second lookup is served from the cache.
    let again = keys_of(
        src.get_key_map(&names(), &MaybeKeyId::DontUse)
            .await
            .unwrap(),
    );
    assert_eq!(again, keys);

    //= spec/searchable-encryption/search-config.md#key-store-cache
    //= type=test
    //= reason=no cache was configured, so the second lookup hit the default cache created for the source
    //# For a Beacon Key Source a [CMC](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/cryptographic-materials-cache.md)
    //# MUST be created.
    assert_eq!(store.calls(), 1);
}

#[tokio::test]
async fn key_id_must_fit_the_key_source() {
    // Guards get-beacon-key-after-encrypt and get-beacon-key-for-query:
    // a single key store uses only its configured beacon key id,
    // and a multi key store needs one from the item.
    let store = FakeKeyStore::new("KeyStoreDdbTable");
    let single = single(&store, None, None);
    for id in [MaybeKeyId::ShouldHave, MaybeKeyId::Id("x".to_owned())] {
        let err = single.get_key_map(&names(), &id).await.unwrap_err();
        assert_eq!(
            val_msg(&err),
            "KeyID should not be supplied with a SingleKeyStore"
        );
    }
    let multi = multi(&store, None, None);
    let err = multi
        .get_key_map(&names(), &MaybeKeyId::DontUse)
        .await
        .unwrap_err();
    assert_eq!(
        val_msg(&err),
        "Fixed KeyID must not be supplied with a MultiKeyStore"
    );
    assert!(matches!(
        multi
            .get_key_map(&names(), &MaybeKeyId::ShouldHave)
            .await
            .unwrap(),
        MaybeKeyMap::ShouldHaveKeys
    ));
    let keys = keys_of(
        multi
            .get_key_map(&names(), &MaybeKeyId::Id("k1".to_owned()))
            .await
            .unwrap(),
    );
    assert_eq!(keys, hmac_keys(&["Name", "std2"], &BEACON_KEY));
    assert_eq!(store.calls(), 1);
}

#[tokio::test]
async fn multi_key_store_caches_per_key_id() {
    let store = FakeKeyStore::new("KeyStoreDdbTable");
    let src = multi(&store, None, None);
    for id in ["k1", "k2", "k1", "k2"] {
        src.get_key_map(&names(), &MaybeKeyId::Id(id.to_owned()))
            .await
            .unwrap();
    }
    assert_eq!(store.calls(), 2);
}

#[tokio::test]
async fn key_store_errors_propagate() {
    let store = FakeKeyStore::failing("KeyStoreDdbTable");

    //= spec/searchable-encryption/search-config.md#get-beacon-key-materials
    //= type=test
    //# If `GetBeaconKey` fails get beacon key MUST fail.
    assert_store_failed(
        single(&store, None, None)
            .get_key_map(&names(), &MaybeKeyId::DontUse)
            .await,
    );
}

#[tokio::test]
async fn missing_beacon_key_is_invalid_materials() {
    // Guards get-beacon-key-materials, next to "If `GetBeaconKey` fails get beacon key MUST fail":
    // materials with no beacon key also fail.
    let store = FakeKeyStore::without_beacon_key();
    let err = single(&store, None, None)
        .get_key_map(&names(), &MaybeKeyId::DontUse)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::InvalidMaterials(_)), "{err:?}");
    assert_eq!(
        err.message(),
        "the key store returned beacon key materials with no beacon key"
    );
}

/// A good key store fills a shared cache.
/// A failing key store with the same logical name then succeeds exactly when the cache identifier is the same.
async fn shared_cache_case(
    make: fn(&FakeKeyStore, Option<SharedCmc>, Option<&str>) -> KeySource,
    key_id: MaybeKeyId,
    bad_partition: Option<&str>,
    good_partition: Option<&str>,
) -> Result<MaybeKeyMap, Error> {
    let cache = shared_cache();
    let bad_store = FakeKeyStore::failing("KeyStoreDdbTable");
    let bad = make(&bad_store, Some(cache.clone()), bad_partition);
    assert_store_failed(bad.get_key_map(&names(), &key_id).await);

    let good_store = FakeKeyStore::new("KeyStoreDdbTable");
    let good = make(&good_store, Some(cache), good_partition);
    good.get_key_map(&names(), &key_id).await.unwrap();

    bad.get_key_map(&names(), &key_id).await
}

#[tokio::test]
async fn shared_cache_single_key_store() {
    let id = MaybeKeyId::DontUse;
    let same = shared_cache_case(single, id.clone(), Some("partitionId"), Some("partitionId"))
        .await
        .unwrap();

    //= spec/searchable-encryption/search-config.md#partition-id-2
    //= type=test
    //= reason=the failing store's source got the keys the other source cached under the same partition id
    //# - If the Partition ID is set by the user and is the same for two [Beacon Key Sources](#beacon-key-source) (or another Material Provider),
    //# they MAY share the same cache entries in the cache.
    assert_eq!(keys_of(same), hmac_keys(&["Name", "std2"], &BEACON_KEY));
    let different = shared_cache_case(
        single,
        id.clone(),
        Some("partitionIdBadVersion"),
        Some("partitionIdGoodVersion"),
    )
    .await;
    assert_store_failed(different);

    // Without a partition id, each key source gets a random one.
    //= spec/searchable-encryption/search-config.md#key-store-cache
    //= type=test
    //= reason=two sources sharing one cache do not see each other's entries
    //# In either case, Cache Identifiers MUST be unique across all key sources.
    assert_store_failed(shared_cache_case(single, id, None, None).await);
}

#[tokio::test]
async fn shared_cache_multi_key_store() {
    let id = MaybeKeyId::Id(KEY_ID.to_owned());
    let same = shared_cache_case(multi, id.clone(), Some("partitionId"), Some("partitionId"))
        .await
        .unwrap();
    assert_eq!(keys_of(same), hmac_keys(&["Name", "std2"], &BEACON_KEY));
    let different = shared_cache_case(
        multi,
        id.clone(),
        Some("partitionIdBadVersion"),
        Some("partitionIdGoodVersion"),
    )
    .await;
    assert_store_failed(different);
    assert_store_failed(shared_cache_case(multi, id, None, None).await);
}

#[tokio::test]
async fn shared_cache_is_scoped_by_logical_key_store_name() {
    let cache = shared_cache();
    let good = single(
        &FakeKeyStore::new("StoreA"),
        Some(cache.clone()),
        Some("pid"),
    );
    good.get_key_map(&names(), &MaybeKeyId::DontUse)
        .await
        .unwrap();
    let other = single(&FakeKeyStore::failing("StoreB"), Some(cache), Some("pid"));
    assert_store_failed(other.get_key_map(&names(), &MaybeKeyId::DontUse).await);
}

fn entry(key_id: &str, created: SystemTime) -> CacheEntry {
    let materials = BeaconKeyMaterials::builder()
        .beacon_key_id(key_id)
        .set_encryption_context(Some(aws_crypto_mpl::types::EncryptionContext::new()))
        .set_hmac_keys(Some(hmac_keys(&["Name"], &BEACON_KEY)))
        .build()
        .unwrap();
    CacheEntry::builder()
        .materials(CachedMaterials::BeaconKey(materials))
        .creation_time(created)
        .expiry_time(created + Duration::from_secs(3600))
        .build()
        .unwrap()
}

#[test]
fn within_ttl() {
    let src = single(&FakeKeyStore::new("ks"), None, None);
    let now = SystemTime::now();
    assert!(src.within_ttl(&entry("k", now)));
    // Just inside the 42 s TTL.
    assert!(src.within_ttl(&entry("k", now - Duration::from_secs(41))));

    //= spec/searchable-encryption/search-config.md#get-beacon-key-materials
    //= type=test
    //# There MUST be a check (cacheEntryWithinLimits) to make sure that for the cache entry found, who's TTL has NOT expired,
    //# `time.now() - cacheEntryCreationTime <= ttlSeconds` is true and
    //# valid for TTL of the [Beacon Key Source](#beacon-key-source) getting the cache entry.
    assert!(!src.within_ttl(&entry("k", now - Duration::from_secs(100))));
    // An entry from the future, under clock skew, is fresh.
    assert!(src.within_ttl(&entry("k", now + Duration::from_secs(100))));
}

#[tokio::test]
async fn stale_shared_entry_is_refetched() {
    let cache = shared_cache();
    let store = FakeKeyStore::new("KeyStoreDdbTable");
    let src = single(&store, Some(cache.clone()), Some("pid"));
    // An entry older than this key source's TTL, as a key source with a longer TTL can leave in a shared cache.
    let id = src.cache_identifier(KEY_ID).await.unwrap();
    cache
        .put_cache_entry()
        .identifier(id)
        .entry(entry(KEY_ID, SystemTime::now() - Duration::from_secs(100)))
        .send()
        .await
        .unwrap();
    let keys = keys_of(
        src.get_key_map(&names(), &MaybeKeyId::DontUse)
            .await
            .unwrap(),
    );
    assert_eq!(keys, hmac_keys(&["Name", "std2"], &BEACON_KEY));

    //= spec/searchable-encryption/search-config.md#get-beacon-key-materials
    //= type=test
    //= reason=the stale cached entry was ignored and the key store was asked
    //# If this is NOT true, then we MUST treat the cache entry as expired.
    assert_eq!(store.calls(), 1);
}

#[test]
fn cached_entry_for_another_key_is_invalid() {
    // Guards get-beacon-key-materials,
    // next to "If a cache entry exists, get beacon key MUST return the entry materials":
    // the entry must hold this beacon key id's materials.
    let e = entry("k1", SystemTime::now());
    assert_eq!(
        cached_hmac_keys(&e, "k1").unwrap(),
        hmac_keys(&["Name"], &BEACON_KEY)
    );
    let err = cached_hmac_keys(&e, "k2").unwrap_err();
    assert!(matches!(err, Error::InvalidMaterials(_)), "{err:?}");
    assert_eq!(
        err.message(),
        "the cache entry for this beacon key does not hold its beacon key materials"
    );
}

#[tokio::test]
async fn cache_identifier_depends_on_each_input() {
    let a = single(&FakeKeyStore::new("ks"), None, Some("p1"));
    let b = single(&FakeKeyStore::new("ks"), None, Some("p2"));
    let c = single(&FakeKeyStore::new("other"), None, Some("p1"));
    let id = a.cache_identifier("k").await.unwrap();
    assert_eq!(id.len(), 48);
    assert_eq!(id, a.cache_identifier("k").await.unwrap());
    assert_ne!(id, a.cache_identifier("k2").await.unwrap());
    assert_ne!(id, b.cache_identifier("k").await.unwrap());
    assert_ne!(id, c.cache_identifier("k").await.unwrap());
}

/// The SHA-384 cache identifier, computed from its pre-image laid out field by field.
fn spec_cache_identifier(partition_id: &[u8], logical_name: &str, key_id: &str) -> Vec<u8> {
    let mut pre_image = vec![
        0x02, // resource id: hierarchical keyring
        0x00, // null byte
        0x03, // scope id: searchable encryption
        0x00, // null byte
    ];
    pre_image.extend_from_slice(partition_id);
    pre_image.push(0x00);
    pre_image.extend_from_slice(logical_name.as_bytes());
    pre_image.push(0x00);
    pre_image.extend_from_slice(key_id.as_bytes());
    let mut out = vec![0u8; DigestAlg::Sha384.output_len()];
    digest(DigestAlg::Sha384, &pre_image, &mut out).unwrap();
    out
}

#[tokio::test]
async fn cache_identifier_matches_the_spec_formula() {
    let src = single(&FakeKeyStore::new("ks"), None, Some("p1"));
    let expected = spec_cache_identifier(b"p1", "ks", "k");
    let id = src.cache_identifier("k").await.unwrap();

    //= spec/searchable-encryption/search-config.md#resource-suffix
    //= type=test
    //# When the [Beacon Key Source](#beacon-key-source) receives a `getKeyMap` request,
    //# the cache entry identifier MUST be calculated as the
    //# SHA-384 hash of the following byte strings, in the order listed:
    //
    //= spec/searchable-encryption/search-config.md#resource-suffix
    //= type=test
    //# The aforementioned 4 definitions ([Resource Identifier](#resource-identifier),
    //# [Scope Identifier](#scope-identifier), [Partition ID](#partition-id-1), and
    //# [Resource Suffix](#resource-suffix)) MUST be appended together with the null byte, 0x00,
    //# and the SHA384 of the result should be taken as the final cache identifier.
    //
    //= spec/searchable-encryption/search-config.md#resource-suffix
    //= type=test
    //# - MUST be the Resource ID for the Hierarchical Keyring (0x02)
    //
    //= spec/searchable-encryption/search-config.md#resource-suffix
    //= type=test
    //# - MUST be the Scope ID for Searchable Encryption (0x03)
    //
    //= spec/searchable-encryption/search-config.md#resource-suffix
    //= type=test
    //# - MUST be the Partition ID for the [Beacon Key Source](#beacon-key-source)
    //
    //= spec/searchable-encryption/search-config.md#searchable-encryption-cache-identifier
    //= type=test
    //# When accessing the underlying cryptographic materials cache,
    //# Searchable Encryption MUST use the formulas specified in this section
    //# in order to compute the [cache entry identifier](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/cryptographic-materials-cache.md#cache-identifier).
    assert_eq!(id, expected);

    // Non-ASCII names show the UTF-8 encoding of each string field.
    let src = single(&FakeKeyStore::new("ks-\u{e9}"), None, Some("p-\u{e9}"));
    let expected = spec_cache_identifier(&[b'p', b'-', 0xc3, 0xa9], "ks-\u{e9}", "k-\u{e9}");
    let id = src.cache_identifier("k-\u{e9}").await.unwrap();

    //= spec/searchable-encryption/search-config.md#resource-suffix
    //= type=test
    //# - MUST be the UTF8 encoded Logical Key Store Name of the keystore for the [beacon versions](#beacon-version-initialization)
    //
    //= spec/searchable-encryption/search-config.md#resource-suffix
    //= type=test
    //# - MUST be the UTF8 encoded branch-key-id
    //
    //= spec/searchable-encryption/search-config.md#logical-key-store-name
    //= type=test
    //# Logical Key Store Name MUST be converted to UTF8 Bytes to be used in
    //# the cache identifiers.
    //
    //= spec/searchable-encryption/search-config.md#partition-id
    //= type=test
    //# If provided, it MUST be interpreted as UTF8 bytes.
    //
    //= spec/searchable-encryption/search-config.md#partition-id-1
    //= type=test
    //# It can either be a String provided by the user, which MUST be interpreted as the bytes of
    //# UTF-8 Encoding of the String, or a v4 UUID, which SHOULD be interpreted as the 16 byte representation of the UUID.
    assert_eq!(id, expected);
}

#[tokio::test]
async fn random_partition_id_is_fixed_at_construction() {
    let src = single(&FakeKeyStore::new("ks"), None, None);
    let first = src.cache_identifier("k").await.unwrap();

    //= spec/searchable-encryption/search-config.md#partition-id-1
    //= type=test
    //= reason=a random partition id drawn per call would change the identifier between calls
    //# The constructor of the [Beacon Key Source](#beacon-key-source) MUST record these bytes at construction time.
    assert_eq!(src.cache_identifier("k").await.unwrap(), first);
    // A second source draws its own random partition id.
    let other = single(&FakeKeyStore::new("ks"), None, None);
    assert_ne!(other.cache_identifier("k").await.unwrap(), first);
}

#[tokio::test]
async fn fresh_cache_entry_is_served() {
    let cache = shared_cache();
    let store = FakeKeyStore::failing("ks");
    let src = single(&store, Some(cache.clone()), Some("pid"));
    // An entry under the spec's identifier, with keys the source would not derive itself
    // (only "Name", not "Name" and "std2").
    cache
        .put_cache_entry()
        .identifier(spec_cache_identifier(b"pid", "ks", KEY_ID))
        .entry(entry(KEY_ID, SystemTime::now()))
        .send()
        .await
        .unwrap();
    let keys = keys_of(
        src.get_key_map(&names(), &MaybeKeyId::DontUse)
            .await
            .unwrap(),
    );

    //= spec/searchable-encryption/search-config.md#get-beacon-key-materials
    //= type=test
    //# If a [cache entry](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/cryptographic-materials-cache.md#cache-entry)
    //# exists, get beacon key MUST return the [entry materials](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/cryptographic-materials-cache.md#materials).
    assert_eq!(keys, hmac_keys(&["Name"], &BEACON_KEY));

    //= spec/searchable-encryption/search-config.md#get-beacon-key-materials
    //= type=test
    //= reason=the entry was put under the spec formula's identifier, and the key store was never asked
    //# Get beacon key MUST Call the associated [Key Store Cache](#key-store-cache)
    //# [Get Cache Entry](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/local-cryptographic-materials-cache.md#get-cache-entry)
    //# with the cache identifier defined in the [Searchable Encryption Cache Identifier](#searchable-encryption-cache-identifier) section.
    //
    //= spec/searchable-encryption/search-config.md#key-store-cache
    //= type=test
    //= reason=the lookup found the entry put under the spec formula's identifier
    //# Cache Identifiers for Searchable Encryption MUST be set as per the section [Searchable Encryption Cache Identifier](#searchable-encryption-cache-identifier).
    assert_eq!(store.calls(), 0);
}

#[tokio::test]
async fn cached_materials_match_what_is_returned() {
    let cache = shared_cache();
    // The store names another beacon key id; the cached materials must still name the requested one.
    let store = FakeKeyStore::answering_with("ks", "another-id");
    let src = single(&store, Some(cache.clone()), Some("pid"));
    let before = SystemTime::now();
    let keys = keys_of(
        src.get_key_map(&names(), &MaybeKeyId::DontUse)
            .await
            .unwrap(),
    );
    let entry = cache
        .get_cache_entry()
        .identifier(spec_cache_identifier(b"pid", "ks", KEY_ID))
        .send()
        .await
        .unwrap()
        .into_entry();

    //= spec/searchable-encryption/search-config.md#get-beacon-key-materials
    //= type=test
    //= reason=the entry is found under the identifier the lookup computed before the key store call
    //# The Searchable Encryption cache identifier
    //# used to [Put Cache Entry](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/local-cryptographic-materials-cache.md#put-cache-entry)
    //# MUST be the same
    //# as the identifier that was used to attempt [Get Cache Entry](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/local-cryptographic-materials-cache.md#get-cache-entry).
    let entry = entry.expect("the fetched keys are cached under the spec identifier");
    let CachedMaterials::BeaconKey(materials) = entry.materials() else {
        panic!("expected beacon key materials, got {:?}", entry.materials());
    };

    //= spec/searchable-encryption/search-config.md#get-beacon-key-materials
    //= type=test
    //# [Beacon Key Materials](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/structures.md#beacon-key-materials) MUST be generated
    //# with the [beacon key id](#beacon-key-id) equal to the `beacon key id`
    //# and the [HMAC Keys](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/structures.md#hmac-keys) equal to a map
    //# of every [standard beacons](beacons.md#standard-beacon-initialization) name to its generated HMAC key.
    assert_eq!(
        (materials.beacon_key_id(), materials.hmac_keys()),
        (KEY_ID, Some(&hmac_keys(&["Name", "std2"], &BEACON_KEY)))
    );
    assert!(entry.creation_time() >= before);

    //= spec/searchable-encryption/search-config.md#get-beacon-key-materials
    //= type=test
    //# These materials MUST be put into the associated [Key Store Cache](#key-store-cache)
    //# with an [Expiry Time](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/cryptographic-materials-cache.md#expiry-time)
    //# equal to now + configured [cacheTTL](#cachettl).
    assert_eq!(
        entry.expiry_time(),
        entry.creation_time() + Duration::from_secs(42)
    );

    //= spec/searchable-encryption/search-config.md#get-beacon-key-materials
    //= type=test
    //# These cached materials MUST be returned.
    assert_eq!(materials.hmac_keys(), Some(&keys));
}

// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests of beacon key lookup and caching, including the reference implementation's
//! shared-cache tests from `Beacon.dfy`, with in-memory key stores.

use aws_crypto_mpl::shared::IntoShared;

use super::*;
use crate::error::Error;
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

/// The failing fixture store was asked for the key: the cache did not serve it.
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

fn val_msg(err: Error) -> String {
    assert!(matches!(err, Error::Validation(_)), "{err:?}");
    err.message().to_owned()
}

#[test]
fn zero_ttl_is_rejected() {
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
    assert_eq!(val_msg(err), "Beacon Cache TTL must be at least 1.");
}

#[test]
fn derive_hmac_keys_matches_the_spec_derivation() {
    let derived = derive_hmac_keys(&names(), &BEACON_KEY).unwrap();
    assert_eq!(derived, hmac_keys(&["Name", "std2"], &BEACON_KEY));
    assert!(derived.values().all(|k| k.len() == 64));
    assert_ne!(derived["Name"], derived["std2"]);
}

#[test]
fn random_partition_id_is_a_v4_uuid() {
    let a = random_partition_id().unwrap();
    let b = random_partition_id().unwrap();
    assert_eq!(a.len(), 16);
    assert_eq!(a[6] >> 4, 4);
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
    assert_eq!(store.calls(), 1);
}

#[tokio::test]
async fn key_id_must_fit_the_key_source() {
    let store = FakeKeyStore::new("KeyStoreDdbTable");
    let single = single(&store, None, None);
    for id in [MaybeKeyId::ShouldHave, MaybeKeyId::Id("x".to_owned())] {
        let err = single.get_key_map(&names(), &id).await.unwrap_err();
        assert_eq!(
            val_msg(err),
            "KeyID should not be supplied with a SingleKeyStore"
        );
    }
    let multi = multi(&store, None, None);
    let err = multi
        .get_key_map(&names(), &MaybeKeyId::DontUse)
        .await
        .unwrap_err();
    assert_eq!(
        val_msg(err),
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
    assert_store_failed(
        single(&store, None, None)
            .get_key_map(&names(), &MaybeKeyId::DontUse)
            .await,
    );
}

#[tokio::test]
async fn missing_beacon_key_is_invalid_materials() {
    let store = FakeKeyStore::without_beacon_key();
    let err = single(&store, None, None)
        .get_key_map(&names(), &MaybeKeyId::DontUse)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::InvalidMaterials(_)), "{err:?}");
    assert_eq!(err.message(), "beacon key unexpectedly empty");
}

/// A good key store fills a shared cache; a failing key store with the same logical name
/// then succeeds exactly when the cache identifier is the same.
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
        .encryption_context(aws_crypto_mpl::types::EncryptionContext::new())
        .hmac_keys(hmac_keys(&["Name"], &BEACON_KEY))
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
    assert!(!src.within_ttl(&entry("k", now - Duration::from_secs(100))));
    // An entry from the future, under clock skew, is fresh.
    assert!(src.within_ttl(&entry("k", now + Duration::from_secs(100))));
}

#[tokio::test]
async fn stale_shared_entry_is_refetched() {
    let cache = shared_cache();
    let store = FakeKeyStore::new("KeyStoreDdbTable");
    let src = single(&store, Some(cache.clone()), Some("pid"));
    // An entry older than this key source's TTL, as one with a longer TTL writes.
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
    assert_eq!(store.calls(), 1);
}

#[test]
fn cached_entry_for_another_key_is_invalid() {
    let e = entry("k1", SystemTime::now());
    assert_eq!(
        cached_hmac_keys(&e, "k1").unwrap(),
        hmac_keys(&["Name"], &BEACON_KEY)
    );
    let err = cached_hmac_keys(&e, "k2").unwrap_err();
    assert!(matches!(err, Error::InvalidMaterials(_)), "{err:?}");
    assert_eq!(err.message(), "Invalid Material Type.");
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

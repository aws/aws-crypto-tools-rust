// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for `CachingCmm` (spec/framework/caching-cmm.md; the Dafny MPL has no caching CMM).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use aws_crypto_mpl::Error;
use aws_crypto_mpl::cmc::{
    Cmc, DeleteCacheEntryInput, DeleteCacheEntryOutput, GetCacheEntryInput, GetCacheEntryOutput,
    LocalCmc, PutCacheEntryInput, PutCacheEntryOutput, SharedCmc, UpdateUsageMetadataInput,
    UpdateUsageMetadataOutput,
};
use aws_crypto_mpl::cmm::{
    CachingCmm, Cmm, DecryptMaterialsInput, DecryptMaterialsOutput, DefaultCmm,
    GetEncryptionMaterialsInput, GetEncryptionMaterialsOutput, MAX_LIMIT_BYTES, MAX_LIMIT_MESSAGES,
    SharedCmm,
};
use aws_crypto_mpl::keyring::RawAesKeyring;
use aws_crypto_mpl::shared::IntoShared;
use aws_crypto_mpl::types::{
    AesWrappingAlg, AlgorithmSuiteId, CommitmentPolicy, EncryptedDataKey, EncryptionContext,
    EncryptionMaterials, EsdkAlgorithmSuiteId, EsdkCommitmentPolicy,
};
use aws_lc_rs::digest::{SHA512, digest};

const POLICY: CommitmentPolicy =
    CommitmentPolicy::Esdk(EsdkCommitmentPolicy::RequireEncryptRequireDecrypt);
const FORBID_POLICY: CommitmentPolicy =
    CommitmentPolicy::Esdk(EsdkCommitmentPolicy::ForbidEncryptAllowDecrypt);
const SUITE: AlgorithmSuiteId =
    AlgorithmSuiteId::Esdk(EsdkAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey);
const NO_KDF_SUITE: AlgorithmSuiteId =
    AlgorithmSuiteId::Esdk(EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf);
const TTL: Duration = Duration::from_secs(60);

fn keyring() -> RawAesKeyring {
    RawAesKeyring::builder()
        .key_namespace("ns")
        .key_name("name")
        .wrapping_key(vec![9u8; 32])
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()
        .unwrap()
}

fn local_cache() -> LocalCmc {
    LocalCmc::builder().entry_capacity(10).build().unwrap()
}

/// Counts the calls that reach the default CMM it wraps.
/// Clones share the counters.
#[derive(Clone)]
struct CountingCmm {
    inner: SharedCmm,
    encrypt_calls: Arc<AtomicUsize>,
    decrypt_calls: Arc<AtomicUsize>,
}

impl CountingCmm {
    fn new() -> Self {
        Self {
            inner: SharedCmm::new(DefaultCmm::new(keyring())),
            encrypt_calls: Arc::default(),
            decrypt_calls: Arc::default(),
        }
    }
}

#[async_trait]
impl Cmm for CountingCmm {
    async fn get_encryption_materials(
        &self,
        input: GetEncryptionMaterialsInput,
    ) -> Result<GetEncryptionMaterialsOutput, Error> {
        self.encrypt_calls.fetch_add(1, Ordering::SeqCst);
        self.inner
            .get_encryption_materials()
            .set_encryption_context(Some(input.encryption_context().clone()))
            .commitment_policy(input.commitment_policy())
            .set_algorithm_suite_id(input.algorithm_suite_id())
            .set_required_encryption_context_keys(Some(
                input.required_encryption_context_keys().clone(),
            ))
            .set_max_plaintext_length(input.max_plaintext_length())
            .send()
            .await
    }

    async fn decrypt_materials(
        &self,
        input: DecryptMaterialsInput,
    ) -> Result<DecryptMaterialsOutput, Error> {
        self.decrypt_calls.fetch_add(1, Ordering::SeqCst);
        self.inner
            .decrypt_materials()
            .algorithm_suite_id(input.algorithm_suite_id())
            .commitment_policy(input.commitment_policy())
            .set_encrypted_data_keys(Some(input.encrypted_data_keys().to_vec()))
            .set_encryption_context(Some(input.encryption_context().clone()))
            .set_reproduced_encryption_context(input.reproduced_encryption_context().cloned())
            .send()
            .await
    }
}

fn caching(counter: &CountingCmm, cache: impl IntoShared<SharedCmc>) -> CachingCmm {
    CachingCmm::builder()
        .underlying_cmm(counter.clone())
        .cache(cache)
        .cache_limit_ttl(TTL)
        .build()
        .unwrap()
}

fn ec(pairs: &[(&str, &str)]) -> EncryptionContext {
    let mut ec = EncryptionContext::new();
    for (k, v) in pairs {
        ec.insert(*k, *v);
    }
    ec
}

async fn encrypt(
    cmm: &CachingCmm,
    ec: EncryptionContext,
    suite: Option<AlgorithmSuiteId>,
    len: Option<u64>,
) -> EncryptionMaterials {
    // The no-KDF suite is non-committing.
    let policy = if suite == Some(NO_KDF_SUITE) {
        FORBID_POLICY
    } else {
        POLICY
    };
    cmm.get_encryption_materials()
        .set_encryption_context(Some(ec))
        .commitment_policy(policy)
        .set_algorithm_suite_id(suite)
        .set_max_plaintext_length(len)
        .send()
        .await
        .unwrap()
        .into_encryption_materials()
}

fn data_key(m: &EncryptionMaterials) -> Vec<u8> {
    m.plaintext_data_key().unwrap().as_bytes().to_vec()
}

#[test]
fn build_rejects_invalid_configuration() {
    let ok = || {
        CachingCmm::builder()
            .keyring(keyring())
            .cache(local_cache())
            .cache_limit_ttl(TTL)
    };
    let built = ok().build().unwrap();
    assert_eq!(built.limit_bytes(), MAX_LIMIT_BYTES);
    assert_eq!(built.limit_messages(), MAX_LIMIT_MESSAGES);
    assert_eq!(built.cache_limit_ttl(), TTL);
    assert!(!built.partition_id().is_empty());

    let cases = [
        ("no cache", ok().set_cache(None)),
        ("no ttl", ok().set_cache_limit_ttl(None)),
        ("zero ttl", ok().cache_limit_ttl(Duration::ZERO)),
        ("no cmm or keyring", ok().set_keyring(None)),
        (
            "cmm and keyring",
            ok().underlying_cmm(DefaultCmm::new(keyring())),
        ),
        ("zero messages", ok().limit_messages(0)),
        (
            "too many messages",
            ok().limit_messages(MAX_LIMIT_MESSAGES + 1),
        ),
        ("too many bytes", ok().limit_bytes(MAX_LIMIT_BYTES + 1)),
    ];
    for (name, builder) in cases {
        let err = builder.build().unwrap_err();
        assert!(err.is_validation(), "{name}: {err:?}");
    }
}

#[test]
fn default_partition_ids_differ() {
    let a = CachingCmm::builder()
        .keyring(keyring())
        .cache(local_cache())
        .cache_limit_ttl(TTL)
        .build()
        .unwrap();
    let b = CachingCmm::builder()
        .keyring(keyring())
        .cache(local_cache())
        .cache_limit_ttl(TTL)
        .build()
        .unwrap();
    assert_ne!(a.partition_id(), b.partition_id());
}

#[tokio::test]
async fn encryption_materials_are_reused_until_the_message_limit() {
    let counter = CountingCmm::new();
    let cmm = CachingCmm::builder()
        .underlying_cmm(counter.clone())
        .cache(local_cache())
        .cache_limit_ttl(TTL)
        .limit_messages(2)
        .build()
        .unwrap();
    let first = encrypt(&cmm, ec(&[("a", "b")]), Some(SUITE), Some(10)).await;
    let second = encrypt(&cmm, ec(&[("a", "b")]), Some(SUITE), Some(10)).await;
    assert_eq!(data_key(&first), data_key(&second));
    assert_eq!(first.encrypted_data_keys(), second.encrypted_data_keys());
    assert_eq!(counter.encrypt_calls.load(Ordering::SeqCst), 1);

    // A third message would exceed limit_messages = 2.
    let third = encrypt(&cmm, ec(&[("a", "b")]), Some(SUITE), Some(10)).await;
    assert_ne!(data_key(&first), data_key(&third));
    assert_eq!(counter.encrypt_calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn encryption_materials_are_replaced_past_the_byte_limit() {
    let counter = CountingCmm::new();
    let cmm = CachingCmm::builder()
        .underlying_cmm(counter.clone())
        .cache(local_cache())
        .cache_limit_ttl(TTL)
        .limit_bytes(10)
        .build()
        .unwrap();
    let first = encrypt(&cmm, EncryptionContext::new(), None, Some(6)).await;
    let second = encrypt(&cmm, EncryptionContext::new(), None, Some(6)).await;
    assert_ne!(data_key(&first), data_key(&second));
    assert_eq!(counter.encrypt_calls.load(Ordering::SeqCst), 2);

    // One message longer than the limit never uses or fills the cache.
    encrypt(&cmm, EncryptionContext::new(), None, Some(11)).await;
    assert_eq!(counter.encrypt_calls.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn unknown_length_and_no_kdf_suites_bypass_the_cache() {
    let counter = CountingCmm::new();
    let cmm = caching(&counter, local_cache());
    let a = encrypt(&cmm, EncryptionContext::new(), Some(SUITE), None).await;
    let b = encrypt(&cmm, EncryptionContext::new(), Some(SUITE), None).await;
    assert_ne!(data_key(&a), data_key(&b));

    let c = encrypt(&cmm, EncryptionContext::new(), Some(NO_KDF_SUITE), Some(1)).await;
    let d = encrypt(&cmm, EncryptionContext::new(), Some(NO_KDF_SUITE), Some(1)).await;
    assert_ne!(data_key(&c), data_key(&d));
    assert_eq!(counter.encrypt_calls.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn entries_are_keyed_by_encryption_context_and_suite() {
    let counter = CountingCmm::new();
    let cmm = caching(&counter, local_cache());
    let base = encrypt(&cmm, ec(&[("a", "b")]), None, Some(1)).await;
    let other_ec = encrypt(&cmm, ec(&[("a", "c")]), None, Some(1)).await;
    let with_suite = encrypt(&cmm, ec(&[("a", "b")]), Some(SUITE), Some(1)).await;
    assert_ne!(data_key(&base), data_key(&other_ec));
    assert_ne!(data_key(&base), data_key(&with_suite));
    assert_eq!(counter.encrypt_calls.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn a_shared_cache_is_shared_only_within_a_partition() {
    let cache = SharedCmc::new(local_cache());
    let counter = CountingCmm::new();
    let build = |partition: Option<&str>| {
        CachingCmm::builder()
            .underlying_cmm(counter.clone())
            .cache(cache.clone())
            .cache_limit_ttl(TTL)
            .set_partition_id(partition.map(str::to_owned))
            .build()
            .unwrap()
    };
    let a = encrypt(&build(Some("p")), EncryptionContext::new(), None, Some(1)).await;
    let b = encrypt(&build(Some("p")), EncryptionContext::new(), None, Some(1)).await;
    assert_eq!(data_key(&a), data_key(&b));
    let c = encrypt(&build(None), EncryptionContext::new(), None, Some(1)).await;
    assert_ne!(data_key(&a), data_key(&c));
    assert_eq!(counter.encrypt_calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn expired_entries_are_not_used() {
    let now = Arc::new(Mutex::new(SystemTime::now()));
    let clock = now.clone();
    let cache = LocalCmc::builder()
        .entry_capacity(10)
        .clock(move || *clock.lock().unwrap())
        .build()
        .unwrap();
    let counter = CountingCmm::new();
    let cmm = caching(&counter, cache);
    let a = encrypt(&cmm, EncryptionContext::new(), None, Some(1)).await;
    *now.lock().unwrap() += TTL + Duration::from_secs(1);
    let b = encrypt(&cmm, EncryptionContext::new(), None, Some(1)).await;
    assert_ne!(data_key(&a), data_key(&b));
    assert_eq!(counter.encrypt_calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn decryption_materials_are_cached_for_a_matching_reproduced_context() {
    let counter = CountingCmm::new();
    let cmm = caching(&counter, local_cache());
    let enc = encrypt(&cmm, ec(&[("a", "b")]), Some(SUITE), Some(1)).await;
    let decrypt = |reproduced: Option<EncryptionContext>| {
        cmm.decrypt_materials()
            .algorithm_suite_id(SUITE)
            .commitment_policy(POLICY)
            .set_encrypted_data_keys(Some(enc.encrypted_data_keys().to_vec()))
            .set_encryption_context(Some(ec(&[("a", "b")])))
            .set_reproduced_encryption_context(reproduced)
            .send()
    };
    for _ in 0..2 {
        let dec = decrypt(None).await.unwrap().into_decryption_materials();
        assert_eq!(
            dec.plaintext_data_key().unwrap().as_bytes(),
            data_key(&enc).as_slice()
        );
    }
    assert_eq!(counter.decrypt_calls.load(Ordering::SeqCst), 1);

    // A conflicting reproduced context is not served from the cache;
    // the underlying CMM rejects it.
    let err = decrypt(Some(ec(&[("a", "x")]))).await.unwrap_err();
    assert!(err.is_encryption_context_mismatch(), "{err:?}");
    assert_eq!(counter.decrypt_calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn no_kdf_decryption_materials_are_not_cached() {
    let counter = CountingCmm::new();
    let cmm = caching(&counter, local_cache());
    let enc = encrypt(&cmm, EncryptionContext::new(), Some(NO_KDF_SUITE), Some(1)).await;
    for _ in 0..2 {
        cmm.decrypt_materials()
            .algorithm_suite_id(NO_KDF_SUITE)
            .commitment_policy(FORBID_POLICY)
            .set_encrypted_data_keys(Some(enc.encrypted_data_keys().to_vec()))
            .set_encryption_context(Some(EncryptionContext::new()))
            .send()
            .await
            .unwrap();
    }
    assert_eq!(counter.decrypt_calls.load(Ordering::SeqCst), 2);
}

/// Records each identifier the caching CMM reads, then delegates to a `LocalCmc`.
struct RecordingCmc {
    inner: SharedCmc,
    gets: Arc<Mutex<Vec<Vec<u8>>>>,
}

#[async_trait]
impl Cmc for RecordingCmc {
    async fn put_cache_entry(
        &self,
        input: PutCacheEntryInput,
    ) -> Result<PutCacheEntryOutput, Error> {
        let (id, entry) = input.into_parts();
        self.inner
            .put_cache_entry()
            .identifier(id)
            .entry(entry)
            .send()
            .await
    }

    async fn get_cache_entry(
        &self,
        input: GetCacheEntryInput,
    ) -> Result<GetCacheEntryOutput, Error> {
        self.gets.lock().unwrap().push(input.identifier().to_vec());
        self.inner
            .get_cache_entry()
            .identifier(input.into_identifier())
            .send()
            .await
    }

    async fn delete_cache_entry(
        &self,
        input: DeleteCacheEntryInput,
    ) -> Result<DeleteCacheEntryOutput, Error> {
        self.inner
            .delete_cache_entry()
            .identifier(input.into_identifier())
            .send()
            .await
    }

    async fn update_usage_metadata(
        &self,
        input: UpdateUsageMetadataInput,
    ) -> Result<UpdateUsageMetadataOutput, Error> {
        self.inner
            .update_usage_metadata()
            .identifier(input.identifier().to_vec())
            .bytes_used(input.bytes_used())
            .send()
            .await
    }
}

fn sha512(parts: &[&[u8]]) -> Vec<u8> {
    digest(&SHA512, &parts.concat()).as_ref().to_vec()
}

fn serialized_edk(edk: &EncryptedDataKey) -> Vec<u8> {
    let mut out = Vec::new();
    for field in [
        edk.key_provider_id().as_bytes(),
        edk.key_provider_info(),
        edk.ciphertext(),
    ] {
        out.extend_from_slice(&u16::try_from(field.len()).unwrap().to_be_bytes());
        out.extend_from_slice(field);
    }
    out
}

//= spec/framework/caching-cmm.md#appendix-a-cache-entry-identifier-formulas
//= type=test
//# When accessing the underlying CMC,
//# the caching CMM MUST use the formulas specified in this appendix
//# in order to compute the [cache entry identifier](cryptographic-materials-cache.md#cache-identifier).
#[tokio::test]
async fn cache_identifiers_follow_the_appendix_a_formulas() {
    let gets = Arc::new(Mutex::new(Vec::new()));
    let recorder = RecordingCmc {
        inner: SharedCmc::new(local_cache()),
        gets: gets.clone(),
    };

    let cmm = CachingCmm::builder()
        .keyring(keyring())
        .cache(recorder)
        .cache_limit_ttl(TTL)
        .partition_id("partition")
        .build()
        .unwrap();
    let context = ec(&[("a", "b")]);
    let ec_hash = sha512(&[&context.serialize().unwrap()]);
    let partition_hash = sha512(&[b"partition"]);

    encrypt(&cmm, context.clone(), None, Some(1)).await;
    let enc = encrypt(&cmm, context.clone(), Some(SUITE), Some(1)).await;
    cmm.decrypt_materials()
        .algorithm_suite_id(SUITE)
        .commitment_policy(POLICY)
        .set_encrypted_data_keys(Some(enc.encrypted_data_keys().to_vec()))
        .set_encryption_context(Some(context.clone()))
        .send()
        .await
        .unwrap();

    let mut edk_hashes: Vec<Vec<u8>> = enc
        .encrypted_data_keys()
        .iter()
        .map(|edk| sha512(&[&serialized_edk(edk)]))
        .collect();
    edk_hashes.sort();
    let suite_id = SUITE.id_bytes();
    let expected = vec![
        sha512(&[&partition_hash, &[0x00], &ec_hash]),
        sha512(&[&partition_hash, &[0x01], &suite_id, &ec_hash]),
        sha512(&[
            &partition_hash,
            &suite_id,
            &edk_hashes.concat(),
            &[0u8; 64],
            &ec_hash,
        ]),
    ];
    assert_eq!(*gets.lock().unwrap(), expected);
}

#[tokio::test]
async fn materials_for_other_required_keys_are_not_reused() {
    let counter = CountingCmm::new();
    let cmm = caching(&counter, local_cache());
    let request = || {
        cmm.get_encryption_materials()
            .set_encryption_context(Some(ec(&[("tenant", "a")])))
            .commitment_policy(POLICY)
            .max_plaintext_length(1u64)
    };
    let required = request()
        .required_encryption_context_keys("tenant")
        .send()
        .await
        .unwrap()
        .into_encryption_materials();
    let plain = request().send().await.unwrap().into_encryption_materials();
    assert_ne!(data_key(&required), data_key(&plain));
    assert!(plain.required_encryption_context_keys().is_empty());
    assert_eq!(counter.encrypt_calls.load(Ordering::SeqCst), 2);
}

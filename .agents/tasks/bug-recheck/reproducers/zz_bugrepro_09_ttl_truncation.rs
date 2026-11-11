// TEMPORARY reproducer for BUG-09 (T14). Delete after running.
// Re-check adaptation for main 620771c: same TTL (1 s), same entry ages
// (900/1500/1950/2050 ms), same shared-LocalCmc scenario and sleeps, same
// observation (keystore call counts). API changes only: Keystore -> KeyStore
// trait shapes; the custom Cmc implements the new input/output Cmc trait;
// CacheEntry::new -> CacheEntry::builder; ttl u64 seconds -> Duration::from_secs;
// CacheType::Shared(cmc) -> .cache(SharedCmc); keyring calls via SharedKeyring.
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use aws_crypto_mpl::Error;
use aws_crypto_mpl::async_trait;
use aws_crypto_mpl::cmc::{
    Cmc, DeleteCacheEntryInput, DeleteCacheEntryOutput, GetCacheEntryInput, GetCacheEntryOutput,
    LocalCmc, PutCacheEntryInput, PutCacheEntryOutput, SharedCmc, UpdateUsageMetadataInput,
    UpdateUsageMetadataOutput,
};
use aws_crypto_mpl::key_store::KeyStore;
use aws_crypto_mpl::key_store::operation::create_key::{CreateKeyInput, CreateKeyOutput};
use aws_crypto_mpl::key_store::operation::create_key_store::{CreateKeyStoreInput, CreateKeyStoreOutput};
use aws_crypto_mpl::key_store::operation::get_active_branch_key::{GetActiveBranchKeyInput, GetActiveBranchKeyOutput};
use aws_crypto_mpl::key_store::operation::get_beacon_key::{GetBeaconKeyInput, GetBeaconKeyOutput};
use aws_crypto_mpl::key_store::operation::get_branch_key_version::{GetBranchKeyVersionInput, GetBranchKeyVersionOutput};
use aws_crypto_mpl::key_store::operation::get_key_store_info::{GetKeyStoreInfoInput, GetKeyStoreInfoOutput};
use aws_crypto_mpl::key_store::operation::version_key::{VersionKeyInput, VersionKeyOutput};
use aws_crypto_mpl::key_store::types::{Discovery, KmsConfiguration};
use aws_crypto_mpl::keyring::{HierarchicalKeyring, SharedKeyring};
use aws_crypto_mpl::types::{
    AlgorithmSuiteId, BranchKeyMaterials, CacheEntry, CachedMaterials, EncryptionContext,
    EncryptionMaterials, EsdkAlgorithmSuiteId,
};

const BKID: &str = "bk";
const VERSION: &str = "11111111-2222-4333-8444-555555555555";

fn bkm() -> BranchKeyMaterials {
    BranchKeyMaterials::builder()
        .branch_key([7u8; 32])
        .branch_key_id(BKID)
        .branch_key_version(VERSION)
        .set_encryption_context(Some(EncryptionContext::new()))
        .build()
        .unwrap()
}

#[derive(Clone)]
struct CountingKeystore {
    active_calls: Arc<Mutex<u32>>,
}

#[async_trait]
impl KeyStore for CountingKeystore {
    async fn get_key_store_info(&self, _: GetKeyStoreInfoInput) -> Result<GetKeyStoreInfoOutput, Error> {
        GetKeyStoreInfoOutput::builder()
            .key_store_id("id")
            .key_store_name("t")
            .logical_key_store_name("L")
            .set_grant_tokens(Some(vec![]))
            .kms_configuration(KmsConfiguration::Discovery(Discovery::builder().build().unwrap()))
            .build()
    }
    async fn create_key_store(&self, _: CreateKeyStoreInput) -> Result<CreateKeyStoreOutput, Error> { unimplemented!() }
    async fn create_key(&self, _: CreateKeyInput) -> Result<CreateKeyOutput, Error> { unimplemented!() }
    async fn version_key(&self, _: VersionKeyInput) -> Result<VersionKeyOutput, Error> { unimplemented!() }
    async fn get_active_branch_key(&self, _: GetActiveBranchKeyInput) -> Result<GetActiveBranchKeyOutput, Error> {
        *self.active_calls.lock().unwrap() += 1;
        GetActiveBranchKeyOutput::builder().branch_key_materials(bkm()).build()
    }
    async fn get_branch_key_version(&self, _: GetBranchKeyVersionInput) -> Result<GetBranchKeyVersionOutput, Error> {
        GetBranchKeyVersionOutput::builder().branch_key_materials(bkm()).build()
    }
    async fn get_beacon_key(&self, _: GetBeaconKeyInput) -> Result<GetBeaconKeyOutput, Error> { unimplemented!() }
}

/// A shared cache that always returns an entry created `age` ago, expiring in an hour.
struct BackdatedCmc {
    age: Duration,
}

#[async_trait]
impl Cmc for BackdatedCmc {
    async fn put_cache_entry(&self, _: PutCacheEntryInput) -> Result<PutCacheEntryOutput, Error> {
        PutCacheEntryOutput::builder().build()
    }
    async fn get_cache_entry(&self, _: GetCacheEntryInput) -> Result<GetCacheEntryOutput, Error> {
        let now = SystemTime::now();
        let entry = CacheEntry::builder()
            .materials(CachedMaterials::BranchKey(bkm()))
            .creation_time(now - self.age)
            .expiry_time(now + Duration::from_secs(3600))
            .build()?;
        GetCacheEntryOutput::builder().entry(entry).build()
    }
    async fn delete_cache_entry(&self, _: DeleteCacheEntryInput) -> Result<DeleteCacheEntryOutput, Error> {
        DeleteCacheEntryOutput::builder().build()
    }
    async fn update_usage_metadata(&self, _: UpdateUsageMetadataInput) -> Result<UpdateUsageMetadataOutput, Error> {
        UpdateUsageMetadataOutput::builder().build()
    }
}

fn em() -> EncryptionMaterials {
    EncryptionMaterials::builder()
        .algorithm_suite_id(AlgorithmSuiteId::Esdk(EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf))
        .build()
        .unwrap()
}

async fn keyring(ks: CountingKeystore, ttl_s: u64, cache: SharedCmc) -> SharedKeyring {
    SharedKeyring::new(
        HierarchicalKeyring::builder()
            .key_store(ks)
            .ttl(Duration::from_secs(ttl_s))
            .branch_key_id(BKID)
            .cache(cache)
            .partition_id("p")
            .build()
            .await
            .unwrap(),
    )
}

#[tokio::test]
async fn backdated_entry_older_than_ttl_is_used() {
    for age_ms in [900u64, 1_500, 1_950, 2_050] {
        let ks = CountingKeystore { active_calls: Arc::new(Mutex::new(0)) };
        let cache = SharedCmc::new(BackdatedCmc { age: Duration::from_millis(age_ms) });
        let kr = keyring(ks.clone(), 1, cache).await;
        kr.on_encrypt().materials(em()).send().await.unwrap();
        let calls = *ks.active_calls.lock().unwrap();
        println!(
            "REPRO BUG-09 ttl_seconds=1, entry age={age_ms} ms -> {} (keystore calls={calls})",
            if calls == 0 { "cache entry USED" } else { "treated as expired" }
        );
    }
}

#[tokio::test]
async fn shared_local_cmc_two_keyrings_different_ttls() {
    let shared = SharedCmc::new(LocalCmc::builder().entry_capacity(1000).entry_pruning_tail_size(1).build().unwrap());
    let ks = CountingKeystore { active_calls: Arc::new(Mutex::new(0)) };
    let kr_long = keyring(ks.clone(), 100, shared.clone()).await;
    let kr_short = keyring(ks.clone(), 1, shared.clone()).await;
    kr_long.on_encrypt().materials(em()).send().await.unwrap();
    println!("REPRO BUG-09 after ttl=100 keyring populates shared LocalCmc: keystore calls = {}", *ks.active_calls.lock().unwrap());
    std::thread::sleep(Duration::from_millis(1_500));
    kr_short.on_encrypt().materials(em()).send().await.unwrap();
    println!("REPRO BUG-09 ttl=1 keyring at ~1.5 s: keystore calls = {} (1 = cache entry used)", *ks.active_calls.lock().unwrap());
    std::thread::sleep(Duration::from_millis(700));
    kr_short.on_encrypt().materials(em()).send().await.unwrap();
    println!("REPRO BUG-09 ttl=1 keyring at ~2.2 s: keystore calls = {} (2 = treated as expired)", *ks.active_calls.lock().unwrap());
}

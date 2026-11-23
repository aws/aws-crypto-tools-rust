// TEMPORARY reproducer for BUG-09 (T14). Delete after running.
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use aws_crypto_mpl::cmc::cache_config::CacheType;
use aws_crypto_mpl::keystore::{KeyStoreInfo, Keystore, KeystoreError, KmsConfiguration};
use aws_crypto_mpl::structures::{
    AlgorithmSuiteId, BeaconKeyMaterials, BranchKeyMaterials, EncryptionContext,
    EncryptionMaterials,
};
use aws_crypto_mpl::{
    CacheEntry, CachedMaterials, Cmc, CmcError, HierarchicalKeyring, Keyring, LocalCmc,
    UsageMetadata,
};

const BKID: &str = "bk";
const VERSION: &str = "11111111-2222-4333-8444-555555555555";

fn bkm() -> BranchKeyMaterials {
    BranchKeyMaterials::new([7u8; 32], BKID.into(), VERSION.into(), EncryptionContext::new()).unwrap()
}

struct CountingKeystore {
    active_calls: Mutex<u32>,
}

#[async_trait]
impl Keystore for CountingKeystore {
    fn get_key_store_info(&self) -> Result<KeyStoreInfo, KeystoreError> {
        Ok(KeyStoreInfo {
            keystore_id: "id".into(),
            keystore_name: "t".into(),
            logical_keystore_name: "L".into(),
            grant_tokens: vec![],
            kms_configuration: KmsConfiguration::Discovery,
        })
    }
    async fn create_key_store(&self) -> Result<String, KeystoreError> { unimplemented!() }
    async fn create_key(&self, _: Option<String>, _: Option<EncryptionContext>) -> Result<String, KeystoreError> { unimplemented!() }
    async fn version_key(&self, _: String) -> Result<(), KeystoreError> { unimplemented!() }
    async fn get_active_branch_key(&self, _: String) -> Result<BranchKeyMaterials, KeystoreError> {
        *self.active_calls.lock().unwrap() += 1;
        Ok(bkm())
    }
    async fn get_branch_key_version(&self, _: String, _: String) -> Result<BranchKeyMaterials, KeystoreError> { Ok(bkm()) }
    async fn get_beacon_key(&self, _: String) -> Result<BeaconKeyMaterials, KeystoreError> { unimplemented!() }
}

/// A shared cache that always returns an entry created `age` ago, expiring in an hour.
struct BackdatedCmc {
    age: Duration,
}

#[async_trait]
impl Cmc for BackdatedCmc {
    async fn put_cache_entry(&self, _: &[u8], _: CacheEntry) -> Result<(), CmcError> { Ok(()) }
    async fn get_cache_entry(&self, _: &[u8]) -> Result<Option<Arc<CacheEntry>>, CmcError> {
        let now = SystemTime::now();
        Ok(Some(Arc::new(CacheEntry::new(
            CachedMaterials::BranchKey(bkm()),
            now - self.age,
            now + Duration::from_secs(3600),
            UsageMetadata::default(),
        ))))
    }
    async fn delete_cache_entry(&self, _: &[u8]) -> Result<(), CmcError> { Ok(()) }
}

fn em() -> EncryptionMaterials {
    EncryptionMaterials::new(AlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf, vec![], EncryptionContext::new(), Default::default(), None, None, None).unwrap()
}

#[tokio::test]
async fn backdated_entry_older_than_ttl_is_used() {
    for age_ms in [900u64, 1_500, 1_950, 2_050] {
        let ks = Arc::new(CountingKeystore { active_calls: Mutex::new(0) });
        let cache: Arc<dyn Cmc> = Arc::new(BackdatedCmc { age: Duration::from_millis(age_ms) });
        let kr = HierarchicalKeyring::new(ks.clone(), 1, Some(BKID.into()), None, Some(CacheType::Shared(cache)), Some("p".into())).unwrap();
        kr.on_encrypt(em()).await.unwrap();
        let calls = *ks.active_calls.lock().unwrap();
        println!(
            "REPRO BUG-09 ttl_seconds=1, entry age={age_ms} ms -> {} (keystore calls={calls})",
            if calls == 0 { "cache entry USED" } else { "treated as expired" }
        );
    }
}

#[tokio::test]
async fn shared_local_cmc_two_keyrings_different_ttls() {
    let shared: Arc<dyn Cmc> = Arc::new(LocalCmc::new(1000, 1).unwrap());
    let ks = Arc::new(CountingKeystore { active_calls: Mutex::new(0) });
    let kr_long = HierarchicalKeyring::new(ks.clone(), 100, Some(BKID.into()), None, Some(CacheType::Shared(shared.clone())), Some("p".into())).unwrap();
    let kr_short = HierarchicalKeyring::new(ks.clone(), 1, Some(BKID.into()), None, Some(CacheType::Shared(shared.clone())), Some("p".into())).unwrap();
    kr_long.on_encrypt(em()).await.unwrap();
    println!("REPRO BUG-09 after ttl=100 keyring populates shared LocalCmc: keystore calls = {}", *ks.active_calls.lock().unwrap());
    std::thread::sleep(Duration::from_millis(1_500));
    kr_short.on_encrypt(em()).await.unwrap();
    println!("REPRO BUG-09 ttl=1 keyring at ~1.5 s: keystore calls = {} (1 = cache entry used)", *ks.active_calls.lock().unwrap());
    std::thread::sleep(Duration::from_millis(700));
    kr_short.on_encrypt(em()).await.unwrap();
    println!("REPRO BUG-09 ttl=1 keyring at ~2.2 s: keystore calls = {} (2 = treated as expired)", *ks.active_calls.lock().unwrap());
}

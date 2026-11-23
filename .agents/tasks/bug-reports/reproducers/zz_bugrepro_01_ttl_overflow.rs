// TEMPORARY reproducer for BUG-01 (T06). Delete after running.
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use aws_crypto_mpl::keystore::{KeyStoreInfo, Keystore, KeystoreError, KmsConfiguration};
use aws_crypto_mpl::structures::{
    AlgorithmSuiteId, BeaconKeyMaterials, BranchKeyMaterials, EncryptionContext,
    EncryptionMaterials,
};
use aws_crypto_mpl::{Cmc, HierarchicalKeyring, Keyring, StormTrackingCmc};

const BKID: &str = "bk";
const VERSION: &str = "11111111-2222-4333-8444-555555555555";

struct FakeKeystore;

#[async_trait]
impl Keystore for FakeKeystore {
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
        Ok(BranchKeyMaterials::new([7u8; 32], BKID.into(), VERSION.into(), EncryptionContext::new()).unwrap())
    }
    async fn get_branch_key_version(&self, _: String, _: String) -> Result<BranchKeyMaterials, KeystoreError> {
        Ok(BranchKeyMaterials::new([7u8; 32], BKID.into(), VERSION.into(), EncryptionContext::new()).unwrap())
    }
    async fn get_beacon_key(&self, _: String) -> Result<BeaconKeyMaterials, KeystoreError> { unimplemented!() }
}

fn panic_msg(e: tokio::task::JoinError) -> String {
    let p = e.into_panic();
    p.downcast_ref::<&str>().map(|s| s.to_string())
        .or_else(|| p.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "<non-string panic>".into())
}

#[test]
fn std_systemtime_add_limits() {
    let now = SystemTime::now();
    println!("REPRO BUG-01 now+u64::MAX s checked_add = {:?}", now.checked_add(Duration::from_secs(u64::MAX)));
    println!("REPRO BUG-01 now+i64::MAX s checked_add = {:?}", now.checked_add(Duration::from_secs(i64::MAX as u64)));
    println!("REPRO BUG-01 now+1e15 s checked_add is_some = {}", now.checked_add(Duration::from_secs(1_000_000_000_000_000)).is_some());
}

#[tokio::test]
async fn hierarchical_ttl_u64_max_accepted_then_on_encrypt_panics() {
    let kr = HierarchicalKeyring::new(Arc::new(FakeKeystore), u64::MAX, Some(BKID.into()), None, None, Some("p".into()));
    println!("REPRO BUG-01a HierarchicalKeyring::new(ttl_seconds = u64::MAX) is_ok = {}", kr.is_ok());
    let kr = Arc::new(kr.unwrap());
    let em = EncryptionMaterials::new(AlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf, vec![], EncryptionContext::new(), Default::default(), None, None, None).unwrap();
    let h = tokio::spawn(async move { kr.on_encrypt(em).await.is_ok() });
    match h.await {
        Err(e) if e.is_panic() => println!("REPRO BUG-01a on_encrypt PANICKED: {}", panic_msg(e)),
        Err(_) => panic!("join error that is not a panic"),
        Ok(ok) => panic!("expected panic; on_encrypt returned is_ok={ok}"),
    }
}

#[tokio::test]
async fn hierarchical_ttl_u64_max_on_decrypt_panics() {
    use aws_crypto_mpl::aws_kms::__test_internals::wrap;
    use aws_crypto_mpl::structures::{DecryptionMaterials, EncryptedDataKey};
    let bkm = BranchKeyMaterials::new([7u8; 32], BKID.into(), VERSION.into(), EncryptionContext::new()).unwrap();
    let ct = wrap(&bkm, &EncryptionContext::new(), &[1u8; 32]).unwrap();
    let edk = EncryptedDataKey::new("aws-kms-hierarchy".into(), BKID.as_bytes().to_vec(), ct);
    let kr = Arc::new(HierarchicalKeyring::new(Arc::new(FakeKeystore), u64::MAX, Some(BKID.into()), None, None, Some("p".into())).unwrap());
    let dm = DecryptionMaterials::new(AlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf, EncryptionContext::new(), Default::default(), None, None, None).unwrap();
    let h = tokio::spawn(async move { kr.on_decrypt(dm, &[edk]).await.is_ok() });
    match h.await {
        Err(e) if e.is_panic() => println!("REPRO BUG-01d on_decrypt PANICKED: {}", panic_msg(e)),
        Err(_) => panic!("join error that is not a panic"),
        Ok(ok) => panic!("expected panic; on_decrypt returned is_ok={ok}"),
    }
}

#[tokio::test]
async fn storm_tracking_huge_grace_interval_accepted_then_second_get_panics() {
    // grace_period, grace_interval, inflight_ttl all u64::MAX seconds: satisfies every check in from_raw.
    let cmc = StormTrackingCmc::new(1000, 1, u64::MAX, u64::MAX, 1, u64::MAX, 1, None);
    println!("REPRO BUG-01b StormTrackingCmc::new(grace_interval = u64::MAX s) is_ok = {}", cmc.is_ok());
    let cmc = Arc::new(cmc.unwrap());
    let first = cmc.get_cache_entry(b"k").await;
    println!("REPRO BUG-01b first get (miss, marks inflight) = {:?}", first.as_ref().map(|o| o.is_some()));
    let c2 = Arc::clone(&cmc);
    let h = tokio::spawn(async move { c2.get_cache_entry(b"k").await.is_ok() });
    match h.await {
        Err(e) if e.is_panic() => println!("REPRO BUG-01b second get PANICKED: {}", panic_msg(e)),
        Err(_) => panic!("join error that is not a panic"),
        Ok(ok) => panic!("expected panic; get returned is_ok={ok}"),
    }
}

#[tokio::test]
async fn storm_tracking_huge_inflight_ttl_accepted_then_waiter_deadline_panics() {
    // grace_interval = 1 s keeps within_grace_interval safe; inflight_ttl = u64::MAX s.
    let cmc = StormTrackingCmc::new(1000, 1, u64::MAX, 1, 1, u64::MAX, 1, None);
    println!("REPRO BUG-01c StormTrackingCmc::new(inflight_ttl = u64::MAX s) is_ok = {}", cmc.is_ok());
    let cmc = Arc::new(cmc.unwrap());
    let _ = cmc.get_cache_entry(b"k").await;
    let c2 = Arc::clone(&cmc);
    let h = tokio::spawn(async move { c2.get_cache_entry(b"k").await.is_ok() });
    match h.await {
        Err(e) if e.is_panic() => println!("REPRO BUG-01c second get PANICKED: {}", panic_msg(e)),
        Err(_) => panic!("join error that is not a panic"),
        Ok(ok) => panic!("expected panic; get returned is_ok={ok}"),
    }
}

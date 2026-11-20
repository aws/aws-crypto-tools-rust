// TEMPORARY reproducer for BUG-01 (T06). Delete after running.
// Re-check adaptation for main 620771c: same inputs and same pass condition
// (each keyring/CMC call is expected to PANIC); only the API is updated:
// positional constructors -> builders, u64 seconds -> Duration::from_secs,
// Keystore -> KeyStore trait with input/output shapes, Keyring calls via the
// SharedKeyring fluent builders.
use std::time::{Duration, SystemTime};

use aws_crypto_mpl::Error;
use aws_crypto_mpl::async_trait;
use aws_crypto_mpl::__test_internals::aws_kms::wrap;
use aws_crypto_mpl::cmc::{SharedCmc, StormTrackingCmc};
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
use aws_crypto_mpl::shared::IntoShared;
use aws_crypto_mpl::types::{
    AlgorithmSuiteId, BranchKeyMaterials, DecryptionMaterials, EncryptedDataKey,
    EncryptionContext, EncryptionMaterials, EsdkAlgorithmSuiteId,
};

const BKID: &str = "bk";
const VERSION: &str = "11111111-2222-4333-8444-555555555555";
const SUITE: AlgorithmSuiteId = AlgorithmSuiteId::Esdk(EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf);

fn bkm() -> BranchKeyMaterials {
    BranchKeyMaterials::builder()
        .branch_key([7u8; 32])
        .branch_key_id(BKID)
        .branch_key_version(VERSION)
        .set_encryption_context(Some(EncryptionContext::new()))
        .build()
        .unwrap()
}

struct FakeKeystore;

#[async_trait]
impl KeyStore for FakeKeystore {
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
        GetActiveBranchKeyOutput::builder().branch_key_materials(bkm()).build()
    }
    async fn get_branch_key_version(&self, _: GetBranchKeyVersionInput) -> Result<GetBranchKeyVersionOutput, Error> {
        GetBranchKeyVersionOutput::builder().branch_key_materials(bkm()).build()
    }
    async fn get_beacon_key(&self, _: GetBeaconKeyInput) -> Result<GetBeaconKeyOutput, Error> { unimplemented!() }
}

fn panic_msg(e: tokio::task::JoinError) -> String {
    let p = e.into_panic();
    p.downcast_ref::<&str>().map(|s| s.to_string())
        .or_else(|| p.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "<non-string panic>".into())
}

async fn keyring_ttl_u64_max() -> Result<HierarchicalKeyring, Error> {
    // Original: HierarchicalKeyring::new(ks, u64::MAX /*ttl s*/, Some(BKID), None, None /*default cache*/, Some("p"))
    HierarchicalKeyring::builder()
        .key_store(FakeKeystore)
        .ttl(Duration::from_secs(u64::MAX))
        .branch_key_id(BKID)
        .partition_id("p")
        .build()
        .await
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
    let kr = keyring_ttl_u64_max().await;
    println!("REPRO BUG-01a HierarchicalKeyring::new(ttl_seconds = u64::MAX) is_ok = {}", kr.is_ok());
    let kr = SharedKeyring::new(kr.unwrap());
    let em = EncryptionMaterials::builder().algorithm_suite_id(SUITE).build().unwrap();
    let h = tokio::spawn(async move { kr.on_encrypt().materials(em).send().await.is_ok() });
    match h.await {
        Err(e) if e.is_panic() => println!("REPRO BUG-01a on_encrypt PANICKED: {}", panic_msg(e)),
        Err(_) => panic!("join error that is not a panic"),
        Ok(ok) => panic!("expected panic; on_encrypt returned is_ok={ok}"),
    }
}

#[tokio::test]
async fn hierarchical_ttl_u64_max_on_decrypt_panics() {
    let ct = wrap(&bkm(), &EncryptionContext::new(), &[1u8; 32]).unwrap();
    let edk = EncryptedDataKey::builder()
        .key_provider_id("aws-kms-hierarchy")
        .key_provider_info(BKID.as_bytes().to_vec())
        .ciphertext(ct)
        .build()
        .unwrap();
    let kr = SharedKeyring::new(keyring_ttl_u64_max().await.unwrap());
    let dm = DecryptionMaterials::builder().algorithm_suite_id(SUITE).build().unwrap();
    let h = tokio::spawn(async move {
        kr.on_decrypt().materials(dm).set_encrypted_data_keys(Some(vec![edk])).send().await.is_ok()
    });
    match h.await {
        Err(e) if e.is_panic() => println!("REPRO BUG-01d on_decrypt PANICKED: {}", panic_msg(e)),
        Err(_) => panic!("join error that is not a panic"),
        Ok(ok) => panic!("expected panic; on_decrypt returned is_ok={ok}"),
    }
}

/// Original: StormTrackingCmc::new(1000, 1, grace_period, grace_interval, 1, inflight_ttl, 1 /*sleep ms*/, None /*seconds*/)
fn storm(grace_period_s: u64, grace_interval_s: u64, in_flight_ttl_s: u64) -> Result<StormTrackingCmc, Error> {
    StormTrackingCmc::builder()
        .entry_capacity(1000)
        .entry_pruning_tail_size(1)
        .grace_period(Duration::from_secs(grace_period_s))
        .grace_interval(Duration::from_secs(grace_interval_s))
        .fan_out(1)
        .in_flight_ttl(Duration::from_secs(in_flight_ttl_s))
        .sleep(Duration::from_millis(1))
        .build()
}

#[tokio::test]
async fn storm_tracking_huge_grace_interval_accepted_then_second_get_panics() {
    // grace_period, grace_interval, inflight_ttl all u64::MAX seconds.
    let cmc = storm(u64::MAX, u64::MAX, u64::MAX);
    println!("REPRO BUG-01b StormTrackingCmc::new(grace_interval = u64::MAX s) is_ok = {}", cmc.is_ok());
    let cmc: SharedCmc = cmc.unwrap().into_shared();
    let first = cmc.get_cache_entry().identifier(b"k".to_vec()).send().await;
    println!("REPRO BUG-01b first get (miss, marks inflight) = {:?}", first.map(|o| o.into_entry().is_some()).map_err(|e| e.to_string()));
    let c2 = cmc.clone();
    let h = tokio::spawn(async move { c2.get_cache_entry().identifier(b"k".to_vec()).send().await.is_ok() });
    match h.await {
        Err(e) if e.is_panic() => println!("REPRO BUG-01b second get PANICKED: {}", panic_msg(e)),
        Err(_) => panic!("join error that is not a panic"),
        Ok(ok) => panic!("expected panic; get returned is_ok={ok}"),
    }
}

#[tokio::test]
async fn storm_tracking_huge_inflight_ttl_accepted_then_waiter_deadline_panics() {
    // grace_interval = 1 s keeps within_grace_interval safe; inflight_ttl = u64::MAX s.
    let cmc = storm(u64::MAX, 1, u64::MAX);
    println!("REPRO BUG-01c StormTrackingCmc::new(inflight_ttl = u64::MAX s) is_ok = {}", cmc.is_ok());
    let cmc: SharedCmc = cmc.unwrap().into_shared();
    let _ = cmc.get_cache_entry().identifier(b"k".to_vec()).send().await;
    let c2 = cmc.clone();
    let h = tokio::spawn(async move { c2.get_cache_entry().identifier(b"k".to_vec()).send().await.is_ok() });
    match h.await {
        Err(e) if e.is_panic() => println!("REPRO BUG-01c second get PANICKED: {}", panic_msg(e)),
        Err(_) => panic!("join error that is not a panic"),
        Ok(ok) => panic!("expected panic; get returned is_ok={ok}"),
    }
}

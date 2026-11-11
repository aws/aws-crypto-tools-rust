// TEMPORARY reproducer for BUG-06 (T13). Delete after running.
// Re-check adaptation for main 620771c: same field values (partition ids,
// logical key store names, branch key ids containing NUL), same comparisons,
// same end-to-end scenario with one shared LocalCmc(capacity 1000, tail 1).
// API changes only: test internals moved to __test_internals::aws_kms, the
// SCOPE_ID consts are re-exported there, Keystore -> KeyStore trait shapes,
// positional constructors -> builders, CacheType::Shared(cmc) -> .cache(SharedCmc).
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aws_crypto_mpl::Error;
use aws_crypto_mpl::async_trait;
use aws_crypto_mpl::__test_internals::aws_kms::{SCOPE_ID_DECRYPT, SCOPE_ID_ENCRYPT, build_cache_identifier, unwrap};
use aws_crypto_mpl::cmc::{LocalCmc, SharedCmc};
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
    AlgorithmSuiteId, BranchKeyMaterials, EncryptionContext, EncryptionMaterials,
    EsdkAlgorithmSuiteId,
};

const BKID: &str = "bk";
const VERSION: &str = "11111111-2222-4333-8444-555555555555";

#[derive(Clone)]
struct NamedKeystore {
    logical: &'static str,
    key_byte: u8,
    active_calls: Arc<Mutex<u32>>,
}

impl NamedKeystore {
    fn materials(&self) -> BranchKeyMaterials {
        BranchKeyMaterials::builder()
            .branch_key([self.key_byte; 32])
            .branch_key_id(BKID)
            .branch_key_version(VERSION)
            .set_encryption_context(Some(EncryptionContext::new()))
            .build()
            .unwrap()
    }
}

#[async_trait]
impl KeyStore for NamedKeystore {
    async fn get_key_store_info(&self, _: GetKeyStoreInfoInput) -> Result<GetKeyStoreInfoOutput, Error> {
        GetKeyStoreInfoOutput::builder()
            .key_store_id("id")
            .key_store_name("t")
            .logical_key_store_name(self.logical)
            .set_grant_tokens(Some(vec![]))
            .kms_configuration(KmsConfiguration::Discovery(Discovery::builder().build().unwrap()))
            .build()
    }
    async fn create_key_store(&self, _: CreateKeyStoreInput) -> Result<CreateKeyStoreOutput, Error> { unimplemented!() }
    async fn create_key(&self, _: CreateKeyInput) -> Result<CreateKeyOutput, Error> { unimplemented!() }
    async fn version_key(&self, _: VersionKeyInput) -> Result<VersionKeyOutput, Error> { unimplemented!() }
    async fn get_active_branch_key(&self, _: GetActiveBranchKeyInput) -> Result<GetActiveBranchKeyOutput, Error> {
        *self.active_calls.lock().unwrap() += 1;
        GetActiveBranchKeyOutput::builder().branch_key_materials(self.materials()).build()
    }
    async fn get_branch_key_version(&self, _: GetBranchKeyVersionInput) -> Result<GetBranchKeyVersionOutput, Error> {
        GetBranchKeyVersionOutput::builder().branch_key_materials(self.materials()).build()
    }
    async fn get_beacon_key(&self, _: GetBeaconKeyInput) -> Result<GetBeaconKeyOutput, Error> { unimplemented!() }
}

#[test]
fn identifier_collides_when_fields_contain_nul() {
    let a_enc = build_cache_identifier(SCOPE_ID_ENCRYPT, b"tenant\0x", "L", BKID, None);
    let b_enc = build_cache_identifier(SCOPE_ID_ENCRYPT, b"tenant", "x\0L", BKID, None);
    println!("REPRO BUG-06 encrypt-scope ids equal for (p=\"tenant\\0x\", n=\"L\") vs (p=\"tenant\", n=\"x\\0L\"): {}", a_enc == b_enc);
    let a_dec = build_cache_identifier(SCOPE_ID_DECRYPT, b"p", "L", "bk\0x", Some(VERSION));
    let b_dec = build_cache_identifier(SCOPE_ID_DECRYPT, b"p", "L\0bk", "x", Some(VERSION));
    println!("REPRO BUG-06 decrypt-scope ids equal for (n=\"L\", bkid=\"bk\\0x\") vs (n=\"L\\0bk\", bkid=\"x\"): {}", a_dec == b_dec);
    let c = build_cache_identifier(SCOPE_ID_ENCRYPT, b"tenantx", "L", BKID, None);
    println!("REPRO BUG-06 control (no NUL, p=\"tenantx\") equal to first: {}", a_enc == c);
}

#[tokio::test]
async fn shared_cache_serves_other_keyrings_branch_key() {
    let shared = SharedCmc::new(LocalCmc::builder().entry_capacity(1000).entry_pruning_tail_size(1).build().unwrap());
    let ks_a = NamedKeystore { logical: "L", key_byte: 0xA1, active_calls: Arc::new(Mutex::new(0)) };
    let ks_b = NamedKeystore { logical: "x\0L", key_byte: 0xB2, active_calls: Arc::new(Mutex::new(0)) };
    let build = |ks: NamedKeystore, partition: &'static str, cache: SharedCmc| async move {
        SharedKeyring::new(
            HierarchicalKeyring::builder()
                .key_store(ks)
                .ttl(Duration::from_secs(3600))
                .branch_key_id(BKID)
                .cache(cache)
                .partition_id(partition)
                .build()
                .await
                .unwrap(),
        )
    };
    let kr_a = build(ks_a.clone(), "tenant\0x", shared.clone()).await;
    let kr_b = build(ks_b.clone(), "tenant", shared.clone()).await;
    let em = || {
        EncryptionMaterials::builder()
            .algorithm_suite_id(AlgorithmSuiteId::Esdk(EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf))
            .build()
            .unwrap()
    };
    kr_a.on_encrypt().materials(em()).send().await.unwrap();
    let out_b = kr_b.on_encrypt().materials(em()).send().await.unwrap().into_materials();
    println!(
        "REPRO BUG-06 keystore A get_active calls = {}, keystore B get_active calls = {}",
        *ks_a.active_calls.lock().unwrap(),
        *ks_b.active_calls.lock().unwrap()
    );
    let ct = out_b.encrypted_data_keys()[0].ciphertext();
    println!(
        "REPRO BUG-06 keyring B's EDK unwraps with keystore A's branch key: {}; with keystore B's own branch key: {}",
        unwrap(&ks_a.materials(), &EncryptionContext::new(), ct).is_ok(),
        unwrap(&ks_b.materials(), &EncryptionContext::new(), ct).is_ok()
    );
}

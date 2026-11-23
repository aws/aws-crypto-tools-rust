// TEMPORARY reproducer for BUG-06 (T13). Delete after running.
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use aws_crypto_mpl::aws_kms::__test_internals::{build_cache_identifier, unwrap};
use aws_crypto_mpl::aws_kms::hierarchical_keyring::{SCOPE_ID_DECRYPT, SCOPE_ID_ENCRYPT};
use aws_crypto_mpl::cmc::cache_config::CacheType;
use aws_crypto_mpl::keystore::{KeyStoreInfo, Keystore, KeystoreError, KmsConfiguration};
use aws_crypto_mpl::structures::{
    AlgorithmSuiteId, BeaconKeyMaterials, BranchKeyMaterials, EncryptionContext,
    EncryptionMaterials,
};
use aws_crypto_mpl::{Cmc, HierarchicalKeyring, Keyring, LocalCmc};

const BKID: &str = "bk";
const VERSION: &str = "11111111-2222-4333-8444-555555555555";

struct NamedKeystore {
    logical: &'static str,
    key_byte: u8,
    active_calls: Mutex<u32>,
}

impl NamedKeystore {
    fn materials(&self) -> BranchKeyMaterials {
        BranchKeyMaterials::new([self.key_byte; 32], BKID.into(), VERSION.into(), EncryptionContext::new()).unwrap()
    }
}

#[async_trait]
impl Keystore for NamedKeystore {
    fn get_key_store_info(&self) -> Result<KeyStoreInfo, KeystoreError> {
        Ok(KeyStoreInfo {
            keystore_id: "id".into(),
            keystore_name: "t".into(),
            logical_keystore_name: self.logical.into(),
            grant_tokens: vec![],
            kms_configuration: KmsConfiguration::Discovery,
        })
    }
    async fn create_key_store(&self) -> Result<String, KeystoreError> { unimplemented!() }
    async fn create_key(&self, _: Option<String>, _: Option<EncryptionContext>) -> Result<String, KeystoreError> { unimplemented!() }
    async fn version_key(&self, _: String) -> Result<(), KeystoreError> { unimplemented!() }
    async fn get_active_branch_key(&self, _: String) -> Result<BranchKeyMaterials, KeystoreError> {
        *self.active_calls.lock().unwrap() += 1;
        Ok(self.materials())
    }
    async fn get_branch_key_version(&self, _: String, _: String) -> Result<BranchKeyMaterials, KeystoreError> { Ok(self.materials()) }
    async fn get_beacon_key(&self, _: String) -> Result<BeaconKeyMaterials, KeystoreError> { unimplemented!() }
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
    let shared: Arc<dyn Cmc> = Arc::new(LocalCmc::new(1000, 1).unwrap());
    let ks_a = Arc::new(NamedKeystore { logical: "L", key_byte: 0xA1, active_calls: Mutex::new(0) });
    let ks_b = Arc::new(NamedKeystore { logical: "x\0L", key_byte: 0xB2, active_calls: Mutex::new(0) });
    let kr_a = HierarchicalKeyring::new(ks_a.clone(), 3600, Some(BKID.into()), None, Some(CacheType::Shared(shared.clone())), Some("tenant\0x".into())).unwrap();
    let kr_b = HierarchicalKeyring::new(ks_b.clone(), 3600, Some(BKID.into()), None, Some(CacheType::Shared(shared.clone())), Some("tenant".into())).unwrap();

    let em = || EncryptionMaterials::new(AlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf, vec![], EncryptionContext::new(), Default::default(), None, None, None).unwrap();
    kr_a.on_encrypt(em()).await.unwrap();
    let out_b = kr_b.on_encrypt(em()).await.unwrap();
    println!(
        "REPRO BUG-06 keystore A get_active calls = {}, keystore B get_active calls = {}",
        *ks_a.active_calls.lock().unwrap(),
        *ks_b.active_calls.lock().unwrap()
    );
    let ct = &out_b.encrypted_data_keys()[0].ciphertext;
    println!(
        "REPRO BUG-06 keyring B's EDK unwraps with keystore A's branch key: {}; with keystore B's own branch key: {}",
        unwrap(&ks_a.materials(), &EncryptionContext::new(), ct).is_ok(),
        unwrap(&ks_b.materials(), &EncryptionContext::new(), ct).is_ok()
    );
}

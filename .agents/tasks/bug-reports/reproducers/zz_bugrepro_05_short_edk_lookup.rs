// TEMPORARY reproducer for BUG-05 part (b) (T16). Delete after running.
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use aws_crypto_mpl::keystore::{KeyStoreInfo, Keystore, KeystoreError, KmsConfiguration};
use aws_crypto_mpl::structures::{
    AlgorithmSuiteId, BeaconKeyMaterials, BranchKeyMaterials, DecryptionMaterials,
    EncryptedDataKey, EncryptionContext,
};
use aws_crypto_mpl::{HierarchicalKeyring, Keyring};

const BKID: &str = "bk";
const VERSION: &str = "11111111-2222-4333-8444-555555555555";
const VERSION_BYTES: [u8; 16] = [0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x43, 0x33, 0x84, 0x44, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55];

struct CountingKeystore {
    version_calls: Mutex<u32>,
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
    async fn get_active_branch_key(&self, _: String) -> Result<BranchKeyMaterials, KeystoreError> { unimplemented!() }
    async fn get_branch_key_version(&self, _: String, v: String) -> Result<BranchKeyMaterials, KeystoreError> {
        *self.version_calls.lock().unwrap() += 1;
        Ok(BranchKeyMaterials::new([7u8; 32], BKID.into(), v, EncryptionContext::new()).unwrap())
    }
    async fn get_beacon_key(&self, _: String) -> Result<BeaconKeyMaterials, KeystoreError> { unimplemented!() }
}

#[tokio::test]
async fn short_edk_reaches_keystore_before_rejection() {
    for len in [43usize, 44, 50, 59, 60] {
        let ks = Arc::new(CountingKeystore { version_calls: Mutex::new(0) });
        let kr = HierarchicalKeyring::new(ks.clone(), 3600, Some(BKID.into()), None, None, Some("p".into())).unwrap();
        let mut ct = vec![0u8; len];
        if len >= 44 {
            ct[28..44].copy_from_slice(&VERSION_BYTES);
        }
        let edk = EncryptedDataKey::new("aws-kms-hierarchy".into(), BKID.as_bytes().to_vec(), ct);
        let dm = DecryptionMaterials::new(AlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf, EncryptionContext::new(), Default::default(), None, None, None).unwrap();
        let r = kr.on_decrypt(dm, &[edk]).await;
        let inner = r.as_ref().err().and_then(|e| e.collected_errors().first().map(|x| x.message.clone()));
        println!(
            "REPRO BUG-05b ciphertext_len={len}: on_decrypt is_err={} keystore get_branch_key_version calls={} inner_error={:?}",
            r.is_err(),
            *ks.version_calls.lock().unwrap(),
            inner
        );
    }
    let _ = VERSION;
}

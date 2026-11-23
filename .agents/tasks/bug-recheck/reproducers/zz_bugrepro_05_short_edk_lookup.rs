// TEMPORARY reproducer for BUG-05 part (b) (T16). Delete after running.
// Re-check adaptation for main 620771c: same ciphertext lengths (43/44/50/59/60),
// same version bytes at offset 28..44, same observation (how many times the
// key store's get_branch_key_version is called, and the error). API changes
// only: Keystore -> KeyStore trait shapes, builders, SharedKeyring fluent calls,
// `collected_errors()[0].message` -> Display + source chain of the error
// (with one candidate EDK the keyring now returns that candidate's error itself).
use std::error::Error as _;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aws_crypto_mpl::Error;
use aws_crypto_mpl::async_trait;
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
    AlgorithmSuiteId, BranchKeyMaterials, DecryptionMaterials, EncryptedDataKey,
    EncryptionContext, EsdkAlgorithmSuiteId,
};

const BKID: &str = "bk";
const VERSION: &str = "11111111-2222-4333-8444-555555555555";
const VERSION_BYTES: [u8; 16] = [0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x43, 0x33, 0x84, 0x44, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55];

#[derive(Clone)]
struct CountingKeystore {
    version_calls: Arc<Mutex<u32>>,
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
    async fn get_active_branch_key(&self, _: GetActiveBranchKeyInput) -> Result<GetActiveBranchKeyOutput, Error> { unimplemented!() }
    async fn get_branch_key_version(&self, input: GetBranchKeyVersionInput) -> Result<GetBranchKeyVersionOutput, Error> {
        *self.version_calls.lock().unwrap() += 1;
        let bkm = BranchKeyMaterials::builder()
            .branch_key([7u8; 32])
            .branch_key_id(BKID)
            .branch_key_version(input.branch_key_version().to_owned())
            .set_encryption_context(Some(EncryptionContext::new()))
            .build()
            .unwrap();
        GetBranchKeyVersionOutput::builder().branch_key_materials(bkm).build()
    }
    async fn get_beacon_key(&self, _: GetBeaconKeyInput) -> Result<GetBeaconKeyOutput, Error> { unimplemented!() }
}

fn describe(e: &Error) -> String {
    let mut s = e.to_string();
    let mut src = e.source();
    while let Some(x) = src {
        s.push_str(&format!(" <- {x}"));
        src = x.source();
    }
    s
}

#[tokio::test]
async fn short_edk_reaches_keystore_before_rejection() {
    for len in [43usize, 44, 50, 59, 60] {
        let ks = CountingKeystore { version_calls: Arc::new(Mutex::new(0)) };
        let kr = SharedKeyring::new(
            HierarchicalKeyring::builder()
                .key_store(ks.clone())
                .ttl(Duration::from_secs(3600))
                .branch_key_id(BKID)
                .partition_id("p")
                .build()
                .await
                .unwrap(),
        );
        let mut ct = vec![0u8; len];
        if len >= 44 {
            ct[28..44].copy_from_slice(&VERSION_BYTES);
        }
        let edk = EncryptedDataKey::builder()
            .key_provider_id("aws-kms-hierarchy")
            .key_provider_info(BKID.as_bytes().to_vec())
            .ciphertext(ct)
            .build()
            .unwrap();
        let dm = DecryptionMaterials::builder()
            .algorithm_suite_id(AlgorithmSuiteId::Esdk(EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf))
            .build()
            .unwrap();
        let r = kr.on_decrypt().materials(dm).set_encrypted_data_keys(Some(vec![edk])).send().await;
        let inner = r.as_ref().err().map(describe);
        println!(
            "REPRO BUG-05b ciphertext_len={len}: on_decrypt is_err={} keystore get_branch_key_version calls={} inner_error={:?}",
            r.is_err(),
            *ks.version_calls.lock().unwrap(),
            inner
        );
    }
    let _ = VERSION;
}

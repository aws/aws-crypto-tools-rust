// TEMPORARY reproducer for BUG-02 (C04-F1 / C04-F2). Delete after running.
use std::sync::Arc;

use async_trait::async_trait;
use aws_crypto_mpl::aws_kms::__test_internals::wrap;
use aws_crypto_mpl::keystore::{KeyStoreInfo, Keystore, KeystoreError, KmsConfiguration};
use aws_crypto_mpl::structures::{
    AlgorithmSuiteId, BeaconKeyMaterials, BranchKeyMaterials, DecryptionMaterials,
    EncryptedDataKey, EncryptionContext, EncryptionMaterials, PlaintextDataKey,
};
use aws_crypto_mpl::{AesGcm, HierarchicalKeyring, Keyring, RawAesKeyring};

const BKID: &str = "bk";
const VERSION: &str = "11111111-2222-4333-8444-555555555555";
const SUITE: AlgorithmSuiteId = AlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf;

fn bkm() -> BranchKeyMaterials {
    BranchKeyMaterials::new([7u8; 32], BKID.into(), VERSION.into(), EncryptionContext::new()).unwrap()
}

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
    async fn get_active_branch_key(&self, _: String) -> Result<BranchKeyMaterials, KeystoreError> { Ok(bkm()) }
    async fn get_branch_key_version(&self, _: String, _: String) -> Result<BranchKeyMaterials, KeystoreError> { Ok(bkm()) }
    async fn get_beacon_key(&self, _: String) -> Result<BeaconKeyMaterials, KeystoreError> { unimplemented!() }
}

fn keyring() -> HierarchicalKeyring {
    HierarchicalKeyring::new(Arc::new(FakeKeystore), 3600, Some(BKID.into()), None, None, Some("p".into())).unwrap()
}

fn empty_dm() -> DecryptionMaterials {
    DecryptionMaterials::new(SUITE, EncryptionContext::new(), Default::default(), None, None, None).unwrap()
}

#[tokio::test]
async fn f1_hierarchical_on_decrypt_returns_wrong_length_pdk() {
    println!("REPRO BUG-02 F1 suite {SUITE:?} encryption_key_length = {}", SUITE.specification().encryption_key_length());
    for pdk_len in [5usize, 0, 64] {
        // An EDK produced by the real wrap() over a PDK of the wrong length,
        // i.e. what any party holding the branch key could produce.
        let ct = wrap(&bkm(), &EncryptionContext::new(), &vec![0xAA; pdk_len]).unwrap();
        let edk = EncryptedDataKey::new("aws-kms-hierarchy".into(), BKID.as_bytes().to_vec(), ct.clone());
        let out = keyring().on_decrypt(empty_dm(), &[edk]).await;
        match out {
            Ok(m) => println!(
                "REPRO BUG-02 F1 edk_ciphertext_len={} -> on_decrypt Ok, plaintext_data_key len = {}",
                ct.len(),
                m.plaintext_data_key().unwrap().len()
            ),
            Err(e) => println!("REPRO BUG-02 F1 edk_ciphertext_len={} -> on_decrypt Err: {}", ct.len(), e.message),
        }
    }
}

#[tokio::test]
async fn f2_constructors_accept_wrong_length_pdk_and_keyrings_pass_it_through() {
    let em = EncryptionMaterials::new(SUITE, vec![], EncryptionContext::new(), Default::default(), Some(PlaintextDataKey::new(vec![0xBB; 5])), None, None);
    println!("REPRO BUG-02 F2 EncryptionMaterials::new(5-byte PDK, suite needs 32) is_ok = {}", em.is_ok());
    let dm = DecryptionMaterials::new(SUITE, EncryptionContext::new(), Default::default(), Some(PlaintextDataKey::new(vec![0xBB; 5])), None, None);
    println!("REPRO BUG-02 F2 DecryptionMaterials::new(5-byte PDK, suite needs 32) is_ok = {}", dm.is_ok());

    let out = keyring().on_encrypt(em.unwrap()).await.unwrap();
    println!(
        "REPRO BUG-02 F2 HierarchicalKeyring::on_encrypt Ok: pdk len = {}, edk ciphertext len = {}",
        out.plaintext_data_key().unwrap().len(),
        out.encrypted_data_keys()[0].ciphertext.len()
    );

    // Same pass-through on the raw AES keyring's on_encrypt; its on_decrypt
    // (unlike the hierarchical one) then rejects the wrong length.
    let raw = RawAesKeyring::new("ns", "name", vec![9u8; 32], AesGcm::Aes256Gcm).unwrap();
    let em2 = EncryptionMaterials::new(SUITE, vec![], EncryptionContext::new(), Default::default(), Some(PlaintextDataKey::new(vec![0xBB; 5])), None, None).unwrap();
    let enc = raw.on_encrypt(em2).await;
    println!("REPRO BUG-02 F2 RawAesKeyring::on_encrypt(5-byte PDK) is_ok = {}", enc.is_ok());
    let edks = enc.unwrap().encrypted_data_keys().to_vec();
    match raw.on_decrypt(empty_dm(), &edks).await {
        Ok(m) => println!("REPRO BUG-02 RawAesKeyring::on_decrypt Ok len {}", m.plaintext_data_key().unwrap().len()),
        Err(e) => println!(
            "REPRO BUG-02 RawAesKeyring::on_decrypt Err: {} | first nested: {:?}",
            e.message,
            e.collected_errors().first().map(|x| x.message.clone())
        ),
    }
}

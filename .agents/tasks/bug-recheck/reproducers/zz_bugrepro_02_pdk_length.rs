// TEMPORARY reproducer for BUG-02 (C04-F1 / C04-F2). Delete after running.
// Re-check adaptation for main 620771c: same inputs (5/0/64-byte PDKs under a
// suite needing 32 bytes, EDKs produced by the crate's own wrap()), same
// printed observations, same unwraps. API changes only: positional
// constructors -> builders, Keystore -> KeyStore trait shapes, keyring calls via
// SharedKeyring fluent builders, Error fields -> Display/source chain.
use std::error::Error as _;
use std::time::Duration;

use aws_crypto_mpl::Error;
use aws_crypto_mpl::async_trait;
use aws_crypto_mpl::__test_internals::aws_kms::wrap;
use aws_crypto_mpl::key_store::KeyStore;
use aws_crypto_mpl::key_store::operation::create_key::{CreateKeyInput, CreateKeyOutput};
use aws_crypto_mpl::key_store::operation::create_key_store::{CreateKeyStoreInput, CreateKeyStoreOutput};
use aws_crypto_mpl::key_store::operation::get_active_branch_key::{GetActiveBranchKeyInput, GetActiveBranchKeyOutput};
use aws_crypto_mpl::key_store::operation::get_beacon_key::{GetBeaconKeyInput, GetBeaconKeyOutput};
use aws_crypto_mpl::key_store::operation::get_branch_key_version::{GetBranchKeyVersionInput, GetBranchKeyVersionOutput};
use aws_crypto_mpl::key_store::operation::get_key_store_info::{GetKeyStoreInfoInput, GetKeyStoreInfoOutput};
use aws_crypto_mpl::key_store::operation::version_key::{VersionKeyInput, VersionKeyOutput};
use aws_crypto_mpl::key_store::types::{Discovery, KmsConfiguration};
use aws_crypto_mpl::keyring::{HierarchicalKeyring, RawAesKeyring, SharedKeyring};
use aws_crypto_mpl::types::{
    AesWrappingAlg, AlgorithmSuiteId, BranchKeyMaterials, DecryptionMaterials, EncryptedDataKey,
    EncryptionContext, EncryptionMaterials, EsdkAlgorithmSuiteId, PlaintextDataKey,
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

/// Error message plus its source chain (replaces the old `e.message` / `collected_errors()`).
fn describe(e: &Error) -> String {
    let mut s = e.to_string();
    let mut src = e.source();
    while let Some(x) = src {
        s.push_str(&format!(" <- {x}"));
        src = x.source();
    }
    s
}

async fn keyring() -> SharedKeyring {
    // Original: HierarchicalKeyring::new(ks, 3600, Some(BKID), None, None, Some("p"))
    SharedKeyring::new(
        HierarchicalKeyring::builder()
            .key_store(FakeKeystore)
            .ttl(Duration::from_secs(3600))
            .branch_key_id(BKID)
            .partition_id("p")
            .build()
            .await
            .unwrap(),
    )
}

fn empty_dm() -> DecryptionMaterials {
    DecryptionMaterials::builder().algorithm_suite_id(SUITE).build().unwrap()
}

fn em_with_pdk(len: usize) -> Result<EncryptionMaterials, Error> {
    EncryptionMaterials::builder()
        .algorithm_suite_id(SUITE)
        .plaintext_data_key(PlaintextDataKey::new(vec![0xBB; len]))
        .build()
}

#[tokio::test]
async fn f1_hierarchical_on_decrypt_returns_wrong_length_pdk() {
    println!("REPRO BUG-02 F1 suite {SUITE:?} encryption_key_length = {}", SUITE.specification().encryption_key_length());
    for pdk_len in [5usize, 0, 64] {
        // An EDK produced by the real wrap() over a PDK of the wrong length,
        // i.e. what any party holding the branch key could produce.
        let ct = wrap(&bkm(), &EncryptionContext::new(), &vec![0xAA; pdk_len]).unwrap();
        let edk = EncryptedDataKey::builder()
            .key_provider_id("aws-kms-hierarchy")
            .key_provider_info(BKID.as_bytes().to_vec())
            .ciphertext(ct.clone())
            .build()
            .unwrap();
        let out = keyring().await.on_decrypt().materials(empty_dm()).set_encrypted_data_keys(Some(vec![edk])).send().await;
        match out {
            Ok(m) => println!(
                "REPRO BUG-02 F1 edk_ciphertext_len={} -> on_decrypt Ok, plaintext_data_key len = {}",
                ct.len(),
                m.into_materials().plaintext_data_key().unwrap().len()
            ),
            Err(e) => println!("REPRO BUG-02 F1 edk_ciphertext_len={} -> on_decrypt Err: {}", ct.len(), describe(&e)),
        }
    }
}

#[tokio::test]
async fn f2_constructors_accept_wrong_length_pdk_and_keyrings_pass_it_through() {
    let em = em_with_pdk(5);
    println!("REPRO BUG-02 F2 EncryptionMaterials::new(5-byte PDK, suite needs 32) is_ok = {}", em.is_ok());
    if let Err(e) = &em {
        println!("REPRO BUG-02 F2 EncryptionMaterials::new Err = {}", describe(e));
    }
    let dm = DecryptionMaterials::builder()
        .algorithm_suite_id(SUITE)
        .plaintext_data_key(PlaintextDataKey::new(vec![0xBB; 5]))
        .build();
    println!("REPRO BUG-02 F2 DecryptionMaterials::new(5-byte PDK, suite needs 32) is_ok = {}", dm.is_ok());
    if let Err(e) = &dm {
        println!("REPRO BUG-02 F2 DecryptionMaterials::new Err = {}", describe(e));
    }
    let out = keyring().await.on_encrypt().materials(em.unwrap()).send().await.unwrap().into_materials();
    println!(
        "REPRO BUG-02 F2 HierarchicalKeyring::on_encrypt Ok: pdk len = {}, edk ciphertext len = {}",
        out.plaintext_data_key().unwrap().len(),
        out.encrypted_data_keys()[0].ciphertext().len()
    );
    // Same pass-through on the raw AES keyring's on_encrypt; its on_decrypt
    // (unlike the hierarchical one) then rejects the wrong length.
    let raw = SharedKeyring::new(
        RawAesKeyring::builder()
            .key_namespace("ns")
            .key_name("name")
            .wrapping_key(vec![9u8; 32])
            .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
            .build()
            .unwrap(),
    );
    let enc = raw.on_encrypt().materials(em_with_pdk(5).unwrap()).send().await;
    println!("REPRO BUG-02 F2 RawAesKeyring::on_encrypt(5-byte PDK) is_ok = {}", enc.is_ok());
    let edks = enc.unwrap().into_materials().encrypted_data_keys().to_vec();
    match raw.on_decrypt().materials(empty_dm()).set_encrypted_data_keys(Some(edks)).send().await {
        Ok(m) => println!("REPRO BUG-02 RawAesKeyring::on_decrypt Ok len {}", m.into_materials().plaintext_data_key().unwrap().len()),
        Err(e) => println!("REPRO BUG-02 RawAesKeyring::on_decrypt Err: {}", describe(&e)),
    }
}

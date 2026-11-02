// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The checks `SharedKeyring` and `SharedCmm` run on the materials a keyring or CMM returns.

use std::borrow::Cow;

use aws_crypto_mpl::cmm::{
    Cmm, DecryptMaterialsInput, DecryptMaterialsOutput, GetEncryptionMaterialsInput,
    GetEncryptionMaterialsOutput, SharedCmm,
};
use aws_crypto_mpl::error::{CmmResource, KeyringResource, Resource};
use aws_crypto_mpl::keyring::{
    Keyring, OnDecryptInput, OnDecryptOutput, OnEncryptInput, OnEncryptOutput, SharedKeyring,
};
use aws_crypto_mpl::types::builders::{DecryptionMaterialsBuilder, EncryptionMaterialsBuilder};
use aws_crypto_mpl::types::{
    AlgorithmSuiteId, CommitmentPolicy, DecryptionMaterials, EncryptedDataKey, EncryptionMaterials,
    EsdkAlgorithmSuiteId, EsdkCommitmentPolicy, SigningKey, VerificationKey,
};
use aws_crypto_mpl::{Error, async_trait};

const KEYRING: &str = "test-keyring";
const CMM: &str = "test-cmm";
const PUBLIC_KEY: &str = "aws-crypto-public-key";

type EncryptFn = dyn Fn(EncryptionMaterials) -> Result<EncryptionMaterials, Error> + Send + Sync;
type DecryptFn = dyn Fn(DecryptionMaterials) -> Result<DecryptionMaterials, Error> + Send + Sync;

/// A keyring whose `on_encrypt` and `on_decrypt` apply a closure to the materials.
struct FnKeyring {
    encrypt: Box<EncryptFn>,
    decrypt: Box<DecryptFn>,
}

impl FnKeyring {
    fn on_encrypt(
        f: impl Fn(EncryptionMaterials) -> Result<EncryptionMaterials, Error> + Send + Sync + 'static,
    ) -> SharedKeyring {
        SharedKeyring::new(Self {
            encrypt: Box::new(f),
            decrypt: Box::new(Ok),
        })
    }

    fn on_decrypt(
        f: impl Fn(DecryptionMaterials) -> Result<DecryptionMaterials, Error> + Send + Sync + 'static,
    ) -> SharedKeyring {
        SharedKeyring::new(Self {
            encrypt: Box::new(Ok),
            decrypt: Box::new(f),
        })
    }
}

#[async_trait]
impl Keyring for FnKeyring {
    fn name(&self) -> Cow<'_, str> {
        Cow::Borrowed(KEYRING)
    }

    async fn on_encrypt(&self, input: OnEncryptInput) -> Result<OnEncryptOutput, Error> {
        Ok((self.encrypt)(input.into_materials())?.into())
    }

    async fn on_decrypt(&self, input: OnDecryptInput) -> Result<OnDecryptOutput, Error> {
        Ok((self.decrypt)(input.into_materials())?.into())
    }
}

/// A CMM that returns fixed materials.
struct FixedCmm {
    encryption: EncryptionMaterials,
    decryption: DecryptionMaterials,
}

#[async_trait]
impl Cmm for FixedCmm {
    fn name(&self) -> Cow<'_, str> {
        Cow::Borrowed(CMM)
    }

    async fn get_encryption_materials(
        &self,
        _input: GetEncryptionMaterialsInput,
    ) -> Result<GetEncryptionMaterialsOutput, Error> {
        Ok(self.encryption.clone().into())
    }

    async fn decrypt_materials(
        &self,
        _input: DecryptMaterialsInput,
    ) -> Result<DecryptMaterialsOutput, Error> {
        Ok(self.decryption.clone().into())
    }
}

fn non_signing() -> AlgorithmSuiteId {
    AlgorithmSuiteId::Esdk(EsdkAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey)
}

fn signing() -> AlgorithmSuiteId {
    AlgorithmSuiteId::Esdk(EsdkAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384)
}

fn policy() -> CommitmentPolicy {
    CommitmentPolicy::Esdk(EsdkCommitmentPolicy::RequireEncryptAllowDecrypt)
}

fn edk(tag: &str) -> EncryptedDataKey {
    EncryptedDataKey::builder()
        .key_provider_id(tag)
        .key_provider_info(tag.as_bytes())
        .ciphertext(tag.as_bytes())
        .build()
        .unwrap()
}

fn pdk(suite: AlgorithmSuiteId, byte: u8) -> Vec<u8> {
    vec![byte; suite.specification().encryption_key_length()]
}

/// Encryption materials as a CMM hands them to a keyring, before any data key.
fn encryption_materials(suite: AlgorithmSuiteId) -> EncryptionMaterialsBuilder {
    let builder = EncryptionMaterials::builder()
        .algorithm_suite_id(suite)
        .encryption_context("purpose", "test")
        .required_encryption_context_keys("purpose");
    if suite.has_asymmetric_signing() {
        builder
            .encryption_context(PUBLIC_KEY, "cHVibGlj")
            .signing_key(SigningKey::new(vec![1; 8]))
    } else {
        builder
    }
}

/// Decryption materials as a CMM hands them to a keyring, before the data key.
fn decryption_materials(suite: AlgorithmSuiteId) -> DecryptionMaterialsBuilder {
    let builder = DecryptionMaterials::builder()
        .algorithm_suite_id(suite)
        .encryption_context("purpose", "test")
        .required_encryption_context_keys("purpose");
    if suite.has_asymmetric_signing() {
        let key_length = suite.specification().verification_key_length().unwrap();
        builder
            .encryption_context(PUBLIC_KEY, "cHVibGlj")
            .verification_key(VerificationKey::new(vec![2; key_length]))
    } else {
        builder
    }
}

/// `materials` rebuilt field by field, so a test can change one field.
fn rebuild(materials: &EncryptionMaterials) -> EncryptionMaterialsBuilder {
    EncryptionMaterials::builder()
        .algorithm_suite_id(materials.algorithm_suite_id())
        .set_encryption_context(Some(materials.encryption_context().clone()))
        .set_required_encryption_context_keys(Some(
            materials.required_encryption_context_keys().clone(),
        ))
        .set_signing_key(materials.signing_key().cloned())
        .set_plaintext_data_key(materials.plaintext_data_key().cloned())
        .set_encrypted_data_keys(Some(materials.encrypted_data_keys().to_vec()))
}

/// `materials` rebuilt field by field, so a test can change one field.
fn rebuild_decryption(materials: &DecryptionMaterials) -> DecryptionMaterialsBuilder {
    DecryptionMaterials::builder()
        .algorithm_suite_id(materials.algorithm_suite_id())
        .set_encryption_context(Some(materials.encryption_context().clone()))
        .set_required_encryption_context_keys(Some(
            materials.required_encryption_context_keys().clone(),
        ))
        .set_verification_key(materials.verification_key().cloned())
        .set_plaintext_data_key(materials.plaintext_data_key().cloned())
}

/// Add a data key, as an honest keyring does.
fn add_data_key(materials: EncryptionMaterials) -> Result<EncryptionMaterials, Error> {
    let key = pdk(materials.algorithm_suite_id(), 7);
    materials.add_data_key(key, edk("honest"))
}

async fn on_encrypt(
    keyring: SharedKeyring,
    materials: EncryptionMaterialsBuilder,
) -> Result<EncryptionMaterials, Error> {
    Ok(keyring
        .on_encrypt()
        .materials(materials.build().unwrap())
        .send()
        .await?
        .into_materials())
}

async fn on_decrypt(
    keyring: SharedKeyring,
    materials: DecryptionMaterialsBuilder,
) -> Result<DecryptionMaterials, Error> {
    Ok(keyring
        .on_decrypt()
        .materials(materials.build().unwrap())
        .encrypted_data_keys(edk("message"))
        .send()
        .await?
        .into_materials())
}

fn assert_invalid(result: Result<impl std::fmt::Debug, Error>, resource: Resource, fragment: &str) {
    let err = result.expect_err("the check must reject these materials");
    assert!(err.is_invalid_materials(), "{err:?}");
    assert!(err.message().contains(fragment), "{err:?}");
    assert_eq!(err.resource(), Some(&resource));
}

fn keyring_resource() -> Resource {
    Resource::Keyring(KeyringResource::new(KEYRING))
}

fn cmm_resource() -> Resource {
    Resource::Cmm(CmmResource::new(CMM))
}

// ===== Keyring on_encrypt =====

#[tokio::test]
async fn on_encrypt_accepts_an_added_data_key() {
    for suite in [non_signing(), signing()] {
        let materials = on_encrypt(
            FnKeyring::on_encrypt(add_data_key),
            encryption_materials(suite),
        )
        .await
        .unwrap();
        assert_eq!(materials.encrypted_data_keys(), &[edk("honest")]);
    }
}

#[tokio::test]
async fn on_encrypt_accepts_an_added_encrypted_data_key() {
    let keyring = FnKeyring::on_encrypt(|m| m.add_encrypted_data_key(edk("second")));
    let start = add_data_key(encryption_materials(signing()).build().unwrap()).unwrap();
    let materials = on_encrypt(keyring, rebuild(&start)).await.unwrap();
    assert_eq!(
        materials.encrypted_data_keys(),
        &[edk("honest"), edk("second")]
    );
}

#[tokio::test]
async fn on_encrypt_accepts_reordered_encrypted_data_keys() {
    let keyring = FnKeyring::on_encrypt(|m| {
        rebuild(&m)
            .set_encrypted_data_keys(Some(vec![edk("c"), edk("b"), edk("a")]))
            .build()
    });
    let start = encryption_materials(non_signing())
        .plaintext_data_key(pdk(non_signing(), 7))
        .encrypted_data_keys(edk("a"))
        .encrypted_data_keys(edk("b"));
    assert!(on_encrypt(keyring, start).await.is_ok());
}

#[tokio::test]
async fn on_encrypt_rejects_no_plaintext_data_key() {
    let keyring = FnKeyring::on_encrypt(Ok);
    let result = on_encrypt(keyring, encryption_materials(non_signing())).await;
    assert_invalid(result, keyring_resource(), "without a plaintext data key");
}

#[tokio::test]
async fn on_encrypt_rejects_a_changed_algorithm_suite() {
    let other = AlgorithmSuiteId::Esdk(EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256);
    let keyring = FnKeyring::on_encrypt(move |m| {
        add_data_key(rebuild(&m).algorithm_suite_id(other).build()?)
    });
    let result = on_encrypt(keyring, encryption_materials(non_signing())).await;
    assert_invalid(result, keyring_resource(), "algorithm suite");
}

#[tokio::test]
async fn on_encrypt_rejects_a_changed_encryption_context() {
    let keyring = FnKeyring::on_encrypt(|m| {
        add_data_key(
            rebuild(&m)
                .encryption_context("added", "by keyring")
                .build()?,
        )
    });
    let result = on_encrypt(keyring, encryption_materials(non_signing())).await;
    assert_invalid(result, keyring_resource(), "encryption context");
}

#[tokio::test]
async fn on_encrypt_rejects_changed_required_encryption_context_keys() {
    let keyring = FnKeyring::on_encrypt(|m| {
        add_data_key(
            rebuild(&m)
                .set_required_encryption_context_keys(None)
                .build()?,
        )
    });
    let result = on_encrypt(keyring, encryption_materials(non_signing())).await;
    assert_invalid(
        result,
        keyring_resource(),
        "required encryption context keys",
    );
}

#[tokio::test]
async fn on_encrypt_rejects_a_changed_signing_key() {
    let keyring = FnKeyring::on_encrypt(|m| {
        add_data_key(
            rebuild(&m)
                .signing_key(SigningKey::new(vec![9; 8]))
                .build()?,
        )
    });
    let result = on_encrypt(keyring, encryption_materials(signing())).await;
    assert_invalid(result, keyring_resource(), "signing key");
}

#[tokio::test]
async fn on_encrypt_rejects_a_replaced_plaintext_data_key() {
    let keyring = FnKeyring::on_encrypt(|m| {
        let replaced = pdk(m.algorithm_suite_id(), 8);
        rebuild(&m).plaintext_data_key(replaced).build()
    });
    let start = encryption_materials(non_signing())
        .plaintext_data_key(pdk(non_signing(), 7))
        .encrypted_data_keys(edk("a"));
    let result = on_encrypt(keyring, start).await;
    assert_invalid(result, keyring_resource(), "plaintext data key");
}

#[tokio::test]
async fn on_encrypt_rejects_a_removed_encrypted_data_key() {
    // Repeats count: two copies of "a" do not survive as one copy of "a" plus "b".
    let keyring = FnKeyring::on_encrypt(|m| {
        rebuild(&m)
            .set_encrypted_data_keys(Some(vec![edk("a"), edk("b")]))
            .build()
    });
    let start = encryption_materials(non_signing())
        .plaintext_data_key(pdk(non_signing(), 7))
        .encrypted_data_keys(edk("a"))
        .encrypted_data_keys(edk("a"));
    let result = on_encrypt(keyring, start).await;
    assert_invalid(result, keyring_resource(), "removed an encrypted data key");
}

#[tokio::test]
async fn on_encrypt_rejects_a_signing_suite_without_a_signing_key() {
    let keyring = FnKeyring::on_encrypt(add_data_key);
    let start = encryption_materials(signing()).set_signing_key(None);
    let result = on_encrypt(keyring, start).await;
    assert_invalid(result, keyring_resource(), "no signing key");
}

#[tokio::test]
async fn on_encrypt_rejects_a_signing_suite_without_the_public_key_in_the_context() {
    let keyring = FnKeyring::on_encrypt(add_data_key);
    let start = encryption_materials(signing())
        .set_encryption_context(None)
        .set_required_encryption_context_keys(None);
    let result = on_encrypt(keyring, start).await;
    assert_invalid(result, keyring_resource(), "has no 'aws-crypto-public-key'");
}

#[tokio::test]
async fn on_encrypt_rejects_a_non_signing_suite_with_the_public_key_in_the_context() {
    let keyring = FnKeyring::on_encrypt(add_data_key);
    let start = encryption_materials(non_signing()).encryption_context(PUBLIC_KEY, "cHVibGlj");
    let result = on_encrypt(keyring, start).await;
    assert_invalid(result, keyring_resource(), "has 'aws-crypto-public-key'");
}

// ===== Keyring on_decrypt =====

#[tokio::test]
async fn on_decrypt_accepts_an_added_data_key() {
    for suite in [non_signing(), signing()] {
        let keyring = FnKeyring::on_decrypt(move |m| m.add_data_key(pdk(suite, 7)));
        let materials = on_decrypt(keyring, decryption_materials(suite))
            .await
            .unwrap();
        assert!(materials.plaintext_data_key().is_some());
    }
}

#[tokio::test]
async fn on_decrypt_rejects_no_plaintext_data_key() {
    let keyring = FnKeyring::on_decrypt(Ok);
    let result = on_decrypt(keyring, decryption_materials(non_signing())).await;
    assert_invalid(result, keyring_resource(), "without a plaintext data key");
}

#[tokio::test]
async fn on_decrypt_rejects_materials_that_already_have_a_plaintext_data_key() {
    let keyring = FnKeyring::on_decrypt(Ok);
    let start = decryption_materials(non_signing()).plaintext_data_key(pdk(non_signing(), 7));
    let result = on_decrypt(keyring, start).await;
    assert_invalid(
        result,
        keyring_resource(),
        "already have a plaintext data key",
    );
}

#[tokio::test]
async fn on_decrypt_rejects_a_changed_encryption_context() {
    let keyring = FnKeyring::on_decrypt(|m| {
        rebuild_decryption(&m)
            .encryption_context("added", "by keyring")
            .plaintext_data_key(pdk(non_signing(), 7))
            .build()
    });
    let result = on_decrypt(keyring, decryption_materials(non_signing())).await;
    assert_invalid(result, keyring_resource(), "encryption context");
}

#[tokio::test]
async fn on_decrypt_rejects_a_changed_verification_key() {
    let keyring = FnKeyring::on_decrypt(|m| {
        let key_length = m.algorithm_suite().verification_key_length().unwrap();
        rebuild_decryption(&m)
            .verification_key(VerificationKey::new(vec![3; key_length]))
            .plaintext_data_key(pdk(signing(), 7))
            .build()
    });
    let result = on_decrypt(keyring, decryption_materials(signing())).await;
    assert_invalid(result, keyring_resource(), "verification key");
}

#[tokio::test]
async fn on_decrypt_rejects_a_signing_suite_without_a_verification_key() {
    let keyring = FnKeyring::on_decrypt(|m| m.add_data_key(pdk(signing(), 7)));
    let start = decryption_materials(signing()).set_verification_key(None);
    let result = on_decrypt(keyring, start).await;
    assert_invalid(result, keyring_resource(), "no verification key");
}

// ===== CMM =====

fn fixed_cmm(
    encryption: EncryptionMaterialsBuilder,
    decryption: DecryptionMaterialsBuilder,
) -> SharedCmm {
    SharedCmm::new(FixedCmm {
        encryption: encryption.build().unwrap(),
        decryption: decryption.build().unwrap(),
    })
}

async fn get_encryption_materials(cmm: &SharedCmm) -> Result<EncryptionMaterials, Error> {
    Ok(cmm
        .get_encryption_materials()
        .set_encryption_context(Some(Default::default()))
        .commitment_policy(policy())
        .send()
        .await?
        .into_encryption_materials())
}

async fn decrypt_materials(cmm: &SharedCmm) -> Result<DecryptionMaterials, Error> {
    Ok(cmm
        .decrypt_materials()
        .algorithm_suite_id(non_signing())
        .commitment_policy(policy())
        .encrypted_data_keys(edk("message"))
        .set_encryption_context(Some(Default::default()))
        .send()
        .await?
        .into_decryption_materials())
}

fn complete_encryption(suite: AlgorithmSuiteId) -> EncryptionMaterialsBuilder {
    encryption_materials(suite)
        .plaintext_data_key(pdk(suite, 7))
        .encrypted_data_keys(edk("a"))
}

fn complete_decryption(suite: AlgorithmSuiteId) -> DecryptionMaterialsBuilder {
    decryption_materials(suite).plaintext_data_key(pdk(suite, 7))
}

#[tokio::test]
async fn cmm_accepts_complete_materials() {
    for suite in [non_signing(), signing()] {
        let cmm = fixed_cmm(complete_encryption(suite), complete_decryption(suite));
        assert!(get_encryption_materials(&cmm).await.is_ok());
        assert!(decrypt_materials(&cmm).await.is_ok());
    }
}

#[tokio::test]
async fn get_encryption_materials_rejects_no_plaintext_data_key() {
    let cmm = fixed_cmm(
        encryption_materials(non_signing()),
        complete_decryption(non_signing()),
    );
    assert_invalid(
        get_encryption_materials(&cmm).await,
        cmm_resource(),
        "no plaintext data key",
    );
}

#[tokio::test]
async fn get_encryption_materials_rejects_no_encrypted_data_keys() {
    let cmm = fixed_cmm(
        encryption_materials(non_signing()).plaintext_data_key(pdk(non_signing(), 7)),
        complete_decryption(non_signing()),
    );
    assert_invalid(
        get_encryption_materials(&cmm).await,
        cmm_resource(),
        "no encrypted data keys",
    );
}

#[tokio::test]
async fn get_encryption_materials_rejects_a_signing_suite_without_a_signing_key() {
    let cmm = fixed_cmm(
        complete_encryption(signing()).set_signing_key(None),
        complete_decryption(non_signing()),
    );
    assert_invalid(
        get_encryption_materials(&cmm).await,
        cmm_resource(),
        "no signing key",
    );
}

#[tokio::test]
async fn decrypt_materials_rejects_no_plaintext_data_key() {
    let cmm = fixed_cmm(
        complete_encryption(non_signing()),
        decryption_materials(non_signing()),
    );
    assert_invalid(
        decrypt_materials(&cmm).await,
        cmm_resource(),
        "no plaintext data key",
    );
}

#[tokio::test]
async fn decrypt_materials_rejects_a_signing_suite_without_a_verification_key() {
    let cmm = fixed_cmm(
        complete_encryption(non_signing()),
        complete_decryption(signing()).set_verification_key(None),
    );
    assert_invalid(
        decrypt_materials(&cmm).await,
        cmm_resource(),
        "no verification key",
    );
}

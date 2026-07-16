// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for the Default CMM.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;

use aws_crypto_mpl::cmm::{Cmm, DecryptMaterialsRequest, DefaultCmm, EncryptionMaterialsRequest};
use aws_crypto_mpl::keyring::Keyring;
use aws_crypto_mpl::structures::{
    AlgorithmSuiteId, CommitmentPolicy, DecryptionMaterials, EncryptedDataKey, EncryptionContext,
    EncryptionMaterials, Esdk, MaterialsError, MaterialsErrorKind, PlaintextDataKey,
};

// ===== Mock Keyring =====

struct MockKeyring {
    pdk_byte: u8,
    edk_provider_id: String,
    encrypt_calls: AtomicU32,
    decrypt_calls: AtomicU32,
}

impl MockKeyring {
    fn new() -> Self {
        Self {
            pdk_byte: 0xAA,
            edk_provider_id: "mock-keyring".to_string(),
            encrypt_calls: AtomicU32::new(0),
            decrypt_calls: AtomicU32::new(0),
        }
    }
}

#[async_trait]
impl Keyring for MockKeyring {
    async fn on_encrypt(
        &self,
        materials: EncryptionMaterials,
    ) -> Result<EncryptionMaterials, MaterialsError> {
        self.encrypt_calls.fetch_add(1, Ordering::SeqCst);
        let suite = materials.algorithm_suite();
        let pdk_bytes = vec![self.pdk_byte; suite.encryption_key_length()];
        let edk = EncryptedDataKey::new(
            self.edk_provider_id.clone(),
            b"mock-info".to_vec(),
            pdk_bytes.clone(),
        );
        EncryptionMaterials::new(
            materials.algorithm_suite_id(),
            vec![edk],
            materials.encryption_context().clone(),
            materials.required_encryption_context_keys().clone(),
            Some(PlaintextDataKey::new(pdk_bytes)),
            materials.signing_key().cloned(),
            None,
        )
    }

    async fn on_decrypt(
        &self,
        materials: DecryptionMaterials,
        _encrypted_data_keys: &[EncryptedDataKey],
    ) -> Result<DecryptionMaterials, MaterialsError> {
        self.decrypt_calls.fetch_add(1, Ordering::SeqCst);
        let suite = materials.algorithm_suite();
        let pdk_bytes = vec![self.pdk_byte; suite.encryption_key_length()];
        DecryptionMaterials::new(
            materials.algorithm_suite_id(),
            materials.encryption_context().clone(),
            materials.required_encryption_context_keys().clone(),
            Some(PlaintextDataKey::new(pdk_bytes)),
            materials.verification_key().cloned(),
            None,
        )
    }
}

// ===== Helpers =====

fn non_signing_suite() -> AlgorithmSuiteId {
    AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey
}

fn signing_suite() -> AlgorithmSuiteId {
    AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384
}

fn p256_signing_suite() -> AlgorithmSuiteId {
    AlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256
}

fn forbid_policy() -> CommitmentPolicy {
    CommitmentPolicy::Esdk(Esdk::ForbidEncryptAllowDecrypt)
}

fn allow_policy() -> CommitmentPolicy {
    CommitmentPolicy::Esdk(Esdk::RequireEncryptAllowDecrypt)
}

// ===== Tests =====

#[tokio::test]
async fn test_default_cmm_init_takes_only_keyring() {
    let keyring: Arc<dyn Keyring> = Arc::new(MockKeyring::new());
    let cmm = DefaultCmm::new(keyring);
    let request = EncryptionMaterialsRequest::new(EncryptionContext::new(), allow_policy());
    assert!(cmm.get_encryption_materials(request).await.is_ok());
}

#[tokio::test]
async fn test_get_encryption_materials_does_not_mutate_callers_ec() {
    let keyring: Arc<dyn Keyring> = Arc::new(MockKeyring::new());
    let cmm = DefaultCmm::new(keyring);
    let mut caller_ec = EncryptionContext::new();
    caller_ec.insert(b"user-key".to_vec(), b"user-value".to_vec());
    let request = EncryptionMaterialsRequest::new(caller_ec, allow_policy())
        .with_algorithm_suite_id(signing_suite());
    let materials = cmm.get_encryption_materials(request).await.unwrap();
    let returned_ec = materials.encryption_context();
    assert_eq!(
        returned_ec.get(b"user-key").map(Vec::as_slice),
        Some(b"user-value".as_slice()),
        "caller's original EC entry must remain unchanged in the materials' EC"
    );
    assert!(
        returned_ec.contains_key(b"aws-crypto-public-key"),
        "CMM must add the aws-crypto-public-key entry to the (copied) EC"
    );
}

#[tokio::test]
async fn test_get_encryption_materials_fails_when_ec_already_has_aws_crypto_public_key() {
    let keyring = Arc::new(MockKeyring::new());
    let cmm = DefaultCmm::new(keyring.clone() as Arc<dyn Keyring>);
    let mut ec = EncryptionContext::new();
    ec.insert(b"aws-crypto-public-key".to_vec(), b"existing".to_vec());
    let request = EncryptionMaterialsRequest::new(ec, allow_policy());
    let err = cmm
        .get_encryption_materials(request)
        .await
        .expect_err("must fail");
    assert_eq!(err.kind, MaterialsErrorKind::Validation);
    assert_eq!(keyring.encrypt_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn test_get_encryption_materials_no_suite_uses_commitment_policy_default() {
    let keyring: Arc<dyn Keyring> = Arc::new(MockKeyring::new());
    let cmm = DefaultCmm::new(keyring);
    let request = EncryptionMaterialsRequest::new(EncryptionContext::new(), allow_policy());
    let materials = cmm.get_encryption_materials(request).await.unwrap();
    assert_eq!(
        materials.algorithm_suite_id(),
        allow_policy().default_algorithm_suite_id()
    );
}

#[tokio::test]
async fn test_get_encryption_materials_unsupported_suite_for_policy_fails() {
    let keyring: Arc<dyn Keyring> = Arc::new(MockKeyring::new());
    let cmm = DefaultCmm::new(keyring);
    // ForbidEncryptAllowDecrypt only allows non-committing suites for encrypt
    let request = EncryptionMaterialsRequest::new(
        EncryptionContext::new(),
        CommitmentPolicy::Esdk(Esdk::ForbidEncryptAllowDecrypt),
    )
    .with_algorithm_suite_id(AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey);
    let err = cmm
        .get_encryption_materials(request)
        .await
        .expect_err("must fail");
    assert_eq!(err.kind, MaterialsErrorKind::Validation);
}

#[tokio::test]
async fn test_get_encryption_materials_returns_same_suite_when_request_specifies_one() {
    let keyring: Arc<dyn Keyring> = Arc::new(MockKeyring::new());
    let cmm = DefaultCmm::new(keyring);
    let suite = non_signing_suite();
    let request = EncryptionMaterialsRequest::new(EncryptionContext::new(), allow_policy())
        .with_algorithm_suite_id(suite);
    let materials = cmm.get_encryption_materials(request).await.unwrap();
    assert_eq!(materials.algorithm_suite_id(), suite);
}

#[tokio::test]
async fn test_get_encryption_materials_signing_suite_attaches_generated_signing_key() {
    let keyring: Arc<dyn Keyring> = Arc::new(MockKeyring::new());
    let cmm = DefaultCmm::new(keyring);
    let request = EncryptionMaterialsRequest::new(EncryptionContext::new(), allow_policy())
        .with_algorithm_suite_id(signing_suite());
    let materials = cmm.get_encryption_materials(request).await.unwrap();
    let sk = materials
        .signing_key()
        .expect("signing key must be present");
    assert_eq!(sk.len(), 48);
}

#[tokio::test]
async fn test_get_encryption_materials_signing_suite_inserts_aws_crypto_public_key_in_ec() {
    let keyring: Arc<dyn Keyring> = Arc::new(MockKeyring::new());
    let cmm = DefaultCmm::new(keyring);
    let request = EncryptionMaterialsRequest::new(EncryptionContext::new(), allow_policy())
        .with_algorithm_suite_id(signing_suite());
    let materials = cmm.get_encryption_materials(request).await.unwrap();
    let ec = materials.encryption_context();
    let vk_b64 = ec
        .get(b"aws-crypto-public-key")
        .expect("must have aws-crypto-public-key");
    let vk_bytes = BASE64_STANDARD.decode(vk_b64).unwrap();
    assert_eq!(vk_bytes.len(), 49); // P-384 compressed point
}

#[tokio::test]
async fn test_get_encryption_materials_calls_keyring_on_encrypt_once() {
    let keyring = Arc::new(MockKeyring::new());
    let cmm = DefaultCmm::new(keyring.clone() as Arc<dyn Keyring>);
    let request = EncryptionMaterialsRequest::new(EncryptionContext::new(), allow_policy())
        .with_algorithm_suite_id(non_signing_suite());
    cmm.get_encryption_materials(request).await.unwrap();
    assert_eq!(keyring.encrypt_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_get_encryption_materials_returns_pdk_set_by_keyring() {
    let keyring: Arc<dyn Keyring> = Arc::new(MockKeyring::new());
    let cmm = DefaultCmm::new(keyring);
    let request = EncryptionMaterialsRequest::new(EncryptionContext::new(), allow_policy())
        .with_algorithm_suite_id(non_signing_suite());
    let materials = cmm.get_encryption_materials(request).await.unwrap();
    // Mock keyring sets sentinel 0xAA PDK; assertion proves CMM passed it through unchanged.
    let pdk = materials.plaintext_data_key().expect("PDK must be present");
    assert_eq!(pdk.as_bytes(), vec![0xAA; 32]);
}

#[tokio::test]
async fn test_get_encryption_materials_returns_edks_set_by_keyring() {
    let keyring: Arc<dyn Keyring> = Arc::new(MockKeyring::new());
    let cmm = DefaultCmm::new(keyring);
    let request = EncryptionMaterialsRequest::new(EncryptionContext::new(), allow_policy())
        .with_algorithm_suite_id(non_signing_suite());
    let materials = cmm.get_encryption_materials(request).await.unwrap();
    // Mock keyring injects EDK with known provider ID; assertion proves CMM passed it through unchanged.
    assert_eq!(materials.encrypted_data_keys().len(), 1);
    assert_eq!(
        materials.encrypted_data_keys()[0].key_provider_id,
        "mock-keyring"
    );
}

#[tokio::test]
async fn test_decrypt_materials_signing_suite_extracts_verification_key() {
    let keyring: Arc<dyn Keyring> = Arc::new(MockKeyring::new());
    let cmm = DefaultCmm::new(keyring);
    let vk_raw = vec![0x02; 49]; // 49 bytes for P-384 SEC1-compressed
    let vk_b64 = BASE64_STANDARD.encode(&vk_raw);
    let mut ec = EncryptionContext::new();
    ec.insert(b"aws-crypto-public-key".to_vec(), vk_b64.into_bytes());
    let request = DecryptMaterialsRequest::new(signing_suite(), allow_policy(), vec![], ec);
    let materials = cmm.decrypt_materials(request).await.unwrap();
    let vk = materials
        .verification_key()
        .expect("verification key must be present");
    assert_eq!(vk.as_bytes(), &vk_raw);
}

#[tokio::test]
async fn test_decrypt_materials_signing_suite_missing_public_key_fails() {
    let keyring: Arc<dyn Keyring> = Arc::new(MockKeyring::new());
    let cmm = DefaultCmm::new(keyring);
    let request = DecryptMaterialsRequest::new(
        signing_suite(),
        allow_policy(),
        vec![],
        EncryptionContext::new(),
    );
    let err = cmm.decrypt_materials(request).await.expect_err("must fail");
    assert_eq!(err.kind, MaterialsErrorKind::AwsCryptoPublicKeyMissing);
}

#[tokio::test]
async fn test_decrypt_materials_non_signing_suite_with_public_key_fails() {
    let keyring: Arc<dyn Keyring> = Arc::new(MockKeyring::new());
    let cmm = DefaultCmm::new(keyring);
    let mut ec = EncryptionContext::new();
    ec.insert(b"aws-crypto-public-key".to_vec(), b"some-value".to_vec());
    let request = DecryptMaterialsRequest::new(non_signing_suite(), allow_policy(), vec![], ec);
    let err = cmm.decrypt_materials(request).await.expect_err("must fail");
    assert_eq!(err.kind, MaterialsErrorKind::AwsCryptoPublicKeyUnexpected);
}

#[tokio::test]
async fn test_decrypt_materials_unsupported_suite_for_policy_fails() {
    let keyring: Arc<dyn Keyring> = Arc::new(MockKeyring::new());
    let cmm = DefaultCmm::new(keyring);
    // RequireEncryptRequireDecrypt only allows committing suites
    let request = DecryptMaterialsRequest::new(
        AlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf,
        CommitmentPolicy::Esdk(Esdk::RequireEncryptRequireDecrypt),
        vec![],
        EncryptionContext::new(),
    );
    let err = cmm.decrypt_materials(request).await.expect_err("must fail");
    assert_eq!(err.kind, MaterialsErrorKind::Validation);
}

#[tokio::test]
async fn test_decrypt_materials_calls_keyring_on_decrypt_once() {
    let keyring = Arc::new(MockKeyring::new());
    let cmm = DefaultCmm::new(keyring.clone() as Arc<dyn Keyring>);
    let request = DecryptMaterialsRequest::new(
        non_signing_suite(),
        allow_policy(),
        vec![],
        EncryptionContext::new(),
    );
    cmm.decrypt_materials(request).await.unwrap();
    assert_eq!(keyring.decrypt_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_decrypt_materials_returns_pdk_set_by_keyring() {
    let keyring: Arc<dyn Keyring> = Arc::new(MockKeyring::new());
    let cmm = DefaultCmm::new(keyring);
    let request = DecryptMaterialsRequest::new(
        non_signing_suite(),
        allow_policy(),
        vec![],
        EncryptionContext::new(),
    );
    let materials = cmm.decrypt_materials(request).await.unwrap();
    // Mock keyring sets sentinel 0xAA PDK; assertion proves CMM passed it through unchanged.
    let pdk = materials.plaintext_data_key().expect("PDK must be present");
    assert_eq!(pdk.as_bytes(), vec![0xAA; 32]);
}

#[tokio::test]
async fn test_get_encryption_materials_p256_signing_suite_generates_signing_key() {
    let keyring: Arc<dyn Keyring> = Arc::new(MockKeyring::new());
    let cmm = DefaultCmm::new(keyring);
    let request = EncryptionMaterialsRequest::new(EncryptionContext::new(), forbid_policy())
        .with_algorithm_suite_id(p256_signing_suite());
    let materials = cmm.get_encryption_materials(request).await.unwrap();
    let sk = materials
        .signing_key()
        .expect("signing key must be present for P-256 suite");
    assert_eq!(sk.len(), 32, "P-256 signing key must be 32 bytes");
    let ec = materials.encryption_context();
    let vk_b64 = ec
        .get(b"aws-crypto-public-key")
        .expect("must have aws-crypto-public-key");
    let vk_bytes = BASE64_STANDARD.decode(vk_b64).unwrap();
    assert_eq!(
        vk_bytes.len(),
        33,
        "P-256 compressed point must be 33 bytes"
    );
}

#[tokio::test]
async fn test_decrypt_materials_malformed_base64_public_key_fails() {
    let keyring: Arc<dyn Keyring> = Arc::new(MockKeyring::new());
    let cmm = DefaultCmm::new(keyring);
    let mut ec = EncryptionContext::new();
    ec.insert(
        b"aws-crypto-public-key".to_vec(),
        b"not-valid-base64!!!".to_vec(),
    );
    let request = DecryptMaterialsRequest::new(signing_suite(), allow_policy(), vec![], ec);
    let err = cmm
        .decrypt_materials(request)
        .await
        .expect_err("must fail on malformed base64");
    assert_eq!(err.kind, MaterialsErrorKind::Validation);
}

#[tokio::test]
async fn test_decrypt_materials_wrong_verification_key_length_fails() {
    let keyring: Arc<dyn Keyring> = Arc::new(MockKeyring::new());
    let cmm = DefaultCmm::new(keyring);
    // P-384 signing suite expects 49-byte verification key; provide a valid base64
    // that decodes to 10 bytes — wrong length.
    let wrong_length_bytes = vec![0x02; 10];
    let vk_b64 = BASE64_STANDARD.encode(&wrong_length_bytes);
    let mut ec = EncryptionContext::new();
    ec.insert(b"aws-crypto-public-key".to_vec(), vk_b64.into_bytes());
    let request = DecryptMaterialsRequest::new(signing_suite(), allow_policy(), vec![], ec);
    let err = cmm
        .decrypt_materials(request)
        .await
        .expect_err("must fail on wrong VK length");
    assert_eq!(err.kind, MaterialsErrorKind::Validation);
}

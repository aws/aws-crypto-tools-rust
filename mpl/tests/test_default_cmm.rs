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
use aws_mpl_primitives::{EcdsaSignatureAlgorithm, ecdsa_sign, ecdsa_verify, signature_len};

// Assert the CMM's signing key composes with the signer, and that the
// verification key it publishes in the encryption context verifies the result.
//
// `ecdsa_sign` accepts the private key DER-encoded and `ecdsa_verify` accepts
// the public key as an X9.62 compressed point — the two forms
// `ecdsa_generate_keypair` emits. Signing and then verifying checks the CMM
// stored each key in the form its consumer requires.
fn assert_signing_key_composes(alg: EcdsaSignatureAlgorithm, sk: &[u8], vk_compressed: &[u8]) {
    // Checked separately from signing because `ecdsa_sign` reports a non-DER key
    // as an opaque aws-lc-rs error; the SEQUENCE tag attributes the failure to
    // the key's format rather than to the signing operation.
    assert_eq!(sk[0], 0x30, "signing key must be a DER SEQUENCE");
    let mut sig = vec![0u8; signature_len(alg)];
    ecdsa_sign(alg, sk, b"message", &mut sig)
        .expect("CMM signing key must be usable by the signer");
    assert!(
        ecdsa_verify(alg, vk_compressed, b"message", &sig).expect("verify must not error"),
        "the published verification key must verify a signature made with the signing key"
    );
}

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
    let vk_b64 = materials
        .encryption_context()
        .get(b"aws-crypto-public-key")
        .expect("must have aws-crypto-public-key")
        .clone();
    let vk = BASE64_STANDARD.decode(&vk_b64).unwrap();
    assert_signing_key_composes(EcdsaSignatureAlgorithm::EcdsaP384, sk.as_bytes(), &vk);
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
    assert_signing_key_composes(EcdsaSignatureAlgorithm::EcdsaP256, sk.as_bytes(), &vk_bytes);
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

// ===== Reproduced Encryption Context =====
//
// The mock keyring copies the encryption context and required encryption
// context keys it receives onto its output materials, so asserting on the
// returned materials asserts on exactly what the keyring was handed. That
// matters because the keyring uses the encryption context as AES-GCM AAD.

fn ec_of(pairs: &[(&str, &str)]) -> EncryptionContext {
    let mut ec = EncryptionContext::new();
    for (k, v) in pairs {
        ec.insert(k.as_bytes().to_vec(), v.as_bytes().to_vec());
    }
    ec
}

fn ec_pairs(ec: &EncryptionContext) -> Vec<(String, String)> {
    ec.iter()
        .map(|(k, v)| {
            (
                String::from_utf8(k.clone()).expect("test EC keys are UTF-8"),
                String::from_utf8(v.clone()).expect("test EC values are UTF-8"),
            )
        })
        .collect()
}

fn reck_keys(materials: &DecryptionMaterials) -> Vec<String> {
    materials
        .required_encryption_context_keys()
        .iter()
        .map(|k| String::from_utf8(k.clone()).expect("test RECK are UTF-8"))
        .collect()
}

#[tokio::test]
async fn test_decrypt_materials_appends_reproduced_only_pairs_to_the_keyring_context() {
    // An encrypting CMM held "a" back from the message, so the keyring must be
    // handed {a, b} — not the message's {b} — or its AAD is short and
    // authentication fails.
    let keyring: Arc<dyn Keyring> = Arc::new(MockKeyring::new());
    let cmm = DefaultCmm::new(keyring);
    let request = DecryptMaterialsRequest::new(
        non_signing_suite(),
        allow_policy(),
        vec![],
        ec_of(&[("b", "b")]),
    )
    .with_reproduced_encryption_context(ec_of(&[("a", "a"), ("b", "b")]));

    let materials = cmm.decrypt_materials(request).await.expect("must succeed");

    assert_eq!(
        ec_pairs(materials.encryption_context()),
        vec![
            ("a".to_string(), "a".to_string()),
            ("b".to_string(), "b".to_string())
        ],
        "the keyring must receive the message context plus the reproduced-only pairs"
    );
    assert_eq!(
        reck_keys(&materials),
        vec!["a".to_string()],
        "keys appended from the reproduced context become required encryption context keys"
    );
}

#[tokio::test]
async fn test_decrypt_materials_appends_when_reproduced_context_is_disjoint() {
    // The reproduced context need not be a superset of the message's; it only
    // has to supply the keys the message lacks.
    let keyring: Arc<dyn Keyring> = Arc::new(MockKeyring::new());
    let cmm = DefaultCmm::new(keyring);
    let request = DecryptMaterialsRequest::new(
        non_signing_suite(),
        allow_policy(),
        vec![],
        ec_of(&[("a", "a")]),
    )
    .with_reproduced_encryption_context(ec_of(&[("b", "b")]));

    let materials = cmm.decrypt_materials(request).await.expect("must succeed");

    assert_eq!(
        ec_pairs(materials.encryption_context()),
        vec![
            ("a".to_string(), "a".to_string()),
            ("b".to_string(), "b".to_string())
        ]
    );
    assert_eq!(reck_keys(&materials), vec!["b".to_string()]);
}

#[tokio::test]
async fn test_decrypt_materials_appends_every_pair_when_message_context_is_empty() {
    let keyring: Arc<dyn Keyring> = Arc::new(MockKeyring::new());
    let cmm = DefaultCmm::new(keyring);
    let request = DecryptMaterialsRequest::new(
        non_signing_suite(),
        allow_policy(),
        vec![],
        EncryptionContext::new(),
    )
    .with_reproduced_encryption_context(ec_of(&[("a", "a"), ("b", "b")]));

    let materials = cmm.decrypt_materials(request).await.expect("must succeed");

    assert_eq!(
        ec_pairs(materials.encryption_context()),
        vec![
            ("a".to_string(), "a".to_string()),
            ("b".to_string(), "b".to_string())
        ]
    );
    assert_eq!(
        reck_keys(&materials),
        vec!["a".to_string(), "b".to_string()]
    );
}

#[tokio::test]
async fn test_decrypt_materials_reproduced_context_matching_message_adds_no_required_keys() {
    // Every reproduced key already exists in the message with the same value,
    // so nothing is appended and no key is required.
    let keyring: Arc<dyn Keyring> = Arc::new(MockKeyring::new());
    let cmm = DefaultCmm::new(keyring);
    let request = DecryptMaterialsRequest::new(
        non_signing_suite(),
        allow_policy(),
        vec![],
        ec_of(&[("a", "a"), ("b", "b")]),
    )
    .with_reproduced_encryption_context(ec_of(&[("a", "a")]));

    let materials = cmm.decrypt_materials(request).await.expect("must succeed");

    assert_eq!(
        ec_pairs(materials.encryption_context()),
        vec![
            ("a".to_string(), "a".to_string()),
            ("b".to_string(), "b".to_string())
        ]
    );
    assert!(
        reck_keys(&materials).is_empty(),
        "a reproduced key already present in the message is not a required key"
    );
}

#[tokio::test]
async fn test_decrypt_materials_conflicting_reproduced_value_fails() {
    let keyring: Arc<dyn Keyring> = Arc::new(MockKeyring::new());
    let cmm = DefaultCmm::new(keyring);
    let request = DecryptMaterialsRequest::new(
        non_signing_suite(),
        allow_policy(),
        vec![],
        ec_of(&[("a", "a")]),
    )
    .with_reproduced_encryption_context(ec_of(&[("a", "different")]));

    let err = cmm
        .decrypt_materials(request)
        .await
        .expect_err("a disagreeing shared key must fail");

    assert_eq!(err.kind, MaterialsErrorKind::EncryptionContextValueMismatch);
    assert!(
        err.message.contains("'a'"),
        "the error must name the disagreeing key: {}",
        err.message
    );
}

#[tokio::test]
async fn test_decrypt_materials_conflicting_reproduced_value_does_not_call_the_keyring() {
    let keyring = Arc::new(MockKeyring::new());
    let cmm = DefaultCmm::new(keyring.clone() as Arc<dyn Keyring>);
    let request = DecryptMaterialsRequest::new(
        non_signing_suite(),
        allow_policy(),
        vec![],
        ec_of(&[("a", "a")]),
    )
    .with_reproduced_encryption_context(ec_of(&[("a", "different")]));

    cmm.decrypt_materials(request)
        .await
        .expect_err("must fail before doing any crypto");

    assert_eq!(
        keyring.decrypt_calls.load(Ordering::SeqCst),
        0,
        "validation must reject the request before the keyring is invoked"
    );
}

#[tokio::test]
async fn test_decrypt_materials_without_reproduced_context_is_unchanged() {
    // Regression guard: omitting the reproduced context must leave the message
    // context untouched and produce no required keys.
    let keyring: Arc<dyn Keyring> = Arc::new(MockKeyring::new());
    let cmm = DefaultCmm::new(keyring);
    let request = DecryptMaterialsRequest::new(
        non_signing_suite(),
        allow_policy(),
        vec![],
        ec_of(&[("a", "a")]),
    );

    let materials = cmm.decrypt_materials(request).await.expect("must succeed");

    assert_eq!(
        ec_pairs(materials.encryption_context()),
        vec![("a".to_string(), "a".to_string())]
    );
    assert!(reck_keys(&materials).is_empty());
}

#[tokio::test]
async fn test_decrypt_materials_signing_suite_public_key_from_reproduced_context() {
    // The reserved verification key may arrive only via the reproduced context;
    // the CMM must look it up after merging, not before.
    let keyring: Arc<dyn Keyring> = Arc::new(MockKeyring::new());
    let cmm = DefaultCmm::new(keyring);
    let vk = vec![0x02; 49];
    let mut reproduced = EncryptionContext::new();
    reproduced.insert(
        b"aws-crypto-public-key".to_vec(),
        BASE64_STANDARD.encode(&vk).into_bytes(),
    );
    let request = DecryptMaterialsRequest::new(
        signing_suite(),
        allow_policy(),
        vec![],
        EncryptionContext::new(),
    )
    .with_reproduced_encryption_context(reproduced);

    let materials = cmm.decrypt_materials(request).await.expect("must succeed");

    assert_eq!(
        materials
            .verification_key()
            .expect("verification key must be extracted from the merged context")
            .as_bytes(),
        &vk,
    );
}

#[tokio::test]
async fn test_decrypt_materials_non_signing_suite_rejects_public_key_from_reproduced_context() {
    // The reserved-key rejection must also see the merged context, so it
    // cannot be smuggled past via the reproduced context.
    let keyring: Arc<dyn Keyring> = Arc::new(MockKeyring::new());
    let cmm = DefaultCmm::new(keyring);
    let mut reproduced = EncryptionContext::new();
    reproduced.insert(b"aws-crypto-public-key".to_vec(), b"some-value".to_vec());
    let request = DecryptMaterialsRequest::new(
        non_signing_suite(),
        allow_policy(),
        vec![],
        EncryptionContext::new(),
    )
    .with_reproduced_encryption_context(reproduced);

    let err = cmm
        .decrypt_materials(request)
        .await
        .expect_err("must reject the reserved key regardless of which context carried it");

    assert_eq!(err.kind, MaterialsErrorKind::AwsCryptoPublicKeyUnexpected);
}

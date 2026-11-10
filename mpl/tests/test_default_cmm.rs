// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for the Default CMM.

use aws_crypto_mpl::Error;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use aws_crypto_mpl::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;

use aws_crypto_mpl::cmm::{DefaultCmm, SharedCmm};
use aws_crypto_mpl::keyring::{
    Keyring, OnDecryptInput, OnDecryptOutput, OnEncryptInput, OnEncryptOutput,
};
use aws_crypto_mpl::types::{
    AlgorithmSuiteId, CommitmentPolicy, DecryptionMaterials, EncryptedDataKey, EncryptionContext,
    EsdkAlgorithmSuiteId, EsdkCommitmentPolicy, PlaintextDataKey,
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

#[derive(Clone)]
struct MockKeyring {
    pdk_byte: u8,
    edk_provider_id: String,
    encrypt_calls: Arc<AtomicU32>,
    decrypt_calls: Arc<AtomicU32>,
}

impl MockKeyring {
    fn new() -> Self {
        Self {
            pdk_byte: 0xAA,
            edk_provider_id: "mock-keyring".to_string(),
            encrypt_calls: Arc::new(AtomicU32::new(0)),
            decrypt_calls: Arc::new(AtomicU32::new(0)),
        }
    }
}

#[async_trait]
impl Keyring for MockKeyring {
    async fn on_encrypt(&self, input: OnEncryptInput) -> Result<OnEncryptOutput, Error> {
        let materials = input.into_materials();
        self.encrypt_calls.fetch_add(1, Ordering::SeqCst);
        let suite = materials.algorithm_suite();
        let pdk_bytes = vec![self.pdk_byte; suite.encryption_key_length()];
        let edk = EncryptedDataKey::builder()
            .key_provider_id(self.edk_provider_id.clone())
            .key_provider_info(b"mock-info")
            .ciphertext(pdk_bytes.clone())
            .build()
            .unwrap();
        Ok(materials
            .add_data_key(PlaintextDataKey::new(pdk_bytes), edk)?
            .into())
    }

    async fn on_decrypt(&self, input: OnDecryptInput) -> Result<OnDecryptOutput, Error> {
        let materials = input.into_materials();
        self.decrypt_calls.fetch_add(1, Ordering::SeqCst);
        let suite = materials.algorithm_suite();
        let pdk_bytes = vec![self.pdk_byte; suite.encryption_key_length()];
        Ok(materials
            .add_data_key(PlaintextDataKey::new(pdk_bytes))?
            .into())
    }
}

// ===== Helpers =====

fn non_signing_suite() -> AlgorithmSuiteId {
    AlgorithmSuiteId::Esdk(EsdkAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey)
}

fn signing_suite() -> AlgorithmSuiteId {
    AlgorithmSuiteId::Esdk(EsdkAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384)
}

fn p256_signing_suite() -> AlgorithmSuiteId {
    AlgorithmSuiteId::Esdk(EsdkAlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256)
}

fn forbid_policy() -> CommitmentPolicy {
    CommitmentPolicy::Esdk(EsdkCommitmentPolicy::ForbidEncryptAllowDecrypt)
}

fn allow_policy() -> CommitmentPolicy {
    CommitmentPolicy::Esdk(EsdkCommitmentPolicy::RequireEncryptAllowDecrypt)
}

// ===== Tests =====

#[tokio::test]
async fn test_default_cmm_init_takes_only_keyring() {
    let keyring = MockKeyring::new();
    let cmm = SharedCmm::new(DefaultCmm::new(keyring));
    let request = cmm
        .get_encryption_materials()
        .set_encryption_context(Some(EncryptionContext::new()))
        .commitment_policy(allow_policy());
    assert!(request.send().await.is_ok());
}

#[tokio::test]
async fn test_get_encryption_materials_does_not_mutate_callers_ec() {
    let keyring = MockKeyring::new();
    let cmm = SharedCmm::new(DefaultCmm::new(keyring));
    let mut caller_ec = EncryptionContext::new();
    caller_ec.insert("user-key", "user-value");
    let request = cmm
        .get_encryption_materials()
        .set_encryption_context(Some(caller_ec))
        .commitment_policy(allow_policy())
        .algorithm_suite_id(signing_suite());
    let materials = request.send().await.unwrap().into_encryption_materials();
    let returned_ec = materials.encryption_context();
    assert_eq!(
        returned_ec.get("user-key"),
        Some("user-value"),
        "caller's original EC entry must remain unchanged in the materials' EC"
    );
    assert!(
        returned_ec.contains_key("aws-crypto-public-key"),
        "CMM must add the aws-crypto-public-key entry to the (copied) EC"
    );
}

#[tokio::test]
async fn test_get_encryption_materials_fails_when_ec_already_has_aws_crypto_public_key() {
    let keyring = MockKeyring::new();
    let cmm = SharedCmm::new(DefaultCmm::new(keyring.clone()));
    let mut ec = EncryptionContext::new();
    ec.insert("aws-crypto-public-key", "existing");
    let request = cmm
        .get_encryption_materials()
        .set_encryption_context(Some(ec))
        .commitment_policy(allow_policy());
    let err = request.send().await.expect_err("must fail");
    assert!(err.is_validation(), "{:?}", err);
    assert_eq!(keyring.encrypt_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn test_get_encryption_materials_no_suite_uses_commitment_policy_default() {
    let keyring = MockKeyring::new();
    let cmm = SharedCmm::new(DefaultCmm::new(keyring));
    let request = cmm
        .get_encryption_materials()
        .set_encryption_context(Some(EncryptionContext::new()))
        .commitment_policy(allow_policy());
    let materials = request.send().await.unwrap().into_encryption_materials();
    assert_eq!(
        materials.algorithm_suite_id(),
        allow_policy().default_algorithm_suite_id()
    );
}

#[tokio::test]
async fn test_get_encryption_materials_forbid_no_suite_defaults_to_hkdf_sha384_ecdsa_p384() {
    let keyring = MockKeyring::new();
    let cmm = SharedCmm::new(DefaultCmm::new(keyring));
    let request = cmm
        .get_encryption_materials()
        .set_encryption_context(Some(EncryptionContext::new()))
        .commitment_policy(forbid_policy());
    let materials = request.send().await.unwrap().into_encryption_materials();
    assert_eq!(
        materials.algorithm_suite_id(),
        AlgorithmSuiteId::Esdk(EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384)
    );
    // A signing suite: the CMM generates a signing key and publishes the
    // verification key in the encryption context.
    assert!(materials.signing_key().is_some());
    assert!(
        materials
            .encryption_context()
            .get("aws-crypto-public-key")
            .is_some()
    );
}

#[tokio::test]
async fn test_get_encryption_materials_unsupported_suite_for_policy_fails() {
    let keyring = MockKeyring::new();
    let cmm = SharedCmm::new(DefaultCmm::new(keyring));
    // ForbidEncryptAllowDecrypt only allows non-committing suites for encrypt
    let request = cmm
        .get_encryption_materials()
        .set_encryption_context(Some(EncryptionContext::new()))
        .commitment_policy(CommitmentPolicy::Esdk(
            EsdkCommitmentPolicy::ForbidEncryptAllowDecrypt,
        ))
        .algorithm_suite_id(AlgorithmSuiteId::Esdk(
            EsdkAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey,
        ));
    let err = request.send().await.expect_err("must fail");
    assert!(err.is_validation(), "{:?}", err);
}

#[tokio::test]
async fn test_get_encryption_materials_returns_same_suite_when_request_specifies_one() {
    let keyring = MockKeyring::new();
    let cmm = SharedCmm::new(DefaultCmm::new(keyring));
    let suite = non_signing_suite();
    let request = cmm
        .get_encryption_materials()
        .set_encryption_context(Some(EncryptionContext::new()))
        .commitment_policy(allow_policy())
        .algorithm_suite_id(suite);
    let materials = request.send().await.unwrap().into_encryption_materials();
    assert_eq!(materials.algorithm_suite_id(), suite);
}

#[tokio::test]
async fn test_get_encryption_materials_signing_suite_attaches_generated_signing_key() {
    let keyring = MockKeyring::new();
    let cmm = SharedCmm::new(DefaultCmm::new(keyring));
    let request = cmm
        .get_encryption_materials()
        .set_encryption_context(Some(EncryptionContext::new()))
        .commitment_policy(allow_policy())
        .algorithm_suite_id(signing_suite());
    let materials = request.send().await.unwrap().into_encryption_materials();
    let sk = materials
        .signing_key()
        .expect("signing key must be present");
    let vk_b64 = materials
        .encryption_context()
        .get("aws-crypto-public-key")
        .expect("must have aws-crypto-public-key");
    let vk = BASE64_STANDARD.decode(vk_b64).unwrap();
    assert_signing_key_composes(EcdsaSignatureAlgorithm::EcdsaP384, sk.as_bytes(), &vk);
}

#[tokio::test]
async fn test_get_encryption_materials_signing_suite_inserts_aws_crypto_public_key_in_ec() {
    let keyring = MockKeyring::new();
    let cmm = SharedCmm::new(DefaultCmm::new(keyring));
    let request = cmm
        .get_encryption_materials()
        .set_encryption_context(Some(EncryptionContext::new()))
        .commitment_policy(allow_policy())
        .algorithm_suite_id(signing_suite());
    let materials = request.send().await.unwrap().into_encryption_materials();
    let ec = materials.encryption_context();
    let vk_b64 = ec
        .get("aws-crypto-public-key")
        .expect("must have aws-crypto-public-key");
    let vk_bytes = BASE64_STANDARD.decode(vk_b64).unwrap();
    assert_eq!(vk_bytes.len(), 49); // P-384 compressed point
}

#[tokio::test]
async fn test_get_encryption_materials_calls_keyring_on_encrypt_once() {
    let keyring = MockKeyring::new();
    let cmm = SharedCmm::new(DefaultCmm::new(keyring.clone()));
    let request = cmm
        .get_encryption_materials()
        .set_encryption_context(Some(EncryptionContext::new()))
        .commitment_policy(allow_policy())
        .algorithm_suite_id(non_signing_suite());
    request.send().await.unwrap();
    assert_eq!(keyring.encrypt_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_get_encryption_materials_returns_pdk_set_by_keyring() {
    let keyring = MockKeyring::new();
    let cmm = SharedCmm::new(DefaultCmm::new(keyring));
    let request = cmm
        .get_encryption_materials()
        .set_encryption_context(Some(EncryptionContext::new()))
        .commitment_policy(allow_policy())
        .algorithm_suite_id(non_signing_suite());
    let materials = request.send().await.unwrap().into_encryption_materials();
    // Mock keyring sets sentinel 0xAA PDK; assertion proves CMM passed it through unchanged.
    let pdk = materials.plaintext_data_key().expect("PDK must be present");
    assert_eq!(pdk.as_bytes(), vec![0xAA; 32]);
}

#[tokio::test]
async fn test_get_encryption_materials_returns_edks_set_by_keyring() {
    let keyring = MockKeyring::new();
    let cmm = SharedCmm::new(DefaultCmm::new(keyring));
    let request = cmm
        .get_encryption_materials()
        .set_encryption_context(Some(EncryptionContext::new()))
        .commitment_policy(allow_policy())
        .algorithm_suite_id(non_signing_suite());
    let materials = request.send().await.unwrap().into_encryption_materials();
    // Mock keyring injects EDK with known provider ID; assertion proves CMM passed it through unchanged.
    assert_eq!(materials.encrypted_data_keys().len(), 1);
    assert_eq!(
        materials.encrypted_data_keys()[0].key_provider_id(),
        "mock-keyring"
    );
}

#[tokio::test]
async fn test_decrypt_materials_signing_suite_extracts_verification_key() {
    let keyring = MockKeyring::new();
    let cmm = SharedCmm::new(DefaultCmm::new(keyring));
    let vk_raw = {
        // Valid P-384 SEC1-compressed shape: 0x02 tag + 48-byte X coordinate.
        let mut v = vec![0u8; 49];
        v[0] = 0x02;
        v
    };
    let vk_b64 = BASE64_STANDARD.encode(&vk_raw);
    let mut ec = EncryptionContext::new();
    ec.insert("aws-crypto-public-key", vk_b64);
    let request = cmm
        .decrypt_materials()
        .algorithm_suite_id(signing_suite())
        .commitment_policy(allow_policy())
        .set_encrypted_data_keys(Some(vec![]))
        .set_encryption_context(Some(ec));
    let materials = request.send().await.unwrap().into_decryption_materials();
    let vk = materials
        .verification_key()
        .expect("verification key must be present");
    assert_eq!(vk.as_bytes(), &vk_raw);
}

#[tokio::test]
async fn test_decrypt_materials_signing_suite_missing_public_key_fails() {
    let keyring = MockKeyring::new();
    let cmm = SharedCmm::new(DefaultCmm::new(keyring));
    let request = cmm
        .decrypt_materials()
        .algorithm_suite_id(signing_suite())
        .commitment_policy(allow_policy())
        .set_encrypted_data_keys(Some(vec![]))
        .set_encryption_context(Some(EncryptionContext::new()));
    let err = request.send().await.expect_err("must fail");
    assert!(err.is_validation(), "{:?}", err);
}

#[tokio::test]
async fn test_decrypt_materials_non_signing_suite_with_public_key_fails() {
    let keyring = MockKeyring::new();
    let cmm = SharedCmm::new(DefaultCmm::new(keyring));
    let mut ec = EncryptionContext::new();
    ec.insert("aws-crypto-public-key", "some-value");
    let request = cmm
        .decrypt_materials()
        .algorithm_suite_id(non_signing_suite())
        .commitment_policy(allow_policy())
        .set_encrypted_data_keys(Some(vec![]))
        .set_encryption_context(Some(ec));
    let err = request.send().await.expect_err("must fail");
    assert!(err.is_validation(), "{:?}", err);
}

#[tokio::test]
async fn test_decrypt_materials_unsupported_suite_for_policy_fails() {
    let keyring = MockKeyring::new();
    let cmm = SharedCmm::new(DefaultCmm::new(keyring));
    // RequireEncryptRequireDecrypt only allows committing suites
    let request = cmm
        .decrypt_materials()
        .algorithm_suite_id(AlgorithmSuiteId::Esdk(
            EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf,
        ))
        .commitment_policy(CommitmentPolicy::Esdk(
            EsdkCommitmentPolicy::RequireEncryptRequireDecrypt,
        ))
        .set_encrypted_data_keys(Some(vec![]))
        .set_encryption_context(Some(EncryptionContext::new()));
    let err = request.send().await.expect_err("must fail");
    assert!(err.is_validation(), "{:?}", err);
}

#[tokio::test]
async fn test_decrypt_materials_calls_keyring_on_decrypt_once() {
    let keyring = MockKeyring::new();
    let cmm = SharedCmm::new(DefaultCmm::new(keyring.clone()));
    let request = cmm
        .decrypt_materials()
        .algorithm_suite_id(non_signing_suite())
        .commitment_policy(allow_policy())
        .set_encrypted_data_keys(Some(vec![]))
        .set_encryption_context(Some(EncryptionContext::new()));
    request.send().await.unwrap();
    assert_eq!(keyring.decrypt_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_decrypt_materials_returns_pdk_set_by_keyring() {
    let keyring = MockKeyring::new();
    let cmm = SharedCmm::new(DefaultCmm::new(keyring));
    let request = cmm
        .decrypt_materials()
        .algorithm_suite_id(non_signing_suite())
        .commitment_policy(allow_policy())
        .set_encrypted_data_keys(Some(vec![]))
        .set_encryption_context(Some(EncryptionContext::new()));
    let materials = request.send().await.unwrap().into_decryption_materials();
    // Mock keyring sets sentinel 0xAA PDK; assertion proves CMM passed it through unchanged.
    let pdk = materials.plaintext_data_key().expect("PDK must be present");
    assert_eq!(pdk.as_bytes(), vec![0xAA; 32]);
}

#[tokio::test]
async fn test_get_encryption_materials_p256_signing_suite_generates_signing_key() {
    let keyring = MockKeyring::new();
    let cmm = SharedCmm::new(DefaultCmm::new(keyring));
    let request = cmm
        .get_encryption_materials()
        .set_encryption_context(Some(EncryptionContext::new()))
        .commitment_policy(forbid_policy())
        .algorithm_suite_id(p256_signing_suite());
    let materials = request.send().await.unwrap().into_encryption_materials();
    let sk = materials
        .signing_key()
        .expect("signing key must be present for P-256 suite");
    let ec = materials.encryption_context();
    let vk_b64 = ec
        .get("aws-crypto-public-key")
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
    let keyring = MockKeyring::new();
    let cmm = SharedCmm::new(DefaultCmm::new(keyring));
    let mut ec = EncryptionContext::new();
    ec.insert("aws-crypto-public-key", "not-valid-base64!!!");
    let request = cmm
        .decrypt_materials()
        .algorithm_suite_id(signing_suite())
        .commitment_policy(allow_policy())
        .set_encrypted_data_keys(Some(vec![]))
        .set_encryption_context(Some(ec));
    let err = request
        .send()
        .await
        .expect_err("must fail on malformed base64");
    assert!(err.is_validation(), "{:?}", err);
}

#[tokio::test]
async fn test_decrypt_materials_wrong_verification_key_length_fails() {
    let keyring = MockKeyring::new();
    let cmm = SharedCmm::new(DefaultCmm::new(keyring));
    // P-384 signing suite expects a 49-byte SEC1-compressed verification key;
    // provide a valid base64 that decodes to 10 bytes — wrong length.
    let wrong_length_bytes = vec![0x04; 10];
    let vk_b64 = BASE64_STANDARD.encode(&wrong_length_bytes);
    let mut ec = EncryptionContext::new();
    ec.insert("aws-crypto-public-key", vk_b64);
    let request = cmm
        .decrypt_materials()
        .algorithm_suite_id(signing_suite())
        .commitment_policy(allow_policy())
        .set_encrypted_data_keys(Some(vec![]))
        .set_encryption_context(Some(ec));
    let err = request
        .send()
        .await
        .expect_err("must fail on wrong VK length");
    assert!(err.is_invalid_materials(), "{:?}", err);
}

#[tokio::test]
async fn test_decrypt_materials_reproduced_ec_matching_values_succeeds() {
    // cmm-interface.md#decrypt-materials: keys present in both the reproduced
    // EC and the message EC with equal values MUST NOT fail.
    // https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/cmm-interface.md#decrypt-materials
    let keyring = MockKeyring::new();
    let cmm = SharedCmm::new(DefaultCmm::new(keyring));
    let mut message_ec = EncryptionContext::new();
    message_ec.insert("shared", "same-value");
    message_ec.insert("message-only", "m");
    let mut reproduced_ec = EncryptionContext::new();
    reproduced_ec.insert("shared", "same-value");
    let request = cmm
        .decrypt_materials()
        .algorithm_suite_id(non_signing_suite())
        .commitment_policy(allow_policy())
        .set_encrypted_data_keys(Some(vec![]))
        .set_encryption_context(Some(message_ec))
        .set_reproduced_encryption_context(Some(reproduced_ec));
    let materials = request
        .send()
        .await
        .expect("matching values must succeed")
        .into_decryption_materials();
    assert!(materials.plaintext_data_key().is_some());
    assert_eq!(
        ec_pairs(materials.encryption_context()),
        vec![
            ("message-only".to_string(), "m".to_string()),
            ("shared".to_string(), "same-value".to_string()),
        ],
        "a reproduced key already present in the message adds nothing"
    );
    assert!(
        reck_keys(&materials).is_empty(),
        "no key was appended, so none is required"
    );
}

#[tokio::test]
async fn test_decrypt_materials_reproduced_ec_mismatched_values_fails() {
    // cmm-interface.md#decrypt-materials: "For every key that exists in both
    // Reproduced Encryption Context and Encryption Context, the values MUST
    // be equal or the operation MUST fail."
    // https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/cmm-interface.md#decrypt-materials
    let keyring = MockKeyring::new();
    let cmm = SharedCmm::new(DefaultCmm::new(keyring));
    let mut message_ec = EncryptionContext::new();
    message_ec.insert("shared", "message-value");
    let mut reproduced_ec = EncryptionContext::new();
    reproduced_ec.insert("shared", "reproduced-value");
    let request = cmm
        .decrypt_materials()
        .algorithm_suite_id(non_signing_suite())
        .commitment_policy(allow_policy())
        .set_encrypted_data_keys(Some(vec![]))
        .set_encryption_context(Some(message_ec))
        .set_reproduced_encryption_context(Some(reproduced_ec));
    let err = request
        .send()
        .await
        .expect_err("mismatched reproduced-EC value must fail");
    assert!(err.is_encryption_context_mismatch(), "{:?}", err);
}

#[tokio::test]
async fn test_decrypt_materials_reproduced_ec_key_only_in_reproduced_is_appended() {
    // cmm-interface.md#decrypt-materials: the returned Required Encryption
    // Context Keys "MUST include all keys added to the decryption materials
    // encryption context that existed in the [request's] reproduced encryption
    // context but did not exist in the [request's] encryption context."
    // https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/cmm-interface.md#decrypt-materials
    //
    // So a reproduced-only pair must appear two ways in the returned materials:
    // added to the encryption context, and listed as a required key. The two
    // assertions below check exactly those, not just that the call succeeded.
    let keyring = MockKeyring::new();
    let cmm = SharedCmm::new(DefaultCmm::new(keyring));
    let message_ec = EncryptionContext::new();
    let mut reproduced_ec = EncryptionContext::new();
    reproduced_ec.insert("only-in-reproduced", "v");
    let request = cmm
        .decrypt_materials()
        .algorithm_suite_id(non_signing_suite())
        .commitment_policy(allow_policy())
        .set_encrypted_data_keys(Some(vec![]))
        .set_encryption_context(Some(message_ec))
        .set_reproduced_encryption_context(Some(reproduced_ec));
    let materials = request
        .send()
        .await
        .expect("reproduced-only key must not fail")
        .into_decryption_materials();
    assert!(materials.plaintext_data_key().is_some());
    assert_eq!(
        ec_pairs(materials.encryption_context()),
        vec![("only-in-reproduced".to_string(), "v".to_string())],
        "the reproduced-only pair must be appended to the context the keyring receives"
    );
    assert_eq!(
        reck_keys(&materials),
        vec!["only-in-reproduced".to_string()],
        "an appended key must be reported as a required encryption context key"
    );
}

// ===== Reproduced Encryption Context =====
//
// The reproduced-EC tests assert on the encryption context and required-EC-keys
// of the materials RETURNED by decrypt_materials, treating them as a stand-in
// for what the CMM handed the keyring. That substitution is valid because
// MockKeyring copies both fields straight from its input materials onto its
// output — so the returned values are exactly what the keyring received.
//
// This matters because a keyring derives its AES-GCM AAD from the encryption
// context: if the CMM hands over a short context, the keyring computes the
// wrong AAD and can't unwrap the data key.

fn ec_of(pairs: &[(&str, &str)]) -> EncryptionContext {
    let mut ec = EncryptionContext::new();
    for &(k, v) in pairs {
        ec.insert(k, v);
    }
    ec
}

fn ec_pairs(ec: &EncryptionContext) -> Vec<(String, String)> {
    ec.iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn reck_keys(materials: &DecryptionMaterials) -> Vec<String> {
    materials.required_encryption_context_keys().to_vec()
}

#[tokio::test]
async fn test_decrypt_materials_appends_reproduced_only_pairs_to_the_keyring_context() {
    // An encrypting CMM held "a" back from the message, so the keyring must be
    // handed {a, b} — not the message's {b} — or its AAD is short and
    // authentication fails.
    let keyring = MockKeyring::new();
    let cmm = SharedCmm::new(DefaultCmm::new(keyring));
    let request = cmm
        .decrypt_materials()
        .algorithm_suite_id(non_signing_suite())
        .commitment_policy(allow_policy())
        .set_encrypted_data_keys(Some(vec![]))
        .set_encryption_context(Some(ec_of(&[("b", "b")])))
        .set_reproduced_encryption_context(Some(ec_of(&[("a", "a"), ("b", "b")])));

    let materials = request
        .send()
        .await
        .expect("must succeed")
        .into_decryption_materials();

    assert_eq!(
        ec_pairs(materials.encryption_context()),
        vec![
            ("a".to_string(), "a".to_string()),
            ("b".to_string(), "b".to_string())
        ],
        "the keyring must receive the message context plus the reproduced-only pairs"
    );
    assert_eq!(reck_keys(&materials), vec!["a".to_string()]);
}

#[tokio::test]
async fn test_decrypt_materials_appends_when_reproduced_context_is_disjoint() {
    // The reproduced context need not be a superset of the message's; it only
    // has to supply the keys the message lacks.
    let keyring = MockKeyring::new();
    let cmm = SharedCmm::new(DefaultCmm::new(keyring));
    let request = cmm
        .decrypt_materials()
        .algorithm_suite_id(non_signing_suite())
        .commitment_policy(allow_policy())
        .set_encrypted_data_keys(Some(vec![]))
        .set_encryption_context(Some(ec_of(&[("a", "a")])))
        .set_reproduced_encryption_context(Some(ec_of(&[("b", "b")])));

    let materials = request
        .send()
        .await
        .expect("must succeed")
        .into_decryption_materials();

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
    let keyring = MockKeyring::new();
    let cmm = SharedCmm::new(DefaultCmm::new(keyring));
    let request = cmm
        .decrypt_materials()
        .algorithm_suite_id(non_signing_suite())
        .commitment_policy(allow_policy())
        .set_encrypted_data_keys(Some(vec![]))
        .set_encryption_context(Some(EncryptionContext::new()))
        .set_reproduced_encryption_context(Some(ec_of(&[("a", "a"), ("b", "b")])));

    let materials = request
        .send()
        .await
        .expect("must succeed")
        .into_decryption_materials();

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
async fn test_decrypt_materials_conflicting_reproduced_value_does_not_call_the_keyring() {
    let keyring = MockKeyring::new();
    let cmm = SharedCmm::new(DefaultCmm::new(keyring.clone()));
    let request = cmm
        .decrypt_materials()
        .algorithm_suite_id(non_signing_suite())
        .commitment_policy(allow_policy())
        .set_encrypted_data_keys(Some(vec![]))
        .set_encryption_context(Some(ec_of(&[("a", "a")])))
        .set_reproduced_encryption_context(Some(ec_of(&[("a", "different")])));

    let err = request
        .send()
        .await
        .expect_err("must fail before doing any crypto");

    assert!(err.is_encryption_context_mismatch(), "{:?}", err);
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
    let keyring = MockKeyring::new();
    let cmm = SharedCmm::new(DefaultCmm::new(keyring));
    let request = cmm
        .decrypt_materials()
        .algorithm_suite_id(non_signing_suite())
        .commitment_policy(allow_policy())
        .set_encrypted_data_keys(Some(vec![]))
        .set_encryption_context(Some(ec_of(&[("a", "a")])));

    let materials = request
        .send()
        .await
        .expect("must succeed")
        .into_decryption_materials();

    assert_eq!(
        ec_pairs(materials.encryption_context()),
        vec![("a".to_string(), "a".to_string())]
    );
    assert!(reck_keys(&materials).is_empty());
}

#[tokio::test]
async fn test_decrypt_materials_signing_suite_public_key_from_reproduced_context() {
    // The reserved verification key may arrive only via the reproduced context;
    // the CMM must look it up after the merge, not before.
    let keyring = MockKeyring::new();
    let cmm = SharedCmm::new(DefaultCmm::new(keyring));
    let vk = vec![0x02; 49];
    let mut reproduced = EncryptionContext::new();
    reproduced.insert("aws-crypto-public-key", BASE64_STANDARD.encode(&vk));
    let request = cmm
        .decrypt_materials()
        .algorithm_suite_id(signing_suite())
        .commitment_policy(allow_policy())
        .set_encrypted_data_keys(Some(vec![]))
        .set_encryption_context(Some(EncryptionContext::new()))
        .set_reproduced_encryption_context(Some(reproduced));

    let materials = request
        .send()
        .await
        .expect("must succeed")
        .into_decryption_materials();

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
    let keyring = MockKeyring::new();
    let cmm = SharedCmm::new(DefaultCmm::new(keyring));
    let mut reproduced = EncryptionContext::new();
    reproduced.insert("aws-crypto-public-key", "some-value");
    let request = cmm
        .decrypt_materials()
        .algorithm_suite_id(non_signing_suite())
        .commitment_policy(allow_policy())
        .set_encrypted_data_keys(Some(vec![]))
        .set_encryption_context(Some(EncryptionContext::new()))
        .set_reproduced_encryption_context(Some(reproduced));

    let err = request
        .send()
        .await
        .expect_err("must reject the reserved key regardless of which context carried it");

    assert!(err.is_validation(), "{:?}", err);
}

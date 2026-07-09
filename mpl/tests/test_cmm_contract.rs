// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Contract tests for the abstract `Cmm` trait.
//!
//! These tests verify the abstract `Cmm` trait contract via the in-file
//! `MockCmm`. They are intentionally NOT duvet-annotated — the corresponding
//! requirements are annotated as `type=exception` in `src/cmm/mod.rs` and
//! will be re-annotated as `type=implementation,test` once concrete CMMs
//! (Default CMM, Caching CMM, Required EC CMM, …) are added.
//!
//! The mock's `get_encryption_materials` / `decrypt_materials` exercise every
//! documented branch of the CMM interface (suite selection, signing-key
//! attachment, `aws-crypto-public-key` insertion / SHOULD-fail rules,
//! reproduced-EC validation, RECK super-set behavior, EDK round trip).

use std::collections::BTreeSet;

use async_trait::async_trait;

use aws_crypto_mpl::cmm::Cmm;
use aws_crypto_mpl::cmm::request::{DecryptMaterialsRequest, EncryptionMaterialsRequest};
use aws_crypto_mpl::structures::{
    AlgorithmSuiteId, CommitmentPolicy, DecryptionMaterials, EncryptedDataKey, EncryptionContext,
    EncryptionMaterials, Esdk, MaterialsError, MaterialsErrorKind, PlaintextDataKey, SigningKey,
    VerificationKey,
};

// MockCmm

/// Switches that select which optional CMM behaviors the mock attempts.
/// Defaults are conservative: attach signing key when the suite signs,
/// validate reproduced EC when present, but skip the `aws-crypto-public-key`
/// EC insertion and the SHOULD-fail public-key rules so the simplest tests
/// don't have to opt out.
#[derive(Debug, Clone, Copy, Default)]
struct MockBehaviors {
    /// On `get_encryption_materials`, attach a deterministic signing key
    /// when the suite has an asymmetric signature algorithm.
    attach_signing_key: bool,
    /// On `get_encryption_materials`, add the `aws-crypto-public-key` EC
    /// entry when the suite has a signature algorithm. Maps to the SHOULD
    /// rule.
    add_public_key_to_ec: bool,
    /// On `decrypt_materials`, validate the reproduced EC against the stored
    /// EC (intersection-by-key value comparison).
    validate_reproduced_ec: bool,
    /// On `decrypt_materials`, enforce the SHOULD-fail
    /// `aws-crypto-public-key` rules tied to the suite's signing algorithm.
    enforce_public_key_should_rules: bool,
}

/// Configurable mock CMM. `provider_id` is used as the EDK key provider id
/// the mock recognises on decrypt; the EDK ciphertext stores the PDK bytes
/// verbatim so symmetric round-trip succeeds.
struct MockCmm {
    behaviors: MockBehaviors,
    provider_id: String,
    provider_info: Vec<u8>,
}

impl MockCmm {
    fn new(behaviors: MockBehaviors) -> Self {
        Self {
            behaviors,
            provider_id: "mock-cmm".to_string(),
            provider_info: b"mock-info".to_vec(),
        }
    }
}

const RESERVED_PUBLIC_KEY: &[u8] = b"aws-crypto-public-key";

#[async_trait]
impl Cmm for MockCmm {
    async fn get_encryption_materials(
        &self,
        request: EncryptionMaterialsRequest,
    ) -> Result<EncryptionMaterials, MaterialsError> {
        let suite_id = request
            .algorithm_suite_id()
            .unwrap_or_else(|| request.commitment_policy().default_algorithm_suite_id());
        let suite = suite_id.specification();

        // Deterministic suite-length PDK — concrete CMMs source from a CSPRNG.
        let pdk_bytes = vec![0xAA; suite.encryption_key_length()];
        let pdk = PlaintextDataKey::new(pdk_bytes.clone());

        let edk = EncryptedDataKey::new(
            self.provider_id.clone(),
            self.provider_info.clone(),
            pdk_bytes,
        );

        // Encryption context: clone the request's, then optionally insert the
        // reserved aws-crypto-public-key entry for signing suites.
        let mut ec = request.encryption_context().clone();
        let mut signing_key: Option<SigningKey> = None;
        if suite_id.has_asymmetric_signing() {
            if self.behaviors.attach_signing_key {
                let signing_len = suite
                    .signing_key_length()
                    .expect("signing suite has signing-key length");
                signing_key = Some(SigningKey::new(vec![0xBB; signing_len]));
            }
            if self.behaviors.add_public_key_to_ec {
                let verification_len = suite
                    .verification_key_length()
                    .expect("signing suite has verification-key length");
                ec.insert(RESERVED_PUBLIC_KEY.to_vec(), vec![0xCC; verification_len]);
            }
        }

        // RECK super-set: the materials' RECK is the request's RECK (or empty
        // if absent). Trivially a super-set of the request's set.
        let reck = request
            .required_encryption_context_keys()
            .cloned()
            .unwrap_or_default();

        EncryptionMaterials::new(suite_id, vec![edk], ec, reck, Some(pdk), signing_key, None)
    }

    async fn decrypt_materials(
        &self,
        request: DecryptMaterialsRequest,
    ) -> Result<DecryptionMaterials, MaterialsError> {
        let suite_id = request.algorithm_suite_id();
        let suite = suite_id.specification();
        let stored_ec = request.encryption_context();

        // SHOULD-fail rules tied to the aws-crypto-public-key reserved entry.
        if self.behaviors.enforce_public_key_should_rules {
            let has_public_key = stored_ec.contains_key(RESERVED_PUBLIC_KEY);
            if suite_id.has_asymmetric_signing() && !has_public_key {
                return Err(MaterialsError::aws_crypto_public_key_missing(
                    "decrypt_materials: signing suite EC missing reserved aws-crypto-public-key",
                ));
            }
            if !suite_id.has_asymmetric_signing() && has_public_key {
                return Err(MaterialsError::aws_crypto_public_key_unexpected(
                    "decrypt_materials: non-signing suite EC contains reserved aws-crypto-public-key",
                ));
            }
        }

        // Reproduced-EC validation: per the spec, "for every key that exists
        // in BOTH reproduced and stored, the values MUST be equal or the
        // operation MUST fail". Intersection-by-key only.
        if self.behaviors.validate_reproduced_ec
            && let Some(reproduced) = request.reproduced_encryption_context()
        {
            for (key, reproduced_value) in reproduced.iter() {
                if let Some(stored_value) = stored_ec.get(key)
                    && reproduced_value != stored_value
                {
                    return Err(MaterialsError::encryption_context_value_mismatch(format!(
                        "decrypt_materials: reproduced EC value differs from stored EC for key {key:?}"
                    )));
                }
            }
        }

        // Recover the PDK from a matching EDK (provider id + provider info).
        let mut recovered_pdk: Option<PlaintextDataKey> = None;
        for edk in request.encrypted_data_keys() {
            if edk.key_provider_id == self.provider_id
                && edk.key_provider_info == self.provider_info
            {
                recovered_pdk = Some(PlaintextDataKey::new(edk.ciphertext.clone()));
                break;
            }
        }
        let pdk = match recovered_pdk {
            Some(pdk) => pdk,
            None => {
                return Err(MaterialsError::no_matching_data_key(
                    "decrypt_materials: no encrypted data key matched this CMM's provider",
                ));
            }
        };

        // Verification key for signing suites — deterministic.
        let verification_key = if suite_id.has_asymmetric_signing() {
            let verification_len = suite
                .verification_key_length()
                .expect("signing suite has verification-key length");
            Some(VerificationKey::new(vec![0xDD; verification_len]))
        } else {
            None
        };

        DecryptionMaterials::new(
            suite_id,
            stored_ec.clone(),
            BTreeSet::new(),
            Some(pdk),
            verification_key,
            None,
        )
    }
}

// Suites
const NON_SIGNING_SUITE: AlgorithmSuiteId = AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey;
const SIGNING_SUITE: AlgorithmSuiteId = AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384;
const POLICY_NON_SIGNING: CommitmentPolicy =
    CommitmentPolicy::Esdk(Esdk::RequireEncryptAllowDecrypt);

// Request-type constructor / getter coverage

#[tokio::test]
async fn test_request_constructors_and_getters() {
    // EncryptionMaterialsRequest — required-only constructor.
    let mut ec = EncryptionContext::new();
    ec.insert(b"k".to_vec(), b"v".to_vec());
    let enc_req = EncryptionMaterialsRequest::new(ec.clone(), POLICY_NON_SIGNING);
    assert_eq!(enc_req.encryption_context().len(), 1);
    assert_eq!(enc_req.commitment_policy(), POLICY_NON_SIGNING);
    assert!(enc_req.algorithm_suite_id().is_none());
    assert!(enc_req.required_encryption_context_keys().is_none());
    assert!(enc_req.max_plaintext_length().is_none());

    // EncryptionMaterialsRequest — with_* setters.
    let mut keys = BTreeSet::new();
    keys.insert(b"k".to_vec());
    let enc_req_full = EncryptionMaterialsRequest::new(ec.clone(), POLICY_NON_SIGNING)
        .with_algorithm_suite_id(NON_SIGNING_SUITE)
        .with_required_encryption_context_keys(keys.clone())
        .with_max_plaintext_length(1_024);
    assert_eq!(enc_req_full.algorithm_suite_id(), Some(NON_SIGNING_SUITE));
    assert_eq!(
        enc_req_full
            .required_encryption_context_keys()
            .expect("RECK was set"),
        &keys
    );
    assert_eq!(enc_req_full.max_plaintext_length(), Some(1_024));

    // DecryptMaterialsRequest — required-only constructor.
    let edks = vec![EncryptedDataKey::new(
        "mock-cmm".to_string(),
        b"mock-info".to_vec(),
        vec![0xAA; 32],
    )];
    let dec_req = DecryptMaterialsRequest::new(
        NON_SIGNING_SUITE,
        POLICY_NON_SIGNING,
        edks.clone(),
        ec.clone(),
    );
    assert_eq!(dec_req.algorithm_suite_id(), NON_SIGNING_SUITE);
    assert_eq!(dec_req.commitment_policy(), POLICY_NON_SIGNING);
    assert_eq!(dec_req.encrypted_data_keys().len(), 1);
    assert_eq!(dec_req.encryption_context().len(), 1);
    assert!(dec_req.reproduced_encryption_context().is_none());

    // DecryptMaterialsRequest — with_* setter.
    let dec_req_full =
        DecryptMaterialsRequest::new(NON_SIGNING_SUITE, POLICY_NON_SIGNING, edks, ec)
            .with_reproduced_encryption_context(EncryptionContext::new());
    assert!(dec_req_full.reproduced_encryption_context().is_some());

    // Sanity: Debug + Clone derives compile and execute.
    let _enc_dbg = format!("{enc_req_full:?}");
    let _dec_dbg = format!("{dec_req_full:?}");
    let _enc_clone = enc_req_full.clone();
    let _dec_clone = dec_req_full.clone();
}

// get_encryption_materials — basic / non-signing

#[tokio::test]
async fn test_get_encryption_materials_with_request_data_returns_valid_materials() {
    let cmm = MockCmm::new(MockBehaviors::default());
    let request = EncryptionMaterialsRequest::new(EncryptionContext::new(), POLICY_NON_SIGNING)
        .with_algorithm_suite_id(NON_SIGNING_SUITE);

    let materials = cmm
        .get_encryption_materials(request)
        .await
        .expect("get_encryption_materials succeeds for non-signing suite");

    assert_eq!(
        materials.algorithm_suite_id(),
        NON_SIGNING_SUITE,
        "materials carry the request's algorithm suite"
    );
    let expected_pdk_len = NON_SIGNING_SUITE.specification().encryption_key_length();
    assert_eq!(
        materials
            .plaintext_data_key()
            .expect("PDK must be set")
            .len(),
        expected_pdk_len,
        "PDK length equals the suite's encryption_key_length ({expected_pdk_len})"
    );
    assert_eq!(
        materials.encrypted_data_keys().len(),
        1,
        "exactly one EDK is appended"
    );
    assert_eq!(
        materials.encrypted_data_keys()[0].ciphertext.len(),
        expected_pdk_len,
        "EDK ciphertext encodes the PDK bytes verbatim"
    );
    assert!(
        materials.signing_key().is_none(),
        "non-signing suite has no signing key on materials"
    );
}

#[tokio::test]
async fn test_get_encryption_materials_signing_suite_attaches_signing_key() {
    let cmm = MockCmm::new(MockBehaviors {
        attach_signing_key: true,
        ..MockBehaviors::default()
    });
    let request = EncryptionMaterialsRequest::new(EncryptionContext::new(), POLICY_NON_SIGNING)
        .with_algorithm_suite_id(SIGNING_SUITE);

    let materials = cmm
        .get_encryption_materials(request)
        .await
        .expect("get_encryption_materials succeeds for signing suite with attach=true");

    let expected_signing_len = SIGNING_SUITE
        .specification()
        .signing_key_length()
        .expect("signing suite has a signing-key length");
    assert_eq!(
        materials
            .signing_key()
            .expect("signing key must be attached")
            .len(),
        expected_signing_len,
        "signing key length matches the suite's signing-key length ({expected_signing_len})"
    );
}

#[tokio::test]
async fn test_get_encryption_materials_non_signing_suite_omits_signing_key() {
    let cmm = MockCmm::new(MockBehaviors {
        // Even with attach_signing_key=true, the non-signing suite must omit
        // the signing key per `EncryptionMaterials::new` validation.
        attach_signing_key: true,
        ..MockBehaviors::default()
    });
    let request = EncryptionMaterialsRequest::new(EncryptionContext::new(), POLICY_NON_SIGNING)
        .with_algorithm_suite_id(NON_SIGNING_SUITE);

    let materials = cmm
        .get_encryption_materials(request)
        .await
        .expect("non-signing suite path succeeds");

    assert!(
        materials.signing_key().is_none(),
        "non-signing suite must not have a signing key"
    );
}

#[tokio::test]
async fn test_get_encryption_materials_required_ec_keys_superset() {
    let cmm = MockCmm::new(MockBehaviors::default());
    let mut ec = EncryptionContext::new();
    ec.insert(b"foo".to_vec(), b"bar".to_vec());
    let mut required = BTreeSet::new();
    required.insert(b"foo".to_vec());

    let request = EncryptionMaterialsRequest::new(ec, POLICY_NON_SIGNING)
        .with_algorithm_suite_id(NON_SIGNING_SUITE)
        .with_required_encryption_context_keys(required.clone());

    let materials = cmm
        .get_encryption_materials(request)
        .await
        .expect("RECK super-set path succeeds");

    assert!(
        materials
            .required_encryption_context_keys()
            .contains(b"foo".as_ref()),
        "materials' RECK is a super-set of the request's RECK"
    );
    assert!(
        materials.encryption_context().contains_key(b"foo"),
        "every key in materials' RECK is present in materials' EC"
    );
}

#[tokio::test]
async fn test_get_encryption_materials_with_signing_suite_adds_aws_crypto_public_key() {
    let cmm = MockCmm::new(MockBehaviors {
        attach_signing_key: true,
        add_public_key_to_ec: true,
        ..MockBehaviors::default()
    });
    let request = EncryptionMaterialsRequest::new(EncryptionContext::new(), POLICY_NON_SIGNING)
        .with_algorithm_suite_id(SIGNING_SUITE);

    let materials = cmm
        .get_encryption_materials(request)
        .await
        .expect("signing-suite + add_public_key_to_ec path succeeds");

    assert!(
        materials
            .encryption_context()
            .contains_key(RESERVED_PUBLIC_KEY),
        "signing suite adds the reserved aws-crypto-public-key entry"
    );
}

#[tokio::test]
async fn test_get_encryption_materials_no_signing_suite_skips_aws_crypto_public_key() {
    let cmm = MockCmm::new(MockBehaviors {
        // Even with add_public_key_to_ec=true, non-signing suite must skip
        // the entry per the SHOULD-NOT rule.
        add_public_key_to_ec: true,
        ..MockBehaviors::default()
    });
    let request = EncryptionMaterialsRequest::new(EncryptionContext::new(), POLICY_NON_SIGNING)
        .with_algorithm_suite_id(NON_SIGNING_SUITE);

    let materials = cmm
        .get_encryption_materials(request)
        .await
        .expect("non-signing suite path succeeds");

    assert!(
        !materials
            .encryption_context()
            .contains_key(RESERVED_PUBLIC_KEY),
        "non-signing suite does not add the reserved aws-crypto-public-key entry"
    );
}

#[tokio::test]
async fn test_get_encryption_materials_uses_commitment_policy_default_when_no_suite() {
    let cmm = MockCmm::new(MockBehaviors::default());
    // No algorithm_suite_id supplied — fall back to the commitment policy's
    // default. ESDK.REQUIRE_ENCRYPT_ALLOW_DECRYPT defaults to the signing suite.
    let request = EncryptionMaterialsRequest::new(EncryptionContext::new(), POLICY_NON_SIGNING);

    let materials = cmm
        .get_encryption_materials(request)
        .await
        .expect("default-suite path succeeds");

    assert_eq!(
        materials.algorithm_suite_id(),
        POLICY_NON_SIGNING.default_algorithm_suite_id(),
        "materials suite falls back to the commitment policy's default"
    );
}

// decrypt_materials — round trip / validation

#[tokio::test]
async fn test_decrypt_materials_round_trip_recovers_pdk() {
    let cmm = MockCmm::new(MockBehaviors {
        attach_signing_key: true,
        ..MockBehaviors::default()
    });
    let enc_request = EncryptionMaterialsRequest::new(EncryptionContext::new(), POLICY_NON_SIGNING)
        .with_algorithm_suite_id(NON_SIGNING_SUITE);
    let enc_materials = cmm
        .get_encryption_materials(enc_request)
        .await
        .expect("encrypt path succeeds");

    let original_pdk_bytes = enc_materials
        .plaintext_data_key()
        .expect("encrypt output has PDK")
        .as_bytes()
        .to_vec();
    let edks: Vec<EncryptedDataKey> = enc_materials.encrypted_data_keys().to_vec();
    let stored_ec = enc_materials.encryption_context().clone();

    let dec_request =
        DecryptMaterialsRequest::new(NON_SIGNING_SUITE, POLICY_NON_SIGNING, edks, stored_ec);
    let dec_materials = cmm
        .decrypt_materials(dec_request)
        .await
        .expect("decrypt path succeeds");

    assert_eq!(
        dec_materials
            .plaintext_data_key()
            .expect("decrypt output has PDK")
            .as_bytes(),
        &original_pdk_bytes,
        "round-trip recovers the original PDK"
    );
}

#[tokio::test]
async fn test_decrypt_materials_validates_reproduced_ec_match_succeeds() {
    let cmm = MockCmm::new(MockBehaviors {
        validate_reproduced_ec: true,
        ..MockBehaviors::default()
    });
    let mut ec = EncryptionContext::new();
    ec.insert(b"purpose".to_vec(), b"prod".to_vec());

    let edks = vec![EncryptedDataKey::new(
        "mock-cmm".to_string(),
        b"mock-info".to_vec(),
        vec![0xAA; 32],
    )];
    let request =
        DecryptMaterialsRequest::new(NON_SIGNING_SUITE, POLICY_NON_SIGNING, edks, ec.clone())
            .with_reproduced_encryption_context(ec.clone());

    let materials = cmm
        .decrypt_materials(request)
        .await
        .expect("matching reproduced EC must succeed");

    assert!(
        materials.plaintext_data_key().is_some(),
        "decrypt yields a PDK when reproduced EC matches stored EC"
    );
}

#[tokio::test]
async fn test_decrypt_materials_reproduced_ec_value_mismatch_fails() {
    let cmm = MockCmm::new(MockBehaviors {
        validate_reproduced_ec: true,
        ..MockBehaviors::default()
    });
    let mut stored = EncryptionContext::new();
    stored.insert(b"purpose".to_vec(), b"prod".to_vec());
    let mut reproduced = EncryptionContext::new();
    reproduced.insert(b"purpose".to_vec(), b"staging".to_vec());

    let edks = vec![EncryptedDataKey::new(
        "mock-cmm".to_string(),
        b"mock-info".to_vec(),
        vec![0xAA; 32],
    )];
    let request = DecryptMaterialsRequest::new(NON_SIGNING_SUITE, POLICY_NON_SIGNING, edks, stored)
        .with_reproduced_encryption_context(reproduced);

    let err = cmm
        .decrypt_materials(request)
        .await
        .expect_err("mismatched reproduced EC must fail");

    assert_eq!(
        err.kind,
        MaterialsErrorKind::EncryptionContextValueMismatch,
        "value-mismatch path yields EncryptionContextValueMismatch; got {err:?}"
    );
}

#[tokio::test]
async fn test_decrypt_materials_signing_suite_missing_public_key_fails() {
    let cmm = MockCmm::new(MockBehaviors {
        enforce_public_key_should_rules: true,
        ..MockBehaviors::default()
    });
    // Signing suite, EC has NO aws-crypto-public-key.
    let edks = vec![EncryptedDataKey::new(
        "mock-cmm".to_string(),
        b"mock-info".to_vec(),
        vec![0xAA; 32],
    )];
    let request = DecryptMaterialsRequest::new(
        SIGNING_SUITE,
        POLICY_NON_SIGNING,
        edks,
        EncryptionContext::new(),
    );

    let err = cmm
        .decrypt_materials(request)
        .await
        .expect_err("signing suite missing public-key entry must fail");

    assert_eq!(
        err.kind,
        MaterialsErrorKind::AwsCryptoPublicKeyMissing,
        "missing-public-key path yields AwsCryptoPublicKeyMissing; got {err:?}"
    );
}

#[tokio::test]
async fn test_decrypt_materials_non_signing_suite_with_public_key_fails() {
    let cmm = MockCmm::new(MockBehaviors {
        enforce_public_key_should_rules: true,
        ..MockBehaviors::default()
    });
    // Non-signing suite, EC contains aws-crypto-public-key.
    let mut ec = EncryptionContext::new();
    ec.insert(RESERVED_PUBLIC_KEY.to_vec(), vec![0xCC; 97]);
    let edks = vec![EncryptedDataKey::new(
        "mock-cmm".to_string(),
        b"mock-info".to_vec(),
        vec![0xAA; 32],
    )];
    let request = DecryptMaterialsRequest::new(NON_SIGNING_SUITE, POLICY_NON_SIGNING, edks, ec);

    let err = cmm
        .decrypt_materials(request)
        .await
        .expect_err("non-signing suite with public-key entry must fail");

    assert_eq!(
        err.kind,
        MaterialsErrorKind::AwsCryptoPublicKeyUnexpected,
        "unexpected-public-key path yields AwsCryptoPublicKeyUnexpected; got {err:?}"
    );
}

#[tokio::test]
async fn test_decrypt_materials_signing_suite_attaches_verification_key() {
    let cmm = MockCmm::new(MockBehaviors::default());
    let edks = vec![EncryptedDataKey::new(
        "mock-cmm".to_string(),
        b"mock-info".to_vec(),
        vec![0xAA; 32],
    )];
    let request = DecryptMaterialsRequest::new(
        SIGNING_SUITE,
        POLICY_NON_SIGNING,
        edks,
        EncryptionContext::new(),
    );

    let materials = cmm
        .decrypt_materials(request)
        .await
        .expect("decrypt for signing suite succeeds");

    let expected_verification_len = SIGNING_SUITE
        .specification()
        .verification_key_length()
        .expect("signing suite has a verification-key length");
    assert_eq!(
        materials
            .verification_key()
            .expect("signing suite must attach a verification key")
            .len(),
        expected_verification_len,
        "verification key length matches the suite's verification-key length ({expected_verification_len})"
    );
}

#[tokio::test]
async fn test_decrypt_materials_no_matching_edk_fails() {
    let cmm = MockCmm::new(MockBehaviors::default());
    // EDK from a DIFFERENT provider — no match.
    let edks = vec![EncryptedDataKey::new(
        "other-cmm".to_string(),
        b"other-info".to_vec(),
        vec![0xDD; 32],
    )];
    let request = DecryptMaterialsRequest::new(
        NON_SIGNING_SUITE,
        POLICY_NON_SIGNING,
        edks,
        EncryptionContext::new(),
    );

    let err = cmm
        .decrypt_materials(request)
        .await
        .expect_err("no-matching-EDK path must fail");

    assert_eq!(
        err.kind,
        MaterialsErrorKind::NoMatchingDataKey,
        "no-matching-EDK path yields NoMatchingDataKey; got {err:?}"
    );
}

// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for spec/client-apis/decrypt.md#get-the-decryption-materials
// The spy CMM below implements the native `aws_crypto_mpl::cmm::Cmm` trait
// whose signatures return `MplError` by value; keep the large-Err allow
// so the delegating spy's `Result` doesn't trip clippy::result_large_err.
#![allow(clippy::result_large_err)]

#[allow(clippy::duplicate_mod)]
mod fixtures;
mod test_helpers;

use aws_crypto_mpl::Error as MplError;
use aws_crypto_mpl::cmm::{self, DecryptMaterialsRequest, DefaultCmm, EncryptionMaterialsRequest};
use aws_crypto_mpl::keyring::RawAesKeyring;
use aws_crypto_mpl::structures::{
    DecryptionMaterials, EncryptionMaterials, KeyDerivationAlgorithm,
};
use aws_esdk::*;
use aws_mpl_primitives::AesGcm;
use fixtures::*;
use std::sync::{Arc, Mutex};
use test_helpers::*;

#[tokio::test(flavor = "multi_thread")]
async fn test_decrypt_fails_with_wrong_keyring() {
    let keyring = test_keyring().await;
    let pt = b"negative test";
    let enc_input = EncryptInput::builder()
        .plaintext(pt)
        .keyring(keyring.clone())
        .build()
        .unwrap();
    let ct = encrypt(&enc_input).await.unwrap().ciphertext;

    // A different keyring (different namespace, different wrapping key) — its
    // default CMM cannot unwrap the EDK encrypted by `keyring`.
    let (ns, name) = namespace_and_name(1);
    let wrong_keyring = RawAesKeyring::new(ns, name, vec![1u8; 32], AesGcm::Aes256Gcm)
        .expect("raw AES keyring construction must succeed for test key material");

    let valid_input = DecryptInput::builder()
        .ciphertext(&ct)
        .keyring(keyring)
        .build()
        .unwrap();
    let invalid_input = DecryptInput::builder()
        .ciphertext(&ct)
        .keyring(wrong_keyring)
        .build()
        .unwrap();

    //= spec/client-apis/decrypt.md#get-the-decryption-materials
    //= type=test
    //= reason=Right keyring → Ok; wrong keyring → default-CMM materials failure, proving the input keyring constructs the default CMM
    //# If a CMM is not supplied as the input, the decrypt operation MUST construct a [default CMM](../framework/default-cmm.md)
    //# from the input [keyring](../framework/keyring-interface.md).
    assert!(
        decrypt(&valid_input).await.is_ok(),
        "right keyring must decrypt"
    );
    let err = decrypt(&invalid_input)
        .await
        .expect_err("wrong keyring must fail to obtain materials");
    assert_eq!(
        err.kind(),
        ErrorKind::NoMatchingDataKey,
        "expected the wrong keyring's default CMM to find no matching data key, got: {:?}",
        err.kind()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_pre_cmm_commitment_policy_check() {
    let keyring = aes_keyring(0).await;
    let pt = b"test pre-cmm commitment policy";
    // Encrypt with a non-committing suite (allowed by ForbidEncryptAllowDecrypt).
    let ct = encrypt_with_suite(
        pt,
        AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256,
        CommitmentPolicy::ForbidEncryptAllowDecrypt,
        &keyring,
    )
    .await;

    // Two decrypt inputs differing only in commitment_policy: the allowing
    // policy accepts the parsed non-committing suite; the requiring policy
    // rejects it pre-CMM.
    let valid_input = DecryptInput::builder()
        .ciphertext(&ct)
        .keyring(keyring.clone())
        .commitment_policy(CommitmentPolicy::ForbidEncryptAllowDecrypt)
        .build()
        .unwrap();
    let invalid_input = DecryptInput::builder()
        .ciphertext(&ct)
        .keyring(keyring)
        .commitment_policy(CommitmentPolicy::RequireEncryptRequireDecrypt)
        .build()
        .unwrap();

    //= spec/client-apis/decrypt.md#get-the-decryption-materials
    //= type=test
    //= reason=Policy that allows the parsed suite → Ok; policy that doesn't → Validation error
    //# If the parsed [algorithm suite ID](../data-format/message-header.md#algorithm-suite-id)
    //# is not supported by the [commitment policy](client.md#commitment-policy)
    //# configured in the [client](client.md) decrypt MUST yield an error.
    //
    //= spec/client-apis/decrypt.md#get-the-decryption-materials
    //= type=test
    //= reason=Test sets commitment_policy on input directly; only the chosen policy reaches the pre-CMM check
    //# - Commitment Policy: This MUST be the commitment policy configured on the client.
    assert!(
        decrypt(&valid_input).await.is_ok(),
        "policy that allows non-committing suite must decrypt"
    );
    let err = decrypt(&invalid_input)
        .await
        .expect_err("policy that requires committing must reject non-committing suite");
    // The parsed-suite-vs-commitment-policy check runs pre-CMM in decrypt.rs and
    // yields a Validation error.
    assert_eq!(
        err.kind(),
        ErrorKind::Validation,
        "expected pre-CMM Validation error, got: {:?}",
        err.kind()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_algorithm_suite_from_decryption_materials() {
    // Directly verify: parse the header to get the algorithm suite, then verify
    // decrypt's output reports the same suite. This proves the materials' suite
    // was used (not some hardcoded default).
    use aws_esdk::__test_internals::*;

    let keyring = aes_keyring(0).await;
    let pt = b"test algorithm suite from materials";
    let ct = encrypt_with_suite(
        pt,
        AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256,
        CommitmentPolicy::ForbidEncryptAllowDecrypt,
        &keyring,
    )
    .await;

    // Parse the header directly to read the algorithm suite from the wire
    let mut cursor = std::io::Cursor::new(ct.as_slice());
    let mut raw = Vec::new();
    let header_body = read_header_body(&mut cursor, None, &mut raw).unwrap();
    let wire_suite_bytes = header_body.algorithm_suite().id();

    // Decrypt and verify the output suite matches what the header contained
    let dec_input = DecryptInput::builder()
        .ciphertext(&ct)
        .keyring(keyring)
        .commitment_policy(CommitmentPolicy::ForbidEncryptAllowDecrypt)
        .build()
        .unwrap();
    let result = decrypt(&dec_input).await.unwrap();

    //= spec/client-apis/decrypt.md#get-the-decryption-materials
    //= type=test
    //= reason=Output suite matches wire-parsed header suite; proves materials' suite was used
    //# The algorithm suite used as input for all decryption described below MUST be the algorithm suite
    //# included in the [decryption materials](../framework/structures.md#decryption-materials).
    assert_eq!(
        result.algorithm_suite_id.id_bytes(),
        wire_suite_bytes,
        "output suite must match header's parsed suite"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_commit_key_derived_and_validated() {
    let keyring = aes_keyring(0).await;
    let pt = b"test commit key derivation and equality";
    // Use committing suite
    let valid_ct = encrypt_with_suite(
        pt,
        AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey,
        CommitmentPolicy::RequireEncryptRequireDecrypt,
        &keyring,
    )
    .await;

    // Tamper the Algorithm Suite Data (commit key) in the header.
    // parse_v2_header_field_offsets gives us the exact byte range.
    let fields = parse_v2_header_field_offsets(&valid_ct);
    let (_, sd_start, _sd_end) = fields
        .iter()
        .find(|(n, _, _)| *n == "Algorithm Suite Data")
        .expect("V2 header must have Algorithm Suite Data field");
    let mut tampered_ct = valid_ct.clone();
    tampered_ct[*sd_start] ^= 0xFF;
    assert_ne!(
        tampered_ct[*sd_start], valid_ct[*sd_start],
        "tamper must change the byte"
    );

    let valid_input = DecryptInput::builder()
        .ciphertext(&valid_ct)
        .keyring(keyring.clone())
        .build()
        .unwrap();
    let tampered_input = DecryptInput::builder()
        .ciphertext(&tampered_ct)
        .keyring(keyring)
        .build()
        .unwrap();

    //= spec/client-apis/decrypt.md#get-the-decryption-materials
    //= type=test
    //= reason=Untampered commit key → Ok; tampered commit key in header → Validation error, proving the equality check runs
    //# If the [algorithm suite](../framework/algorithm-suites.md#algorithm-suites-encryption-key-derivation-settings) supports [key commitment](../framework/algorithm-suites.md#key-commitment)
    //# then the [commit key](../framework/algorithm-suites.md#commit-key) MUST be derived from the plaintext data key
    //# using the [commit key derivation](../framework/algorithm-suites.md#algorithm-suites-commit-key-derivation-settings).
    //
    //= spec/client-apis/decrypt.md#get-the-decryption-materials
    //= type=test
    //= reason=Header commit key must equal derived commit key; tampering breaks equality → Validation error
    //# The derived commit key MUST equal the commit key stored in the message header.
    assert!(
        decrypt(&valid_input).await.is_ok(),
        "valid commit key must decrypt"
    );
    assert_eq!(
        decrypt(&tampered_input).await.unwrap_err().kind(),
        ErrorKind::Validation,
        "tampered commit key must produce Validation error"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_kdf_algorithm_from_materials_suite() {
    // Parse the header to verify the algorithm suite uses HKDF, then decrypt
    // to prove that KDF algorithm was actually used for key derivation.
    use aws_esdk::__test_internals::*;

    let keyring = aes_keyring(0).await;
    let pt = b"test kdf algorithm from materials";
    let ct = encrypt_with_suite(
        pt,
        AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256,
        CommitmentPolicy::ForbidEncryptAllowDecrypt,
        &keyring,
    )
    .await;

    // Parse header and verify the suite's KDF is HKDF (not Identity)
    let mut cursor = std::io::Cursor::new(ct.as_slice());
    let mut raw = Vec::new();
    let header_body = read_header_body(&mut cursor, None, &mut raw).unwrap();
    let suite = header_body.algorithm_suite();
    // Sanity check: the suite parsed from the header declares HKDF derivation.
    assert!(
        matches!(
            suite.encryption_kdf(),
            KeyDerivationAlgorithm::HkdfSha256
                | KeyDerivationAlgorithm::HkdfSha384
                | KeyDerivationAlgorithm::HkdfSha512
        ),
        "parsed suite must use HKDF derivation, got: {:?}",
        suite.encryption_kdf()
    );

    let dec_input = DecryptInput::builder()
        .ciphertext(&ct)
        .keyring(keyring)
        .commitment_policy(CommitmentPolicy::ForbidEncryptAllowDecrypt)
        .build()
        .unwrap();
    //= spec/client-apis/decrypt.md#get-the-decryption-materials
    //= type=test
    //= reason=KDF is an invisible AEAD input; a wrong KDF derives a wrong key → AES-GCM tag fails, so decrypt success proves the suite's HKDF was used
    //# The algorithm suite used to derive a data key from the plaintext data key MUST be
    //# the [key derivation algorithm](../framework/algorithm-suites.md#key-derivation-algorithm) included in the
    //# [algorithm suite](../framework/algorithm-suites.md) associated with
    //# the returned decryption materials.
    let result = decrypt(&dec_input).await.unwrap();
    assert_eq!(
        result.plaintext, pt,
        "HKDF-derived key must decrypt the body"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_unsupported_esdk_algorithm_suite_yields_error() {
    let keyring = aes_keyring(0).await;
    let pt = b"unsupported esdk suite test";

    let enc_input = EncryptInput::builder()
        .plaintext(pt)
        .keyring(keyring.clone())
        .build()
        .unwrap();
    let valid_ct = encrypt(&enc_input).await.unwrap().ciphertext;

    // Tamper the algorithm suite ID bytes in the header to an invalid value.
    // V2 header: byte 0 = version (0x02), bytes 1-2 = algorithm suite ID.
    let mut tampered_ct = valid_ct.clone();
    tampered_ct[1] = 0xFF;
    tampered_ct[2] = 0xFF;

    let valid_input = DecryptInput::builder()
        .ciphertext(&valid_ct)
        .keyring(keyring.clone())
        .build()
        .unwrap();
    let tampered_input = DecryptInput::builder()
        .ciphertext(&tampered_ct)
        .keyring(keyring)
        .build()
        .unwrap();

    //= spec/client-apis/decrypt.md#get-the-decryption-materials
    //= type=test
    //= reason=Supported ESDK suite ID → Ok; tampered to non-ESDK 0xFFFF → Validation error
    //# If this algorithm suite is not [supported for the ESDK](../framework/algorithm-suites.md#supported-algorithm-suites-enum)
    //# decrypt MUST yield an error.
    //
    //= spec/client-apis/decrypt.md#get-the-decryption-materials
    //= type=test
    //= reason=Tampered header suite ID changes the parsed input; failure proves parsed suite is used
    //# - Algorithm Suite ID: This MUST be the parsed
    //# [algorithm suite ID](../data-format/message-header.md#algorithm-suite-id)
    //# from the message header.
    assert!(
        decrypt(&valid_input).await.is_ok(),
        "valid suite ID must decrypt"
    );
    assert_eq!(
        decrypt(&tampered_input).await.unwrap_err().kind(),
        ErrorKind::Validation,
        "non-ESDK suite ID must produce Validation error"
    );
}

/// Spy CMM for decrypt: records the inputs it received from the decrypt call,
/// then delegates to an inner (real) default CMM so the returned materials are
/// the genuine ones the ESDK uses to complete the round-trip.
struct DecryptSpyCmm {
    inner: DefaultCmm,
    observed_edk_count: Arc<Mutex<Option<usize>>>,
    observed_ec_keys: Arc<Mutex<Option<Vec<String>>>>,
}

#[async_trait::async_trait]
impl cmm::Cmm for DecryptSpyCmm {
    async fn get_encryption_materials(
        &self,
        request: EncryptionMaterialsRequest,
    ) -> Result<EncryptionMaterials, MplError> {
        self.inner.get_encryption_materials(request).await
    }

    async fn decrypt_materials(
        &self,
        request: DecryptMaterialsRequest,
    ) -> Result<DecryptionMaterials, MplError> {
        // Record observations from the request the ESDK constructed.
        *self.observed_edk_count.lock().unwrap() = Some(request.encrypted_data_keys().len());
        let keys: Vec<String> = request
            .encryption_context()
            .iter()
            .map(|(k, _)| k.to_owned())
            .collect();
        *self.observed_ec_keys.lock().unwrap() = Some(keys);
        // Delegate to the inner default CMM so real materials are returned.
        self.inner.decrypt_materials(request).await
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_cmm_decrypt_call_receives_header_edks_and_ec() {
    let keyring = test_keyring().await;
    let mut ec = EncryptionContext::new();
    ec.insert("spy-key", "spy-val");
    let pt = b"spy cmm decrypt test";
    let enc_input = EncryptInput::builder()
        .plaintext(pt)
        .encryption_context(ec)
        .keyring(keyring.clone())
        .build()
        .unwrap();
    let ct = encrypt(&enc_input).await.unwrap().ciphertext;

    let inner_cmm = DefaultCmm::new(keyring);
    let observed_edk_count = Arc::new(Mutex::new(None));
    let observed_ec_keys = Arc::new(Mutex::new(None));
    let spy_cmm = DecryptSpyCmm {
        inner: inner_cmm,
        observed_edk_count: observed_edk_count.clone(),
        observed_ec_keys: observed_ec_keys.clone(),
    };

    let dec_input = DecryptInput::builder()
        .ciphertext(&ct)
        .cmm(spy_cmm)
        .build()
        .unwrap();
    let result = decrypt(&dec_input).await.unwrap();
    //= spec/client-apis/decrypt.md#cryptographic-materials-manager
    //= type=test
    //= reason=the spy CMM wraps a real CMM and was invoked during decrypt; its returned materials were used (spy call observed below)
    //# This CMM MUST obtain the [decryption materials](../framework/structures.md#decryption-materials) required for decryption.
    //
    //= spec/client-apis/decrypt.md#get-the-decryption-materials
    //= type=test
    //= reason=the spy CMM recorded the Decrypt Materials call and returned the materials used (observations asserted below)
    //# This operation MUST obtain this set of [decryption materials](../framework/structures.md#decryption-materials),
    //# by calling [Decrypt Materials](../framework/cmm-interface.md#decrypt-materials) on a [CMM](../framework/cmm-interface.md).
    //
    //= spec/client-apis/decrypt.md#get-the-decryption-materials
    //= type=test
    //= reason=We passed spy_cmm as the input CMM; the spy observing the call proves the input CMM was used
    //# The CMM used MUST be the input CMM, if supplied.
    assert_eq!(result.plaintext, pt);

    //= spec/client-apis/decrypt.md#get-the-decryption-materials
    //= type=test
    //= reason=spy CMM observes the constructed DecryptMaterialsInput carrying parsed EDKs and encryption context
    //# The call to the CMM's [Decrypt Materials](../framework/cmm-interface.md#decrypt-materials) operation
    //# MUST be constructed as follows:
    //
    //= spec/client-apis/decrypt.md#get-the-decryption-materials
    //= type=test
    //= reason=Spy CMM observes EDK count matches header (1 EDK from single keyring)
    //# - Encrypted Data Keys: This MUST be the parsed [encrypted data keys](../data-format/message-header.md#encrypted-data-keys)
    //# from the message header.
    let edk_count = observed_edk_count.lock().unwrap().unwrap();
    assert_eq!(edk_count, 1, "CMM must receive 1 EDK from header");

    //= spec/client-apis/decrypt.md#get-the-decryption-materials
    //= type=test
    //= reason=Spy CMM observes EC contains the key we encrypted with
    //# - Encryption Context: This MUST be the parsed [encryption context](../data-format/message-header.md#aad)
    //# from the message header.
    let ec_keys = observed_ec_keys.lock().unwrap().clone().unwrap();
    assert!(
        ec_keys.contains(&"spy-key".to_string()),
        "CMM must receive EC from header containing 'spy-key'"
    );
}

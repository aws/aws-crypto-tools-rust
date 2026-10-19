// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for encrypt.md#behavior, encrypt.md#get-the-encryption-materials,
//! encrypt.md#construct-the-header, and encrypt.md#output.

#[allow(clippy::duplicate_mod)]
mod fixtures;
mod test_helpers;

use aws_crypto_mpl::Error as MplError;
use aws_crypto_mpl::async_trait;
use aws_crypto_mpl::cmm::{Cmm, DefaultCmm};
use aws_crypto_mpl::cmm::{
    DecryptMaterialsInput, DecryptMaterialsOutput, GetEncryptionMaterialsInput,
    GetEncryptionMaterialsOutput,
};
use aws_esdk::types::*;
use aws_esdk::*;
use std::num::NonZeroU32;
use std::sync::Arc;
use test_helpers::*;

#[tokio::test(flavor = "multi_thread")]
async fn test_step_2_construct_header() {
    // A successful encrypt produces output starting with a valid header version byte
    // for both V1 and V2 message formats.
    let v2 = encrypt_v2(b"test step 2 v2").await;
    //= spec/client-apis/encrypt.md#construct-the-header
    //= type=test
    //= reason=Version byte on wire matches suite's message format version
    //# The [message format version](../data-format/message-header.md#supported-versions) MUST be the value associated with the [algorithm suite](../framework/algorithm-suites.md#supported-algorithm-suites).
    assert_eq!(
        v2[0], 0x02,
        "V2 output must start with header version byte 0x02"
    );

    let v1 = encrypt_v1(b"test step 2 v1").await;
    assert_eq!(
        v1[0], 0x01,
        "V1 output must start with header version byte 0x01"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_step_4_construct_signature() {
    // Encrypt with a signing suite; verify footer exists on the wire, then decrypt as corroboration.
    let keyring = test_keyring().await;
    let ct = Client::default()
        .encrypt()
        .plaintext(b"test step 4")
        .keyring(keyring.clone())
        .algorithm_suite_id(AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384)
        .send()
        .await
        .unwrap()
        .into_ciphertext();
    //= spec/client-apis/encrypt.md#behavior
    //= type=test
    //= reason=Footer is present on wire; decrypt verifies it — proves encrypt performed signature step
    //# - If the [encryption materials gathered](#get-the-encryption-materials) has a algorithm suite
    //# including a [signature algorithm](../framework/algorithm-suites.md#signature-algorithm),
    //# the Encrypt operation MUST perform this step.
    assert!(
        has_footer(&ct),
        "signing suite must produce a footer on the wire"
    );
    let pt = Client::default()
        .decrypt()
        .ciphertext(&ct)
        .keyring(keyring)
        .send()
        .await
        .unwrap()
        .into_plaintext();
    assert_eq!(pt, b"test step 4");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_no_extra_data_in_output_message() {
    // Compute the end-of-message offset by walking the frames (and the footer if a
    // signing suite is in use) and assert it equals the ciphertext length.
    let pt = b"no extra data test";

    // Case 1: V2 non-signing — body ends at the final frame.
    let ct = encrypt_without_signing_suite(pt).await;
    let frames = parse_all_frames(&ct, 4096);
    let body_end = frames.last().expect("at least one frame").end_offset;
    //= spec/client-apis/encrypt.md#behavior
    //= type=test
    //# Any data that is not specified within the [message format](../data-format/message.md)
    //# MUST NOT be added to the output message.
    assert_eq!(
        body_end,
        ct.len(),
        "V2 non-signing: ciphertext must end exactly at the final frame; trailing bytes = {}",
        ct.len() - body_end
    );

    // Case 2: V2 signing — body ends, then footer (sig_len + signature) ends at ct.len().
    let ct = encrypt_with_signing_suite(pt).await;
    let frames = parse_all_frames(&ct, 4096);
    let body_end = frames.last().expect("at least one frame").end_offset;
    let (footer_offset, sig_len) = find_footer_offset(&ct);
    assert_eq!(
        footer_offset, body_end,
        "V2 signing: footer must begin immediately after the final frame"
    );
    assert_eq!(
        footer_offset + 2 + sig_len as usize,
        ct.len(),
        "V2 signing: ciphertext must end exactly at the footer; trailing bytes = {}",
        ct.len() - (footer_offset + 2 + sig_len as usize)
    );

    // Round-trip corroboration.
    let result = round_trip(pt).await;
    assert_eq!(result, pt);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_input_suite_vs_commitment_policy_error() {
    // Non-committing suite + RequireEncryptRequireDecrypt → must fail.
    let keyring = test_keyring().await;
    let result = esdk_with(CommitmentPolicy::RequireEncryptRequireDecrypt)
        .encrypt()
        .plaintext(b"commitment check")
        .keyring(keyring)
        .algorithm_suite_id(AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256)
        .send()
        .await;
    let err = result.expect_err("encrypt must fail when input suite violates commitment policy");
    // Encrypt rejects the suite before any cryptography, with a Validation error.
    //
    //= spec/client-apis/encrypt.md#get-the-encryption-materials
    //= type=test
    //# If an [input algorithm suite](#algorithm-suite) is provided
    //# that is not supported by the [commitment policy](client.md#commitment-policy)
    //# configured in the [client](client.md) encrypt MUST yield an error.
    //
    //= spec/client-apis/encrypt.md#get-the-encryption-materials
    //= type=test
    //= reason=Test sets commitment_policy on the client; policy-violation error proves it was passed
    //# - Commitment Policy: This MUST be the [commitment policy](client.md#commitment-policy) configured in the [client](client.md) exposing this encrypt function.
    assert!(
        err.is_validation(),
        "expected Validation error, got: {err:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_obtain_materials_from_cmm() {
    // A successful encrypt proves materials were obtained from the CMM.
    // (The spy-CMM tests in this file directly prove the CMM was called with
    // expected fields; this test provides regression coverage for the basic path.)
    let pt = b"obtain materials test";
    let output = encrypt_default(pt).await;
    assert!(
        !output.ciphertext().is_empty(),
        "encrypt must produce ciphertext from CMM-provided materials"
    );
    // Regression coverage for the basic keyring->materials path. The "a supplied keyring
    // MUST use a default CMM" requirement is proven by the cross-compat test in
    // test_keyring_to_default_cmm.rs (test_keyring_constructs_default_cmm_for_encrypt);
    // a bare encrypt-success here cannot distinguish a default CMM from any other CMM.
    // The output algorithm suite comes from encryption materials; verify it is a valid ESDK suite.
    // The default CMM selects AlgAes256GcmHkdfSha512CommitKeyEcdsaP384 when no suite is specified.
    //= spec/client-apis/encrypt.md#get-the-encryption-materials
    //= type=test
    //= reason=output algorithm suite is taken from the CMM-returned materials
    //# To construct the [encrypted message](#encrypted-message),
    //# some fields MUST be constructed using information obtained
    //# from a set of valid [encryption materials](../framework/structures.md#encryption-materials).
    assert_eq!(
        output.algorithm_suite_id(),
        AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384,
        "output suite must come from encryption materials returned by the CMM"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_cmm_used_must_be_input_cmm() {
    // Wrap a real CMM in a spy, pass the spy as the input CMM, and assert the spy's
    // get_encryption_materials was invoked. This directly proves encrypt called the
    // input CMM rather than constructing some other CMM internally.
    let keyring = test_keyring().await;
    let inner_cmm = DefaultCmm::new(keyring.clone());
    let observed_suite = Arc::new(std::sync::Mutex::new(None));
    let observed_len = Arc::new(std::sync::Mutex::new(None));
    let spy = SpyCmm {
        inner: inner_cmm,
        observed_algorithm_suite_id: observed_suite.clone(),
        observed_max_plaintext_length: observed_len.clone(),
    };
    let pt = b"input cmm test";
    let ct = Client::default()
        .encrypt()
        .plaintext(pt)
        .cmm(spy)
        .send()
        .await
        .unwrap()
        .into_ciphertext();

    //= spec/client-apis/encrypt.md#get-the-encryption-materials
    //= type=test
    //= reason=spy CMM recorded its get_encryption_materials call
    //# This operation MUST obtain this set of [encryption materials](../framework/structures.md#encryption-materials)
    //# by calling [Get Encryption Materials](../framework/cmm-interface.md#get-encryption-materials) on a [CMM](../framework/cmm-interface.md).
    //
    //= spec/client-apis/encrypt.md#get-the-encryption-materials
    //= type=test
    //= reason=Spy wrapping the input CMM recorded its get_encryption_materials call, proving the input CMM was used
    //# The CMM used MUST be the input CMM, if supplied.
    assert!(
        observed_len.lock().unwrap().is_some(),
        "encrypt must call get_encryption_materials on the input CMM"
    );

    // Round-trip corroboration.
    assert_eq!(
        Client::default()
            .decrypt()
            .ciphertext(&ct)
            .keyring(keyring)
            .send()
            .await
            .unwrap()
            .into_plaintext(),
        pt
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_cmm_request_encryption_context() {
    // Encrypt with a non-empty encryption context and verify it appears in the output.
    let keyring = test_keyring().await;
    let ec = fixtures::ec_of(&[("mykey", "myval")]);
    let output = Client::default()
        .encrypt()
        .plaintext(b"ec test")
        .set_encryption_context(Some(ec.clone()))
        .keyring(keyring.clone())
        .send()
        .await
        .unwrap();
    //= spec/client-apis/encrypt.md#get-the-encryption-materials
    //= type=test
    //# - Encryption Context: If provided, this MUST be the [input encryption context](#encryption-context).
    assert!(
        output.encryption_context().contains_key("mykey"),
        "output encryption context must contain the input key"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_cmm_request_empty_encryption_context() {
    // Encrypt with no encryption context; verify no user-provided keys in output.
    let pt = b"empty ec test";
    let output = encrypt_default(pt).await;
    let decrypted = decrypt_ciphertext(output.ciphertext()).await;
    assert_eq!(
        decrypted.plaintext(),
        pt,
        "round-trip must recover original plaintext"
    );
    //= spec/client-apis/encrypt.md#get-the-encryption-materials
    //= type=test
    //# Otherwise, this MUST be an empty encryption context.
    assert!(
        !output
            .encryption_context()
            .iter()
            .any(|(k, _)| !k.starts_with("aws-crypto-")),
        "output encryption context must not contain user-provided keys when input EC is empty"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_cmm_request_algorithm_suite_provided() {
    // Encrypt with a specific algorithm suite and verify the output uses it.
    let keyring = test_keyring().await;
    let output = Client::default()
        .encrypt()
        .plaintext(b"suite test")
        .keyring(keyring)
        .algorithm_suite_id(AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey)
        .send()
        .await
        .unwrap();
    //= spec/client-apis/encrypt.md#get-the-encryption-materials
    //= type=test
    //# - Algorithm Suite: If provided, this MUST be the [input algorithm suite](#algorithm-suite).
    assert_eq!(
        output.algorithm_suite_id(),
        AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey,
        "output algorithm suite must match the input algorithm suite"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_suite_from_materials_used() {
    // Encrypt with a specific suite and verify the output reports the same suite.
    let keyring = test_keyring().await;
    let output = Client::default()
        .encrypt()
        .plaintext(b"suite from materials")
        .keyring(keyring)
        .algorithm_suite_id(AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey)
        .send()
        .await
        .unwrap();
    //= spec/client-apis/encrypt.md#get-the-encryption-materials
    //= type=test
    //# The [algorithm suite](../framework/algorithm-suites.md) used in all aspects of this operation
    //# MUST be the algorithm suite in the [encryption materials](../framework/structures.md#encryption-materials)
    //# returned from the [Get Encryption Materials](../framework/cmm-interface.md#get-encryption-materials) call.
    assert_eq!(
        output.algorithm_suite_id(),
        AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey
    );
}

/// CMM that forwards to a default CMM, then republishes the materials with the
/// first encrypted data key duplicated.
///
/// The native MPL has no multi-keyring, so a keyring can only ever produce one
/// EDK. Returning two from a caller-implemented CMM is the only way to drive the
/// ESDK's maximum-EDK check on encrypt.
#[derive(Clone)]
struct DuplicateEdkCmm {
    inner: DefaultCmm,
}

#[async_trait]
impl Cmm for DuplicateEdkCmm {
    async fn get_encryption_materials(
        &self,
        request: GetEncryptionMaterialsInput,
    ) -> Result<GetEncryptionMaterialsOutput, MplError> {
        let materials = self
            .inner
            .get_encryption_materials()
            .set_encryption_context(Some(request.encryption_context().clone()))
            .commitment_policy(request.commitment_policy())
            .set_algorithm_suite_id(request.algorithm_suite_id())
            .set_required_encryption_context_keys(Some(
                request.required_encryption_context_keys().clone(),
            ))
            .set_max_plaintext_length(request.max_plaintext_length())
            .send()
            .await?
            .into_encryption_materials();
        let Some(first) = materials.encrypted_data_keys().first().cloned() else {
            return Err(MplError::validation(
                "inner CMM returned no encrypted data keys",
            ));
        };
        let materials = materials.add_encrypted_data_key(first)?;
        GetEncryptionMaterialsOutput::builder()
            .encryption_materials(materials)
            .build()
    }

    async fn decrypt_materials(
        &self,
        request: DecryptMaterialsInput,
    ) -> Result<DecryptMaterialsOutput, MplError> {
        self.inner
            .decrypt_materials()
            .algorithm_suite_id(request.algorithm_suite_id())
            .commitment_policy(request.commitment_policy())
            .set_encrypted_data_keys(Some(request.encrypted_data_keys().to_vec()))
            .set_encryption_context(Some(request.encryption_context().clone()))
            .set_reproduced_encryption_context(request.reproduced_encryption_context().cloned())
            .send()
            .await
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_max_edk_exceeded_error() {
    // The CMM returns 2 EDKs; the client allows at most 1.
    let cmm = DuplicateEdkCmm {
        inner: DefaultCmm::new(test_keyring().await),
    };
    let err = esdk_with_max_edks(1)
        .encrypt()
        .plaintext(b"max edk test")
        .cmm(cmm.clone())
        .send()
        .await
        .expect_err("encrypt must fail when EDK count exceeds max");

    //= spec/client-apis/encrypt.md#get-the-encryption-materials
    //= type=test
    //# If the number of [encrypted data keys](../framework/structures.md#encrypted-data-keys) on the [encryption materials](../framework/structures.md#encryption-materials)
    //# is greater than the [maximum number of encrypted data keys](client.md#maximum-number-of-encrypted-data-keys) configured in the [client](client.md) encrypt MUST yield an error.
    assert!(
        err.is_validation(),
        "expected Validation error, got: {err:?}"
    );

    // The same CMM under a maximum of 2 encrypts, so the failure above is the
    // maximum-EDK check and not the extra EDK being rejected some other way.
    assert!(
        esdk_with_max_edks(2)
            .encrypt()
            .plaintext(b"max edk test")
            .cmm(cmm)
            .send()
            .await
            .is_ok(),
        "2 EDKs must encrypt when the configured maximum is 2"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_encrypt_data_key_derived_from_plaintext_data_key() {
    // Decrypt re-derives the same key from the plaintext data key; success proves
    // encrypt used the correctly derived data key.
    let pt = b"derived data key test";
    let result = round_trip(pt).await;
    //= spec/client-apis/encrypt.md#get-the-encryption-materials
    //= type=test
    //= reason=Decrypt re-derives the same key; mismatch would cause decryption failure
    //# The data key used as input for all encryption described below MUST be a data key derived from the plaintext data key
    //# included in the [encryption materials](../framework/structures.md#encryption-materials).
    assert_eq!(result, pt);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_frame_length_input_used() {
    // Encrypt with a custom frame length and verify the header records that exact value.
    let keyring = test_keyring().await;
    let ct = Client::default()
        .encrypt()
        .plaintext(b"custom frame length")
        .keyring(keyring.clone())
        .frame_length(NonZeroU32::new(512).unwrap())
        .send()
        .await
        .unwrap()
        .into_ciphertext();

    let fields = parse_v2_header_field_offsets(&ct);
    let (_, fl_start, fl_end) = fields
        .iter()
        .find(|(n, _, _)| *n == "Frame Length")
        .expect("V2 header must have a Frame Length field");
    assert_eq!(fl_end - fl_start, 4, "frame_length field must be 4 bytes");
    let on_wire = u32::from_be_bytes([
        ct[*fl_start],
        ct[fl_start + 1],
        ct[fl_start + 2],
        ct[fl_start + 3],
    ]);
    //= spec/client-apis/encrypt.md#get-the-encryption-materials
    //= type=test
    //# The frame length used in the procedures described below MUST be the input [frame length](#frame-length),
    //# if supplied.
    assert_eq!(
        on_wire, 512,
        "header frame_length must equal the input frame length"
    );

    let result = Client::default()
        .decrypt()
        .ciphertext(&ct)
        .keyring(keyring)
        .send()
        .await
        .unwrap();
    assert_eq!(result.plaintext(), b"custom frame length");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_default_frame_length_used() {
    // Encrypt without specifying a frame length and verify the header records the default (4096).
    let pt = b"default frame length test";
    let ct = encrypt_default(pt).await.into_ciphertext();

    let fields = parse_v2_header_field_offsets(&ct);
    let (_, fl_start, fl_end) = fields
        .iter()
        .find(|(n, _, _)| *n == "Frame Length")
        .expect("V2 header must have a Frame Length field");
    assert_eq!(fl_end - fl_start, 4, "frame_length field must be 4 bytes");
    let on_wire = u32::from_be_bytes([
        ct[*fl_start],
        ct[fl_start + 1],
        ct[fl_start + 2],
        ct[fl_start + 3],
    ]);
    //= spec/client-apis/encrypt.md#get-the-encryption-materials
    //= type=test
    //# If no input frame length is supplied, the default frame length MUST be used.
    assert_eq!(
        on_wire, 4096,
        "default frame_length on the wire must be 4096"
    );

    // Round-trip corroboration.
    let result = round_trip(pt).await;
    assert_eq!(result, pt);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_message_format_version_matches_suite() {
    // Encrypt with a V2 (committing) suite and verify the first byte is 0x02 (version 2).
    let keyring = test_keyring().await;
    let ct = Client::default()
        .encrypt()
        .plaintext(b"version test")
        .keyring(keyring.clone())
        .algorithm_suite_id(AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey)
        .send()
        .await
        .unwrap()
        .into_ciphertext();
    //= spec/client-apis/encrypt.md#construct-the-header
    //= type=test
    //# The [message format version](../data-format/message-header.md#supported-versions) MUST be the value associated with the [algorithm suite](../framework/algorithm-suites.md#supported-algorithm-suites).
    assert_eq!(
        ct[0], 0x02,
        "V2 committing suite must produce message version 2"
    );

    // Encrypt with a V1 (non-committing) suite and verify the first byte is 0x01 (version 1).
    let ct_v1 = esdk_v1()
        .encrypt()
        .plaintext(b"version test v1")
        .keyring(keyring)
        .algorithm_suite_id(AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256)
        .send()
        .await
        .unwrap()
        .into_ciphertext();
    assert_eq!(
        ct_v1[0], 0x01,
        "V1 non-committing suite must produce message version 1"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_output_includes_encrypted_message() {
    let output = encrypt_default(b"output encrypted message test").await;
    //= spec/client-apis/encrypt.md#output
    //= type=test
    //# - Encrypt operation output MUST include an [encrypted message](#encrypted-message) value.
    assert!(
        !output.ciphertext().is_empty(),
        "output must include non-empty encrypted message"
    );
    //= spec/client-apis/encrypt.md#encrypted-message
    //= type=test
    //# This MUST be a sequence of bytes
    //# and conform to the [message format specification](../data-format/message.md).
    assert!(
        output.ciphertext()[0] == 0x01 || output.ciphertext()[0] == 0x02,
        "first byte must be a valid ESDK version (0x01 or 0x02), got {:#04x}",
        output.ciphertext()[0]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_output_includes_encryption_context() {
    let keyring = test_keyring().await;
    let ec = fixtures::ec_of(&[("testkey", "testval")]);
    let output = Client::default()
        .encrypt()
        .plaintext(b"output ec test")
        .set_encryption_context(Some(ec))
        .keyring(keyring)
        .send()
        .await
        .unwrap();
    //= spec/client-apis/encrypt.md#output
    //= type=test
    //# - Encrypt operation output MUST include an [encryption context](#encryption-context) value.
    assert!(
        output.encryption_context().contains_key("testkey"),
        "output must include the encryption context"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_output_includes_algorithm_suite() {
    let keyring = test_keyring().await;
    let output = Client::default()
        .encrypt()
        .plaintext(b"output suite test")
        .keyring(keyring)
        .algorithm_suite_id(AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey)
        .send()
        .await
        .unwrap();
    //= spec/client-apis/encrypt.md#output
    //= type=test
    //# - Encrypt operation output MUST include an [algorithm suite](#algorithm-suite) value.
    //
    //= spec/client-apis/encrypt.md#algorithm-suite-1
    //= type=test
    //# This algorithm suite MUST be [supported for the ESDK](../framework/algorithm-suites.md#supported-algorithm-suites-enum).
    assert_eq!(
        output.algorithm_suite_id(),
        AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey,
        "output must include the algorithm suite"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_reserved_encryption_context_prefix_must_fail() {
    let keyring = test_keyring().await;
    let ec = fixtures::ec_of(&[("aws-crypto-foo", "bar")]);
    let result = Client::default()
        .encrypt()
        .plaintext(b"should fail")
        .set_encryption_context(Some(ec))
        .keyring(keyring)
        .send()
        .await;
    let err =
        result.expect_err("encrypt must fail when encryption context has aws-crypto- prefix key");
    //= spec/client-apis/encrypt.md#encryption-context
    //= type=test
    //# If the input encryption context contains any entries with a key beginning with `aws-crypto-`,
    //# the encryption operation MUST fail.
    assert!(
        err.is_validation(),
        "expected Validation error, got: {err:?}"
    );
}

// Boundary: `aws-crypto` without the trailing dash MUST be accepted.
#[tokio::test(flavor = "multi_thread")]
async fn test_reserved_encryption_context_prefix_boundary_no_dash() {
    // Proves only 'aws-crypto-' (with dash) is reserved; 'aws-crypto' alone is valid.
    let keyring = test_keyring().await;
    let ec = fixtures::ec_of(&[("aws-crypto", "bar")]);
    let result = Client::default()
        .encrypt()
        .plaintext(b"should succeed")
        .set_encryption_context(Some(ec))
        .keyring(keyring)
        .send()
        .await;
    assert!(
        result.is_ok(),
        "encrypt must accept key 'aws-crypto' (no trailing dash): only 'aws-crypto-' is reserved, got: {:?}",
        result.err()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_algorithm_suite_used_for_encryption() {
    let keyring = test_keyring().await;
    let output = Client::default()
        .encrypt()
        .plaintext(b"suite used test")
        .keyring(keyring.clone())
        .algorithm_suite_id(AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey)
        .send()
        .await
        .unwrap();
    //= spec/client-apis/encrypt.md#algorithm-suite
    //= type=test
    //# The [algorithm suite](../framework/algorithm-suites.md) that MUST be used for encryption.
    assert_eq!(
        output.algorithm_suite_id(),
        AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey,
        "the specified algorithm suite must be used for encryption"
    );
    // Verify round-trip to prove the suite was actually used for encryption
    let pt = Client::default()
        .decrypt()
        .ciphertext(output.ciphertext())
        .keyring(keyring)
        .send()
        .await
        .unwrap()
        .into_plaintext();
    assert_eq!(pt, b"suite used test");
}

// Spy CMM that records what inputs it received, then delegates to a real CMM.
struct SpyCmm {
    inner: DefaultCmm,
    observed_algorithm_suite_id:
        Arc<std::sync::Mutex<Option<Option<aws_crypto_mpl::types::AlgorithmSuiteId>>>>,
    observed_max_plaintext_length: Arc<std::sync::Mutex<Option<Option<i64>>>>,
}

#[async_trait]
impl Cmm for SpyCmm {
    async fn get_encryption_materials(
        &self,
        request: GetEncryptionMaterialsInput,
    ) -> Result<GetEncryptionMaterialsOutput, MplError> {
        // Record observations from the request the ESDK constructed.
        *self.observed_algorithm_suite_id.lock().unwrap() = Some(request.algorithm_suite_id());
        *self.observed_max_plaintext_length.lock().unwrap() =
            Some(request.max_plaintext_length().map(|len| len as i64));

        self.inner
            .get_encryption_materials()
            .set_encryption_context(Some(request.encryption_context().clone()))
            .commitment_policy(request.commitment_policy())
            .set_algorithm_suite_id(request.algorithm_suite_id())
            .set_required_encryption_context_keys(Some(
                request.required_encryption_context_keys().clone(),
            ))
            .set_max_plaintext_length(request.max_plaintext_length())
            .send()
            .await
    }

    async fn decrypt_materials(
        &self,
        request: DecryptMaterialsInput,
    ) -> Result<DecryptMaterialsOutput, MplError> {
        self.inner
            .decrypt_materials()
            .algorithm_suite_id(request.algorithm_suite_id())
            .commitment_policy(request.commitment_policy())
            .set_encrypted_data_keys(Some(request.encrypted_data_keys().to_vec()))
            .set_encryption_context(Some(request.encryption_context().clone()))
            .set_reproduced_encryption_context(request.reproduced_encryption_context().cloned())
            .send()
            .await
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_cmm_request_no_algorithm_suite_field() {
    // Spy CMM observes algorithm_suite_id is None when caller omits it.
    let keyring = test_keyring().await;
    let inner_cmm = DefaultCmm::new(keyring.clone());
    let observed_suite = std::sync::Arc::new(std::sync::Mutex::new(None));
    let observed_len = std::sync::Arc::new(std::sync::Mutex::new(None));
    let cmm_ref = SpyCmm {
        inner: inner_cmm,
        observed_algorithm_suite_id: observed_suite.clone(),
        observed_max_plaintext_length: observed_len.clone(),
    };

    let pt = b"no suite spy test";
    let output = Client::default()
        .encrypt()
        .plaintext(pt)
        .cmm(cmm_ref)
        .send()
        .await
        .unwrap();

    // Verify spy observed None for algorithm_suite_id
    let observed = *observed_suite.lock().unwrap();
    //= spec/client-apis/encrypt.md#get-the-encryption-materials
    //= type=test
    //= reason=Spy CMM directly observes the call was constructed with expected fields
    //# The call to [Get Encryption Materials](../framework/cmm-interface.md#get-encryption-materials)
    //# on that CMM MUST be constructed as follows:
    //
    //= spec/client-apis/encrypt.md#get-the-encryption-materials
    //= type=test
    //= reason=Spy CMM observes algorithm_suite_id is None when caller omits it
    //# If no Algorithm Suite is provided, this field MUST NOT be included.
    assert_eq!(
        observed,
        Some(None),
        "CMM must receive algorithm_suite_id=None when caller omits it"
    );

    // Round-trip corroboration
    assert_eq!(
        Client::default()
            .decrypt()
            .ciphertext(output.ciphertext())
            .keyring(keyring)
            .send()
            .await
            .unwrap()
            .into_plaintext(),
        pt
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_cmm_request_max_plaintext_length_equals_input() {
    // Spy CMM observes max_plaintext_length equals input plaintext length.
    let keyring = test_keyring().await;
    let inner_cmm = DefaultCmm::new(keyring.clone());
    let observed_suite = std::sync::Arc::new(std::sync::Mutex::new(None));
    let observed_len = std::sync::Arc::new(std::sync::Mutex::new(None));
    let cmm_ref = SpyCmm {
        inner: inner_cmm,
        observed_algorithm_suite_id: observed_suite.clone(),
        observed_max_plaintext_length: observed_len.clone(),
    };

    let pt = b"spy plaintext 23 bytes!"; // 23 bytes
    Client::default()
        .encrypt()
        .plaintext(pt)
        .cmm(cmm_ref)
        .send()
        .await
        .unwrap();

    // Verify spy observed max_plaintext_length == plaintext.len()
    let observed = *observed_len.lock().unwrap();
    //= spec/client-apis/encrypt.md#get-the-encryption-materials
    //= type=test
    //= reason=Spy CMM observes max_plaintext_length equals input plaintext length
    //# - Max Plaintext Length: If the [input plaintext](#plaintext) has known length,
    //# this length MUST be used.
    assert_eq!(
        observed,
        Some(Some(
            i64::try_from(pt.len()).expect("test plaintext fits in i64")
        )),
        "CMM must receive max_plaintext_length equal to input plaintext length"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_step_failure_must_halt_and_indicate_failure() {
    // Non-committing suite + RequireEncryptRequireDecrypt causes step 1 to fail.
    let keyring = test_keyring().await;
    let result = esdk_with(CommitmentPolicy::RequireEncryptRequireDecrypt)
        .encrypt()
        .plaintext(b"halt test")
        .keyring(keyring)
        .algorithm_suite_id(AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256)
        .send()
        .await;
    let err = result.expect_err("encrypt must halt and indicate failure when a step fails");
    // The failing step is the commitment policy check, which returns Validation.
    assert!(
        err.is_validation(),
        "expected Validation error, got: {err:?}"
    );
    //= spec/client-apis/encrypt.md#behavior
    //= type=test
    //# If any of these steps fails, this operation MUST halt and indicate a failure to the caller.
}

#[tokio::test(flavor = "multi_thread")]
async fn test_plaintext_length_bound_used_for_unknown_length() {
    // A spy CMM records the max_plaintext_length it receives. For an unknown-length
    // stream with data_size=Some(100), the bound (100) must reach the CMM.
    let keyring = test_keyring().await;
    let inner_cmm = DefaultCmm::new(keyring);
    let observed_len = std::sync::Arc::new(std::sync::Mutex::new(None));
    let cmm_ref = SpyCmm {
        inner: inner_cmm,
        observed_algorithm_suite_id: std::sync::Arc::new(std::sync::Mutex::new(None)),
        observed_max_plaintext_length: observed_len.clone(),
    };
    //= spec/client-apis/encrypt.md#input
    //= type=test
    //= reason=data_size sets the optional Plaintext Length Bound; the spy below confirms it reaches the CMM
    //# If the [plaintext](#plaintext) is of unknown length, the caller MAY also input a
    //# [Plaintext Length Bound](#plaintext-length-bound).

    let plaintext = vec![0xAAu8; 50];
    let mut reader = std::io::Cursor::new(&plaintext);
    let mut output = Vec::new();
    Client::default()
        .encrypt_stream()
        .cmm(cmm_ref)
        .data_size(100)
        .plaintext(&mut reader)
        .ciphertext(&mut output)
        .send()
        .await
        .unwrap();

    let observed = *observed_len.lock().unwrap();
    //= spec/client-apis/encrypt.md#get-the-encryption-materials
    //= type=test
    //= reason=Spy CMM observes max_plaintext_length == 100, the Plaintext Length Bound for the unknown-length stream
    //# If the input [plaintext](#plaintext) has unknown length and a [Plaintext Length Bound](#plaintext-length-bound)
    //# was provided, this MUST be the [Plaintext Length Bound](#plaintext-length-bound).
    assert_eq!(
        observed,
        Some(Some(100)),
        "CMM must receive max_plaintext_length == the Plaintext Length Bound (100)"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_no_plaintext_length_bound_field_not_included() {
    // A spy CMM records the max_plaintext_length it receives. For an unknown-length
    // stream with data_size=None, no bound must reach the CMM (the field is omitted).
    let keyring = test_keyring().await;
    let inner_cmm = DefaultCmm::new(keyring);
    let observed_len = std::sync::Arc::new(std::sync::Mutex::new(None));
    let cmm_ref = SpyCmm {
        inner: inner_cmm,
        observed_algorithm_suite_id: std::sync::Arc::new(std::sync::Mutex::new(None)),
        observed_max_plaintext_length: observed_len.clone(),
    };
    let plaintext = vec![0xBBu8; 50];
    let mut reader = std::io::Cursor::new(&plaintext);
    let mut output = Vec::new();
    Client::default()
        .encrypt_stream()
        .cmm(cmm_ref)
        .plaintext(&mut reader)
        .ciphertext(&mut output)
        .send()
        .await
        .unwrap();

    let observed = *observed_len.lock().unwrap();
    //= spec/client-apis/encrypt.md#get-the-encryption-materials
    //= type=test
    //= reason=Spy CMM observes max_plaintext_length is None when no Plaintext Length Bound is provided
    //# If no Plaintext Length Bound is provided, this field MUST NOT be included.
    assert_eq!(
        observed,
        Some(None),
        "CMM must receive max_plaintext_length=None when no bound is provided"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_streaming_header_released_after_serialization() {
    // encrypt_stream writes header before body; output starts with valid version byte.
    let keyring = test_keyring().await;
    let plaintext = vec![0xCCu8; 20];
    let mut reader = std::io::Cursor::new(&plaintext);
    let mut output = Vec::new();
    Client::default()
        .encrypt_stream()
        .keyring(keyring.clone())
        .data_size(20)
        .plaintext(&mut reader)
        .ciphertext(&mut output)
        .send()
        .await
        .unwrap();

    // Regression coverage: streaming output begins with a valid header version byte. This
    // does NOT prove the "header MUST be released" timing requirement (a buffer-everything
    // implementation would pass identically), so it carries no type=test. The release
    // behavior is annotated on the source side (write_header in encrypt.rs).
    assert!(
        output[0] == 0x01 || output[0] == 0x02,
        "streaming output must begin with a valid version byte"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_message_bodies_not_equal_must_fail() {
    // Tamper encrypted body content; AES-GCM auth failure proves body integrity.
    let pt = b"body equality test";
    let valid_ct = encrypt_without_signing_suite(pt).await;
    let keyring = test_keyring().await;

    let body_start = find_body_start(&valid_ct, 4096).expect("body start");
    let content_off = body_start + 4 + 4 + IV_LEN + 4;
    let mut tampered_ct = valid_ct.clone();
    tampered_ct[content_off] ^= 0xFF;
    assert_ne!(
        tampered_ct[content_off], valid_ct[content_off],
        "tamper must change the byte"
    );

    // Regression coverage: the encrypted body is authenticated, so tampering ciphertext
    // content is rejected on decrypt. NOTE: this does NOT prove the encrypt-side
    // "message bodies not equal MUST fail" requirement (it observes decrypt-side AES-GCM
    // auth, not an encrypt comparison). That requirement is annotated type=implication in
    // encrypt.rs (the body is written directly to the output, so inequality is impossible).
    assert!(
        Client::default()
            .decrypt()
            .ciphertext(&valid_ct)
            .keyring(keyring.clone())
            .send()
            .await
            .is_ok(),
        "valid ct must decrypt"
    );
    assert!(
        Client::default()
            .decrypt()
            .ciphertext(&tampered_ct)
            .keyring(keyring)
            .send()
            .await
            .unwrap_err()
            .is_cryptographic(),
        "tampered body content must produce Cryptographic error"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_must_not_encrypt_using_nonframed_content_type() {
    // Verify content type byte on the wire is 0x02 (Framed) for both V1 and V2.
    for version in VERSIONS {
        let keyring = test_keyring().await;
        let ct = encrypt_with_version(b"nonframed test", version, keyring).await;
        let content_type_byte = match version {
            Version::V1 => {
                let (ct_offset, _, _, _) = parse_v1_trailing_offsets(&ct);
                ct[ct_offset]
            }
            Version::V2 => {
                let ct_offset = content_type_offset_v2(&ct);
                ct[ct_offset]
            }
        };
        //= spec/client-apis/encrypt.md#nonframed-message-body-encryption
        //= type=test
        //= reason=On-wire content type byte is 0x02 (Framed), proving nonframed is never used
        //# Implementations of the AWS Encryption SDK MUST NOT encrypt using the nonframed content type.
        assert_eq!(
            content_type_byte, 0x02,
            "{version:?}: content type must be 0x02 (Framed), not 0x01 (Non-framed)"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_frame_fields_serialized_per_spec() {
    // A 25-byte plaintext at frame_length=10 under a non-signing suite yields a
    // deterministic, footer-free structure: 2 regular frames (seq 1, 2; 10 bytes each)
    // + 1 final frame (seq 3; 5 bytes). Each field below is read independently from the
    // wire, so a mis-serialized frame field would change the observed value.
    let pt: &[u8] = b"frame field serialization";
    assert_eq!(pt.len(), 25, "test relies on a 25-byte plaintext");
    let ct = encrypt_nonsigning_with_frame_length(pt, 10).await;

    let frames = parse_all_frames(&ct, 10);
    //= spec/client-apis/encrypt.md#construct-a-frame
    //= type=test
    //= reason=Walking the wire yields exactly the regular+final frames the framing requires
    //# The Encrypt operation MUST serialize a regular frame or final frame with the following specifics:
    assert_eq!(
        frames.len(),
        3,
        "25 bytes / frame_length 10 must produce 3 frames"
    );

    // Frames 1-2 of 3: regular frames — sequence numbers read from the wire must be 1 then 2.
    //= spec/client-apis/encrypt.md#construct-a-frame
    //= type=test
    //= reason=On-wire sequence numbers and per-frame layout match the Regular Frame spec
    //# Regular frame serialization MUST conform to the [Regular Frame](../data-format/message-body.md#regular-frame) specification.
    //
    //= spec/client-apis/encrypt.md#construct-a-frame
    //= type=test
    //= reason=seq_num/IV/tag are read from wire offsets and checked against the regular-frame layout
    //# For a regular frame, each field MUST be serialized according to its specification:
    assert!(
        !frames[0].is_final && !frames[1].is_final,
        "first two frames must be regular"
    );
    assert_eq!(
        frames[0].seq_num, 1,
        "first regular frame sequence number must be 1"
    );
    assert_eq!(
        frames[1].seq_num, 2,
        "second regular frame sequence number must be 2"
    );
    assert_eq!(
        frames[0].iv.len(),
        IV_LEN,
        "regular frame IV must be IV_LEN bytes"
    );
    assert_eq!(
        frames[0].tag.len(),
        TAG_LEN,
        "regular frame tag must be TAG_LEN bytes"
    );

    // Frame 3 of 3: final frame — ENDFRAME marker and on-wire content length read from the wire.
    let final_frame = &frames[2];
    //= spec/client-apis/encrypt.md#construct-a-frame
    //= type=test
    //= reason=ENDFRAME sentinel and final-frame layout are read from the wire
    //# Final frame serialization MUST conform to the [Final Frame](../data-format/message-body.md#final-frame) specification.
    //
    //= spec/client-apis/encrypt.md#construct-a-frame
    //= type=test
    //= reason=Final-frame seq num and on-wire content-length field are checked against the spec
    //# For a final frame, each field MUST be serialized according to its specification:
    assert!(final_frame.is_final, "third frame must be the final frame");
    assert_eq!(
        final_frame.endframe_marker_bytes,
        Some(&ENDFRAME_MARKER[..]),
        "final frame must carry the ENDFRAME sequence-number-end marker"
    );
    assert_eq!(
        final_frame.seq_num, 3,
        "final frame sequence number must be 3"
    );
    assert_eq!(
        final_frame.content_length, 5,
        "final frame on-wire content length must be 5"
    );

    // Round-trip corroboration.
    let decrypted = decrypt_ciphertext(&ct).await.into_plaintext();
    assert_eq!(decrypted, pt, "round-trip must recover the plaintext");
}

// TODO(native-mpl): DBE suites not modeled
// #[test]
// fn test_non_esdk_materials_suite_yields_error() {
//     // The ESDK-support guard that encrypt applies to the retrieved materials suite
//     // (get_esdk_algorithm_suite_id) must reject a non-ESDK (DBE) algorithm suite.
//     use aws_esdk::__test_internals::get_esdk_algorithm_suite_id;
//
//     let non_esdk = aws_mpl_legacy::suites::AlgorithmSuiteId::Dbe(
//         aws_mpl_legacy::suites::DbeAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeySymsigHmacSha384,
//     );
//     let err = get_esdk_algorithm_suite_id(non_esdk)
//         .expect_err("non-ESDK materials suite must be rejected");
//     assert_eq!(
//         err.kind,
//         ErrorKind::Internal,
//         "non-ESDK materials suite must yield an error, got: {err:?}"
//     );
// }

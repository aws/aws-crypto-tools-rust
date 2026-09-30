// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Test: the algorithm suite in the retrieved encryption materials MAY be
//! different from the input algorithm suite (encrypt.md#get-the-encryption-materials).

#[allow(clippy::duplicate_mod)]
mod fixtures;
mod test_helpers;

use async_trait::async_trait;
use aws_crypto_mpl::cmm::{Cmm, DecryptMaterialsRequest, DefaultCmm, EncryptionMaterialsRequest};
use aws_crypto_mpl::keyring::RawAesKeyring;
use aws_crypto_mpl::structures::{DecryptionMaterials, EncryptionMaterials, MaterialsError};
use aws_esdk::*;
use aws_mpl_primitives::AesGcm;
use fixtures::*;

// Wraps a real CMM but forces a different algorithm suite on encrypt.
struct SuiteOverrideCmm {
    inner: DefaultCmm,
    suite: AlgorithmSuiteId,
}

#[async_trait]
impl Cmm for SuiteOverrideCmm {
    async fn get_encryption_materials(
        &self,
        request: EncryptionMaterialsRequest,
    ) -> Result<EncryptionMaterials, MaterialsError> {
        // Rebuild the inner request, replacing the caller's requested suite
        // with the CMM's chosen suite while carrying the remaining fields
        // through unchanged. The inner default CMM then produces materials
        // bound to the overridden suite.
        let mut inner_request = EncryptionMaterialsRequest::new(
            request.encryption_context().clone(),
            request.commitment_policy(),
        )
        .with_algorithm_suite_id(aws_crypto_mpl::structures::AlgorithmSuiteId::Esdk(
            self.suite,
        ));
        if let Some(keys) = request.required_encryption_context_keys() {
            inner_request = inner_request.with_required_encryption_context_keys(keys.clone());
        }
        if let Some(len) = request.max_plaintext_length() {
            inner_request = inner_request.with_max_plaintext_length(len);
        }
        self.inner.get_encryption_materials(inner_request).await
    }

    async fn decrypt_materials(
        &self,
        request: DecryptMaterialsRequest,
    ) -> Result<DecryptionMaterials, MaterialsError> {
        self.inner.decrypt_materials(request).await
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_encrypt_uses_cmm_suite_not_input_suite() {
    // CMM overrides caller's suite; output reflects CMM's choice, not caller's.
    let (ns, name) = namespace_and_name(0);
    let keyring = RawAesKeyring::builder()
        .key_namespace(ns)
        .key_name(name)
        .wrapping_key(vec![0u8; 32])
        .wrapping_alg(AesGcm::Aes256Gcm)
        .build()
        .expect("raw AES keyring construction must succeed for test key material");

    // The CMM always resolves to a committing-only suite, ignoring the
    // caller's requested suite, over a default CMM backed by the raw AES keyring.
    let cmm = SuiteOverrideCmm {
        inner: DefaultCmm::new(keyring.clone()),
        suite: AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey,
    };

    // Caller requests signing+committing, but CMM overrides to committing-only.
    let enc_input = EncryptInput::builder()
        .plaintext(b"hello")
        .cmm(cmm)
        .algorithm_suite_id(AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384)
        .build()
        .unwrap();

    let out = encrypt(&enc_input).await.unwrap();

    // Output must reflect the CMM's suite, not the caller's.
    //= spec/client-apis/encrypt.md#get-the-encryption-materials
    //= type=test
    //# Note that the algorithm suite in the retrieved encryption materials MAY be different
    //# from the [input algorithm suite](#algorithm-suite).
    assert_eq!(
        out.algorithm_suite_id,
        AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey
    );
    assert_ne!(
        out.algorithm_suite_id,
        AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384
    );

    // Round-trip to prove the ciphertext is valid.
    let dec = decrypt(
        &DecryptInput::builder()
            .ciphertext(&out.ciphertext)
            .keyring(keyring)
            .build()
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(dec.plaintext, b"hello");
    assert_eq!(
        dec.algorithm_suite_id,
        AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey
    );
}

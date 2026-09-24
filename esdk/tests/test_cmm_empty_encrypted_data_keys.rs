// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Encrypt rejects CMM materials that carry no encrypted data keys.
//!
//! Local because a caller's CMM impl is a native trait, unreachable from the
//! cross-language interop vectors.

use aws_crypto_mpl::cmm::{Cmm, DecryptMaterialsRequest, EncryptionMaterialsRequest};
use aws_crypto_mpl::structures::{
    AlgorithmSuiteId, DecryptionMaterials, EncryptionMaterials, MaterialsError, PlaintextDataKey,
};
use aws_esdk::*;
use std::collections::BTreeSet;
use std::sync::Arc;

/// A non-committing, non-signing suite, so the fabricated materials need no
/// signing key and pass under ForbidEncryptAllowDecrypt.
const SUITE: AlgorithmSuiteId = AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256;

/// A CMM that returns materials with a plaintext data key and no EDKs.
struct NoEdkCmm;

#[async_trait::async_trait]
impl Cmm for NoEdkCmm {
    async fn get_encryption_materials(
        &self,
        _request: EncryptionMaterialsRequest,
    ) -> Result<EncryptionMaterials, MaterialsError> {
        EncryptionMaterials::new(
            SUITE,
            Vec::new(),
            EncryptionContext::from([("key", "value")]),
            BTreeSet::from(["key".to_string()]),
            Some(PlaintextDataKey::new(vec![0u8; 32])),
            None,
            None,
        )
    }

    async fn decrypt_materials(
        &self,
        _request: DecryptMaterialsRequest,
    ) -> Result<DecryptionMaterials, MaterialsError> {
        unreachable!("encrypt-only test")
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypt_rejects_cmm_materials_without_encrypted_data_keys() {
    let mut input =
        EncryptInput::with_cmm(b"plaintext", EncryptionContext::new(), Arc::new(NoEdkCmm));
    input.commitment_policy = EsdkCommitmentPolicy::ForbidEncryptAllowDecrypt;
    input.algorithm_suite_id = Some(SUITE);
    let err = encrypt(&input)
        .await
        .expect_err("materials without encrypted data keys must be rejected");
    assert_eq!(err.kind, ErrorKind::ValidationError, "got: {err:?}");
    assert_eq!(
        err.message,
        "Encrypted data key count must be greater than 0"
    );
}

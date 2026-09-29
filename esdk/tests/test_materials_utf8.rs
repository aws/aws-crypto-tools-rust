// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The ESDK rejects non-UTF-8 encryption context returned by a CMM.
//!
//! The MPL models the encryption context and the required-encryption-context
//! key set as raw bytes (`BTreeMap<Vec<u8>, Vec<u8>>` and `BTreeSet<Vec<u8>>`),
//! but the ESDK message format serializes both as UTF-8 strings. A CMM is
//! caller-supplied code, so it can hand back bytes that are not UTF-8. These
//! tests pin that the ESDK errors on that input rather than silently dropping
//! the offending entry, which would change the encryption context -- and, for a
//! required key, the bytes written to the message header.
//!
//! Local because a caller's CMM impl is a native trait, unreachable from the
//! cross-language interop vectors.

#[allow(clippy::duplicate_mod)]
mod fixtures;
mod test_helpers;

use aws_crypto_mpl::cmm::{Cmm, DecryptMaterialsRequest, EncryptionMaterialsRequest};
use aws_crypto_mpl::structures::{
    AlgorithmSuiteId, DecryptionMaterials, EncryptionContext as MplEncryptionContext,
    EncryptionMaterials, MaterialsError, PlaintextDataKey,
};
use aws_esdk::*;
use std::collections::BTreeSet;

/// A non-committing, non-signing suite, so the fabricated materials below need
/// no signing or verification key and pass under ForbidEncryptAllowDecrypt.
const SUITE: AlgorithmSuiteId = AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256;

/// `0xFF` is not a valid UTF-8 byte in any position.
const BAD: &[u8] = b"\xff";

/// A CMM that returns materials whose encryption context and required-key set
/// are exactly what the test asks for, including non-UTF-8 bytes.
struct FabricatingCmm {
    encryption_context: MplEncryptionContext,
    required_keys: BTreeSet<Vec<u8>>,
}

impl FabricatingCmm {
    fn new(pairs: &[(&[u8], &[u8])], required: &[&[u8]]) -> Self {
        let mut ec = MplEncryptionContext::new();
        for (k, v) in pairs {
            ec.insert((*k).to_vec(), (*v).to_vec());
        }
        Self {
            encryption_context: ec,
            required_keys: required.iter().map(|k| (*k).to_vec()).collect(),
        }
    }
}

#[async_trait::async_trait]
impl Cmm for FabricatingCmm {
    async fn get_encryption_materials(
        &self,
        _request: EncryptionMaterialsRequest,
    ) -> Result<EncryptionMaterials, MaterialsError> {
        EncryptionMaterials::new(
            SUITE,
            Vec::new(),
            self.encryption_context.clone(),
            self.required_keys.clone(),
            Some(PlaintextDataKey::new(vec![0u8; 32])),
            None,
            None,
        )
    }

    async fn decrypt_materials(
        &self,
        _request: DecryptMaterialsRequest,
    ) -> Result<DecryptionMaterials, MaterialsError> {
        DecryptionMaterials::new(
            SUITE,
            self.encryption_context.clone(),
            self.required_keys.clone(),
            Some(PlaintextDataKey::new(vec![0u8; 32])),
            None,
            None,
        )
    }
}

/// Drive encrypt with a CMM returning the given context, and return the error.
async fn encrypt_err(pairs: &[(&[u8], &[u8])], required: &[&[u8]]) -> aws_esdk::Error {
    let cmm = FabricatingCmm::new(pairs, required);
    let input = EncryptInput::builder()
        .plaintext(b"utf8 boundary test")
        .cmm(cmm)
        .commitment_policy(EsdkCommitmentPolicy::ForbidEncryptAllowDecrypt)
        .algorithm_suite_id(SUITE)
        .build()
        .unwrap();
    encrypt(&input)
        .await
        .expect_err("non-UTF-8 encryption context must be rejected")
}

/// Drive decrypt with a CMM returning the given context, and return the error.
/// The ciphertext is a real message; the fabricated CMM replaces the materials.
async fn decrypt_err(
    ciphertext: &[u8],
    pairs: &[(&[u8], &[u8])],
    required: &[&[u8]],
) -> aws_esdk::Error {
    let cmm = FabricatingCmm::new(pairs, required);
    let input = DecryptInput::builder()
        .ciphertext(ciphertext)
        .cmm(cmm)
        .commitment_policy(EsdkCommitmentPolicy::ForbidEncryptAllowDecrypt)
        .build()
        .unwrap();
    decrypt(&input)
        .await
        .expect_err("non-UTF-8 encryption context must be rejected")
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypt_rejects_non_utf8_encryption_context_key() {
    let err = encrypt_err(&[(BAD, b"value")], &[]).await;
    assert_eq!(err.kind, ErrorKind::ValidationError, "got: {err:?}");
    assert!(
        err.message
            .contains("Encryption context key is not valid UTF-8"),
        "error must name the offending field, got: {}",
        err.message
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypt_rejects_non_utf8_encryption_context_value() {
    let err = encrypt_err(&[(b"key", BAD)], &[]).await;
    assert_eq!(err.kind, ErrorKind::ValidationError, "got: {err:?}");
    assert!(
        err.message
            .contains("Encryption context value is not valid UTF-8"),
        "error must name the offending field, got: {}",
        err.message
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypt_rejects_non_utf8_required_encryption_context_key() {
    // The MPL requires the required-key set to be a subset of the encryption
    // context keys, so the bad key appears in both. The required-key check runs
    // first, so this is the error that surfaces.
    let err = encrypt_err(&[(BAD, b"value")], &[BAD]).await;
    assert_eq!(err.kind, ErrorKind::ValidationError, "got: {err:?}");
    assert!(
        err.message
            .contains("Required encryption context key is not valid UTF-8"),
        "a non-UTF-8 required key must be reported as such, not as a plain \
         encryption context key, got: {}",
        err.message
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn decrypt_rejects_non_utf8_encryption_context_key() {
    let ciphertext = test_helpers::encrypt_v1(b"utf8 boundary test").await;
    let err = decrypt_err(&ciphertext, &[(BAD, b"value")], &[]).await;
    assert_eq!(err.kind, ErrorKind::ValidationError, "got: {err:?}");
    assert!(
        err.message
            .contains("Encryption context key is not valid UTF-8"),
        "error must name the offending field, got: {}",
        err.message
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn decrypt_rejects_non_utf8_required_encryption_context_key() {
    let ciphertext = test_helpers::encrypt_v1(b"utf8 boundary test").await;
    let err = decrypt_err(&ciphertext, &[(BAD, b"value")], &[BAD]).await;
    assert_eq!(err.kind, ErrorKind::ValidationError, "got: {err:?}");
    assert!(
        err.message
            .contains("Required encryption context key is not valid UTF-8"),
        "a non-UTF-8 required key must be reported as such, got: {}",
        err.message
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_utf8_encryption_context_passes_the_check_and_fails_later() {
    // Positive control. The same fabricating CMM with all-UTF-8 bytes must get
    // past the UTF-8 gate and fail only on its empty encrypted-data-key list,
    // which is a later check. Without this, the five tests above could be
    // passing because the fabricated materials are rejected for some reason
    // that has nothing to do with UTF-8.
    let err = encrypt_err(&[(b"key", b"value")], &[b"key"]).await;
    assert_eq!(err.kind, ErrorKind::ValidationError, "got: {err:?}");
    assert_eq!(
        err.message, "Encrypted data key count must be greater than 0",
        "an all-UTF-8 context must reach the encrypted-data-key check, got: {}",
        err.message
    );
}

// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! A misbehaving caller-implemented CMM driven through the public API, to
//! prove the operations validate CMM-returned materials rather than trusting
//! them: empty EDK lists, non-serializable encryption contexts, oversized EDK
//! fields, wrong-length data keys, and a materials suite that disagrees with
//! the message header.

// The MPL trait signatures return the large `aws_mpl_legacy` error type by value.
#![allow(clippy::result_large_err)]

#[allow(clippy::duplicate_mod)]
mod fixtures;
mod test_helpers;

use aws_esdk::*;
use aws_mpl_legacy::dafny::operation::decrypt_materials::{
    DecryptMaterialsInput, DecryptMaterialsOutput,
};
use aws_mpl_legacy::dafny::operation::get_encryption_materials::{
    GetEncryptionMaterialsInput, GetEncryptionMaterialsOutput,
};
use aws_mpl_legacy::dafny::types::cryptographic_materials_manager::{
    CryptographicMaterialsManager, CryptographicMaterialsManagerRef as LegacyCmmRef,
};
use aws_mpl_legacy::dafny::types::error::Error as MplError;
use test_helpers::test_keyring;

/// How the hostile CMM corrupts the materials it returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tamper {
    /// Return encryption materials with an empty EDK list.
    EmptyEdks,
    /// Add an encryption-context value larger than a UInt16 can describe.
    OversizedEcValue,
    /// Append an EDK whose provider info exceeds a UInt16 length.
    OversizedEdkField,
    /// Truncate the plaintext data key to 16 bytes.
    ShortDataKey,
    /// Ask the inner CMM for a different suite than the message header names
    /// (decrypt only).
    SwapSuiteId,
    /// Strip the verification key from decryption materials (decrypt only).
    StripVerificationKey,
    /// Pass through unmodified.
    None,
}

/// Wraps a real default CMM and corrupts its output per `Tamper`.
struct HostileCmm {
    inner: LegacyCmmRef,
    tamper: Tamper,
}

impl CryptographicMaterialsManager for HostileCmm {
    fn get_encryption_materials(
        &self,
        input: GetEncryptionMaterialsInput,
    ) -> Result<GetEncryptionMaterialsOutput, MplError> {
        let mut out = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                self.inner
                    .get_encryption_materials()
                    .encryption_context(input.encryption_context.unwrap())
                    .commitment_policy(input.commitment_policy.unwrap())
                    .set_algorithm_suite_id(input.algorithm_suite_id)
                    .set_max_plaintext_length(input.max_plaintext_length)
                    .send()
                    .await
            })
        })?;
        if let Some(materials) = out.encryption_materials.as_mut() {
            match self.tamper {
                Tamper::EmptyEdks => materials.encrypted_data_keys = Some(Vec::new()),
                Tamper::OversizedEcValue => {
                    if let Some(ec) = materials.encryption_context.as_mut() {
                        ec.insert("oversized".to_string(), "v".repeat(70_000));
                    }
                }
                Tamper::OversizedEdkField => {
                    let edk = aws_mpl_legacy::dafny::types::EncryptedDataKey::builder()
                        .key_provider_id("hostile")
                        .key_provider_info(aws_smithy_types::Blob::new(vec![0u8; 70_000]))
                        .ciphertext(aws_smithy_types::Blob::new(b"x".to_vec()))
                        .build()
                        .unwrap();
                    materials
                        .encrypted_data_keys
                        .get_or_insert_with(Vec::new)
                        .push(edk);
                }
                Tamper::ShortDataKey => {
                    let short = materials
                        .plaintext_data_key
                        .as_ref()
                        .map(|k| aws_smithy_types::Blob::new(k.as_ref()[..16].to_vec()));
                    materials.plaintext_data_key = short;
                }
                Tamper::SwapSuiteId | Tamper::StripVerificationKey | Tamper::None => {}
            }
        }
        Ok(out)
    }

    fn decrypt_materials(
        &self,
        input: DecryptMaterialsInput,
    ) -> Result<DecryptMaterialsOutput, MplError> {
        let requested_suite = if self.tamper == Tamper::SwapSuiteId {
            // Same AES-256 key size as the 0x0178 suite the header names, so
            // the materials stay internally consistent — only the suite
            // disagrees with the header.
            aws_mpl_legacy::dafny::types::AlgorithmSuiteId::Esdk(
                aws_mpl_legacy::dafny::types::EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf,
            )
        } else {
            input.algorithm_suite_id.unwrap()
        };
        let mut out = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                self.inner
                    .decrypt_materials()
                    .algorithm_suite_id(requested_suite)
                    .commitment_policy(input.commitment_policy.unwrap())
                    .encrypted_data_keys(input.encrypted_data_keys.unwrap())
                    .encryption_context(input.encryption_context.unwrap())
                    .set_reproduced_encryption_context(input.reproduced_encryption_context)
                    .send()
                    .await
            })
        })?;
        if let Some(materials) = out.decryption_materials.as_mut() {
            match self.tamper {
                Tamper::OversizedEcValue => {
                    if let Some(ec) = materials.encryption_context.as_mut() {
                        ec.insert("oversized".to_string(), "v".repeat(70_000));
                    }
                }
                Tamper::StripVerificationKey => materials.verification_key = None,
                _ => {}
            }
        }
        Ok(out)
    }
}

async fn hostile_cmm(tamper: Tamper) -> LegacyCmmRef {
    LegacyCmmRef::from(HostileCmm {
        inner: mpl()
            .create_default_cryptographic_materials_manager()
            .keyring(test_keyring().await)
            .send()
            .await
            .unwrap(),
        tamper,
    })
}

// A CMM that returns zero EDKs on encrypt: the message header cannot be
// serialized (EDK count must be > 0).
#[tokio::test(flavor = "multi_thread")]
async fn test_cmm_returning_zero_edks_fails_encrypt() {
    let valid_input = EncryptInput::with_legacy_cmm(
        b"x",
        EncryptionContext::new(),
        hostile_cmm(Tamper::None).await,
    );
    let hostile_input = EncryptInput::with_legacy_cmm(
        b"x",
        EncryptionContext::new(),
        hostile_cmm(Tamper::EmptyEdks).await,
    );

    assert!(
        encrypt(&valid_input).await.is_ok(),
        "pass-through CMM must encrypt"
    );
    let err = encrypt(&hostile_input)
        .await
        .expect_err("zero EDKs must fail encrypt");
    let ErrorKind::LegacyError(legacy) = &err.kind else {
        panic!("expected LegacyError, got: {:?}", err.kind);
    };
    assert!(
        format!("{legacy:?}").contains("Invalid Encryption Materials"),
        "materials validation must reject the empty EDK list; got: {legacy:?}"
    );
}

// A CMM that returns an encryption-context value too large to serialize:
// encrypt must reject the materials.
#[tokio::test(flavor = "multi_thread")]
async fn test_cmm_returning_oversized_ec_fails_encrypt() {
    let hostile_input = EncryptInput::with_legacy_cmm(
        b"x",
        EncryptionContext::new(),
        hostile_cmm(Tamper::OversizedEcValue).await,
    );
    let err = encrypt(&hostile_input)
        .await
        .expect_err("oversized EC value must fail encrypt");
    assert_eq!(err.kind, ErrorKind::ValidationError, "got {err:?}");
    assert!(
        err.message.contains("serializable encryption materials"),
        "error must name the materials check; got: {}",
        err.message
    );
}

// A CMM that appends an EDK with an oversized field: encrypt must reject the
// materials.
#[tokio::test(flavor = "multi_thread")]
async fn test_cmm_returning_oversized_edk_field_fails_encrypt() {
    let hostile_input = EncryptInput::with_legacy_cmm(
        b"x",
        EncryptionContext::new(),
        hostile_cmm(Tamper::OversizedEdkField).await,
    );
    let err = encrypt(&hostile_input)
        .await
        .expect_err("oversized EDK field must fail encrypt");
    assert_eq!(err.kind, ErrorKind::ValidationError, "got {err:?}");
    assert!(
        err.message.contains("serializable encrypted data keys"),
        "error must name the EDK check; got: {}",
        err.message
    );
}

// A CMM that truncates the plaintext data key under a NoKdf (identity KDF)
// suite: the identity derivation must reject the wrong-length key.
#[tokio::test(flavor = "multi_thread")]
async fn test_cmm_returning_short_data_key_fails_identity_kdf_encrypt() {
    let mut hostile_input = EncryptInput::with_legacy_cmm(
        b"x",
        EncryptionContext::new(),
        hostile_cmm(Tamper::ShortDataKey).await,
    );
    hostile_input.algorithm_suite_id = Some(EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf);
    hostile_input.commitment_policy = EsdkCommitmentPolicy::ForbidEncryptAllowDecrypt;
    let err = encrypt(&hostile_input)
        .await
        .expect_err("16-byte key under an AES-256 identity-KDF suite must fail");
    let ErrorKind::LegacyError(legacy) = &err.kind else {
        panic!("expected LegacyError, got: {:?}", err.kind);
    };
    assert!(
        format!("{legacy:?}").contains("Invalid Encryption Materials"),
        "materials validation must reject the wrong-length key; got: {legacy:?}"
    );
}

// A CMM that returns materials for a different suite than the header names:
// decrypt must reject the mismatch.
#[tokio::test(flavor = "multi_thread")]
async fn test_cmm_returning_mismatched_suite_fails_decrypt() {
    let keyring = test_keyring().await;
    let mut enc_input = EncryptInput::with_legacy_keyring(b"x", EncryptionContext::new(), keyring);
    enc_input.algorithm_suite_id = Some(EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256);
    enc_input.commitment_policy = EsdkCommitmentPolicy::ForbidEncryptAllowDecrypt;
    let ct = encrypt(&enc_input).await.unwrap().ciphertext;

    let mut valid_input = DecryptInput::with_legacy_cmm(
        &ct,
        EncryptionContext::new(),
        hostile_cmm(Tamper::None).await,
    );
    valid_input.commitment_policy = EsdkCommitmentPolicy::ForbidEncryptAllowDecrypt;
    let mut hostile_input = DecryptInput::with_legacy_cmm(
        &ct,
        EncryptionContext::new(),
        hostile_cmm(Tamper::SwapSuiteId).await,
    );
    hostile_input.commitment_policy = EsdkCommitmentPolicy::ForbidEncryptAllowDecrypt;

    assert!(
        decrypt(&valid_input).await.is_ok(),
        "pass-through CMM must decrypt"
    );
    let err = decrypt(&hostile_input)
        .await
        .expect_err("materials suite differing from header suite must fail");
    assert_eq!(err.kind, ErrorKind::ValidationError, "got {err:?}");
    assert!(
        err.message
            .contains("Stored header algorithm suite does not match"),
        "error must name the suite equality check; got: {}",
        err.message
    );
}

// A CMM that returns a decryption-materials encryption context too large to
// have come from a message header: decrypt must reject the materials.
#[tokio::test(flavor = "multi_thread")]
async fn test_cmm_returning_oversized_ec_fails_decrypt() {
    let keyring = test_keyring().await;
    let enc_input = EncryptInput::with_legacy_keyring(b"x", EncryptionContext::new(), keyring);
    let ct = encrypt(&enc_input).await.unwrap().ciphertext;

    let hostile_input = DecryptInput::with_legacy_cmm(
        &ct,
        EncryptionContext::new(),
        hostile_cmm(Tamper::OversizedEcValue).await,
    );
    let err = decrypt(&hostile_input)
        .await
        .expect_err("oversized EC in decryption materials must fail");
    assert_eq!(err.kind, ErrorKind::ValidationError, "got {err:?}");
    assert!(
        err.message.contains("serializable decryption materials"),
        "error must name the materials check; got: {}",
        err.message
    );
}

// A CMM that strips the verification key from a signing-suite message's
// decryption materials: decrypt must fail rather than skip signature
// verification.
#[tokio::test(flavor = "multi_thread")]
async fn test_cmm_stripping_verification_key_fails_decrypt() {
    let keyring = test_keyring().await;
    let mut enc_input = EncryptInput::with_legacy_keyring(b"x", EncryptionContext::new(), keyring);
    enc_input.algorithm_suite_id =
        Some(EsdkAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384);
    let ct = encrypt(&enc_input).await.unwrap().ciphertext;

    let hostile_input = DecryptInput::with_legacy_cmm(
        &ct,
        EncryptionContext::new(),
        hostile_cmm(Tamper::StripVerificationKey).await,
    );
    let err = decrypt(&hostile_input)
        .await
        .expect_err("stripped verification key must fail decrypt");
    let ErrorKind::LegacyError(legacy) = &err.kind else {
        panic!("expected LegacyError, got: {:?}", err.kind);
    };
    assert!(
        format!("{legacy:?}").contains("Invalid Decryption Materials"),
        "materials validation must reject the missing verification key; got: {legacy:?}"
    );
}

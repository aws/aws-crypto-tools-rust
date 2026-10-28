// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Fixtures shared by the `structured_api_*` tests, ported from
//! `StructuredEncryption/test/StructuredDataTestFixtures.dfy`.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use aws_db_esdk::async_trait;
use aws_db_esdk::cmm::{
    Cmm, DecryptMaterialsInput, DecryptMaterialsOutput, DefaultCmm, GetEncryptionMaterialsInput,
    GetEncryptionMaterialsOutput, SharedCmm,
};
use aws_db_esdk::keyring::RawAesKeyring;
use aws_db_esdk::mpl::Error as MplError;
use aws_db_esdk::mpl::types::{
    AlgorithmSuiteId as MplAlgorithmSuiteId, DbeAlgorithmSuiteId, DecryptionMaterials,
    EncryptedDataKey, EncryptionContext, EncryptionMaterials, EsdkAlgorithmSuiteId,
    PlaintextDataKey,
};
use aws_db_esdk::structured::{AuthenticateAction, StructuredDataTerminal, StructuredEncryption};
use aws_db_esdk::types::{AesWrappingAlg, CryptoAction};

pub const TABLE: &str = "myTable";
pub const HEADER: &str = "aws_dbe_head";
pub const FOOTER: &str = "aws_dbe_foot";

pub const TEST_TYPE_ID: [u8; 2] = [0xFF, 0xFF];
pub const TEST_BLOB_VALUE: [u8; 13] = [
    0x21, 0x64, 0x6c, 0x72, 0x6f, 0x77, 0x20, 0x2c, 0x6f, 0x6c, 0x6c, 0x65, 0x68,
];

pub const STRING: [u8; 2] = [0x00, 0x01];
pub const NUMBER: [u8; 2] = [0x00, 0x02];
pub const BOOLEAN: [u8; 2] = [0x00, 0x04];
pub const NULL: [u8; 2] = [0x00, 0x00];

pub fn blob() -> StructuredDataTerminal {
    StructuredDataTerminal::new(TEST_TYPE_ID, TEST_BLOB_VALUE.to_vec())
}

/// `TEST_STRUCTURED_DATA`.
pub fn test_structured_data() -> HashMap<String, StructuredDataTerminal> {
    ["foo", "bar", "fizzbuzz"]
        .into_iter()
        .map(|k| (k.to_owned(), blob()))
        .collect()
}

/// `TEST_CRYPTO_SCHEMA`.
pub fn test_crypto_schema() -> HashMap<String, CryptoAction> {
    HashMap::from([
        ("foo".to_owned(), CryptoAction::EncryptAndSign),
        ("bar".to_owned(), CryptoAction::SignOnly),
        ("fizzbuzz".to_owned(), CryptoAction::DoNothing),
    ])
}

/// `TEST_CRYPTO_SCHEMA_AUTH_ONLY`.
pub fn test_crypto_schema_auth_only() -> HashMap<String, CryptoAction> {
    HashMap::from([
        ("foo".to_owned(), CryptoAction::EncryptAndSign),
        ("bar".to_owned(), CryptoAction::SignOnly),
    ])
}

/// `TEST_AUTHENTICATE_SCHEMA`.
pub fn test_authenticate_schema() -> HashMap<String, AuthenticateAction> {
    HashMap::from([
        ("foo".to_owned(), AuthenticateAction::Sign),
        ("bar".to_owned(), AuthenticateAction::Sign),
        ("fizzbuzz".to_owned(), AuthenticateAction::DoNotSign),
        (HEADER.to_owned(), AuthenticateAction::DoNotSign),
        (FOOTER.to_owned(), AuthenticateAction::DoNotSign),
    ])
}

/// A Raw AES keyring with a fixed 32-byte key of `key_byte`,
/// standing in for the reference's KMS keyring so the tests run offline.
fn keyring_with_key(key_byte: u8) -> RawAesKeyring {
    RawAesKeyring::builder()
        .key_namespace("structured-api-test")
        .key_name("aes-key")
        .wrapping_key(vec![key_byte; 32])
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()
        .unwrap()
}

/// A default CMM over [`keyring_with_key`].
pub fn cmm_with_key(key_byte: u8) -> SharedCmm {
    SharedCmm::new(DefaultCmm::new(keyring_with_key(key_byte)))
}

pub fn cmm() -> SharedCmm {
    cmm_with_key(0x01)
}

/// What a [`RecordingCmm`] does after recording a `get_encryption_materials` call.
#[derive(Clone, Copy, Debug)]
pub enum OnEncrypt {
    /// Forward the request unchanged to the default CMM.
    Forward,
    /// Forward the request, but ask for this algorithm suite instead.
    OverrideSuite(MplAlgorithmSuiteId),
    /// Return materials with a non-DBE (ESDK) algorithm suite.
    EsdkMaterials,
    /// Return materials with a DBE algorithm suite but no plaintext data key.
    NoPlaintextKey,
    /// Return materials whose encryption context has a key too long to store in the header.
    OversizedContext,
    /// Fail with [`RECORDING_CMM_FAILURE`].
    Fail,
}

/// The message of the error [`OnEncrypt::Fail`] returns.
pub const RECORDING_CMM_FAILURE: &str = "the recording CMM refused to supply materials";

/// What a [`RecordingCmm`] does after recording a `decrypt_materials` call.
#[derive(Clone, Copy, Debug)]
pub enum OnDecrypt {
    /// Forward the request unchanged to the default CMM.
    Forward,
    /// Forward the request, then return its materials under the symmetric DBE suite.
    SymmetricSuite,
    /// Return materials with a non-DBE (ESDK) algorithm suite.
    EsdkMaterials,
    /// Forward the request, then return its materials with only the header's stored encryption context.
    StoredContextOnly,
    /// Forward the request, then return its materials without a plaintext data key.
    NoPlaintextKey,
    /// Forward the request, then return its materials with an encryption context key too long to store in a header.
    OversizedContext,
    /// Fail with [`RECORDING_CMM_FAILURE`].
    Fail,
}

/// A CMM that records every `get_encryption_materials` and `decrypt_materials` input it receives,
/// over a default CMM with the same keyring as [`cmm`].
pub struct RecordingCmm {
    inner: DefaultCmm,
    on_encrypt: OnEncrypt,
    on_decrypt: OnDecrypt,
    calls: Arc<Mutex<Vec<GetEncryptionMaterialsInput>>>,
    decrypt_calls: Arc<Mutex<Vec<DecryptMaterialsInput>>>,
}

/// A [`RecordingCmm`] and the list it records each `get_encryption_materials` input into.
pub fn recording_cmm(
    on_encrypt: OnEncrypt,
) -> (SharedCmm, Arc<Mutex<Vec<GetEncryptionMaterialsInput>>>) {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let cmm = RecordingCmm {
        inner: DefaultCmm::new(keyring_with_key(0x01)),
        on_encrypt,
        on_decrypt: OnDecrypt::Forward,
        calls: Arc::clone(&calls),
        decrypt_calls: Arc::new(Mutex::new(Vec::new())),
    };
    (SharedCmm::new(cmm), calls)
}

/// A [`RecordingCmm`] and the list it records each `decrypt_materials` input into.
pub fn decrypt_recording_cmm(
    on_decrypt: OnDecrypt,
) -> (SharedCmm, Arc<Mutex<Vec<DecryptMaterialsInput>>>) {
    let decrypt_calls = Arc::new(Mutex::new(Vec::new()));
    let cmm = RecordingCmm {
        inner: DefaultCmm::new(keyring_with_key(0x01)),
        on_encrypt: OnEncrypt::Forward,
        on_decrypt,
        calls: Arc::new(Mutex::new(Vec::new())),
        decrypt_calls: Arc::clone(&decrypt_calls),
    };
    (SharedCmm::new(cmm), decrypt_calls)
}

/// `materials` rebuilt with `suite` and `encryption_context`.
/// A verification key is kept only if the new suite signs with ECDSA.
fn rebuilt_materials(
    materials: &DecryptionMaterials,
    suite: MplAlgorithmSuiteId,
    encryption_context: EncryptionContext,
) -> Result<DecryptMaterialsOutput, MplError> {
    let verification_key = if suite.has_asymmetric_signing() {
        materials.verification_key().cloned()
    } else {
        None
    };
    let materials = DecryptionMaterials::builder()
        .algorithm_suite_id(suite)
        .encryption_context(encryption_context)
        .set_plaintext_data_key(materials.plaintext_data_key().cloned())
        .set_symmetric_signing_key(materials.symmetric_signing_key().cloned())
        .set_verification_key(verification_key)
        .build()?;
    DecryptMaterialsOutput::builder()
        .decryption_materials(materials)
        .build()
}

/// The symmetric DBE suite, which needs no signing key in the materials.
const SYMMETRIC_DBE_SUITE: DbeAlgorithmSuiteId =
    DbeAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeySymsigHmacSha384;

/// Materials built directly, bypassing any keyring.
/// With a plaintext data key they carry one encrypted data key (and its symmetric signing key);
/// without one they carry none, since the MPL allows encrypted data keys only alongside it.
fn direct_materials(
    suite: MplAlgorithmSuiteId,
    plaintext_data_key: Option<PlaintextDataKey>,
    encryption_context: EncryptionContext,
) -> Result<GetEncryptionMaterialsOutput, MplError> {
    let has_key = plaintext_data_key.is_some();
    let mut materials = EncryptionMaterials::builder()
        .algorithm_suite_id(suite)
        .encryption_context(encryption_context)
        .set_plaintext_data_key(plaintext_data_key);
    if has_key {
        materials = materials.encrypted_data_keys(vec![
            EncryptedDataKey::builder()
                .key_provider_id("p")
                .key_provider_info(Vec::new())
                .ciphertext(vec![1])
                .build()?,
        ]);
        if suite.has_symmetric_signing() {
            // 48 bytes: an HMAC-SHA-384 key.
            materials = materials.symmetric_signing_keys(vec![vec![9u8; 48].into()]);
        }
    }
    GetEncryptionMaterialsOutput::builder()
        .encryption_materials(materials.build()?)
        .build()
}

#[async_trait]
impl Cmm for RecordingCmm {
    async fn get_encryption_materials(
        &self,
        input: GetEncryptionMaterialsInput,
    ) -> Result<GetEncryptionMaterialsOutput, MplError> {
        self.calls.lock().unwrap().push(input.clone());
        let suite = match self.on_encrypt {
            OnEncrypt::Forward => input.algorithm_suite_id(),
            OnEncrypt::OverrideSuite(suite) => Some(suite),
            OnEncrypt::EsdkMaterials => {
                return direct_materials(
                    MplAlgorithmSuiteId::Esdk(EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf),
                    Some(vec![7u8; 32].into()),
                    input.encryption_context().clone(),
                );
            }
            OnEncrypt::NoPlaintextKey => {
                return direct_materials(
                    MplAlgorithmSuiteId::Dbe(SYMMETRIC_DBE_SUITE),
                    None,
                    input.encryption_context().clone(),
                );
            }
            OnEncrypt::OversizedContext => {
                let mut ec = input.encryption_context().clone();
                ec.insert("k".repeat(usize::from(u16::MAX) + 1), "v");
                return direct_materials(
                    MplAlgorithmSuiteId::Dbe(SYMMETRIC_DBE_SUITE),
                    Some(vec![7u8; 32].into()),
                    ec,
                );
            }
            OnEncrypt::Fail => return Err(MplError::validation(RECORDING_CMM_FAILURE)),
        };
        self.inner
            .get_encryption_materials()
            .encryption_context(input.encryption_context().clone())
            .commitment_policy(input.commitment_policy())
            .set_algorithm_suite_id(suite)
            .set_required_encryption_context_keys(input.required_encryption_context_keys().cloned())
            .set_max_plaintext_length(input.max_plaintext_length())
            .send()
            .await
    }

    async fn decrypt_materials(
        &self,
        input: DecryptMaterialsInput,
    ) -> Result<DecryptMaterialsOutput, MplError> {
        self.decrypt_calls.lock().unwrap().push(input.clone());
        match self.on_decrypt {
            OnDecrypt::Fail => return Err(MplError::validation(RECORDING_CMM_FAILURE)),
            OnDecrypt::EsdkMaterials => {
                let materials = DecryptionMaterials::builder()
                    .algorithm_suite_id(MplAlgorithmSuiteId::Esdk(
                        EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf,
                    ))
                    .encryption_context(input.encryption_context().clone())
                    .plaintext_data_key(vec![7u8; 32])
                    .build()?;
                return DecryptMaterialsOutput::builder()
                    .decryption_materials(materials)
                    .build();
            }
            OnDecrypt::Forward
            | OnDecrypt::SymmetricSuite
            | OnDecrypt::StoredContextOnly
            | OnDecrypt::NoPlaintextKey
            | OnDecrypt::OversizedContext => {}
        }
        let stored = input.encryption_context().clone();
        let out = self
            .inner
            .decrypt_materials()
            .algorithm_suite_id(input.algorithm_suite_id())
            .commitment_policy(input.commitment_policy())
            .encrypted_data_keys(input.encrypted_data_keys().to_vec())
            .encryption_context(stored.clone())
            .set_reproduced_encryption_context(input.reproduced_encryption_context().cloned())
            .send()
            .await?;
        let materials = out.decryption_materials();
        match self.on_decrypt {
            OnDecrypt::SymmetricSuite => rebuilt_materials(
                materials,
                MplAlgorithmSuiteId::Dbe(SYMMETRIC_DBE_SUITE),
                materials.encryption_context().clone(),
            ),
            OnDecrypt::StoredContextOnly => {
                rebuilt_materials(materials, materials.algorithm_suite_id(), stored)
            }
            OnDecrypt::NoPlaintextKey => {
                let materials = DecryptionMaterials::builder()
                    .algorithm_suite_id(materials.algorithm_suite_id())
                    .encryption_context(materials.encryption_context().clone())
                    .set_verification_key(materials.verification_key().cloned())
                    .build()?;
                DecryptMaterialsOutput::builder()
                    .decryption_materials(materials)
                    .build()
            }
            OnDecrypt::OversizedContext => {
                let mut ec = materials.encryption_context().clone();
                ec.insert("k".repeat(usize::from(u16::MAX) + 1), "v");
                rebuilt_materials(materials, materials.algorithm_suite_id(), ec)
            }
            _ => Ok(out),
        }
    }
}

pub const fn client() -> StructuredEncryption {
    StructuredEncryption::new()
}

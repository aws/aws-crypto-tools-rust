// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! A caller-implemented CMM (legacy `CryptographicMaterialsManager` trait)
//! driven through the public encrypt/decrypt API.
//!
//! This pins the CMM extension interface and the behavior the ESDK expects
//! from it. If these tests break, a change has likely broken
//! caller-implemented CMMs.

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
    CryptographicMaterialsManager, CryptographicMaterialsManagerRef,
};
use aws_mpl_legacy::dafny::types::error::Error as MplError;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Caller-implemented CMM. Forwards materials requests to an inner default
/// CMM and records that each trait method was invoked.
struct RecordingCmm {
    inner: CryptographicMaterialsManagerRef,
    saw_get_encryption_materials: Arc<AtomicBool>,
    saw_decrypt_materials: Arc<AtomicBool>,
}

impl CryptographicMaterialsManager for RecordingCmm {
    fn get_encryption_materials(
        &self,
        input: GetEncryptionMaterialsInput,
    ) -> Result<GetEncryptionMaterialsOutput, MplError> {
        self.saw_get_encryption_materials
            .store(true, Ordering::Relaxed);
        tokio::task::block_in_place(|| {
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
        })
    }

    fn decrypt_materials(
        &self,
        input: DecryptMaterialsInput,
    ) -> Result<DecryptMaterialsOutput, MplError> {
        self.saw_decrypt_materials.store(true, Ordering::Relaxed);
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                self.inner
                    .decrypt_materials()
                    .algorithm_suite_id(input.algorithm_suite_id.unwrap())
                    .commitment_policy(input.commitment_policy.unwrap())
                    .encrypted_data_keys(input.encrypted_data_keys.unwrap())
                    .encryption_context(input.encryption_context.unwrap())
                    .set_reproduced_encryption_context(input.reproduced_encryption_context)
                    .send()
                    .await
            })
        })
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn custom_cmm_round_trips_via_public_api() {
    let saw_get_encryption_materials = Arc::new(AtomicBool::new(false));
    let saw_decrypt_materials = Arc::new(AtomicBool::new(false));

    // Custom CMM over a default CMM backed by a local raw AES keyring.
    let cmm = CryptographicMaterialsManagerRef::from(RecordingCmm {
        inner: mpl()
            .create_default_cryptographic_materials_manager()
            .keyring(test_helpers::test_keyring().await)
            .send()
            .await
            .unwrap(),
        saw_get_encryption_materials: Arc::clone(&saw_get_encryption_materials),
        saw_decrypt_materials: Arc::clone(&saw_decrypt_materials),
    });
    let plaintext = b"custom cmm round trip";

    // Encrypt and decrypt entirely through the custom CMM.
    let out = encrypt(&EncryptInput::with_legacy_cmm(
        plaintext,
        EncryptionContext::new(),
        cmm.clone(),
    ))
    .await
    .unwrap();
    let dec = decrypt(&DecryptInput::with_legacy_cmm(
        &out.ciphertext,
        EncryptionContext::new(),
        cmm,
    ))
    .await
    .unwrap();
    assert_eq!(dec.plaintext, plaintext);

    // Both trait methods must have been driven by the ESDK.
    assert!(
        saw_get_encryption_materials.load(Ordering::Relaxed),
        "encrypt must call the custom CMM's get_encryption_materials"
    );
    assert!(
        saw_decrypt_materials.load(Ordering::Relaxed),
        "decrypt must call the custom CMM's decrypt_materials"
    );
}

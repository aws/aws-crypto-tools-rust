// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! A caller-implemented CMM (native `aws_crypto_mpl::cmm::Cmm` trait) driven
//! through the public encrypt/decrypt API.
//!
//! This pins the CMM extension interface and the behavior the ESDK expects
//! from it. If these tests break, a change has likely broken
//! caller-implemented CMMs.
//!
//! Local because a caller's CMM impl is a native trait, unreachable from the
//! cross-language interop vectors.

#[allow(clippy::duplicate_mod)]
mod fixtures;
mod test_helpers;

use aws_crypto_mpl::Error as MplError;
use aws_crypto_mpl::cmm::{Cmm, DefaultCmm};
use aws_crypto_mpl::cmm::{
    DecryptMaterialsInput, DecryptMaterialsOutput, GetEncryptionMaterialsInput,
    GetEncryptionMaterialsOutput,
};
use aws_esdk::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Caller-implemented CMM. Forwards materials requests to an inner default
/// CMM and records that each trait method was invoked.
#[derive(Clone)]
struct RecordingCmm {
    inner: DefaultCmm,
    saw_get_encryption_materials: Arc<AtomicBool>,
    saw_decrypt_materials: Arc<AtomicBool>,
}

#[async_trait::async_trait]
impl Cmm for RecordingCmm {
    async fn get_encryption_materials(
        &self,
        request: GetEncryptionMaterialsInput,
    ) -> Result<GetEncryptionMaterialsOutput, MplError> {
        self.saw_get_encryption_materials
            .store(true, Ordering::Relaxed);
        // Forward the request unchanged to the wrapped default CMM.
        self.inner.get_encryption_materials(request).await
    }

    async fn decrypt_materials(
        &self,
        request: DecryptMaterialsInput,
    ) -> Result<DecryptMaterialsOutput, MplError> {
        self.saw_decrypt_materials.store(true, Ordering::Relaxed);
        // Forward the request unchanged to the wrapped default CMM.
        self.inner.decrypt_materials(request).await
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn custom_cmm_round_trips_via_public_api() {
    let saw_get_encryption_materials = Arc::new(AtomicBool::new(false));
    let saw_decrypt_materials = Arc::new(AtomicBool::new(false));

    // Custom CMM over a default CMM backed by a local raw AES keyring.
    let cmm = RecordingCmm {
        inner: DefaultCmm::new(test_helpers::test_keyring().await),
        saw_get_encryption_materials: Arc::clone(&saw_get_encryption_materials),
        saw_decrypt_materials: Arc::clone(&saw_decrypt_materials),
    };
    let plaintext = b"custom cmm round trip";

    // Encrypt and decrypt entirely through the custom CMM.
    let out = encrypt(
        &EncryptInput::builder()
            .plaintext(plaintext)
            .cmm(cmm.clone())
            .build()
            .unwrap(),
    )
    .await
    .unwrap();
    let dec = decrypt(
        &DecryptInput::builder()
            .ciphertext(&out.ciphertext)
            .cmm(cmm)
            .build()
            .unwrap(),
    )
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

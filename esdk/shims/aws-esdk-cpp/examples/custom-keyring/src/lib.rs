// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Your custom keyring, defined in Rust and exported to C++.
//!
//! Step 2 (`AuditKeyring`): define your keyring.
//! Step 3 (`custom_keyring_create`): export it as a handle for C++ to adopt.
//! See README.md for the full setup, and example.cpp for the C++ side.

use std::ffi::c_void;

use aws_crypto_mpl::keyring::{
    Keyring, OnDecryptInput, OnDecryptOutput, OnEncryptInput, OnEncryptOutput, RawAesKeyring,
};
use aws_crypto_mpl::types::{AesWrappingAlg, EncryptedDataKey};
use aws_crypto_mpl::{Error, async_trait};

/// Step 2: define your keyring.
///
/// Wraps another keyring and logs the key providers of the encrypted data keys each call writes or tries.
struct AuditKeyring {
    inner: RawAesKeyring,
}

fn providers(edks: &[EncryptedDataKey]) -> Vec<&str> {
    edks.iter().map(EncryptedDataKey::key_provider_id).collect()
}

#[async_trait]
impl Keyring for AuditKeyring {
    async fn on_encrypt(&self, input: OnEncryptInput) -> Result<OnEncryptOutput, Error> {
        let output = Keyring::on_encrypt(&self.inner, input).await?;
        println!(
            "audit: encrypt wrote data keys for {:?}",
            providers(output.materials().encrypted_data_keys())
        );
        Ok(output)
    }

    async fn on_decrypt(&self, input: OnDecryptInput) -> Result<OnDecryptOutput, Error> {
        println!(
            "audit: decrypt tried data keys from {:?}",
            providers(input.encrypted_data_keys())
        );
        Keyring::on_decrypt(&self.inner, input).await
    }
}

/// Step 3: export your keyring.
#[unsafe(no_mangle)]
pub extern "C" fn custom_keyring_create() -> *mut c_void {
    // For demonstration only: a real application must source its wrapping key
    // from a secure store and never hardcode it.
    let Ok(inner) = RawAesKeyring::builder()
        .key_namespace("my-key-namespace")
        .key_name("my-key-name")
        .wrapping_key(vec![0x2A; 32])
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()
    else {
        return std::ptr::null_mut();
    };
    aws_esdk_cpp::into_keyring_handle(AuditKeyring { inner })
}

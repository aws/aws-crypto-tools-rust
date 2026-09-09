// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! A keyring decides how each message's data key is protected.
//! AWS provides a set of keyrings that meet most use cases.
//! If your use case is not covered by AWS-provided keyrings, you can implement your own.
//!
//! `build_keyring` defines the keyring; the rest of the example uses it like any other.

use aws_esdk::{DecryptInput, EncryptInput, EncryptionContext, decrypt, encrypt, mpl};
use aws_mpl_legacy::dafny::types::AesWrappingAlg;
use aws_mpl_legacy::dafny::types::keyring::KeyringRef;
use aws_smithy_types::Blob;

/// For demonstration only: a real application must source its wrapping key from a secure store and never hardcode it.
const WRAPPING_KEY: [u8; 32] = [0x2A; 32];

/// Define your keyring.
///
/// TODO(native-mpl): once native MPL is available, model the custom keyring example off of
/// https://github.com/aws/aws-encryption-sdk-python/blob/master/examples/src/custom_mpl_cmm_example.py
async fn build_keyring() -> Result<KeyringRef, Box<dyn std::error::Error>> {
    Ok(mpl()
        .create_raw_aes_keyring()
        .key_namespace("custom-keyring-example")
        .key_name("demo-key")
        .wrapping_key(Blob::new(WRAPPING_KEY))
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .send()
        .await?)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let keyring = build_keyring().await?;

    let plaintext = b"Hello World";

    let encrypted = encrypt(&EncryptInput::with_legacy_keyring(
        plaintext,
        EncryptionContext::new(),
        keyring.clone(),
    ))
    .await?;

    let decrypted = decrypt(&DecryptInput::with_legacy_keyring(
        &encrypted.ciphertext,
        EncryptionContext::new(),
        keyring,
    ))
    .await?;

    assert_eq!(
        decrypted.plaintext, plaintext,
        "Decryption failed: plaintext mismatch"
    );
    println!("Success! Encryption and decryption completed successfully.");
    Ok(())
}

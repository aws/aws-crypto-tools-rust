// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Reuses data keys across messages with a caching CMM.
//!
//! Runs offline.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use aws_esdk::async_trait;
use aws_esdk::cmc::LocalCmc;
use aws_esdk::cmm::CachingCmm;
use aws_esdk::keyring::{
    Keyring, OnDecryptInput, OnDecryptOutput, OnEncryptInput, OnEncryptOutput, RawAesKeyring,
};
use aws_esdk::mpl::Error as MplError;
use aws_esdk::types::{AesWrappingAlg, EncryptionContext};

/// Wraps a raw AES keyring and counts how many times encrypt calls it.
#[derive(Clone)]
struct CountingKeyring {
    inner: RawAesKeyring,
    encrypt_calls: Arc<AtomicUsize>,
}

#[async_trait]
impl Keyring for CountingKeyring {
    async fn on_encrypt(&self, input: OnEncryptInput) -> Result<OnEncryptOutput, MplError> {
        self.encrypt_calls.fetch_add(1, Ordering::SeqCst);
        self.inner
            .on_encrypt()
            .materials(input.into_materials())
            .send()
            .await
    }

    async fn on_decrypt(&self, input: OnDecryptInput) -> Result<OnDecryptOutput, MplError> {
        let (materials, encrypted_data_keys) = input.into_parts();
        self.inner
            .on_decrypt()
            .materials(materials)
            .set_encrypted_data_keys(Some(encrypted_data_keys))
            .send()
            .await
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // For demonstration only.
    // A real application must load its wrapping key from a secure store, never hardcode it.
    let keyring = CountingKeyring {
        inner: RawAesKeyring::builder()
            .key_namespace("my-key-namespace")
            .key_name("my-key-name")
            .wrapping_key(vec![0x01u8; 32])
            .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
            .build()?,
        encrypt_calls: Arc::new(AtomicUsize::new(0)),
    };

    // A cache entry holds a plaintext data key.
    // When an entry reaches any limit below, the CMM asks the keyring for a new data key.
    let cmm = CachingCmm::builder()
        .keyring(keyring.clone())
        .cache(LocalCmc::builder().entry_capacity(100).build()?)
        // How long the CMM reuses a data key, on encrypt and on decrypt.
        // After you revoke access to the wrapping key, encrypt and decrypt can keep working for up to this long.
        .cache_limit_ttl(Duration::from_secs(300))
        // How many messages one data key encrypts.
        // If a data key leaks, at most this many messages are exposed.
        .limit_messages(2)
        // How many plaintext bytes one data key encrypts, across all its messages.
        // A message longer than this never uses the cache.
        // Neither does a stream without a plaintext length bound.
        .limit_bytes(1024 * 1024)
        .build()?;

    let plaintext = b"Hello World";

    // The encryption context is authenticated, not encrypted, and is bound to the message.
    // Only messages with the same encryption context share a data key.
    let encryption_context =
        EncryptionContext::from([("purpose", "example"), ("is not", "secret")]);

    let esdk = aws_esdk::Client::default();

    let mut messages = Vec::new();
    for _ in 0..3 {
        let encrypted = esdk
            .encrypt()
            .plaintext(plaintext)
            .set_encryption_context(Some(encryption_context.clone()))
            .cmm(cmm.clone())
            .send()
            .await?;
        messages.push(encrypted);
    }

    // The second message reused the first one's data key.
    // The third would exceed the message limit, so it got a new data key.
    assert_eq!(
        keyring.encrypt_calls.load(Ordering::SeqCst),
        2,
        "Caching failed: unexpected number of keyring calls"
    );

    for encrypted in &messages {
        let decrypted = esdk
            .decrypt()
            .ciphertext(encrypted.ciphertext())
            .set_encryption_context(Some(encryption_context.clone()))
            .cmm(cmm.clone())
            .send()
            .await?;
        assert_eq!(
            decrypted.plaintext(),
            plaintext,
            "Decryption failed: plaintext mismatch"
        );
    }

    println!("Success! Three messages took two calls to the keyring.");
    Ok(())
}

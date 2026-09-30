// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Handles the errors encrypt and decrypt return.

use std::error::Error as _;

use aws_crypto_mpl::{AesGcm, RawAesKeyring};
use aws_esdk::{DecryptInput, DisplayErrorContext, EncryptInput, ErrorKind, decrypt, encrypt};

fn raw_aes_keyring(key_byte: u8) -> Result<RawAesKeyring, aws_crypto_mpl::Error> {
    // For demonstration only: a real application must source its wrapping key from a secure store and never hardcode it.
    RawAesKeyring::new(
        "my-key-namespace",
        "my-key-name",
        vec![key_byte; 32],
        AesGcm::Aes256Gcm,
    )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let keyring = raw_aes_keyring(0x01)?;
    let encrypted = encrypt(
        &EncryptInput::builder()
            .plaintext(b"Hello World")
            .keyring(keyring)
            .build()?,
    )
    .await?;

    // Decrypt with a keyring whose key did not encrypt the message.
    let input = DecryptInput::builder()
        .ciphertext(&encrypted.ciphertext)
        .keyring(raw_aes_keyring(0x02)?)
        .build()?;

    let err = decrypt(&input)
        .await
        .expect_err("a different wrapping key cannot decrypt the message");

    // Decide from the kind; the message is for logs. ErrorKind is
    // non-exhaustive, so a match on it always needs a catch-all arm.
    if err.is_retryable() {
        println!("retry later: {err}");
    } else {
        match err.kind() {
            ErrorKind::Validation => println!("fix the input: {err}"),
            ErrorKind::RemoteAccessDenied | ErrorKind::RemoteResourceNotFound => {
                println!("fix the configuration: {err}");
            }
            ErrorKind::NoMatchingDataKey
            | ErrorKind::Cryptographic
            | ErrorKind::Serialization
            | ErrorKind::EncryptionContextMismatch => println!("reject the message: {err}"),
            _ => println!("failed: {err}"),
        }
    }
    assert_eq!(err.kind(), ErrorKind::Cryptographic);

    // Each error in the chain describes one layer; DisplayErrorContext prints them all.
    println!("{}", DisplayErrorContext(&err));

    // The keyring's own error is reachable by type.
    let keyring_error = err
        .source()
        .and_then(|c| c.downcast_ref::<aws_crypto_mpl::Error>())
        .expect("the keyring's error is the source");
    println!(
        "the keyring tried {} encrypted data key(s)",
        keyring_error.collected().len()
    );

    Ok(())
}

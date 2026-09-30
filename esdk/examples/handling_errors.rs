// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Handles the errors encrypt and decrypt return.
//!
//! Each failure below is triggered on purpose, then handled by
//! `handle`, which decides what to do from the error's kind alone.

use std::error::Error as _;

use aws_crypto_mpl::{AesGcm, RawAesKeyring};
use aws_esdk::{DecryptInput, EncryptInput, Error, ErrorKind, decrypt, encrypt};

/// What an application does about a failed call.
#[derive(Debug, PartialEq)]
enum Action {
    Retry,
    RejectInput,
    FixConfiguration,
    RejectMessage,
    Fail,
}

/// Decide what to do about `err` from its kind and retryability.
fn handle(err: &Error) -> Action {
    // A retryable error, such as a throttled KMS or DynamoDB request, might
    // succeed if the same call is made again later.
    if err.is_retryable() {
        return Action::Retry;
    }
    // ErrorKind is non-exhaustive: new kinds can appear in later releases,
    // so a match on it always needs a catch-all arm.
    match err.kind() {
        ErrorKind::Validation => Action::RejectInput,
        ErrorKind::RemoteAccessDenied | ErrorKind::RemoteResourceNotFound => {
            Action::FixConfiguration
        }
        ErrorKind::NoMatchingDataKey
        | ErrorKind::Cryptographic
        | ErrorKind::Serialization
        | ErrorKind::EncryptionContextMismatch => Action::RejectMessage,
        _ => Action::Fail,
    }
}

/// Print an error with every error in its `source()` chain.
fn report(err: &Error) {
    println!("{err}");
    let mut cause = err.source();
    while let Some(c) = cause {
        println!("  caused by: {c}");
        cause = c.source();
    }
}

fn raw_aes_keyring(key_byte: u8) -> Result<RawAesKeyring, Box<dyn std::error::Error>> {
    // For demonstration only: a real application must source its wrapping key from a secure store and never hardcode it.
    Ok(RawAesKeyring::new(
        "my-key-namespace",
        "my-key-name",
        vec![key_byte; 32],
        AesGcm::Aes256Gcm,
    )?)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let keyring = raw_aes_keyring(0x01)?;
    let plaintext = b"Hello World";
    let encrypted = encrypt(
        &EncryptInput::builder()
            .plaintext(plaintext)
            .keyring(keyring.clone())
            .build()?,
    )
    .await?;

    // An input without a keyring or CMM is rejected before anything runs.
    let err = EncryptInput::builder()
        .plaintext(plaintext)
        .build()
        .expect_err("an input needs a keyring or CMM");
    report(&err);
    assert_eq!(err.kind(), ErrorKind::Validation);
    assert_eq!(handle(&err), Action::RejectInput);

    // A keyring whose key did not encrypt the message cannot decrypt it.
    // The keyring's own error is the source.
    let err = decrypt(
        &DecryptInput::builder()
            .ciphertext(&encrypted.ciphertext)
            .keyring(raw_aes_keyring(0x02)?)
            .build()?,
    )
    .await
    .expect_err("a different wrapping key cannot decrypt the message");
    report(&err);
    assert_eq!(handle(&err), Action::RejectMessage);
    let keyring_error = err
        .source()
        .and_then(|c| c.downcast_ref::<aws_crypto_mpl::Error>())
        .expect("the keyring's error is the source");
    println!("  the keyring reported {:?}", keyring_error.kind());

    // A modified message fails authentication.
    let mut tampered = encrypted.ciphertext.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    let err = decrypt(
        &DecryptInput::builder()
            .ciphertext(&tampered)
            .keyring(keyring.clone())
            .build()?,
    )
    .await
    .expect_err("a modified message must not decrypt");
    report(&err);
    assert_eq!(err.kind(), ErrorKind::Cryptographic);
    assert_eq!(handle(&err), Action::RejectMessage);

    // Bytes that are not an encrypted message cannot be read at all.
    let err = decrypt(
        &DecryptInput::builder()
            .ciphertext(b"not an encrypted message")
            .keyring(keyring)
            .build()?,
    )
    .await
    .expect_err("arbitrary bytes are not a message");
    report(&err);
    assert_eq!(err.kind(), ErrorKind::Serialization);
    assert_eq!(handle(&err), Action::RejectMessage);

    println!("Success! Every error was handled by its kind.");
    Ok(())
}

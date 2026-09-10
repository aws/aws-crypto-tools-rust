// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Behavioral coverage for the public input/output types: `new()`
//! constructors, `From` conversions into `Keyring`/`Cmm`, their equality
//! semantics, and the `DecryptStreamInput`/`EncryptStreamInput` constructors,
//! each driven through a real round trip so a constructor that wires the
//! wrong field fails here.

#[allow(clippy::duplicate_mod)]
mod fixtures;
mod test_helpers;

use aws_esdk::*;
use test_helpers::test_keyring;

// The four output types are caller-constructible via new() and start at
// their defaults.
#[test]
fn test_output_new_constructors_default() {
    assert_eq!(EncryptOutput::new(), EncryptOutput::default());
    assert_eq!(EncryptStreamOutput::new(), EncryptStreamOutput::default());
    assert_eq!(DecryptOutput::new(), DecryptOutput::default());
    assert_eq!(DecryptStreamOutput::new(), DecryptStreamOutput::default());
    assert!(DecryptOutput::new().plaintext.is_empty());
}

// An EncryptInput assembled from new() + `Keyring::from(legacy)` encrypts and
// decrypts, proving the From conversion wires the Legacy variant.
#[tokio::test(flavor = "multi_thread")]
async fn test_keyring_from_legacy_round_trips() {
    let legacy = test_keyring().await;
    let pt = b"from-impl round trip";

    let mut enc_input = EncryptInput::new();
    enc_input.plaintext = pt;
    enc_input.keyring = Some(Keyring::from(legacy.clone()));
    let ct = encrypt(&enc_input).await.unwrap().ciphertext;

    let mut dec_input = DecryptInput::new();
    dec_input.ciphertext = &ct;
    dec_input.keyring = Some(legacy.into());
    assert_eq!(decrypt(&dec_input).await.unwrap().plaintext, pt);
}

// A Cmm assembled via `Cmm::from(legacy_cmm)` drives a round trip, proving
// the From conversion wires the Legacy variant.
#[tokio::test(flavor = "multi_thread")]
async fn test_cmm_from_legacy_round_trips() {
    let cmm = mpl()
        .create_default_cryptographic_materials_manager()
        .keyring(test_keyring().await)
        .send()
        .await
        .unwrap();
    let pt = b"cmm from-impl round trip";

    let mut enc_input = EncryptInput::new();
    enc_input.plaintext = pt;
    enc_input.cmm = Some(Cmm::from(cmm.clone()));
    let ct = encrypt(&enc_input).await.unwrap().ciphertext;

    let mut dec_input = DecryptInput::new();
    dec_input.ciphertext = &ct;
    dec_input.cmm = Some(cmm.into());
    assert_eq!(decrypt(&dec_input).await.unwrap().plaintext, pt);
}

// Keyring/Cmm equality: same legacy ref compares equal, different refs don't.
#[tokio::test(flavor = "multi_thread")]
async fn test_keyring_and_cmm_equality_on_legacy_refs() {
    let a = test_keyring().await;
    let b = test_helpers::aes_keyring(1).await;
    assert_eq!(Keyring::from(a.clone()), Keyring::from(a.clone()));
    assert_ne!(Keyring::from(a.clone()), Keyring::from(b));

    let cmm_a = mpl()
        .create_default_cryptographic_materials_manager()
        .keyring(a.clone())
        .send()
        .await
        .unwrap();
    let cmm_b = mpl()
        .create_default_cryptographic_materials_manager()
        .keyring(a)
        .send()
        .await
        .unwrap();
    assert_eq!(Cmm::from(cmm_a.clone()), Cmm::from(cmm_a));
    assert_ne!(
        Cmm::from(
            mpl()
                .create_default_cryptographic_materials_manager()
                .keyring(test_keyring().await)
                .send()
                .await
                .unwrap()
        ),
        Cmm::from(cmm_b)
    );
}

// EncryptStreamInput::with_legacy_cmm and DecryptStreamInput::with_legacy_cmm
// round-trip through the streaming API, proving both constructors wire the
// CMM into the operation.
#[tokio::test(flavor = "multi_thread")]
async fn test_stream_inputs_with_legacy_cmm_round_trip() {
    let cmm = mpl()
        .create_default_cryptographic_materials_manager()
        .keyring(test_keyring().await)
        .send()
        .await
        .unwrap();
    let pt = b"streaming cmm constructors".to_vec();

    let enc_input = EncryptStreamInput::with_legacy_cmm(EncryptionContext::new(), cmm.clone());
    let mut ct = Vec::new();
    encrypt_stream(&mut std::io::Cursor::new(pt.clone()), &mut ct, &enc_input)
        .await
        .unwrap();

    let dec_input = DecryptStreamInput::with_legacy_cmm(EncryptionContext::new(), cmm);
    let mut out = Vec::new();
    decrypt_stream(&mut std::io::Cursor::new(ct), &mut out, &dec_input)
        .await
        .unwrap();
    assert_eq!(out, pt);
}

// DecryptStreamInput::from_encrypt copies the material source and policy from
// an EncryptInput; the copied input must decrypt that EncryptInput's message.
#[tokio::test(flavor = "multi_thread")]
async fn test_decrypt_stream_input_from_encrypt_round_trips() {
    let keyring = test_keyring().await;
    let pt = b"stream from_encrypt";
    let enc_input = EncryptInput::with_legacy_keyring(pt, EncryptionContext::new(), keyring);
    let ct = encrypt(&enc_input).await.unwrap().ciphertext;

    let dec_input = DecryptStreamInput::from_encrypt(&enc_input);
    let mut out = Vec::new();
    decrypt_stream(&mut std::io::Cursor::new(ct), &mut out, &dec_input)
        .await
        .unwrap();
    assert_eq!(out, pt);
}

// DecryptStreamInput::new() validates exactly like the default: no material
// source is a ValidationError.
#[tokio::test(flavor = "multi_thread")]
async fn test_decrypt_stream_input_new_requires_material_source() {
    let dec_input = DecryptStreamInput::new();
    let mut out = Vec::new();
    let err = decrypt_stream(&mut std::io::Cursor::new(Vec::new()), &mut out, &dec_input)
        .await
        .expect_err("no keyring and no CMM must fail validation");
    assert_eq!(err.kind, ErrorKind::ValidationError, "got {err:?}");
}

// EncryptInput::new() with no material source fails validation; with both a
// keyring and a CMM it also fails. Together with the round trips above this
// pins the "exactly one" rule across the constructor surface.
#[tokio::test(flavor = "multi_thread")]
async fn test_exactly_one_material_source_across_constructors() {
    let keyring = test_keyring().await;
    let cmm = mpl()
        .create_default_cryptographic_materials_manager()
        .keyring(keyring.clone())
        .send()
        .await
        .unwrap();

    let mut none_input = EncryptInput::new();
    none_input.plaintext = b"x";
    let err = encrypt(&none_input).await.expect_err("no source must fail");
    assert_eq!(err.kind, ErrorKind::ValidationError, "got {err:?}");

    let mut both_input = EncryptInput::with_legacy_keyring(b"x", EncryptionContext::new(), keyring);
    both_input.cmm = Some(Cmm::from(cmm));
    let err = encrypt(&both_input).await.expect_err("both must fail");
    assert_eq!(err.kind, ErrorKind::ValidationError, "got {err:?}");
}

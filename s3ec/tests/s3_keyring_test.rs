// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for the shared `S3Keyring` base trait
//! (`../spec/s3-encryption/materials/s3-keyring.md`): the consolidated
//! OnEncrypt / OnDecrypt template methods and their validation guards,
//! exercised through the raw `AesKeyring` and `RsaKeyring` implementations.

use aws_s3_encryption::config::EncryptionAlgorithm;
use aws_s3_encryption::error::S3EncryptionError;
use aws_s3_encryption::keyring::{
    AesKeyring, DecryptionMaterials, EncryptionMaterials, RsaKeyring, S3Keyring,
};

const SUITE: EncryptionAlgorithm = EncryptionAlgorithm::AlgAes256GcmIv12Tag16NoKdf;

fn rsa_pkcs8_key() -> Vec<u8> {
    use aws_lc_rs::encoding::AsDer;
    use aws_lc_rs::rsa::{KeySize, PrivateDecryptingKey};
    let key = PrivateDecryptingKey::generate(KeySize::Rsa2048).unwrap();
    key.as_der().unwrap().as_ref().to_vec()
}

#[test]
fn s3_keyring_consolidates_on_encrypt_on_decrypt_for_all_keyrings() {
    // The same OnEncrypt/OnDecrypt control flow is inherited by every raw S3
    // Keyring (AES and RSA), proving the trait consolidates the functionality
    // common to all S3 Keyrings rather than duplicating it per keyring.
    let aes = AesKeyring::new(vec![0x42u8; 32]);
    let rsa = RsaKeyring::new(rsa_pkcs8_key());

    for keyring in [
        &aes as &dyn S3Keyring,
        &rsa as &dyn S3Keyring,
    ] {
        let mut enc = EncryptionMaterials::new(SUITE);
        keyring.on_encrypt(&mut enc).unwrap();
        let pdk = enc.plaintext_data_key().unwrap().to_vec();
        let edk = enc.encrypted_data_key().unwrap().to_vec();

        let mut dec = DecryptionMaterials::new(SUITE);
        keyring.on_decrypt(&mut dec, &[edk]).unwrap();

        //= ../spec/s3-encryption/materials/s3-keyring.md#overview
        //= type=test
        //= reason=both raw keyrings inherit the same on_encrypt/on_decrypt template and round-trip a data key through it, demonstrating the shared consolidated S3 Keyring base
        //# The S3EC SHOULD implement an S3 Keyring to consolidate validation and other functionality common to all S3 Keyrings.
        assert_eq!(dec.plaintext_data_key().unwrap(), pdk.as_slice());
    }
}

#[test]
fn on_encrypt_generates_data_key_when_plaintext_is_absent() {
    let keyring = AesKeyring::new(vec![0x42u8; 32]);
    let mut materials = EncryptionMaterials::new(SUITE);
    assert!(materials.plaintext_data_key().is_none(), "precondition: no PDK");

    keyring.on_encrypt(&mut materials).unwrap();

    //= ../spec/s3-encryption/materials/s3-keyring.md#onencrypt
    //= type=test
    //= reason=materials started with no plaintext data key; after on_encrypt a fresh 32-byte data key is present, so GenerateDataKey was called
    //# If the Plaintext Data Key in the input EncryptionMaterials is null, the S3 Keyring MUST call the GenerateDataKey method using the materials.
    assert_eq!(materials.plaintext_data_key().unwrap().len(), 32);
}

#[test]
fn on_encrypt_returns_materials_unchanged_when_edk_present() {
    // When the materials already carry an encrypted data key, OnEncrypt returns
    // them as-is and must NOT re-wrap (which would overwrite the EDK with a
    // real AES-GCM wrap of different bytes/length).
    let keyring = AesKeyring::new(vec![0x42u8; 32]);
    let existing_pdk = vec![0x5Au8; 32];
    let sentinel_edk = vec![0xEEu8; 48];

    let mut materials =
        EncryptionMaterials::with_data_keys(SUITE, existing_pdk, sentinel_edk.clone());
    keyring.on_encrypt(&mut materials).unwrap();

    //= ../spec/s3-encryption/materials/s3-keyring.md#onencrypt
    //= type=test
    //= reason=materials carrying an EDK are returned unchanged; the sentinel EDK survives, proving EncryptDataKey was not called again
    //# If the materials returned from GenerateDataKey contain an EncryptedDataKey, the S3 Keyring MUST return the materials.
    assert_eq!(materials.encrypted_data_key().unwrap(), sentinel_edk.as_slice());
}

#[test]
fn on_encrypt_encrypts_data_key_when_no_edk_present() {
    let keyring = AesKeyring::new(vec![0x42u8; 32]);
    let existing_pdk = vec![0x5Au8; 32];
    let mut materials = EncryptionMaterials::with_plaintext_data_key(SUITE, existing_pdk.clone());
    assert!(materials.encrypted_data_key().is_none(), "precondition: no EDK");

    keyring.on_encrypt(&mut materials).unwrap();

    // The produced EDK must unwrap back to the preserved plaintext data key,
    // proving EncryptDataKey wrapped exactly that key.
    let edk = materials.encrypted_data_key().unwrap();
    let recovered = keyring.unwrap(edk, SUITE).unwrap();
    //= ../spec/s3-encryption/materials/s3-keyring.md#onencrypt
    //= type=test
    //= reason=with a PDK but no EDK, on_encrypt produced an EDK that unwraps back to the input PDK, proving EncryptDataKey was called on the materials
    //# If the materials returned from GenerateDataKey do not contain an EncryptedDataKey, the S3 Keyring MUST call the EncryptDataKey method using the materials.
    assert_eq!(recovered, existing_pdk);
}

#[test]
fn on_decrypt_rejects_materials_already_containing_plaintext_data_key() {
    let keyring = AesKeyring::new(vec![0x42u8; 32]);
    let (_pdk, edk) = keyring.wrap(SUITE).unwrap();

    // A valid (empty-PDK) materials decrypts; materials that already carry a
    // plaintext data key are rejected.
    let mut valid = DecryptionMaterials::new(SUITE);
    let mut with_pdk = DecryptionMaterials::with_plaintext_data_key(SUITE, vec![0x00u8; 32]);

    //= ../spec/s3-encryption/materials/s3-keyring.md#ondecrypt
    //= type=test
    //= reason=empty-PDK materials decrypt; materials already containing a PDK -> S3EncryptionError::Crypto, proving the guard
    //# If the input DecryptionMaterials contains a Plaintext Data Key, the S3 Keyring MUST throw an exception.
    assert!(keyring.on_decrypt(&mut valid, std::slice::from_ref(&edk)).is_ok());
    assert!(matches!(
        keyring.on_decrypt(&mut with_pdk, &[edk]).unwrap_err(),
        S3EncryptionError::Crypto(_)
    ));
}

#[test]
fn on_decrypt_rejects_edk_count_other_than_one() {
    let keyring = AesKeyring::new(vec![0x42u8; 32]);
    let (_pdk, edk) = keyring.wrap(SUITE).unwrap();

    // Exactly one EDK succeeds; zero or two EDKs are rejected.
    let mut one = DecryptionMaterials::new(SUITE);
    let mut zero = DecryptionMaterials::new(SUITE);
    let mut two = DecryptionMaterials::new(SUITE);

    //= ../spec/s3-encryption/materials/s3-keyring.md#ondecrypt
    //= type=test
    //= reason=exactly 1 EDK decrypts; 0 EDKs and 2 EDKs each -> S3EncryptionError::Crypto, proving the count guard rejects any number other than 1
    //# If the input collection of EncryptedDataKey instances contains any number of EDKs other than 1, the S3 Keyring MUST throw an exception.
    assert!(keyring.on_decrypt(&mut one, std::slice::from_ref(&edk)).is_ok());
    assert!(matches!(
        keyring.on_decrypt(&mut zero, &[]).unwrap_err(),
        S3EncryptionError::Crypto(_)
    ));
    assert!(matches!(
        keyring.on_decrypt(&mut two, &[edk.clone(), edk]).unwrap_err(),
        S3EncryptionError::Crypto(_)
    ));
}

#[test]
fn on_decrypt_calls_decrypt_data_key_and_adds_plaintext_to_materials() {
    let keyring = AesKeyring::new(vec![0x42u8; 32]);
    let (expected_pdk, edk) = keyring.wrap(SUITE).unwrap();

    let mut materials = DecryptionMaterials::new(SUITE);
    assert!(materials.plaintext_data_key().is_none(), "precondition: no PDK");
    keyring.on_decrypt(&mut materials, &[edk]).unwrap();

    //= ../spec/s3-encryption/materials/s3-keyring.md#ondecrypt
    //= type=test
    //= reason=after on_decrypt the materials carry the plaintext data key recovered by DecryptDataKey, equal to the key that was wrapped
    //# The S3 Keyring MUST call the DecryptDataKey method using the materials and add the resulting plaintext data key to the materials.
    assert_eq!(materials.plaintext_data_key().unwrap(), expected_pdk.as_slice());
}

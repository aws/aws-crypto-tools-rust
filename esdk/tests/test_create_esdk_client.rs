// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use aws_crypto_mpl::cmm::DefaultCmm;
use aws_crypto_mpl::keyring::RawAesKeyring;
use aws_esdk::{DecryptInput, EncryptInput, EncryptionContext, ErrorKind, decrypt, encrypt};
use aws_mpl_primitives::AesGcm;
use std::num::NonZeroU32;

#[allow(clippy::duplicate_mod)]
mod fixtures;
mod test_helpers;

use test_helpers::{encrypt_with_suite, test_keyring};

// A ciphertext produced by ESDK-.NET v4.0.0, which serialized the message
// header incorrectly. This SDK must not be able to decrypt it.
const ESDK_NET_V400_MESSAGE: &[u8] = &[
    2, 5, 120, 238, 5, 239, 107, 129, 136, 211, 103, 75, 18, 140, 11, 74, 26, 191, 92, 27, 202,
    170, 33, 28, 9, 117, 252, 29, 29, 92, 213, 21, 231, 172, 234, 0, 95, 0, 1, 0, 21, 97, 119, 115,
    45, 99, 114, 121, 112, 116, 111, 45, 112, 117, 98, 108, 105, 99, 45, 107, 101, 121, 0, 68, 65,
    119, 102, 117, 103, 90, 99, 107, 57, 116, 100, 53, 104, 78, 108, 49, 78, 108, 75, 111, 47, 104,
    105, 114, 53, 85, 47, 48, 81, 109, 98, 73, 111, 107, 79, 72, 81, 87, 97, 72, 83, 43, 115, 117,
    119, 75, 73, 77, 82, 76, 99, 67, 80, 49, 54, 55, 56, 43, 49, 82, 75, 49, 48, 82, 101, 119, 61,
    61, 0, 1, 0, 21, 83, 111, 109, 101, 32, 109, 97, 110, 97, 103, 101, 100, 32, 114, 97, 119, 32,
    107, 101, 121, 115, 0, 47, 77, 121, 32, 50, 53, 54, 45, 98, 105, 116, 32, 65, 69, 83, 32, 119,
    114, 97, 112, 112, 105, 110, 103, 32, 107, 101, 121, 0, 0, 0, 128, 0, 0, 0, 12, 229, 254, 197,
    205, 110, 124, 222, 48, 217, 121, 252, 11, 0, 48, 64, 60, 232, 232, 76, 229, 15, 118, 224, 152,
    79, 93, 113, 166, 255, 172, 255, 148, 185, 150, 195, 179, 78, 52, 186, 38, 216, 48, 118, 45,
    113, 204, 71, 102, 116, 148, 199, 109, 178, 19, 2, 203, 150, 201, 65, 32, 199, 180, 2, 0, 0,
    16, 0, 67, 72, 208, 112, 230, 137, 188, 187, 0, 28, 183, 198, 192, 45, 248, 108, 2, 129, 34,
    42, 59, 155, 70, 117, 182, 216, 239, 27, 210, 78, 62, 104, 181, 247, 141, 50, 133, 42, 72, 200,
    185, 57, 20, 49, 193, 240, 171, 140, 255, 255, 255, 255, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 1, 0, 0, 0, 15, 67, 37, 106, 11, 15, 23, 78, 239, 208, 185, 4, 36, 182, 9, 63, 62, 83,
    97, 42, 250, 252, 185, 165, 14, 182, 231, 83, 176, 227, 191, 92, 0, 103, 48, 101, 2, 49, 0,
    193, 152, 7, 169, 197, 137, 244, 88, 9, 1, 6, 56, 96, 13, 220, 201, 56, 16, 50, 68, 70, 36,
    174, 38, 14, 241, 207, 11, 139, 154, 166, 224, 191, 20, 12, 175, 56, 117, 183, 120, 119, 228,
    173, 130, 71, 110, 211, 189, 2, 48, 99, 98, 250, 36, 53, 182, 2, 204, 198, 55, 150, 51, 159,
    101, 231, 34, 42, 30, 57, 204, 88, 114, 138, 94, 12, 79, 52, 71, 178, 34, 61, 246, 55, 163,
    145, 95, 80, 61, 85, 143, 32, 0, 98, 20, 88, 251, 204, 5,
];

// Guards against regressing into the ESDK-.NET v4.0.0 header serialization:
// the message must fail header authentication rather than decrypt.
#[tokio::test(flavor = "multi_thread")]
async fn test_net_v400_message_is_not_readable() {
    let raw_aes_keyring = RawAesKeyring::new(
        "Some managed raw keys",
        "My 256-bit AES wrapping key",
        vec![0u8; 32],
        AesGcm::Aes256Gcm,
    )
    .expect("raw AES keyring construction must succeed for the .NET v4.0.0 regression key");

    let input = DecryptInput::builder()
        .ciphertext(ESDK_NET_V400_MESSAGE)
        .keyring(raw_aes_keyring)
        .build()
        .unwrap();

    let err = decrypt(&input)
        .await
        .expect_err("v4.0.0 .NET message must not decrypt");
    assert!(
        matches!(err.kind(), ErrorKind::Cryptographic),
        "expected Cryptographic error, got {:?}",
        err.kind()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_default_commitment_policy() {
    let keyring = test_keyring().await;
    //= spec/client-apis/client.md#initialization
    //= type=test
    //= reason=EncryptInput and DecryptInput built without a commitment policy both return RequireEncryptRequireDecrypt
    //# If no [commitment policy](#commitment-policy) is provided the default MUST be [REQUIRE_ENCRYPT_REQUIRE_DECRYPT](../framework/algorithm-suites.md#require_encrypt_require_decrypt).
    let expected = CommitmentPolicy::RequireEncryptRequireDecrypt;
    assert_eq!(
        EncryptInput::builder()
            .plaintext(b"")
            .keyring(keyring.clone())
            .build()
            .unwrap()
            .commitment_policy(),
        expected,
        "EncryptInput default commitment policy"
    );
    assert_eq!(
        DecryptInput::builder()
            .ciphertext(b"")
            .keyring(keyring)
            .build()
            .unwrap()
            .commitment_policy(),
        expected,
        "DecryptInput default commitment policy"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_default_max_encrypted_data_keys_is_none() {
    let keyring = test_keyring().await;
    //= spec/client-apis/client.md#initialization
    //= type=test
    //# If no [maximum number of encrypted data keys](#maximum-number-of-encrypted-data-keys) is provided
    //# the default MUST result in no limit on the number of encrypted data keys (aside from the limit imposed by the [message format](../format/message-header.md)).
    assert!(
        EncryptInput::builder()
            .plaintext(b"")
            .keyring(keyring.clone())
            .build()
            .unwrap()
            .max_encrypted_data_keys()
            .is_none(),
        "EncryptInput default max_encrypted_data_keys must be None (no limit)"
    );
    assert!(
        DecryptInput::builder()
            .ciphertext(b"")
            .keyring(keyring)
            .build()
            .unwrap()
            .max_encrypted_data_keys()
            .is_none(),
        "DecryptInput default max_encrypted_data_keys must be None (no limit)"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_frame_length_accepts_max_u32() {
    //= spec/data-format/message-body.md#framed-data
    //= type=test
    //= reason=an EncryptInput builds with a frame length of u32::MAX, proving the implementation accepts the maximum allowed value
    //# - The total bytes allowed in a single frame MUST be less than or equal to `2^32 - 1`.
    let input = EncryptInput::builder()
        .plaintext(b"pt")
        .keyring(test_keyring().await)
        .frame_length(NonZeroU32::MAX)
        .build()
        .unwrap();
    assert_eq!(input.frame_length().get(), u32::MAX);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_frame_length_default_is_4096() {
    //= spec/client-apis/encrypt.md#frame-length
    //= type=test
    //# This value MUST default to 4096 bytes.
    let input = EncryptInput::builder()
        .plaintext(b"pt")
        .keyring(test_keyring().await)
        .build()
        .unwrap();
    assert_eq!(input.frame_length().get(), 4096);
}

// Round-trip a fully-populated EncryptInput and DecryptInput through
// encrypt() and decrypt(). Each populated optional field is proven
// "accepted" by the operation returning Ok(_).
#[tokio::test(flavor = "multi_thread")]
async fn test_encrypt_decrypt_accepts_all_optional_inputs() {
    let keyring = test_keyring().await;
    let mut ec = EncryptionContext::new();
    ec.insert("greet", "hello");
    let plaintext = b"round-trip plaintext";

    let encrypt_input = EncryptInput::builder()
        //= spec/client-apis/encrypt.md#input
        //= type=test
        //= reason=the algorithm suite is set to a non-default V1 suite; encrypt() succeeds
        //# - Encrypt operation input MUST accept an optional [Algorithm Suite](#algorithm-suite) argument.
        .algorithm_suite_id(AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256)
        //= spec/client-apis/client.md#initialization
        //= type=test
        //= reason=the commitment policy is set non-default; encrypt() honors it
        //# - On client initialization,
        //# the caller MUST have the option to provide a [commitment policy](#commitment-policy).
        //
        //= spec/client-apis/client.md#commitment-policy
        //= type=test
        //= reason=commitment_policy is an CommitmentPolicy from aws_esdk; encrypt() honors it
        //# The AWS Encryption SDK MUST use the ESDK [commitment policies](../framework/commitment-policy.md) defined in the Material Providers Library.
        .commitment_policy(CommitmentPolicy::ForbidEncryptAllowDecrypt)
        //= spec/client-apis/encrypt.md#input
        //= type=test
        //= reason=the frame length is set to a non-default 1024; encrypt() succeeds
        //# - Encrypt operation input MUST accept an optional [Frame Length](#frame-length) argument.
        .frame_length(NonZeroU32::new(1024).unwrap())
        //= spec/client-apis/client.md#initialization
        //= type=test
        //= reason=the EDK cap is set to 5; encrypt() succeeds
        //# - On client initialization,
        //# the caller MUST have the option to provide a [maximum number of encrypted data keys](#maximum-number-of-encrypted-data-keys).
        .max_encrypted_data_keys(std::num::NonZeroUsize::new(5).unwrap())
        //= spec/client-apis/encrypt.md#input
        //= type=test
        //= reason=encrypt() returns Ok with plaintext populated, proving the required plaintext argument is accepted
        //# - Encrypt operation input MUST accept a required [plaintext](#plaintext) argument.
        .plaintext(plaintext)
        //= spec/client-apis/encrypt.md#input
        //= type=test
        //= reason=the encryption context is populated; encrypt() succeeds
        //# - Encrypt operation input MUST accept an optional [Encryption Context](#encryption-context) argument.
        .encryption_context(ec.clone())
        //= spec/client-apis/encrypt.md#input
        //= type=test
        //= reason=a keyring is set; encrypt() succeeds
        //# - Encrypt operation input MUST accept an optional [keyring](../framework/keyring-interface.md) argument.
        .keyring(keyring.clone())
        .build()
        .unwrap();

    let encrypt_output = encrypt(&encrypt_input)
        .await
        .expect("encrypt must accept a fully-populated EncryptInput");

    let decrypt_input = DecryptInput::builder()
        //= spec/client-apis/decrypt.md#input
        //= type=test
        //= reason=the ciphertext is the &[u8] produced by encrypt(); decrypt() succeeds
        //# - Decrypt operation input MUST accept a required [Encrypted Message](#encrypted-message) argument.
        //
        //= spec/client-apis/decrypt.md#encrypted-message
        //= type=test
        //= reason=ciphertext is the byte-sequence ESDK message; decrypt() accepts and round-trips it
        //# The input encrypted message MUST be a sequence of bytes in the
        //# [message format](../data-format/message.md) specified by the AWS Encryption SDK.
        .ciphertext(&encrypt_output.ciphertext)
        //= spec/client-apis/decrypt.md#input
        //= type=test
        //= reason=the encryption context is populated; decrypt() succeeds
        //# - Decrypt operation input MUST accept an optional [Encryption Context](#encryption-context) argument.
        .encryption_context(ec.clone())
        //= spec/client-apis/decrypt.md#input
        //= type=test
        //= reason=a keyring is set; decrypt() succeeds
        //# - Decrypt operation input MUST accept an optional [Keyring](../framework/keyring-interface.md) argument.
        .keyring(keyring)
        .commitment_policy(CommitmentPolicy::ForbidEncryptAllowDecrypt)
        .max_encrypted_data_keys(std::num::NonZeroUsize::new(5).unwrap())
        .build()
        .unwrap();

    let decrypt_output = decrypt(&decrypt_input)
        .await
        .expect("decrypt must accept a fully-populated DecryptInput");

    assert_eq!(
        decrypt_output.plaintext, plaintext,
        "round-trip plaintext must match"
    );
    assert_eq!(
        decrypt_output.encryption_context.get("greet"),
        Some("hello"),
        "encrypt/decrypt must honor the encryption context input"
    );
}

// encrypt/decrypt accept a CMM input; uses a default CMM from a raw-AES keyring.
#[tokio::test(flavor = "multi_thread")]
async fn test_encrypt_decrypt_accepts_cmm() {
    let keyring = test_keyring().await;
    let cmm = DefaultCmm::new(keyring);
    let plaintext = b"cmm round-trip plaintext";

    let encrypt_input = EncryptInput::builder()
        .plaintext(plaintext)
        //= spec/client-apis/encrypt.md#input
        //= type=test
        //= reason=a CMM is set; encrypt() succeeds
        //# - Encrypt operation input MUST accept an optional [cryptographic Materials Manager (CMM)](../framework/cmm-interface.md) argument.
        .cmm(cmm.clone())
        .build()
        .unwrap();

    let encrypt_output = encrypt(&encrypt_input)
        .await
        .expect("encrypt must accept a CMM input");

    let decrypt_input = DecryptInput::builder()
        .ciphertext(&encrypt_output.ciphertext)
        //= spec/client-apis/decrypt.md#input
        //= type=test
        //= reason=a CMM is set; decrypt() succeeds
        //# - Decrypt operation input MUST accept an optional [Cryptographic Materials Manager (CMM)](../framework/cmm-interface.md) argument.
        .cmm(cmm)
        .build()
        .unwrap();

    let decrypt_output = decrypt(&decrypt_input)
        .await
        .expect("decrypt must accept a CMM input");

    assert_eq!(
        decrypt_output.plaintext, plaintext,
        "round-trip plaintext must match when using a CMM"
    );
}

// EncryptInputBuilder::build() rejects an input that sets neither keyring nor
// cmm, and one that sets both.
#[tokio::test(flavor = "multi_thread")]
async fn test_encrypt_rejects_neither_and_both_sources() {
    let keyring = test_keyring().await;
    let cmm = DefaultCmm::new(keyring.clone());

    //= spec/client-apis/encrypt.md#input
    //= type=test
    //# The Encrypt operation MUST validate that exactly one keyring or CMM was provided by the caller.
    //
    //= spec/client-apis/encrypt.md#input
    //= type=test
    //# If the caller does not provide exactly one of a keyring or CMM, the Encrypt operation MUST fail.
    let err = EncryptInput::builder()
        .plaintext(b"no source")
        .build()
        .expect_err("build must fail when neither keyring nor cmm is set");
    assert!(
        matches!(err.kind(), ErrorKind::Validation),
        "expected Validation error, got {:?}",
        err.kind()
    );

    let err = EncryptInput::builder()
        .plaintext(b"two sources")
        .keyring(keyring)
        .cmm(cmm)
        .build()
        .expect_err("build must fail when both keyring and cmm are set");
    assert!(
        matches!(err.kind(), ErrorKind::Validation),
        "expected Validation error, got {:?}",
        err.kind()
    );
}

// DecryptInputBuilder::build() rejects an input that sets neither keyring nor
// cmm, and one that sets both.
#[tokio::test(flavor = "multi_thread")]
async fn test_decrypt_rejects_neither_and_both_sources() {
    let keyring = test_keyring().await;
    let cmm = DefaultCmm::new(keyring.clone());

    //= spec/client-apis/decrypt.md#input
    //= type=test
    //# The Decrypt operation MUST validate that exactly one of a keyring or CMM was provided by the caller.
    //
    //= spec/client-apis/decrypt.md#input
    //= type=test
    //# If the caller does not provide exactly one of a keyring or CMM, the Decrypt operation MUST fail.
    let err = DecryptInput::builder()
        .ciphertext(b"")
        .build()
        .expect_err("build must fail when neither keyring nor cmm is set");
    assert!(
        matches!(err.kind(), ErrorKind::Validation),
        "expected Validation error, got {:?}",
        err.kind()
    );

    let err = DecryptInput::builder()
        .ciphertext(b"")
        .keyring(keyring)
        .cmm(cmm)
        .build()
        .expect_err("build must fail when both keyring and cmm are set");
    assert!(
        matches!(err.kind(), ErrorKind::Validation),
        "expected Validation error, got {:?}",
        err.kind()
    );
}

// Esdk client tests

use aws_esdk::AlgorithmSuiteId;
use aws_esdk::CommitmentPolicy;
use aws_esdk::{Esdk, EsdkConfig};

#[test]
fn test_esdk_default_uses_default_config() {
    // Default Esdk has the spec-default commitment policy and no EDK cap.
    let esdk = Esdk::default();
    //= spec/client-apis/client.md#initialization
    //= type=test
    //# If no [commitment policy](#commitment-policy) is provided the default MUST be [REQUIRE_ENCRYPT_REQUIRE_DECRYPT](../framework/algorithm-suites.md#require_encrypt_require_decrypt).
    assert_eq!(
        esdk.config().commitment_policy,
        CommitmentPolicy::RequireEncryptRequireDecrypt,
        "Esdk::default() must use the default commitment policy"
    );
    //= spec/client-apis/client.md#initialization
    //= type=test
    //# If no [maximum number of encrypted data keys](#maximum-number-of-encrypted-data-keys) is provided
    //# the default MUST result in no limit on the number of encrypted data keys (aside from the limit imposed by the [message format](../format/message-header.md)).
    assert!(
        esdk.config().max_encrypted_data_keys.is_none(),
        "Esdk::default() must have no EDK cap"
    );
}

#[test]
fn test_esdk_builder_sets_commitment_policy() {
    //= spec/client-apis/client.md#initialization
    //= type=test
    //# - On client initialization,
    //# the caller MUST have the option to provide a [commitment policy](#commitment-policy).
    let esdk = Esdk::builder()
        .commitment_policy(CommitmentPolicy::ForbidEncryptAllowDecrypt)
        .build();
    assert_eq!(
        esdk.config().commitment_policy,
        CommitmentPolicy::ForbidEncryptAllowDecrypt,
        "builder().commitment_policy(...) must set it on the resulting Esdk's config"
    );
}

#[test]
fn test_esdk_builder_sets_max_encrypted_data_keys() {
    let cap = std::num::NonZeroUsize::new(3).unwrap();
    //= spec/client-apis/client.md#initialization
    //= type=test
    //# - On client initialization,
    //# the caller MUST have the option to provide a [maximum number of encrypted data keys](#maximum-number-of-encrypted-data-keys).
    let esdk = Esdk::builder().max_encrypted_data_keys(cap).build();
    assert_eq!(
        esdk.config().max_encrypted_data_keys,
        Some(cap),
        "builder().max_encrypted_data_keys(...) must set it on the resulting Esdk's config"
    );
}

#[test]
fn test_esdk_new_takes_explicit_config() {
    // Direct construction from a built EsdkConfig is also supported.
    let mut config = EsdkConfig::default();
    config.commitment_policy = CommitmentPolicy::ForbidEncryptAllowDecrypt;
    config.max_encrypted_data_keys = std::num::NonZeroUsize::new(7);
    let esdk = Esdk::new(config);
    assert_eq!(
        esdk.config().commitment_policy,
        CommitmentPolicy::ForbidEncryptAllowDecrypt
    );
    assert_eq!(
        esdk.config().max_encrypted_data_keys,
        std::num::NonZeroUsize::new(7)
    );
}

// Esdk methods reject calls whose input *also* sets commitment_policy or
// max_encrypted_data_keys: providing config in two places at once is reserved.
// The rejection check fires before any materials are requested.

#[tokio::test(flavor = "multi_thread")]
async fn test_esdk_encrypt_rejects_input_with_non_default_commitment_policy() {
    let esdk = Esdk::default();
    let input = EncryptInput::builder()
        .plaintext(b"")
        .keyring(test_keyring().await)
        .commitment_policy(CommitmentPolicy::ForbidEncryptAllowDecrypt)
        .build()
        .unwrap();

    let err = esdk
        .encrypt(&input)
        .await
        .expect_err("Esdk::encrypt must reject input that sets commitment_policy when the client also configures it");
    assert!(
        matches!(err.kind(), ErrorKind::Validation),
        "expected Validation error, got {:?}",
        err.kind()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_esdk_encrypt_rejects_input_with_max_encrypted_data_keys() {
    let esdk = Esdk::default();
    let input = EncryptInput::builder()
        .plaintext(b"")
        .keyring(test_keyring().await)
        .max_encrypted_data_keys(std::num::NonZeroUsize::new(2).unwrap())
        .build()
        .unwrap();

    let err = esdk
        .encrypt(&input)
        .await
        .expect_err("Esdk::encrypt must reject input that sets max_encrypted_data_keys when the client also configures it");
    assert!(
        matches!(err.kind(), ErrorKind::Validation),
        "expected Validation error, got {:?}",
        err.kind()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_esdk_decrypt_rejects_input_with_non_default_commitment_policy() {
    let esdk = Esdk::default();
    let input = DecryptInput::builder()
        .ciphertext(b"")
        .keyring(test_keyring().await)
        .commitment_policy(CommitmentPolicy::ForbidEncryptAllowDecrypt)
        .build()
        .unwrap();

    let err = esdk
        .decrypt(&input)
        .await
        .expect_err("Esdk::decrypt must reject input that sets commitment_policy when the client also configures it");
    assert!(
        matches!(err.kind(), ErrorKind::Validation),
        "expected Validation error, got {:?}",
        err.kind()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_esdk_decrypt_rejects_input_with_max_encrypted_data_keys() {
    let esdk = Esdk::default();
    let input = DecryptInput::builder()
        .ciphertext(b"")
        .keyring(test_keyring().await)
        .max_encrypted_data_keys(std::num::NonZeroUsize::new(2).unwrap())
        .build()
        .unwrap();

    let err = esdk
        .decrypt(&input)
        .await
        .expect_err("Esdk::decrypt must reject input that sets max_encrypted_data_keys when the client also configures it");
    assert!(
        matches!(err.kind(), ErrorKind::Validation),
        "expected Validation error, got {:?}",
        err.kind()
    );
}

// Round-trip: configure the Esdk client, hand it inputs that DO NOT set client
// config, and verify the encrypt/decrypt pair succeeds and produces the
// original plaintext.
#[tokio::test(flavor = "multi_thread")]
async fn test_esdk_encrypt_decrypt_round_trip() {
    let plaintext: &[u8] = b"hello via Esdk client";
    let keyring = test_keyring().await;

    let esdk = Esdk::builder()
        .commitment_policy(CommitmentPolicy::RequireEncryptRequireDecrypt)
        .build();

    let ec = EncryptionContext::new();
    let enc_input = EncryptInput::builder()
        .plaintext(plaintext)
        .encryption_context(ec.clone())
        .keyring(keyring.clone())
        .build()
        .unwrap();
    //= spec/client-apis/client.md#encrypt
    //= type=test
    //# The AWS Encryption SDK Client MUST provide an [encrypt](./encrypt.md#input) function
    //# that adheres to [encrypt](./encrypt.md).
    let ct = esdk
        .encrypt(&enc_input)
        .await
        .expect("Esdk::encrypt must succeed for a default input + configured client");

    let dec_input = DecryptInput::builder()
        .ciphertext(&ct.ciphertext)
        .encryption_context(ec)
        .keyring(keyring)
        .build()
        .unwrap();
    //= spec/client-apis/client.md#decrypt
    //= type=test
    //# The AWS Encryption SDK Client MUST provide an [decrypt](./decrypt.md#input) function
    //# that adheres to [decrypt](./decrypt.md).
    let pt = esdk
        .decrypt(&dec_input)
        .await
        .expect("Esdk::decrypt must succeed on the matching ciphertext");
    assert_eq!(
        pt.plaintext, plaintext,
        "Esdk round-trip must produce the original plaintext"
    );
}

// Proves the Esdk's configured commitment policy actually reaches the
// encryption logic: with `ForbidEncryptAllowDecrypt` configured on the client
// and a known committing (V2) suite explicitly selected on the input,
// encrypt must reject. If the client's policy were not being applied to the
// underlying call, the input would carry `RequireEncryptRequireDecrypt` (the
// EncryptInput default) and the call with a committing suite would succeed —
// so the failure here is what falsifies "the Esdk's commitment_policy is
// applied."
#[tokio::test(flavor = "multi_thread")]
async fn test_esdk_commitment_policy_actually_gates_encrypt() {
    let keyring = test_keyring().await;
    let esdk = Esdk::builder()
        .commitment_policy(CommitmentPolicy::ForbidEncryptAllowDecrypt)
        .build();

    let enc_input = EncryptInput::builder()
        .plaintext(b"x")
        .keyring(keyring)
        // Explicitly request a V2 committing suite. ForbidEncryptAllowDecrypt
        // forbids committing on encrypt → must fail.
        .algorithm_suite_id(AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey)
        .build()
        .unwrap();
    let err = esdk
        .encrypt(&enc_input)
        .await
        .expect_err("ForbidEncryptAllowDecrypt + committing V2 suite must fail encrypt");
    // The ESDK checks the algorithm suite against the commitment policy before calling the MPL,
    // and returns a Validation error for the conflict.
    assert_eq!(
        err.kind(),
        ErrorKind::Validation,
        "expected Validation error, got {:?}: {}",
        err.kind(),
        err.message()
    );
    let inner = err.to_string();
    //= spec/client-apis/client.md#commitment-policy
    //= type=test
    //= reason=the ESDK gates the algorithm suite against the commitment policy and yields a Validation error
    //# The AWS Encryption SDK MUST use the ESDK [commitment policies](../framework/commitment-policy.md) defined in the Material Providers Library.
    assert!(
        inner.contains("commitment policy"),
        "expected a commitment-policy rejection, got: {inner}"
    );
}

// Symmetric to `test_esdk_commitment_policy_actually_gates_encrypt`: proves
// the Esdk's configured commitment policy actually reaches the decrypt path.
//
// Setup: produce a non-committing (V1) ciphertext via the free `encrypt` with
// `ForbidEncryptAllowDecrypt` set on the input. Then configure the client with
// `ForbidEncryptAllowDecrypt` and verify `Esdk::decrypt` succeeds. If the
// client's policy were not being applied, the input would carry the default
// `RequireEncryptRequireDecrypt`, which would reject the V1 ciphertext —
// so the success here falsifies "the Esdk's commitment_policy is applied on
// decrypt."
#[tokio::test(flavor = "multi_thread")]
async fn test_esdk_commitment_policy_actually_gates_decrypt() {
    let keyring = test_keyring().await;
    let plaintext = b"decrypt gating proof";

    // Build a non-committing V1 ciphertext using the free encrypt path with the
    // matching ForbidEncryptAllowDecrypt policy on the input. (Esdk::encrypt
    // can't produce this ciphertext under the default RequireEncryptRequireDecrypt,
    // which is why we use the free function here for setup.)
    let ct = encrypt_with_suite(
        plaintext,
        AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256,
        CommitmentPolicy::ForbidEncryptAllowDecrypt,
        &keyring,
    )
    .await;

    // Configure the Esdk with ForbidEncryptAllowDecrypt and try to decrypt.
    let esdk = Esdk::builder()
        .commitment_policy(CommitmentPolicy::ForbidEncryptAllowDecrypt)
        .build();
    let dec_input = DecryptInput::builder()
        .ciphertext(&ct)
        .keyring(keyring)
        .build()
        .unwrap();

    let out = esdk
        .decrypt(&dec_input)
        .await
        .expect("Esdk(ForbidEncryptAllowDecrypt) must accept a V1 non-committing ciphertext");
    assert_eq!(
        out.plaintext, plaintext,
        "decrypt under Esdk client must round-trip the V1 plaintext"
    );

    // Sanity: the *default* Esdk (RequireEncryptRequireDecrypt) must reject
    // the same V1 ciphertext, confirming the previous success was due to the
    // ForbidEncryptAllowDecrypt config flowing through (not just "any V1
    // ciphertext decrypts via Esdk::decrypt").
    let default_esdk = Esdk::default();
    let err = default_esdk.decrypt(&dec_input).await.expect_err(
        "default Esdk (RequireEncryptRequireDecrypt) must reject V1 non-committing ciphertext",
    );
    assert_eq!(
        err.kind(),
        ErrorKind::Validation,
        "expected Validation error, got {:?}: {}",
        err.kind(),
        err.message()
    );
    let inner = err.to_string();
    //= spec/client-apis/client.md#commitment-policy
    //= type=test
    //= reason=the ESDK gates the parsed algorithm suite against the commitment policy and yields a Validation error
    //# The AWS Encryption SDK MUST use the ESDK [commitment policies](../framework/commitment-policy.md) defined in the Material Providers Library.
    assert!(
        inner.contains("commitment policy"),
        "expected a commitment-policy rejection, got: {inner}"
    );
}

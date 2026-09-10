// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Round-trips every supported ESDK algorithm suite and asserts the suite ID
//! serialized on the wire, so each suite's AES key size, KDF, and signature
//! configuration is exercised end to end (128/192/256-bit suites included).

#[allow(clippy::duplicate_mod)]
mod fixtures;
mod test_helpers;

use aws_esdk::*;
use aws_mpl_legacy::commitment::EsdkCommitmentPolicy;
use aws_mpl_legacy::suites::EsdkAlgorithmSuiteId;
use test_helpers::test_keyring;

// Known suite IDs from spec/framework/algorithm-suites.md, repeated here
// verbatim so the on-wire assertion is against the specification values
// (not against the source constants).
const V1_SUITES: [(EsdkAlgorithmSuiteId, [u8; 2]); 9] = [
    (
        EsdkAlgorithmSuiteId::AlgAes128GcmIv12Tag16NoKdf,
        [0x00, 0x14],
    ),
    (
        EsdkAlgorithmSuiteId::AlgAes192GcmIv12Tag16NoKdf,
        [0x00, 0x46],
    ),
    (
        EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf,
        [0x00, 0x78],
    ),
    (
        EsdkAlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256,
        [0x01, 0x14],
    ),
    (
        EsdkAlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha256,
        [0x01, 0x46],
    ),
    (
        EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256,
        [0x01, 0x78],
    ),
    (
        EsdkAlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256,
        [0x02, 0x14],
    ),
    (
        EsdkAlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384,
        [0x03, 0x46],
    ),
    (
        EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384,
        [0x03, 0x78],
    ),
];

const V2_SUITES: [(EsdkAlgorithmSuiteId, [u8; 2]); 2] = [
    (
        EsdkAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey,
        [0x04, 0x78],
    ),
    (
        EsdkAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384,
        [0x05, 0x78],
    ),
];

// Every V1 (non-committing) suite round-trips, reports the requested suite in
// the output, and serializes the spec-defined suite ID at the V1 header
// offset (bytes 2-3, after Version and Type).
#[tokio::test(flavor = "multi_thread")]
async fn test_v1_suites_round_trip_with_on_wire_suite_id() {
    for (suite, expected_id) in V1_SUITES {
        let keyring = test_keyring().await;
        let pt = b"suite sweep v1";
        let mut enc_input =
            EncryptInput::with_legacy_keyring(pt, EncryptionContext::new(), keyring.clone());
        enc_input.algorithm_suite_id = Some(suite);
        enc_input.commitment_policy = EsdkCommitmentPolicy::ForbidEncryptAllowDecrypt;
        let out = encrypt(&enc_input)
            .await
            .unwrap_or_else(|e| panic!("{suite:?} encrypt failed: {e:?}"));
        assert_eq!(out.algorithm_suite_id, suite, "{suite:?} output suite");

        let ct = out.ciphertext;
        assert_eq!(ct[0], 0x01, "{suite:?} version byte");
        assert_eq!(
            [ct[2], ct[3]],
            expected_id,
            "{suite:?} on-wire suite ID bytes"
        );

        let mut dec_input =
            DecryptInput::with_legacy_keyring(&ct, EncryptionContext::new(), keyring);
        dec_input.commitment_policy = EsdkCommitmentPolicy::ForbidEncryptAllowDecrypt;
        let dec = decrypt(&dec_input)
            .await
            .unwrap_or_else(|e| panic!("{suite:?} decrypt failed: {e:?}"));
        assert_eq!(dec.plaintext, pt, "{suite:?} plaintext");
        assert_eq!(dec.algorithm_suite_id, suite, "{suite:?} decrypt suite");
    }
}

// Both V2 (committing) suites round-trip, report the requested suite, and
// serialize the spec-defined suite ID at the V2 header offset (bytes 1-2,
// after Version).
#[tokio::test(flavor = "multi_thread")]
async fn test_v2_suites_round_trip_with_on_wire_suite_id() {
    for (suite, expected_id) in V2_SUITES {
        let keyring = test_keyring().await;
        let pt = b"suite sweep v2";
        let mut enc_input =
            EncryptInput::with_legacy_keyring(pt, EncryptionContext::new(), keyring.clone());
        enc_input.algorithm_suite_id = Some(suite);
        let out = encrypt(&enc_input)
            .await
            .unwrap_or_else(|e| panic!("{suite:?} encrypt failed: {e:?}"));
        assert_eq!(out.algorithm_suite_id, suite, "{suite:?} output suite");

        let ct = out.ciphertext;
        assert_eq!(ct[0], 0x02, "{suite:?} version byte");
        assert_eq!(
            [ct[1], ct[2]],
            expected_id,
            "{suite:?} on-wire suite ID bytes"
        );

        let dec_input = DecryptInput::with_legacy_keyring(&ct, EncryptionContext::new(), keyring);
        let dec = decrypt(&dec_input)
            .await
            .unwrap_or_else(|e| panic!("{suite:?} decrypt failed: {e:?}"));
        assert_eq!(dec.plaintext, pt, "{suite:?} plaintext");
        assert_eq!(dec.algorithm_suite_id, suite, "{suite:?} decrypt suite");
    }
}

// RequireEncryptAllowDecrypt: committing suite encrypts under it, and a
// non-committing message still decrypts under it.
#[tokio::test(flavor = "multi_thread")]
async fn test_require_encrypt_allow_decrypt_policy() {
    let keyring = test_keyring().await;
    let pt = b"require-encrypt-allow-decrypt";

    // Encrypt side: committing suite is allowed.
    let mut enc_input =
        EncryptInput::with_legacy_keyring(pt, EncryptionContext::new(), keyring.clone());
    enc_input.commitment_policy = EsdkCommitmentPolicy::RequireEncryptAllowDecrypt;
    let ct = encrypt(&enc_input).await.unwrap().ciphertext;

    // Decrypt side: both committing and non-committing messages are allowed.
    let mut dec_input =
        DecryptInput::with_legacy_keyring(&ct, EncryptionContext::new(), keyring.clone());
    dec_input.commitment_policy = EsdkCommitmentPolicy::RequireEncryptAllowDecrypt;
    assert_eq!(decrypt(&dec_input).await.unwrap().plaintext, pt);

    let mut v1_enc =
        EncryptInput::with_legacy_keyring(pt, EncryptionContext::new(), keyring.clone());
    v1_enc.algorithm_suite_id = Some(EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256);
    v1_enc.commitment_policy = EsdkCommitmentPolicy::ForbidEncryptAllowDecrypt;
    let v1_ct = encrypt(&v1_enc).await.unwrap().ciphertext;
    let mut v1_dec = DecryptInput::with_legacy_keyring(&v1_ct, EncryptionContext::new(), keyring);
    v1_dec.commitment_policy = EsdkCommitmentPolicy::RequireEncryptAllowDecrypt;
    assert_eq!(decrypt(&v1_dec).await.unwrap().plaintext, pt);
}

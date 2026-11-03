// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Raw ECDH keyring tests, ported from the Dafny `TesRawECDHKeyring.dfy`:
//! - round trips for every key agreement scheme and curve, with direct and intermediate key wrapping
//! - the encrypt-only and decrypt-only schemes refusing the other operation
//! - the builder rejecting keys on a different curve
//! - the decrypt failures

use aws_crypto_mpl::keyring::{
    EphemeralPrivateKeyToStaticPublicKeyInput, PublicKeyDiscoveryInput, RawEcdhKeyring,
    RawEcdhStaticConfigurations, RawPrivateKeyToStaticPublicKeyInput,
};
use aws_crypto_mpl::types::{
    AlgorithmSuiteId, DbeAlgorithmSuiteId, DecryptionMaterials, EcdhCurveSpec, EncryptedDataKey,
    EncryptionContext, EncryptionMaterials, EsdkAlgorithmSuiteId,
};
use aws_mpl_primitives::{EcdhKeyPair, ecdh_generate_key_pair};

const SUITE: AlgorithmSuiteId =
    AlgorithmSuiteId::Esdk(EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf);
const DBE_SUITE: AlgorithmSuiteId =
    AlgorithmSuiteId::Dbe(DbeAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeySymsigHmacSha384);

const CURVES: [EcdhCurveSpec; 3] = [
    EcdhCurveSpec::EccNistP256,
    EcdhCurveSpec::EccNistP384,
    EcdhCurveSpec::EccNistP521,
];

fn prim_curve(curve: EcdhCurveSpec) -> aws_mpl_primitives::EcdhCurveSpec {
    match curve {
        EcdhCurveSpec::EccNistP256 => aws_mpl_primitives::EcdhCurveSpec::EccNistP256,
        EcdhCurveSpec::EccNistP384 => aws_mpl_primitives::EcdhCurveSpec::EccNistP384,
        _ => aws_mpl_primitives::EcdhCurveSpec::EccNistP521,
    }
}

fn key_pair(curve: EcdhCurveSpec) -> EcdhKeyPair {
    ecdh_generate_key_pair(prim_curve(curve)).unwrap()
}

fn ec() -> EncryptionContext {
    let mut ec = EncryptionContext::new();
    ec.insert("keyA", "valA");
    ec
}

fn enc_materials(suite: AlgorithmSuiteId) -> EncryptionMaterials {
    EncryptionMaterials::builder()
        .algorithm_suite_id(suite)
        .set_encryption_context(Some(ec()))
        .build()
        .unwrap()
}

fn dec_materials(suite: AlgorithmSuiteId) -> DecryptionMaterials {
    DecryptionMaterials::builder()
        .algorithm_suite_id(suite)
        .set_encryption_context(Some(ec()))
        .build()
        .unwrap()
}

fn keyring(
    curve: EcdhCurveSpec,
    scheme: RawEcdhStaticConfigurations,
) -> Result<RawEcdhKeyring, aws_crypto_mpl::Error> {
    RawEcdhKeyring::builder()
        .curve_spec(curve)
        .key_agreement_scheme(scheme)
        .build()
}

fn static_keyring(
    curve: EcdhCurveSpec,
    sender_private_key: &[u8],
    recipient_public_key: &[u8],
) -> RawEcdhKeyring {
    keyring(
        curve,
        RawEcdhStaticConfigurations::RawPrivateKeyToStaticPublicKey(
            RawPrivateKeyToStaticPublicKeyInput::builder()
                .sender_static_private_key(sender_private_key)
                .recipient_public_key(recipient_public_key)
                .build()
                .unwrap(),
        ),
    )
    .unwrap()
}

fn ephemeral_keyring(curve: EcdhCurveSpec, recipient_public_key: &[u8]) -> RawEcdhKeyring {
    keyring(
        curve,
        RawEcdhStaticConfigurations::EphemeralPrivateKeyToStaticPublicKey(
            EphemeralPrivateKeyToStaticPublicKeyInput::builder()
                .recipient_public_key(recipient_public_key)
                .build()
                .unwrap(),
        ),
    )
    .unwrap()
}

fn discovery_keyring(curve: EcdhCurveSpec, recipient_private_key: &[u8]) -> RawEcdhKeyring {
    keyring(
        curve,
        RawEcdhStaticConfigurations::PublicKeyDiscovery(
            PublicKeyDiscoveryInput::builder()
                .recipient_static_private_key(recipient_private_key)
                .build()
                .unwrap(),
        ),
    )
    .unwrap()
}

async fn encrypt(k: &RawEcdhKeyring, suite: AlgorithmSuiteId) -> EncryptionMaterials {
    k.on_encrypt()
        .materials(enc_materials(suite))
        .send()
        .await
        .unwrap()
        .into_materials()
}

async fn decrypt(
    k: &RawEcdhKeyring,
    suite: AlgorithmSuiteId,
    edks: Vec<EncryptedDataKey>,
) -> Result<DecryptionMaterials, aws_crypto_mpl::Error> {
    k.on_decrypt()
        .materials(dec_materials(suite))
        .set_encrypted_data_keys(Some(edks))
        .send()
        .await
        .map(|out| out.into_materials())
}

/// Encrypt with `encryptor`, decrypt with `decryptor`, and check the data keys match.
async fn assert_round_trip(
    encryptor: &RawEcdhKeyring,
    decryptor: &RawEcdhKeyring,
    suite: AlgorithmSuiteId,
) {
    let out = encrypt(encryptor, suite).await;
    assert_eq!(out.encrypted_data_keys().len(), 1);
    assert_eq!(out.encrypted_data_keys()[0].key_provider_id(), "raw-ecdh");
    let dec = decrypt(decryptor, suite, out.encrypted_data_keys().to_vec())
        .await
        .unwrap();
    assert_eq!(
        dec.plaintext_data_key().unwrap().as_bytes(),
        out.plaintext_data_key().unwrap().as_bytes()
    );
}

#[tokio::test]
async fn a_static_keyring_decrypts_its_own_message_on_every_curve() {
    for curve in CURVES {
        let sender = key_pair(curve);
        let recipient = key_pair(curve);
        let k = static_keyring(curve, &sender.private_key, &recipient.public_key);
        assert_round_trip(&k, &k, SUITE).await;
        assert_round_trip(&k, &k, DBE_SUITE).await;
    }
}

#[tokio::test]
async fn the_recipient_decrypts_with_a_static_keyring_or_discovery() {
    for curve in CURVES {
        let sender = key_pair(curve);
        let recipient = key_pair(curve);
        let sender_keyring = static_keyring(curve, &sender.private_key, &recipient.public_key);
        // The recipient's static keyring has the two keys the other way round.
        let recipient_keyring = static_keyring(curve, &recipient.private_key, &sender.public_key);
        let discovery = discovery_keyring(curve, &recipient.private_key);
        for suite in [SUITE, DBE_SUITE] {
            assert_round_trip(&sender_keyring, &recipient_keyring, suite).await;
            assert_round_trip(&recipient_keyring, &sender_keyring, suite).await;
            assert_round_trip(&sender_keyring, &discovery, suite).await;
        }
    }
}

#[tokio::test]
async fn an_ephemeral_message_decrypts_with_discovery() {
    for curve in CURVES {
        let recipient = key_pair(curve);
        let ephemeral = ephemeral_keyring(curve, &recipient.public_key);
        let discovery = discovery_keyring(curve, &recipient.private_key);
        assert_round_trip(&ephemeral, &discovery, SUITE).await;
        assert_round_trip(&ephemeral, &discovery, DBE_SUITE).await;
    }
}

#[tokio::test]
async fn discovery_cannot_encrypt() {
    let recipient = key_pair(EcdhCurveSpec::EccNistP256);
    let discovery = discovery_keyring(EcdhCurveSpec::EccNistP256, &recipient.private_key);
    let err = discovery
        .on_encrypt()
        .materials(enc_materials(SUITE))
        .send()
        .await
        .unwrap_err();
    assert!(err.is_validation(), "{err:?}");
    assert!(err.to_string().contains("forbidden on encrypt"), "{err}");
}

#[tokio::test]
async fn ephemeral_cannot_decrypt_even_its_own_message() {
    let recipient = key_pair(EcdhCurveSpec::EccNistP256);
    let ephemeral = ephemeral_keyring(EcdhCurveSpec::EccNistP256, &recipient.public_key);
    let out = encrypt(&ephemeral, SUITE).await;
    let err = decrypt(&ephemeral, SUITE, out.encrypted_data_keys().to_vec())
        .await
        .unwrap_err();
    assert!(err.is_validation(), "{err:?}");
    assert!(err.to_string().contains("forbidden on decrypt"), "{err}");
}

#[test]
fn the_builder_rejects_keys_on_another_curve() {
    for key_curve in CURVES {
        let sender = key_pair(key_curve);
        let recipient = key_pair(key_curve);
        for curve in CURVES.into_iter().filter(|c| *c != key_curve) {
            let err = keyring(
                curve,
                RawEcdhStaticConfigurations::RawPrivateKeyToStaticPublicKey(
                    RawPrivateKeyToStaticPublicKeyInput::builder()
                        .sender_static_private_key(sender.private_key.clone())
                        .recipient_public_key(recipient.public_key.clone())
                        .build()
                        .unwrap(),
                ),
            )
            .unwrap_err();
            assert!(err.is_validation(), "{key_curve:?} as {curve:?}: {err:?}");
            let err = keyring(
                curve,
                RawEcdhStaticConfigurations::EphemeralPrivateKeyToStaticPublicKey(
                    EphemeralPrivateKeyToStaticPublicKeyInput::builder()
                        .recipient_public_key(recipient.public_key.clone())
                        .build()
                        .unwrap(),
                ),
            )
            .unwrap_err();
            assert!(err.is_validation(), "{key_curve:?} as {curve:?}: {err:?}");
            let err = keyring(
                curve,
                RawEcdhStaticConfigurations::PublicKeyDiscovery(
                    PublicKeyDiscoveryInput::builder()
                        .recipient_static_private_key(recipient.private_key.clone())
                        .build()
                        .unwrap(),
                ),
            )
            .unwrap_err();
            assert!(err.is_validation(), "{key_curve:?} as {curve:?}: {err:?}");
        }
    }
}

#[test]
fn the_builder_requires_every_input() {
    assert!(
        RawEcdhKeyring::builder()
            .build()
            .unwrap_err()
            .is_validation()
    );
    assert!(
        RawPrivateKeyToStaticPublicKeyInput::builder()
            .recipient_public_key(vec![1])
            .build()
            .unwrap_err()
            .is_validation()
    );
    assert!(
        EphemeralPrivateKeyToStaticPublicKeyInput::builder()
            .build()
            .unwrap_err()
            .is_validation()
    );
    assert!(
        PublicKeyDiscoveryInput::builder()
            .build()
            .unwrap_err()
            .is_validation()
    );
}

#[tokio::test]
async fn another_recipient_finds_no_matching_data_key() {
    let curve = EcdhCurveSpec::EccNistP256;
    let recipient = key_pair(curve);
    let other = key_pair(curve);
    let out = encrypt(&ephemeral_keyring(curve, &recipient.public_key), SUITE).await;
    let err = decrypt(
        &discovery_keyring(curve, &other.private_key),
        SUITE,
        out.encrypted_data_keys().to_vec(),
    )
    .await
    .unwrap_err();
    assert!(err.is_no_matching_data_key(), "{err:?}");
}

#[tokio::test]
async fn a_tampered_ciphertext_or_encryption_context_fails() {
    let curve = EcdhCurveSpec::EccNistP256;
    let recipient = key_pair(curve);
    let discovery = discovery_keyring(curve, &recipient.private_key);
    for suite in [SUITE, DBE_SUITE] {
        let out = encrypt(&ephemeral_keyring(curve, &recipient.public_key), suite).await;
        let edk = &out.encrypted_data_keys()[0];
        let len = edk.ciphertext().len();
        // A flipped bit in the salt, the commitment key, and the AES-GCM tag.
        for index in [0, 40, len - 1] {
            let mut ciphertext = edk.ciphertext().to_vec();
            ciphertext[index] ^= 1;
            let bad = EncryptedDataKey::builder()
                .key_provider_id(edk.key_provider_id())
                .key_provider_info(edk.key_provider_info().to_vec())
                .ciphertext(ciphertext)
                .build()
                .unwrap();
            let err = decrypt(&discovery, suite, vec![bad]).await.unwrap_err();
            assert!(err.is_cryptographic(), "{suite:?} byte {index}: {err:?}");
        }

        let mut other_ec = ec();
        other_ec.insert("keyB", "valB");
        let err = discovery
            .on_decrypt()
            .materials(
                DecryptionMaterials::builder()
                    .algorithm_suite_id(suite)
                    .set_encryption_context(Some(other_ec))
                    .build()
                    .unwrap(),
            )
            .set_encrypted_data_keys(Some(out.encrypted_data_keys().to_vec()))
            .send()
            .await
            .unwrap_err();
        assert!(err.is_cryptographic(), "{suite:?}: {err:?}");
    }
}

#[tokio::test]
async fn malformed_provider_info_fails() {
    let curve = EcdhCurveSpec::EccNistP256;
    let recipient = key_pair(curve);
    let out = encrypt(&ephemeral_keyring(curve, &recipient.public_key), SUITE).await;
    let edk = &out.encrypted_data_keys()[0];
    let mut wrong_version = edk.key_provider_info().to_vec();
    wrong_version[0] = 2;
    for info in [vec![1u8; 10], wrong_version] {
        let bad = EncryptedDataKey::builder()
            .key_provider_id("raw-ecdh")
            .key_provider_info(info)
            .ciphertext(edk.ciphertext().to_vec())
            .build()
            .unwrap();
        let err = decrypt(
            &discovery_keyring(curve, &recipient.private_key),
            SUITE,
            vec![bad],
        )
        .await
        .unwrap_err();
        assert!(err.is_cryptographic(), "{err:?}");
    }
}

// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! AWS KMS ECDH keyring tests, ported from the Dafny `TestAwsKmsEcdhKeyring.dfy`
//! and the KMS cases of `TesRawECDHKeyring.dfy`.
//!
//! Most tests stand in for AWS KMS with an HTTP client that answers `GetPublicKey` and
//! `DeriveSharedSecret` from local key pairs, so a message from either keyring decrypts
//! with the raw ECDH keyring that holds the other party's private key.
//! `real_kms_round_trip` calls AWS KMS with the CI test keys in account `370957321024`,
//! region `us-west-2`, and fails without credentials for that account.

use std::sync::Arc;

use aws_config::{BehaviorVersion, Region};
use aws_crypto_mpl::aws_sdk_kms::Client as KmsClient;
use aws_crypto_mpl::aws_sdk_kms::config::Credentials;
use aws_crypto_mpl::keyring::{
    AwsKmsEcdhKeyring, KmsEcdhStaticConfigurations, KmsPrivateKeyToStaticPublicKeyInput,
    KmsPublicKeyDiscoveryInput, PublicKeyDiscoveryInput, RawEcdhKeyring,
    RawEcdhStaticConfigurations, RawPrivateKeyToStaticPublicKeyInput,
};
use aws_crypto_mpl::types::{
    AlgorithmSuiteId, DbeAlgorithmSuiteId, DecryptionMaterials, EcdhCurveSpec, EncryptedDataKey,
    EncryptionContext, EncryptionMaterials, EsdkAlgorithmSuiteId,
};
use aws_mpl_primitives::{EcdhKeyPair, ecdh_derive_shared_secret, ecdh_generate_key_pair};
use aws_smithy_http_client::test_util::infallible_client_fn;
use aws_smithy_types::base64;
use serde_json::{Value, json};

const SUITE: AlgorithmSuiteId =
    AlgorithmSuiteId::Esdk(EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf);
const DBE_SUITE: AlgorithmSuiteId =
    AlgorithmSuiteId::Dbe(DbeAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeySymsigHmacSha384);

const SENDER_ARN: &str = "arn:aws:kms:us-west-2:111122223333:key/sender";
const RECIPIENT_ARN: &str = "arn:aws:kms:us-west-2:111122223333:key/recipient";
/// A key that the fake AWS KMS reports with key usage `ENCRYPT_DECRYPT`.
const SYMMETRIC_ARN: &str = "arn:aws:kms:us-west-2:111122223333:key/symmetric";
/// A key for which the fake AWS KMS answers with another key's ID.
const WRONG_ID_ARN: &str = "arn:aws:kms:us-west-2:111122223333:key/wrong-id";

const P256: EcdhCurveSpec = EcdhCurveSpec::EccNistP256;
const PRIM_P256: aws_mpl_primitives::EcdhCurveSpec = aws_mpl_primitives::EcdhCurveSpec::EccNistP256;

/// The local key pairs that stand in for AWS KMS keys.
struct Keys {
    sender: EcdhKeyPair,
    recipient: EcdhKeyPair,
}

fn keys() -> Arc<Keys> {
    Arc::new(Keys {
        sender: ecdh_generate_key_pair(PRIM_P256).unwrap(),
        recipient: ecdh_generate_key_pair(PRIM_P256).unwrap(),
    })
}

/// An AWS KMS client whose requests a local function answers.
fn fake_kms(keys: Arc<Keys>) -> KmsClient {
    let http_client = infallible_client_fn(move |request| {
        let target = request
            .headers()
            .get("x-amz-target")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let body: Value = serde_json::from_slice(request.body().bytes().unwrap()).unwrap();
        let key_id = body["KeyId"].as_str().unwrap();
        let pair = match key_id {
            SENDER_ARN | SYMMETRIC_ARN | WRONG_ID_ARN => &keys.sender,
            _ => &keys.recipient,
        };
        let response_key_id = if key_id == WRONG_ID_ARN {
            SENDER_ARN
        } else {
            key_id
        };
        let response = match target.as_str() {
            "TrentService.GetPublicKey" => json!({
                "KeyId": response_key_id,
                "PublicKey": base64::encode(&pair.public_key),
                "KeyUsage": if key_id == SYMMETRIC_ARN { "ENCRYPT_DECRYPT" } else { "KEY_AGREEMENT" },
                "KeySpec": "ECC_NIST_P256",
            }),
            "TrentService.DeriveSharedSecret" => {
                assert_eq!(body["KeyAgreementAlgorithm"], "ECDH");
                let public_key = base64::decode(body["PublicKey"].as_str().unwrap()).unwrap();
                let secret =
                    ecdh_derive_shared_secret(PRIM_P256, &pair.private_key, &public_key).unwrap();
                json!({
                    "KeyId": response_key_id,
                    "SharedSecret": base64::encode(&secret),
                    "KeyAgreementAlgorithm": "ECDH",
                    "KeyOrigin": "AWS_KMS",
                })
            }
            other => panic!("unexpected AWS KMS operation {other}"),
        };
        http::Response::builder()
            .status(200)
            .body(response.to_string())
            .unwrap()
    });
    let config = aws_crypto_mpl::aws_sdk_kms::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new("us-west-2"))
        .credentials_provider(Credentials::new("akid", "secret", None, None, "test"))
        .http_client(http_client)
        .build();
    KmsClient::from_conf(config)
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

fn static_scheme(
    sender_kms_identifier: &str,
    sender_public_key: Option<Vec<u8>>,
    recipient_public_key: &[u8],
) -> KmsEcdhStaticConfigurations {
    KmsEcdhStaticConfigurations::KmsPrivateKeyToStaticPublicKey(
        KmsPrivateKeyToStaticPublicKeyInput::builder()
            .sender_kms_identifier(sender_kms_identifier)
            .set_sender_public_key(sender_public_key)
            .recipient_public_key(recipient_public_key)
            .build()
            .unwrap(),
    )
}

fn discovery_scheme(recipient_kms_identifier: &str) -> KmsEcdhStaticConfigurations {
    KmsEcdhStaticConfigurations::KmsPublicKeyDiscovery(
        KmsPublicKeyDiscoveryInput::builder()
            .recipient_kms_identifier(recipient_kms_identifier)
            .build()
            .unwrap(),
    )
}

async fn build(
    client: KmsClient,
    scheme: KmsEcdhStaticConfigurations,
) -> Result<AwsKmsEcdhKeyring, aws_crypto_mpl::Error> {
    AwsKmsEcdhKeyring::builder()
        .curve_spec(P256)
        .key_agreement_scheme(scheme)
        .kms_client(client)
        .build()
        .await
}

fn raw_discovery(private_key: &[u8]) -> RawEcdhKeyring {
    RawEcdhKeyring::builder()
        .curve_spec(P256)
        .key_agreement_scheme(RawEcdhStaticConfigurations::PublicKeyDiscovery(
            PublicKeyDiscoveryInput::builder()
                .recipient_static_private_key(private_key)
                .build()
                .unwrap(),
        ))
        .build()
        .unwrap()
}

fn raw_static(private_key: &[u8], recipient_public_key: &[u8]) -> RawEcdhKeyring {
    RawEcdhKeyring::builder()
        .curve_spec(P256)
        .key_agreement_scheme(RawEcdhStaticConfigurations::RawPrivateKeyToStaticPublicKey(
            RawPrivateKeyToStaticPublicKeyInput::builder()
                .sender_static_private_key(private_key)
                .recipient_public_key(recipient_public_key)
                .build()
                .unwrap(),
        ))
        .build()
        .unwrap()
}

/// Each keyring type has its own `on_encrypt` and `on_decrypt`, so these are macros, not functions.
macro_rules! encrypt {
    ($keyring:expr, $suite:expr) => {
        $keyring
            .on_encrypt()
            .materials(enc_materials($suite))
            .send()
            .await
            .map(|out| out.into_materials())
    };
}

macro_rules! decrypt {
    ($keyring:expr, $suite:expr, $edks:expr) => {
        $keyring
            .on_decrypt()
            .materials(dec_materials($suite))
            .set_encrypted_data_keys(Some($edks))
            .send()
            .await
            .map(|out| out.into_materials())
    };
}

fn assert_same_key(enc: &EncryptionMaterials, dec: &DecryptionMaterials) {
    assert_eq!(
        enc.plaintext_data_key().unwrap().as_bytes(),
        dec.plaintext_data_key().unwrap().as_bytes()
    );
}

#[tokio::test]
async fn a_kms_sender_message_decrypts_with_the_recipient_private_key() {
    let keys = keys();
    for sender_public_key in [None, Some(keys.sender.public_key.clone())] {
        let kms = build(
            fake_kms(keys.clone()),
            static_scheme(SENDER_ARN, sender_public_key, &keys.recipient.public_key),
        )
        .await
        .unwrap();
        for suite in [SUITE, DBE_SUITE] {
            let enc = encrypt!(kms, suite).unwrap();
            let edks = enc.encrypted_data_keys().to_vec();
            assert_eq!(edks.len(), 1);
            assert_eq!(edks[0].key_provider_id(), "aws-kms-ecdh");
            // The sender's keyring decrypts its own message,
            assert_same_key(&enc, &decrypt!(kms, suite, edks.clone()).unwrap());
            // and so does the recipient, by discovery or with a static keyring.
            let discovery = raw_discovery(&keys.recipient.private_key);
            assert_same_key(&enc, &decrypt!(discovery, suite, edks.clone()).unwrap());
            let recipient = raw_static(&keys.recipient.private_key, &keys.sender.public_key);
            assert_same_key(&enc, &decrypt!(recipient, suite, edks).unwrap());
        }
    }
}

#[tokio::test]
async fn kms_discovery_decrypts_a_raw_ecdh_message() {
    let keys = keys();
    let discovery = build(fake_kms(keys.clone()), discovery_scheme(RECIPIENT_ARN))
        .await
        .unwrap();
    let sender = raw_static(&keys.sender.private_key, &keys.recipient.public_key);
    for suite in [SUITE, DBE_SUITE] {
        let enc = encrypt!(sender, suite).unwrap();
        let dec = decrypt!(discovery, suite, enc.encrypted_data_keys().to_vec()).unwrap();
        assert_same_key(&enc, &dec);
    }
}

#[tokio::test]
async fn discovery_cannot_encrypt() {
    let discovery = build(fake_kms(keys()), discovery_scheme(RECIPIENT_ARN))
        .await
        .unwrap();
    let err = encrypt!(discovery, SUITE).unwrap_err();
    assert!(err.is_validation(), "{err:?}");
    assert!(err.to_string().contains("forbidden on encrypt"), "{err}");
}

#[tokio::test]
async fn another_recipient_finds_no_matching_data_key() {
    let keys = keys();
    let discovery = build(fake_kms(keys.clone()), discovery_scheme(RECIPIENT_ARN))
        .await
        .unwrap();
    let other = ecdh_generate_key_pair(PRIM_P256).unwrap();
    let enc = encrypt!(
        raw_static(&keys.sender.private_key, &other.public_key),
        SUITE
    )
    .unwrap();
    let err = decrypt!(discovery, SUITE, enc.encrypted_data_keys().to_vec()).unwrap_err();
    assert!(err.is_no_matching_data_key(), "{err:?}");
}

#[tokio::test]
async fn a_tampered_ciphertext_fails() {
    let keys = keys();
    let discovery = build(fake_kms(keys.clone()), discovery_scheme(RECIPIENT_ARN))
        .await
        .unwrap();
    let enc = encrypt!(
        raw_static(&keys.sender.private_key, &keys.recipient.public_key),
        SUITE
    )
    .unwrap();
    let edk = &enc.encrypted_data_keys()[0];
    let mut ciphertext = edk.ciphertext().to_vec();
    *ciphertext.last_mut().unwrap() ^= 1;
    let bad = EncryptedDataKey::builder()
        .key_provider_id(edk.key_provider_id())
        .key_provider_info(edk.key_provider_info().to_vec())
        .ciphertext(ciphertext)
        .build()
        .unwrap();
    let err = decrypt!(discovery, SUITE, vec![bad]).unwrap_err();
    assert!(err.is_cryptographic(), "{err:?}");
}

#[tokio::test]
async fn build_rejects_a_key_that_is_not_a_key_agreement_key() {
    let keys = keys();
    let err = build(
        fake_kms(keys.clone()),
        static_scheme(SYMMETRIC_ARN, None, &keys.recipient.public_key),
    )
    .await
    .unwrap_err();
    assert!(err.is_service(), "{err:?}");
    assert!(err.to_string().contains("GetPublicKey"), "{err}");
}

#[tokio::test]
async fn a_response_for_another_key_fails() {
    let keys = keys();
    let err = build(fake_kms(keys.clone()), discovery_scheme(WRONG_ID_ARN))
        .await
        .unwrap_err();
    assert!(err.is_service(), "{err:?}");

    let kms = build(
        fake_kms(keys.clone()),
        static_scheme(
            WRONG_ID_ARN,
            Some(keys.sender.public_key.clone()),
            &keys.recipient.public_key,
        ),
    )
    .await
    .unwrap();
    let err = encrypt!(kms, SUITE).unwrap_err();
    assert!(err.is_service(), "{err:?}");
    assert!(err.to_string().contains("DeriveSharedSecret"), "{err}");
}

#[tokio::test]
async fn build_validates_its_inputs() {
    let keys = keys();
    let missing = |builder: aws_crypto_mpl::keyring::AwsKmsEcdhKeyringBuilder| async move {
        builder.build().await.unwrap_err()
    };
    let scheme = static_scheme(
        SENDER_ARN,
        Some(keys.sender.public_key.clone()),
        &keys.recipient.public_key,
    );
    let full = AwsKmsEcdhKeyring::builder()
        .curve_spec(P256)
        .key_agreement_scheme(scheme.clone())
        .kms_client(fake_kms(keys.clone()));
    assert!(full.clone().build().await.is_ok());
    assert!(
        missing(full.clone().set_kms_client(None))
            .await
            .is_validation()
    );
    assert!(
        missing(full.clone().set_curve_spec(None))
            .await
            .is_validation()
    );
    assert!(
        missing(full.clone().set_key_agreement_scheme(None))
            .await
            .is_validation()
    );
    assert!(
        missing(full.clone().set_grant_tokens(Some(vec![String::new()])))
            .await
            .is_validation()
    );
    // Keys on another curve.
    assert!(
        missing(full.clone().curve_spec(EcdhCurveSpec::EccNistP384))
            .await
            .is_validation()
    );
    for (sender_kms_identifier, sender_public_key, recipient_public_key) in [
        (
            "key/abc",
            Some(keys.sender.public_key.clone()),
            keys.recipient.public_key.clone(),
        ),
        (
            SENDER_ARN,
            Some(vec![1, 2, 3]),
            keys.recipient.public_key.clone(),
        ),
        (SENDER_ARN, Some(keys.sender.public_key.clone()), Vec::new()),
    ] {
        let err = build(
            fake_kms(keys.clone()),
            static_scheme(
                sender_kms_identifier,
                sender_public_key,
                &recipient_public_key,
            ),
        )
        .await
        .unwrap_err();
        assert!(err.is_validation(), "{err:?}");
    }
    assert!(
        KmsPrivateKeyToStaticPublicKeyInput::builder()
            .recipient_public_key(vec![1])
            .build()
            .unwrap_err()
            .is_validation()
    );
    assert!(
        KmsPublicKeyDiscoveryInput::builder()
            .build()
            .unwrap_err()
            .is_validation()
    );
}

#[tokio::test]
async fn real_kms_round_trip() {
    const SENDER: &str =
        "arn:aws:kms:us-west-2:370957321024:key/eabdf483-6be2-4d2d-8ee4-8c2583d416e9";
    const RECIPIENT: &str =
        "arn:aws:kms:us-west-2:370957321024:key/0265c8e9-5b6a-4055-8f70-63719e09fda5";
    const RECIPIENT_PUBLIC_KEY: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9istdPCuX9nF8EmA4tioe/k0TCa2M9VeBW1N9n0sxPA6uPVOfLtE4+KuYxAGT0dYoK6CY93nowUy1yS+R7A+wA==";
    let cfg = aws_config::defaults(BehaviorVersion::latest())
        .region(Region::new("us-west-2"))
        .load()
        .await;
    let client = KmsClient::new(&cfg);
    let sender = build(
        client.clone(),
        static_scheme(SENDER, None, &base64::decode(RECIPIENT_PUBLIC_KEY).unwrap()),
    )
    .await
    .unwrap();
    let recipient = build(client, discovery_scheme(RECIPIENT)).await.unwrap();
    for suite in [SUITE, DBE_SUITE] {
        let enc = encrypt!(sender, suite).unwrap();
        let dec = decrypt!(recipient, suite, enc.encrypted_data_keys().to_vec()).unwrap();
        assert_same_key(&enc, &dec);
    }
}

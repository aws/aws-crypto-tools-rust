// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Every modeled keyring and CMM builds from its `CreateClient` config.
//! The offline ones also round-trip a message; the AWS KMS ones only build,
//! because building contacts no AWS service when every key is supplied.

use aws_esdk_test_server::handlers::AppState;
use aws_esdk_test_server::model::{
    AesWrappingAlg, AwsKmsDiscoveryKeyringConfig, AwsKmsEcdhKeyringConfig, AwsKmsKeyringConfig,
    AwsKmsMrkDiscoveryKeyringConfig, AwsKmsMrkKeyringConfig, AwsKmsMrkMultiKeyringConfig,
    AwsKmsMultiKeyringConfig, AwsKmsRsaKeyringConfig, CachingCmmConfig, CreateClientRequest,
    CryptographicMaterialsManager, DecryptRequest, DefaultCmmConfig, DiscoveryFilter,
    EcdhCurveSpec, EncryptRequest, EphemeralPrivateKeyToStaticPublicKeyConfig, EsdkClientConfig,
    EsdkCommitmentPolicy, Keyring, KmsEcdhKeyAgreementScheme, KmsPrivateKeyToStaticPublicKeyConfig,
    KmsRsaEncryptionAlgorithm, MultiKeyringConfig, PaddingScheme, PublicKeyDiscoveryConfig,
    RawAesKeyringConfig, RawEcdhKeyAgreementScheme, RawEcdhKeyringConfig,
    RawPrivateKeyToStaticPublicKeyConfig, RawRsaKeyringConfig, RequiredEncryptionContextCmmConfig,
};
use aws_mpl_primitives::{ecdh_generate_key_pair, EcdhCurveSpec as PrimCurve, EcdhKeyPair};
use std::collections::BTreeMap;

const KMS_KEY_ARN: &str =
    "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f";
const MRK_ARN: &str = "arn:aws:kms:us-west-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7";
const ECDH_KEY_ARN: &str =
    "arn:aws:kms:us-west-2:370957321024:key/eabdf483-6be2-4d2d-8ee4-8c2583d416e9";

const RSA_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCpspcXyiO3wdmj
gOnXlLHyYQFI7mkugjNlKZb+a34yKpTZbQ55OJa5R6B7RN4HRr869W6yfW30Nhw5
0UXp6wIr4BzxB7jnWVDFRPgS3q4OzjxdtWu8AAyCAZCRqhWgu1ddTvISJ4LhWBYn
jXRseUBIpSSLXfyty+ZZtuNmEBzJa3YfAAf+2UsB8CyKwRV2pHWUYWJEWEOVn+J7
3pNSt2pO1IZmkFwZ+9irIGLMPP/IIR6p4XArBilFoWvbqhsHZm0+5fwHlY7MhdY4
35y2GT+AK6kCauYkLXOVG6xnKJiRlg4qtMJCbc4otCV13d0O0ZqkiWiKWS6IZiEZ
GWP96/qZAgMBAAECggEAAtPhCCXXhk67t/vI5SjB9eST+qcqEN+B483ApPVvy5Bq
uJxWonAb2WonTqw+WU5VTjIpsIJ+CwJ0hrxAlOBLFDgnnZa0iAPG8s6Obz0z4BKj
m/CO/p44Tf4gwOQLittsS+6OcEaA6cPaBvCflHokm9OQWRNx9Sxqyyr6dGh1HA3t
/j6ka/p5UM4EZZAya9kGksPwJo2RYQDeU4ZH/3VjHC1ZAh0GvFOyQxb8VygPUfpU
1D6FZPLmQjVCRKJq+Yr5MJt9fP9NLFps0/JD8+tl40DF+xtfl8yevNJEHTk0AAiB
j0NDvmMxjxJLM9PKFpn/8Fbac7ySrhxQyz86gepxwQKBgQDgNI7SEsMxdaVl7x7P
0DrsGQ76F7yZph0zRusjOR2B0jWSk9aFVMYirgY0jHSmhHug/+glNTYLfp2SV5RW
DwNtF5tWwzWOIrpbbZ+T3Yw8+oxy1Dr1L0Ywqti9iEUEkfQKGy4lZHLvdX3+Sp9j
6gX6Uf1/YLON81U1fBAbiRoE4QKBgQDBwzYa4GGVIh7GIxFEcTxFDbnKhpv/d5Pr
ye+fjFqWzMVBDvTh4Z3B/pWuHpn2lFQMaSpY36hu5YcqoHLcUCYld3blWgZcuOz3
4Zc2whS+uJrg6VNic/hbfBsuBF1Ivjw+1pOlnS9EnNM2PF4IDzdRcV0MtyzIwF5g
0cSlVHj0uQKBgBxjSzoaGhDnHnwbnMEfUnaWbakI3F5wA/58GkWpc6z+Wr4mbeEP
7M5zTmHU7ugumiC2hkQ/yooGDBl9cVC8MejcNlTz/pHyn7n31V65jIokByh66sQk
qjR7TVoiKOr9N/MXoe4mG89qBvvtouTZuswJGZnJOrLcfot5G+kAoQTBAoGBAI/1
rdlCJL5c32hu3YFwcEsN66Ahav3fpjNlkXeFHDk2Ysf3iNHagw+DS0pWyiV+BwRB
jokBg28Bce+lzjEKC42CuP+mZ1u0ubtiDKtOf4NEPS4lrSJU741pI/iInZZSYQh+
/KvroRblPbfqGiL6yyrjgzLTVZ7B7l0Y/XWo0UVhAoGAR7I9/nxJvEtTblMbGod+
GjcaMc2iwrwQPS+Qwfu0JbSaumW8mmN2VtUyD/BiQtc/R4klxebOcFrf1rAGpl5N
iQr05Yv9toiMak0fEq2ZAo5646q/4eC1pxdUl2cWsRVpeNk9LI0pND1jBn14NA1p
w9JQo2VTZJb9EBIcYy01tgE=
-----END PRIVATE KEY-----\n";
const RSA_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqbKXF8ojt8HZo4Dp15Sx
8mEBSO5pLoIzZSmW/mt+MiqU2W0OeTiWuUege0TeB0a/OvVusn1t9DYcOdFF6esC
K+Ac8Qe451lQxUT4Et6uDs48XbVrvAAMggGQkaoVoLtXXU7yEieC4VgWJ410bHlA
SKUki138rcvmWbbjZhAcyWt2HwAH/tlLAfAsisEVdqR1lGFiRFhDlZ/ie96TUrdq
TtSGZpBcGfvYqyBizDz/yCEeqeFwKwYpRaFr26obB2ZtPuX8B5WOzIXWON+cthk/
gCupAmrmJC1zlRusZyiYkZYOKrTCQm3OKLQldd3dDtGapIloilkuiGYhGRlj/ev6
mQIDAQAB
-----END PUBLIC KEY-----\n";

fn raw_aes() -> Keyring {
    Keyring {
        raw_aes: Some(RawAesKeyringConfig {
            key_namespace: "esdk-test-server".to_owned(),
            key_name: "raw-aes".to_owned(),
            wrapping_key: (0u8..32).collect(),
            wrapping_alg: AesWrappingAlg::Alg256,
        }),
        ..Default::default()
    }
}

fn raw_rsa() -> Keyring {
    Keyring {
        raw_rsa: Some(RawRsaKeyringConfig {
            key_namespace: "esdk-test-server".to_owned(),
            key_name: "raw-rsa".to_owned(),
            padding_scheme: PaddingScheme::OaepSha256Mgf1,
            public_key: Some(RSA_PUBLIC_KEY.as_bytes().to_vec()),
            private_key: Some(RSA_PRIVATE_KEY.as_bytes().to_vec()),
        }),
        ..Default::default()
    }
}

fn p256() -> EcdhKeyPair {
    ecdh_generate_key_pair(PrimCurve::EccNistP256).expect("generate P-256 key pair")
}

fn raw_ecdh(scheme: RawEcdhKeyAgreementScheme, curve_spec: EcdhCurveSpec) -> Keyring {
    Keyring {
        raw_ecdh: Some(RawEcdhKeyringConfig {
            key_agreement_scheme: scheme,
            curve_spec,
        }),
        ..Default::default()
    }
}

fn raw_ecdh_static(sender: &EcdhKeyPair, recipient: &EcdhKeyPair) -> Keyring {
    raw_ecdh(
        RawEcdhKeyAgreementScheme {
            raw_private_key_to_static_public_key: Some(RawPrivateKeyToStaticPublicKeyConfig {
                sender_static_private_key: sender.private_key.clone(),
                recipient_public_key: recipient.public_key.clone(),
            }),
            ..Default::default()
        },
        EcdhCurveSpec::EccNistP256,
    )
}

fn raw_ecdh_ephemeral(recipient: &EcdhKeyPair) -> Keyring {
    raw_ecdh(
        RawEcdhKeyAgreementScheme {
            ephemeral_private_key_to_static_public_key: Some(
                EphemeralPrivateKeyToStaticPublicKeyConfig {
                    recipient_public_key: recipient.public_key.clone(),
                },
            ),
            ..Default::default()
        },
        EcdhCurveSpec::EccNistP256,
    )
}

fn raw_ecdh_discovery(recipient: &EcdhKeyPair) -> Keyring {
    raw_ecdh(
        RawEcdhKeyAgreementScheme {
            public_key_discovery: Some(PublicKeyDiscoveryConfig {
                recipient_static_private_key: recipient.private_key.clone(),
            }),
            ..Default::default()
        },
        EcdhCurveSpec::EccNistP256,
    )
}

fn default_cmm(keyring: Keyring) -> CryptographicMaterialsManager {
    CryptographicMaterialsManager {
        default_cmm: Some(DefaultCmmConfig { keyring }),
        ..Default::default()
    }
}

fn caching(
    underlying: CryptographicMaterialsManager,
    limit_messages: Option<i64>,
    shared_cache_name: Option<&str>,
) -> CryptographicMaterialsManager {
    CryptographicMaterialsManager {
        caching: Some(CachingCmmConfig {
            underlying_cmm: Box::new(underlying),
            cache_limit_ttl_seconds: 60,
            partition_id: shared_cache_name.map(str::to_owned),
            limit_bytes: None,
            limit_messages,
            shared_cache_name: shared_cache_name.map(str::to_owned),
        }),
        ..Default::default()
    }
}

fn config(cmm: CryptographicMaterialsManager) -> CreateClientRequest {
    CreateClientRequest {
        config: EsdkClientConfig {
            commitment_policy: EsdkCommitmentPolicy::RequireEncryptRequireDecrypt,
            max_encrypted_data_keys: None,
            cmm,
        },
    }
}

async fn create(state: &AppState, cmm: CryptographicMaterialsManager) -> String {
    state
        .create_client(config(cmm))
        .await
        .unwrap_or_else(|e| panic!("CreateClient failed: {}", e.message()))
        .client_id
}

async fn create_err(cmm: CryptographicMaterialsManager) -> String {
    match AppState::new().create_client(config(cmm)).await {
        Ok(_) => panic!("CreateClient must fail"),
        Err(e) => e.message().to_owned(),
    }
}

fn ec() -> BTreeMap<String, String> {
    BTreeMap::from([("purpose".to_owned(), "keyring-configs".to_owned())])
}

async fn encrypt(state: &AppState, client_id: &str) -> Vec<u8> {
    state
        .encrypt(EncryptRequest {
            client_id: client_id.to_owned(),
            plaintext: b"keyring configs".to_vec(),
            encryption_context: Some(ec()),
            algorithm_suite_id: None,
            frame_length: None,
        })
        .await
        .unwrap_or_else(|e| panic!("Encrypt failed: {}", e.message()))
        .ciphertext
}

async fn decrypt(state: &AppState, client_id: &str, ciphertext: Vec<u8>) -> Vec<u8> {
    state
        .decrypt(DecryptRequest {
            client_id: client_id.to_owned(),
            ciphertext,
            encryption_context: Some(ec()),
        })
        .await
        .unwrap_or_else(|e| panic!("Decrypt failed: {}", e.message()))
        .plaintext
}

/// Encrypt with `encrypt_cmm`, decrypt with `decrypt_cmm`, and check the plaintext survives.
async fn round_trip(
    encrypt_cmm: CryptographicMaterialsManager,
    decrypt_cmm: CryptographicMaterialsManager,
) {
    let state = AppState::new();
    let encryptor = create(&state, encrypt_cmm).await;
    let decryptor = create(&state, decrypt_cmm).await;
    let ciphertext = encrypt(&state, &encryptor).await;
    assert_eq!(
        decrypt(&state, &decryptor, ciphertext).await,
        b"keyring configs"
    );
}

#[tokio::test]
async fn raw_rsa_round_trips() {
    round_trip(default_cmm(raw_rsa()), default_cmm(raw_rsa())).await;
}

#[tokio::test]
async fn raw_ecdh_static_round_trips() {
    let (sender, recipient) = (p256(), p256());
    let keyring = raw_ecdh_static(&sender, &recipient);
    round_trip(default_cmm(keyring.clone()), default_cmm(keyring)).await;
}

#[tokio::test]
async fn raw_ecdh_static_decrypts_by_discovery() {
    let (sender, recipient) = (p256(), p256());
    round_trip(
        default_cmm(raw_ecdh_static(&sender, &recipient)),
        default_cmm(raw_ecdh_discovery(&recipient)),
    )
    .await;
}

#[tokio::test]
async fn raw_ecdh_ephemeral_decrypts_by_discovery() {
    let recipient = p256();
    round_trip(
        default_cmm(raw_ecdh_ephemeral(&recipient)),
        default_cmm(raw_ecdh_discovery(&recipient)),
    )
    .await;
}

#[tokio::test]
async fn raw_ecdh_rejects_sm2() {
    let recipient = p256();
    let mut keyring = raw_ecdh_ephemeral(&recipient);
    if let Some(config) = keyring.raw_ecdh.as_mut() {
        config.curve_spec = EcdhCurveSpec::Sm2;
    }
    let message = create_err(default_cmm(keyring)).await;
    assert!(message.contains("SM2"), "{message}");
}

#[tokio::test]
async fn raw_ecdh_rejects_two_schemes() {
    let recipient = p256();
    let mut keyring = raw_ecdh_ephemeral(&recipient);
    if let Some(config) = keyring.raw_ecdh.as_mut() {
        config.key_agreement_scheme.public_key_discovery = Some(PublicKeyDiscoveryConfig {
            recipient_static_private_key: recipient.private_key.clone(),
        });
    }
    let message = create_err(default_cmm(keyring)).await;
    assert!(
        message.contains("exactly one variant, found 2"),
        "{message}"
    );
}

#[tokio::test]
async fn multi_keyring_child_decrypts_alone() {
    let multi = Keyring {
        multi: Some(MultiKeyringConfig {
            generator: Some(Box::new(raw_aes())),
            child_keyrings: vec![raw_rsa()],
        }),
        ..Default::default()
    };
    round_trip(default_cmm(multi), default_cmm(raw_rsa())).await;
}

#[tokio::test]
async fn required_encryption_context_cmm_round_trips() {
    let cmm = CryptographicMaterialsManager {
        required_encryption_context: Some(RequiredEncryptionContextCmmConfig {
            underlying_cmm: Box::new(default_cmm(raw_aes())),
            required_encryption_context_keys: vec!["purpose".to_owned()],
        }),
        ..Default::default()
    };
    round_trip(cmm.clone(), cmm).await;
}

#[tokio::test]
async fn required_encryption_context_cmm_rejects_a_missing_key() {
    let state = AppState::new();
    let client_id = create(
        &state,
        CryptographicMaterialsManager {
            required_encryption_context: Some(RequiredEncryptionContextCmmConfig {
                underlying_cmm: Box::new(default_cmm(raw_aes())),
                required_encryption_context_keys: vec!["absent".to_owned()],
            }),
            ..Default::default()
        },
    )
    .await;
    let result = state
        .encrypt(EncryptRequest {
            client_id,
            plaintext: b"keyring configs".to_vec(),
            encryption_context: Some(ec()),
            algorithm_suite_id: None,
            frame_length: None,
        })
        .await;
    assert!(
        result.is_err(),
        "Encrypt must fail without the required key"
    );
}

/// The encrypted data key section of a V2 message header: the count and every key.
fn edks(ciphertext: &[u8]) -> Vec<u8> {
    let u16_at = |at: usize| usize::from(u16::from_be_bytes([ciphertext[at], ciphertext[at + 1]]));
    // Version (1), suite id (2), message id (32), then the AAD length and the AAD.
    let start = 37 + u16_at(35);
    let mut at = start + 2;
    for _ in 0..u16_at(start) {
        // Provider id, provider info, and ciphertext, each with a 2-byte length.
        for _ in 0..3 {
            at += 2 + u16_at(at);
        }
    }
    ciphertext[start..at].to_vec()
}

#[tokio::test]
async fn caching_cmm_reuses_the_data_key() {
    let state = AppState::new();
    let client_id = create(&state, caching(default_cmm(raw_aes()), None, None)).await;
    let first = encrypt(&state, &client_id).await;
    let second = encrypt(&state, &client_id).await;
    assert_eq!(edks(&first), edks(&second));
    assert_eq!(
        decrypt(&state, &client_id, second).await,
        b"keyring configs"
    );
}

#[tokio::test]
async fn caching_cmm_message_limit_forces_a_new_data_key() {
    let state = AppState::new();
    let client_id = create(&state, caching(default_cmm(raw_aes()), Some(1), None)).await;
    let first = encrypt(&state, &client_id).await;
    let second = encrypt(&state, &client_id).await;
    assert_ne!(edks(&first), edks(&second));
}

#[tokio::test]
async fn caching_cmms_share_a_named_cache() {
    let state = AppState::new();
    let a = create(
        &state,
        caching(default_cmm(raw_aes()), None, Some("shared")),
    )
    .await;
    let b = create(
        &state,
        caching(default_cmm(raw_aes()), None, Some("shared")),
    )
    .await;
    let c = create(&state, caching(default_cmm(raw_aes()), None, None)).await;
    let from_a = encrypt(&state, &a).await;
    assert_eq!(edks(&from_a), edks(&encrypt(&state, &b).await));
    assert_ne!(edks(&from_a), edks(&encrypt(&state, &c).await));
}

#[tokio::test]
async fn caching_cmm_rejects_a_negative_limit() {
    let message = create_err(caching(default_cmm(raw_aes()), Some(-1), None)).await;
    assert!(message.contains("limitMessages"), "{message}");
}

#[tokio::test]
async fn aws_kms_keyrings_build() {
    let state = AppState::new();
    let discovery_filter = || {
        Some(DiscoveryFilter {
            partition: "aws".to_owned(),
            account_ids: vec!["658956600833".to_owned()],
        })
    };
    let keyrings = [
        Keyring {
            aws_kms: Some(AwsKmsKeyringConfig {
                kms_key_id: KMS_KEY_ARN.to_owned(),
                grant_tokens: None,
            }),
            ..Default::default()
        },
        Keyring {
            aws_kms_mrk: Some(AwsKmsMrkKeyringConfig {
                kms_key_id: MRK_ARN.to_owned(),
                grant_tokens: None,
            }),
            ..Default::default()
        },
        Keyring {
            aws_kms_multi: Some(AwsKmsMultiKeyringConfig {
                generator: Some(KMS_KEY_ARN.to_owned()),
                kms_key_ids: Some(vec![MRK_ARN.to_owned()]),
                grant_tokens: None,
            }),
            ..Default::default()
        },
        Keyring {
            aws_kms_mrk_multi: Some(AwsKmsMrkMultiKeyringConfig {
                generator: Some(MRK_ARN.to_owned()),
                kms_key_ids: None,
                grant_tokens: None,
            }),
            ..Default::default()
        },
        Keyring {
            aws_kms_discovery: Some(AwsKmsDiscoveryKeyringConfig {
                discovery_filter: discovery_filter(),
                grant_tokens: None,
            }),
            ..Default::default()
        },
        Keyring {
            aws_kms_mrk_discovery: Some(AwsKmsMrkDiscoveryKeyringConfig {
                region: "us-west-2".to_owned(),
                discovery_filter: discovery_filter(),
                grant_tokens: None,
            }),
            ..Default::default()
        },
        Keyring {
            aws_kms_rsa: Some(AwsKmsRsaKeyringConfig {
                kms_key_id: KMS_KEY_ARN.to_owned(),
                public_key: Some(RSA_PUBLIC_KEY.as_bytes().to_vec()),
                encryption_algorithm: Some(KmsRsaEncryptionAlgorithm::OaepSha256),
                grant_tokens: None,
            }),
            ..Default::default()
        },
    ];
    for keyring in keyrings {
        create(&state, default_cmm(keyring)).await;
    }
}

#[tokio::test]
async fn aws_kms_ecdh_static_keyring_builds() {
    // With the sender public key supplied, building calls no AWS KMS API.
    let (sender, recipient) = (p256(), p256());
    let keyring = Keyring {
        aws_kms_ecdh: Some(AwsKmsEcdhKeyringConfig {
            key_agreement_scheme: KmsEcdhKeyAgreementScheme {
                kms_private_key_to_static_public_key: Some(KmsPrivateKeyToStaticPublicKeyConfig {
                    sender_kms_identifier: ECDH_KEY_ARN.to_owned(),
                    sender_public_key: Some(sender.public_key.clone()),
                    recipient_public_key: recipient.public_key.clone(),
                }),
                ..Default::default()
            },
            curve_spec: EcdhCurveSpec::EccNistP256,
            grant_tokens: None,
        }),
        ..Default::default()
    };
    create(&AppState::new(), default_cmm(keyring)).await;
}

#[tokio::test]
async fn aws_kms_ecdh_rejects_no_scheme() {
    let keyring = Keyring {
        aws_kms_ecdh: Some(AwsKmsEcdhKeyringConfig {
            key_agreement_scheme: KmsEcdhKeyAgreementScheme::default(),
            curve_spec: EcdhCurveSpec::EccNistP256,
            grant_tokens: None,
        }),
        ..Default::default()
    };
    let message = create_err(default_cmm(keyring)).await;
    assert!(
        message.contains("exactly one variant, found 0"),
        "{message}"
    );
}

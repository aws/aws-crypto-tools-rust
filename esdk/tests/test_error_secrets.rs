// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Errors never contain plaintext, key material, ciphertext,
//! DynamoDB attribute values, or encryption context values.

mod fake_aws;

use async_trait::async_trait;
use aws_crypto_mpl::keyring::{Keyring, RawAesKeyring};
use aws_crypto_mpl::structures::{
    DecryptionMaterials, EncryptedDataKey, EncryptionContext, EncryptionMaterials, PlaintextDataKey,
};
use aws_esdk::{AlgorithmSuiteId, DecryptInput, EncryptInput, Error, decrypt, encrypt};
use aws_mpl_primitives::AesGcm;
use fake_aws::{BRANCH_KEY_ID, FakeAws, KEY_ARN, Reply};

const PLAINTEXT: &str = "SECRET-PLAINTEXT-7f3a";
const EC_VALUE: &str = "SECRET-EC-VALUE-91c2";
const OTHER_EC_VALUE: &str = "SECRET-EC-OTHER-4d0e";
/// Stands in for a wrapping key, a data key, and a branch key.
const KEY_BYTE: u8 = 0x5a;

/// Every way a secret could appear: as text, and as the bytes `KEY_BYTE`
/// in `Debug` (decimal), hex, ASCII (`Z`), and base64.
fn forbidden() -> Vec<String> {
    vec![
        PLAINTEXT.to_owned(),
        EC_VALUE.to_owned(),
        OTHER_EC_VALUE.to_owned(),
        "90, 90, 90".to_owned(),
        "5a5a5a".to_owned(),
        "ZZZZ".to_owned(),
        "WlpaWlpa".to_owned(),
    ]
}

#[track_caller]
fn assert_no_secrets(err: &Error) {
    for text in [err.to_string(), format!("{err:#}"), format!("{err:?}")] {
        for secret in forbidden() {
            assert!(!text.contains(&secret), "found {secret:?} in: {text}");
        }
    }
}

fn context(value: &str) -> EncryptionContext {
    let mut ec = EncryptionContext::new();
    ec.insert("tenant", value);
    ec
}

fn raw(name: &str) -> RawAesKeyring {
    RawAesKeyring::new("ns", name, vec![KEY_BYTE; 32], AesGcm::Aes256Gcm).unwrap()
}

/// A raw AES keyring whose data key is `KEY_BYTE` repeated.
struct KnownDataKey(RawAesKeyring);

#[async_trait]
impl Keyring for KnownDataKey {
    async fn on_encrypt(
        &self,
        m: EncryptionMaterials,
    ) -> Result<EncryptionMaterials, aws_crypto_mpl::Error> {
        let m = EncryptionMaterials::new(
            m.algorithm_suite_id(),
            m.encrypted_data_keys().to_vec(),
            m.encryption_context().clone(),
            m.required_encryption_context_keys().clone(),
            Some(PlaintextDataKey::new(vec![KEY_BYTE; 32])),
            m.signing_key().cloned(),
            m.symmetric_signing_keys().map(<[_]>::to_vec),
        )?;
        self.0.on_encrypt(m).await
    }

    async fn on_decrypt(
        &self,
        m: DecryptionMaterials,
        edks: &[EncryptedDataKey],
    ) -> Result<DecryptionMaterials, aws_crypto_mpl::Error> {
        self.0.on_decrypt(m, edks).await
    }
}

async fn ciphertext() -> Vec<u8> {
    let input = EncryptInput::builder()
        .plaintext(PLAINTEXT.as_bytes())
        .encryption_context(context(EC_VALUE))
        .algorithm_suite_id(AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey)
        .keyring(KnownDataKey(raw("name")))
        .build()
        .unwrap();
    encrypt(&input).await.unwrap().ciphertext
}

async fn decrypt_error(
    ciphertext: &[u8],
    ec: Option<&str>,
    keyring: impl Keyring + 'static,
) -> Error {
    let mut input = DecryptInput::builder()
        .ciphertext(ciphertext)
        .keyring(keyring);
    if let Some(value) = ec {
        input = input.encryption_context(context(value));
    }
    decrypt(&input.build().unwrap()).await.unwrap_err()
}

#[tokio::test]
async fn failed_decrypts_contain_no_secrets() {
    let ciphertext = ciphertext().await;

    let wrong_keyring = decrypt_error(&ciphertext, None, raw("other-name")).await;
    assert!(wrong_keyring.is_no_matching_data_key(), "{wrong_keyring:?}");
    assert_no_secrets(&wrong_keyring);

    let mismatch = decrypt_error(&ciphertext, Some(OTHER_EC_VALUE), raw("name")).await;
    assert!(mismatch.is_encryption_context_mismatch(), "{mismatch:?}");
    assert_no_secrets(&mismatch);

    let mut tampered = ciphertext.clone();
    let i = tampered.len() - 17;
    tampered[i] ^= 1;
    let tag = decrypt_error(&tampered, None, raw("name")).await;
    assert!(tag.is_cryptographic(), "{tag:?}");
    assert_no_secrets(&tag);
}

#[tokio::test]
async fn malformed_branch_key_records_contain_no_attribute_values() {
    // `enc` must be Binary; this one is a String holding key-like bytes.
    let enc_as_string = format!(
        r#"{{"Item":{{"branch-key-id":{{"S":"{BRANCH_KEY_ID}"}},"type":{{"S":"branch:ACTIVE"}},"kms-arn":{{"S":"{KEY_ARN}"}},"enc":{{"S":"ZZZZZZZZ"}}}}}}"#
    );
    // Custom encryption context attributes must be Strings; this one is a String Set.
    let ec_as_set = fake_aws::record(
        "branch:ACTIVE",
        "AAAA",
        &format!(r#","aws-crypto-ec:tenant":{{"SS":["{EC_VALUE}"]}}"#),
    );
    for item in [enc_as_string, ec_as_set] {
        let fake = FakeAws::new(move |op, _| {
            (op == "DynamoDB_20120810.GetItem").then(|| Reply::ok(item.clone()))
        });
        let input = EncryptInput::builder()
            .plaintext(PLAINTEXT.as_bytes())
            .encryption_context(context(EC_VALUE))
            .keyring(fake.keyring().await)
            .build()
            .unwrap();
        let err = encrypt(&input).await.unwrap_err();
        assert!(err.is_invalid_materials(), "{err:?}");
        assert_no_secrets(&err);
    }
}

#[tokio::test]
async fn kms_failures_contain_no_branch_key_bytes() {
    // The fake KMS returns a 16-byte branch key of `KEY_BYTE`, which the record format rejects.
    let fake = FakeAws::new(|op, _| {
        (op == "TrentService.Decrypt").then(|| {
            Reply::ok(format!(
                r#"{{"KeyId":"{KEY_ARN}","Plaintext":"WlpaWlpaWlpaWlpaWlpaWg==","EncryptionAlgorithm":"SYMMETRIC_DEFAULT"}}"#
            ))
        })
    });
    let input = EncryptInput::builder()
        .plaintext(PLAINTEXT.as_bytes())
        .encryption_context(context(EC_VALUE))
        .keyring(fake.keyring().await)
        .build()
        .unwrap();
    let err = encrypt(&input).await.unwrap_err();
    assert!(err.is_invalid_materials(), "{err:?}");
    assert_no_secrets(&err);
}

/// Decrypt a message under the fake's branch key with a hierarchical keyring backed by `fake`.
async fn hierarchical_decrypt_error(fake: FakeAws) -> Error {
    let input = EncryptInput::builder()
        .plaintext(PLAINTEXT.as_bytes())
        .encryption_context(context(EC_VALUE))
        .keyring(FakeAws::ok().keyring().await)
        .build()
        .unwrap();
    let ciphertext = encrypt(&input).await.unwrap().ciphertext;
    let input = DecryptInput::builder()
        .ciphertext(&ciphertext)
        .keyring(fake.keyring().await)
        .build()
        .unwrap();
    decrypt(&input).await.unwrap_err()
}

#[tokio::test]
async fn an_unparseable_kms_response_does_not_reach_the_error() {
    // A KMS Decrypt response cut off after its plaintext branch key of `KEY_BYTE`.
    let fake = FakeAws::new(|op, _| {
        (op == "TrentService.Decrypt").then(|| {
            Reply::ok(format!(
                r#"{{"KeyId":"{KEY_ARN}","Plaintext":"WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo=","EncryptionAlgorithm":"SYMM"#
            ))
        })
    });
    let err = hierarchical_decrypt_error(fake).await;
    assert!(err.is_service(), "{err:?}");
    assert_no_secrets(&err);
}

#[tokio::test]
async fn an_unparseable_dynamodb_response_does_not_reach_the_error() {
    // A GetItem response cut off inside a branch key record's encryption context attribute.
    let fake = FakeAws::new(|op, _| {
        (op == "DynamoDB_20120810.GetItem").then(|| {
            Reply::ok(format!(
                r#"{{"Item":{{"branch-key-id":{{"S":"{BRANCH_KEY_ID}"}},"aws-crypto-ec:tenant":{{"S":"{EC_VALUE}"#
            ))
        })
    });
    let err = hierarchical_decrypt_error(fake).await;
    assert!(err.is_service(), "{err:?}");
    assert_no_secrets(&err);
}

// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Errors never contain plaintext, key material, ciphertext,
//! DynamoDB attribute values, or encryption context values.

mod fake_aws;

use aws_crypto_mpl::async_trait;
use aws_crypto_mpl::keyring::{Keyring, RawAesKeyring, SharedKeyring};
use aws_crypto_mpl::keyring::{OnDecryptInput, OnEncryptInput};
use aws_crypto_mpl::keyring::{OnDecryptOutput, OnEncryptOutput};
use aws_crypto_mpl::types::AesWrappingAlg;
use aws_crypto_mpl::types::{EncryptionContext, EncryptionMaterials, PlaintextDataKey};
use aws_esdk::types::AlgorithmSuiteId;
use aws_esdk::{Client, Error};
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
    RawAesKeyring::builder()
        .key_namespace("ns")
        .key_name(name)
        .wrapping_key(vec![KEY_BYTE; 32])
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()
        .unwrap()
}

/// A raw AES keyring whose data key is `KEY_BYTE` repeated.
struct KnownDataKey(SharedKeyring);

#[async_trait]
impl Keyring for KnownDataKey {
    async fn on_encrypt(
        &self,
        input: OnEncryptInput,
    ) -> Result<OnEncryptOutput, aws_crypto_mpl::Error> {
        let m = input.materials();
        let m = EncryptionMaterials::builder()
            .algorithm_suite_id(m.algorithm_suite_id())
            .encrypted_data_keys(m.encrypted_data_keys().to_vec())
            .encryption_context(m.encryption_context().clone())
            .required_encryption_context_keys(m.required_encryption_context_keys().clone())
            .plaintext_data_key(PlaintextDataKey::new(vec![KEY_BYTE; 32]))
            .set_signing_key(m.signing_key().cloned())
            .set_symmetric_signing_keys(m.symmetric_signing_keys().map(<[_]>::to_vec))
            .build()?;
        self.0.on_encrypt().materials(m).send().await
    }

    async fn on_decrypt(
        &self,
        input: OnDecryptInput,
    ) -> Result<OnDecryptOutput, aws_crypto_mpl::Error> {
        Keyring::on_decrypt(&self.0, input).await
    }
}

async fn ciphertext() -> Vec<u8> {
    Client::default()
        .encrypt()
        .plaintext(PLAINTEXT.as_bytes())
        .encryption_context(context(EC_VALUE))
        .algorithm_suite_id(AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey)
        .keyring(KnownDataKey(SharedKeyring::new(raw("name"))))
        .send()
        .await
        .unwrap()
        .into_ciphertext()
}

async fn decrypt_error(
    ciphertext: &[u8],
    ec: Option<&str>,
    keyring: impl Keyring + 'static,
) -> Error {
    Client::default()
        .decrypt()
        .ciphertext(ciphertext)
        .keyring(keyring)
        .set_encryption_context(ec.map(context))
        .send()
        .await
        .unwrap_err()
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
        let err = Client::default()
            .encrypt()
            .plaintext(PLAINTEXT.as_bytes())
            .encryption_context(context(EC_VALUE))
            .keyring(fake.keyring().await)
            .send()
            .await
            .unwrap_err();
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
    let err = Client::default()
        .encrypt()
        .plaintext(PLAINTEXT.as_bytes())
        .encryption_context(context(EC_VALUE))
        .keyring(fake.keyring().await)
        .send()
        .await
        .unwrap_err();
    assert!(err.is_invalid_materials(), "{err:?}");
    assert_no_secrets(&err);
}

/// The error from decrypting, against `fake`, a message encrypted under the fake's branch key.
async fn hierarchical_decrypt_error(fake: FakeAws) -> Error {
    let ciphertext = Client::default()
        .encrypt()
        .plaintext(PLAINTEXT.as_bytes())
        .encryption_context(context(EC_VALUE))
        .keyring(FakeAws::ok().keyring().await)
        .send()
        .await
        .unwrap()
        .into_ciphertext();
    Client::default()
        .decrypt()
        .ciphertext(&ciphertext)
        .keyring(fake.keyring().await)
        .send()
        .await
        .unwrap_err()
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

/// `Debug` of the encrypt builder and the decrypt output hides the plaintext, as the AWS SDK for Rust does.
#[tokio::test]
async fn debug_hides_the_plaintext() {
    let esdk = Client::default();
    let builder = esdk
        .encrypt()
        .plaintext(PLAINTEXT.as_bytes())
        .keyring(raw("k"));
    let builder_debug = format!("{builder:?}");

    let encrypted = builder.send().await.unwrap();
    let decrypted = esdk
        .decrypt()
        .ciphertext(encrypted.ciphertext())
        .keyring(raw("k"))
        .send()
        .await
        .unwrap();
    assert_eq!(decrypted.plaintext(), PLAINTEXT.as_bytes());
    let output_debug = format!("{decrypted:?}");

    // `{:?}` of a `&[u8]` prints decimal bytes; the first three of PLAINTEXT are "SEC".
    let plaintext_bytes = format!("{:?}", &PLAINTEXT.as_bytes()[..3]).replace(['[', ']'], "");
    for text in [&builder_debug, &output_debug] {
        assert!(text.contains("*** Sensitive Data Redacted ***"), "{text}");
        assert!(!text.contains(PLAINTEXT), "{text}");
        assert!(!text.contains(&plaintext_bytes), "{text}");
    }
}

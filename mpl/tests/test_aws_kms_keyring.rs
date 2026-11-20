// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! AWS KMS keyring tests the shared test-server suite can't run:
//! the Rust getters and setters, and AWS KMS responses no real KMS sends.

#![cfg(feature = "kms")]

use aws_crypto_mpl::Error;
use aws_crypto_mpl::keyring::{AwsKmsKeyring, SharedKeyring};
use aws_crypto_mpl::types::{
    AlgorithmSuiteId, DecryptionMaterials, EncryptedDataKey, EncryptionContext,
    EncryptionMaterials, EsdkAlgorithmSuiteId, PlaintextDataKey,
};
use aws_sdk_kms::Client as KmsClient;
use aws_smithy_runtime_api::client::http::{
    HttpConnector, HttpConnectorFuture, SharedHttpConnector, http_client_fn,
};
use aws_smithy_runtime_api::client::orchestrator::HttpRequest;
use aws_smithy_runtime_api::http::{Response, StatusCode};
use aws_smithy_types::body::SdkBody;
use aws_smithy_types::retry::RetryConfig;

const KEY_ARN: &str = "arn:aws:kms:us-west-2:111122223333:key/1234abcd";
const SUITE: AlgorithmSuiteId =
    AlgorithmSuiteId::Esdk(EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf);
/// 32 bytes, the data key length of `SUITE`, in base64.
const PLAINTEXT_32: &str = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=";

/// Answers every AWS KMS request with the same JSON body.
#[derive(Clone, Debug)]
struct FakeKms(String);

impl HttpConnector for FakeKms {
    fn call(&self, _request: HttpRequest) -> HttpConnectorFuture {
        let mut response = Response::new(
            StatusCode::try_from(200).unwrap(),
            SdkBody::from(self.0.clone()),
        );
        response
            .headers_mut()
            .insert("content-type", "application/x-amz-json-1.1");
        HttpConnectorFuture::ready(Ok(response))
    }
}

fn kms_client(body: impl Into<String>) -> KmsClient {
    let fake = FakeKms(body.into());
    let config = aws_sdk_kms::Config::builder()
        .behavior_version(aws_sdk_kms::config::BehaviorVersion::latest())
        .region(aws_sdk_kms::config::Region::new("us-west-2"))
        .credentials_provider(aws_sdk_kms::config::Credentials::new(
            "AKIDFAKE",
            "fake-secret",
            None,
            None,
            "fake",
        ))
        .retry_config(RetryConfig::disabled())
        .http_client(http_client_fn(move |_, _| {
            SharedHttpConnector::new(fake.clone())
        }))
        .build();
    KmsClient::from_conf(config)
}

async fn keyring(kms_key_id: &str, body: impl Into<String>) -> AwsKmsKeyring {
    AwsKmsKeyring::builder()
        .kms_key_id(kms_key_id)
        .kms_client(kms_client(body))
        .build()
        .await
        .unwrap()
}

fn encryption_materials(pdk: Option<Vec<u8>>) -> EncryptionMaterials {
    EncryptionMaterials::builder()
        .algorithm_suite_id(SUITE)
        .set_encryption_context(Some(EncryptionContext::new()))
        .set_plaintext_data_key(pdk.map(PlaintextDataKey::new))
        .build()
        .unwrap()
}

fn decryption_materials(pdk: Option<Vec<u8>>) -> DecryptionMaterials {
    DecryptionMaterials::builder()
        .algorithm_suite_id(SUITE)
        .set_encryption_context(Some(EncryptionContext::new()))
        .set_plaintext_data_key(pdk.map(PlaintextDataKey::new))
        .build()
        .unwrap()
}

fn edk(ciphertext: Vec<u8>) -> EncryptedDataKey {
    EncryptedDataKey::builder()
        .key_provider_id("aws-kms")
        .key_provider_info(KEY_ARN.as_bytes().to_vec())
        .ciphertext(ciphertext)
        .build()
        .unwrap()
}

async fn on_encrypt_err(keyring: &AwsKmsKeyring, pdk: Option<Vec<u8>>) -> Error {
    keyring
        .on_encrypt()
        .materials(encryption_materials(pdk))
        .send()
        .await
        .unwrap_err()
}

async fn on_decrypt_err(
    keyring: &AwsKmsKeyring,
    pdk: Option<Vec<u8>>,
    edks: Vec<EncryptedDataKey>,
) -> Error {
    keyring
        .on_decrypt()
        .materials(decryption_materials(pdk))
        .set_encrypted_data_keys(Some(edks))
        .send()
        .await
        .unwrap_err()
}

#[tokio::test]
async fn builder_setters_and_getters() {
    let keyring = AwsKmsKeyring::builder()
        .kms_key_id(KEY_ARN)
        .kms_client(kms_client("{}"))
        .grant_tokens("first")
        .grant_tokens("second")
        .build()
        .await
        .unwrap();
    assert_eq!(keyring.kms_key_id(), KEY_ARN);
    assert_eq!(keyring.grant_tokens(), ["first", "second"]);
    assert_eq!(keyring.name(), format!("aws-kms {KEY_ARN}"));
    assert_eq!(SharedKeyring::new(keyring.clone()).name(), keyring.name());

    let debug = format!("{keyring:?}");
    assert!(debug.contains(KEY_ARN), "{debug}");
    assert!(
        !debug.contains("first"),
        "Debug shows a grant token: {debug}"
    );
}

#[tokio::test]
async fn generate_data_key_with_no_ciphertext_fails() {
    let body = format!(r#"{{"KeyId":"{KEY_ARN}","Plaintext":"{PLAINTEXT_32}"}}"#);
    let err = on_encrypt_err(&keyring(KEY_ARN, body).await, None).await;
    assert!(matches!(err, Error::Service(_)), "{err:?}");
    assert!(err.message().contains("Invalid ciphertext"), "{err}");
}

#[tokio::test]
async fn generate_data_key_with_ciphertext_for_recipient_fails() {
    let body = format!(
        r#"{{"KeyId":"{KEY_ARN}","Plaintext":"{PLAINTEXT_32}","CiphertextBlob":"AAAA","CiphertextForRecipient":"AAAA"}}"#
    );
    let err = on_encrypt_err(&keyring(KEY_ARN, body).await, None).await;
    assert!(matches!(err, Error::Service(_)), "{err:?}");
    assert!(err.message().contains("CiphertextForRecipient"), "{err}");
}

#[tokio::test]
async fn generate_data_key_with_a_key_id_too_long_for_the_edk_fails() {
    let long_arn = format!(
        "arn:aws:kms:us-west-2:111122223333:key/{}",
        "a".repeat(65_536)
    );
    let body =
        format!(r#"{{"KeyId":"{long_arn}","Plaintext":"{PLAINTEXT_32}","CiphertextBlob":"AAAA"}}"#);
    let err = on_encrypt_err(&keyring(KEY_ARN, body).await, None).await;
    assert!(matches!(err, Error::Service(_)), "{err:?}");
    assert!(err.message().contains("Key ID too long"), "{err}");
}

#[tokio::test]
async fn encrypt_with_no_ciphertext_fails() {
    let body = format!(r#"{{"KeyId":"{KEY_ARN}"}}"#);
    let err = on_encrypt_err(&keyring(KEY_ARN, body).await, Some(vec![0; 32])).await;
    assert!(matches!(err, Error::Service(_)), "{err:?}");
    assert!(err.message().contains("Invalid Ciphertext Blob"), "{err}");
}

#[tokio::test]
async fn decrypt_with_a_plaintext_data_key_already_set_fails() {
    let keyring = keyring(KEY_ARN, "{}").await;
    let err = on_decrypt_err(&keyring, Some(vec![0; 32]), vec![edk(vec![1])]).await;
    assert!(matches!(err, Error::InvalidMaterials(_)), "{err:?}");
}

#[tokio::test]
async fn decrypt_with_a_raw_key_id_fails() {
    let keyring = keyring("1234abcd", "{}").await;
    let err = on_decrypt_err(&keyring, None, vec![edk(vec![1])]).await;
    assert!(matches!(err, Error::Validation(_)), "{err:?}");
    assert!(err.message().contains("KeyID cannot be used"), "{err}");
}

#[tokio::test]
async fn decrypt_with_an_alias_arn_fails() {
    let keyring = keyring("arn:aws:kms:us-west-2:111122223333:alias/my-alias", "{}").await;
    let err = on_decrypt_err(&keyring, None, vec![edk(vec![1])]).await;
    assert!(matches!(err, Error::Validation(_)), "{err:?}");
    assert!(err.message().contains("Alias cannot be used"), "{err}");
}

#[tokio::test]
async fn decrypt_with_an_empty_edk_ciphertext_fails() {
    // The fake would decrypt anything, so only the length check stops this EDK.
    let body = format!(r#"{{"KeyId":"{KEY_ARN}","Plaintext":"{PLAINTEXT_32}"}}"#);
    let err = on_decrypt_err(&keyring(KEY_ARN, body).await, None, vec![edk(Vec::new())]).await;
    assert!(matches!(err, Error::Cryptographic(_)), "{err:?}");
    assert!(err.message().contains("Ciphertext length invalid"), "{err}");
}

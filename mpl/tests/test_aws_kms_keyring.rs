// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for [`AwsKmsKeyring`] (Dafny AwsKmsKeyring.dfy).
//!
//! The round trips call AWS KMS with the CI test key
//! `9d989aa2-2f9c-438c-a745-cc57d3ad0126` in account `370957321024`, region `us-west-2`,
//! like the hierarchical keyring's integration tests. Without credentials they fail.

use aws_config::{BehaviorVersion, Region};
use aws_crypto_mpl::aws_sdk_kms::Client as KmsClient;
use aws_crypto_mpl::keyring::AwsKmsKeyring;
use aws_crypto_mpl::types::{
    AlgorithmSuiteId, DbeAlgorithmSuiteId, DecryptionMaterials, EncryptedDataKey,
    EncryptionContext, EncryptionMaterials, EsdkAlgorithmSuiteId,
};

const KEY_ARN: &str = "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126";

fn offline_client() -> KmsClient {
    let config = aws_crypto_mpl::aws_sdk_kms::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new("us-west-2"))
        .build();
    KmsClient::from_conf(config)
}

async fn client() -> KmsClient {
    let cfg = aws_config::defaults(BehaviorVersion::latest())
        .region(Region::new("us-west-2"))
        .load()
        .await;
    KmsClient::new(&cfg)
}

fn ec() -> EncryptionContext {
    let mut ec = EncryptionContext::new();
    ec.insert("purpose", "test");
    ec
}

#[test]
fn build_validates_the_key_id_and_grant_tokens() {
    let build = |id: &str| {
        AwsKmsKeyring::builder()
            .kms_key_id(id)
            .kms_client(offline_client())
            .build()
    };
    assert!(build(KEY_ARN).is_ok());
    assert!(build("alias/my-key").is_ok());
    assert!(build("9d989aa2-2f9c-438c-a745-cc57d3ad0126").is_ok());
    assert!(
        build("arn:aws:kms:us-west-2:370957321024:key")
            .unwrap_err()
            .is_validation()
    );
    assert!(
        build("arn:aws:s3:us-west-2:370957321024:key/x")
            .unwrap_err()
            .is_validation()
    );
    assert!(build("key/abc").unwrap_err().is_validation());
    assert!(build("").unwrap_err().is_validation());
    assert!(
        AwsKmsKeyring::builder()
            .kms_key_id(KEY_ARN)
            .build()
            .unwrap_err()
            .is_validation()
    );
    assert!(
        AwsKmsKeyring::builder()
            .kms_key_id(KEY_ARN)
            .kms_client(offline_client())
            .set_grant_tokens(Some(vec!["t".to_owned(); 11]))
            .build()
            .unwrap_err()
            .is_validation()
    );
}

#[tokio::test]
async fn decrypt_needs_a_key_arn_and_skips_other_providers() {
    let suite = AlgorithmSuiteId::Esdk(EsdkAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey);
    let materials = || {
        DecryptionMaterials::builder()
            .algorithm_suite_id(suite)
            .build()
            .unwrap()
    };
    let alias = AwsKmsKeyring::builder()
        .kms_key_id("alias/my-key")
        .kms_client(offline_client())
        .build()
        .unwrap();
    let err = alias
        .on_decrypt()
        .materials(materials())
        .encrypted_data_keys(Vec::<EncryptedDataKey>::new())
        .send()
        .await
        .unwrap_err();
    assert!(err.is_validation(), "{err:?}");

    let keyring = AwsKmsKeyring::builder()
        .kms_key_id(KEY_ARN)
        .kms_client(offline_client())
        .build()
        .unwrap();
    let other = EncryptedDataKey::builder()
        .key_provider_id("other")
        .key_provider_info(b"info".to_vec())
        .ciphertext(vec![1, 2, 3])
        .build()
        .unwrap();
    let err = keyring
        .on_decrypt()
        .materials(materials())
        .encrypted_data_keys(vec![other])
        .send()
        .await
        .unwrap_err();
    assert!(err.is_no_matching_data_key(), "{err:?}");
}

async fn round_trip(suite: AlgorithmSuiteId) {
    let keyring = AwsKmsKeyring::builder()
        .kms_key_id(KEY_ARN)
        .kms_client(client().await)
        .build()
        .unwrap();
    let materials = EncryptionMaterials::builder()
        .algorithm_suite_id(suite)
        .encryption_context(ec())
        .build()
        .unwrap();
    // GenerateDataKey, then Encrypt for a second EDK of the same data key.
    let encrypted = keyring
        .on_encrypt()
        .materials(materials)
        .send()
        .await
        .unwrap()
        .into_materials();
    let encrypted = keyring
        .on_encrypt()
        .materials(encrypted)
        .send()
        .await
        .unwrap()
        .into_materials();
    assert_eq!(encrypted.encrypted_data_keys().len(), 2);
    for edk in encrypted.encrypted_data_keys() {
        assert_eq!(edk.key_provider_id(), "aws-kms");
        assert_eq!(edk.key_provider_info(), KEY_ARN.as_bytes());
        let decrypted = keyring
            .on_decrypt()
            .materials(
                DecryptionMaterials::builder()
                    .algorithm_suite_id(suite)
                    .encryption_context(ec())
                    .build()
                    .unwrap(),
            )
            .encrypted_data_keys(vec![edk.clone()])
            .send()
            .await
            .unwrap()
            .into_materials();
        assert!(
            decrypted
                .plaintext_data_key()
                .unwrap()
                .ct_eq(encrypted.plaintext_data_key().unwrap())
        );
    }
}

#[tokio::test]
async fn integ_direct_key_wrapping_round_trips_through_kms() {
    round_trip(AlgorithmSuiteId::Esdk(
        EsdkAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey,
    ))
    .await;
}

#[tokio::test]
async fn integ_intermediate_key_wrapping_round_trips_through_kms() {
    round_trip(AlgorithmSuiteId::Dbe(
        DbeAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeySymsigHmacSha384,
    ))
    .await;
}

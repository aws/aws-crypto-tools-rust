// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for the AWS KMS multi-keyring builders (Dafny `AwsKmsMultiKeys.dfy`,
//! `AwsKmsMrkMultiKeys.dfy`, `AwsKmsDiscoveryMultiKeys.dfy`,
//! `AwsKmsMrkDiscoveryMultiKeys.dfy`), and through them the discovery, MRK and
//! MRK-discovery keyrings.
//!
//! The round trips call AWS KMS with the CI test key
//! `9d989aa2-2f9c-438c-a745-cc57d3ad0126` in account `370957321024`, region `us-west-2`,
//! like the other AWS KMS keyring tests. Without credentials they fail.

use aws_config::{BehaviorVersion, Region, SdkConfig};
use aws_crypto_mpl::keyring::{DiscoveryFilter, MultiKeyring};
use aws_crypto_mpl::types::{
    AlgorithmSuiteId, DecryptionMaterials, EncryptedDataKey, EncryptionContext,
    EncryptionMaterials, EsdkAlgorithmSuiteId,
};

const KEY_ARN: &str = "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126";
const ACCOUNT: &str = "370957321024";
const SUITE: AlgorithmSuiteId =
    AlgorithmSuiteId::Esdk(EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256);

fn offline_config() -> SdkConfig {
    SdkConfig::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new("us-west-2"))
        .build()
}

async fn config() -> SdkConfig {
    aws_config::defaults(BehaviorVersion::latest())
        .region(Region::new("us-west-2"))
        .load()
        .await
}

fn ec() -> EncryptionContext {
    let mut ec = EncryptionContext::new();
    ec.insert("purpose", "test");
    ec
}

fn filter(account: &str) -> DiscoveryFilter {
    DiscoveryFilter::builder()
        .partition("aws")
        .account_ids(account)
        .build()
        .unwrap()
}

async fn encrypt(keyring: &MultiKeyring) -> (Vec<u8>, Vec<EncryptedDataKey>) {
    let materials = EncryptionMaterials::builder()
        .algorithm_suite_id(SUITE)
        .set_encryption_context(Some(ec()))
        .build()
        .unwrap();
    let out = keyring
        .on_encrypt()
        .materials(materials)
        .send()
        .await
        .unwrap()
        .into_materials();
    (
        out.plaintext_data_key().unwrap().as_bytes().to_vec(),
        out.encrypted_data_keys().to_vec(),
    )
}

async fn decrypt(
    keyring: &MultiKeyring,
    edks: Vec<EncryptedDataKey>,
) -> Result<Vec<u8>, aws_crypto_mpl::Error> {
    let materials = DecryptionMaterials::builder()
        .algorithm_suite_id(SUITE)
        .set_encryption_context(Some(ec()))
        .build()
        .unwrap();
    Ok(keyring
        .on_decrypt()
        .materials(materials)
        .set_encrypted_data_keys(Some(edks))
        .send()
        .await?
        .into_materials()
        .plaintext_data_key()
        .unwrap()
        .as_bytes()
        .to_vec())
}

#[tokio::test]
async fn the_strict_builders_validate_their_keys() {
    // No keys at all.
    let err = MultiKeyring::aws_kms()
        .sdk_config(offline_config())
        .build()
        .await
        .unwrap_err();
    assert!(err.is_validation(), "{err:?}");
    let err = MultiKeyring::aws_kms_mrk()
        .sdk_config(offline_config())
        .build()
        .await
        .unwrap_err();
    assert!(err.is_validation(), "{err:?}");

    // A malformed key identifier.
    for bad in ["arn:aws:kms:us-west-2:370957321024:key", ""] {
        let err = MultiKeyring::aws_kms()
            .sdk_config(offline_config())
            .generator(bad)
            .build()
            .await
            .unwrap_err();
        assert!(err.is_validation(), "{bad}: {err:?}");
        let err = MultiKeyring::aws_kms_mrk()
            .sdk_config(offline_config())
            .kms_key_ids(bad)
            .build()
            .await
            .unwrap_err();
        assert!(err.is_validation(), "{bad}: {err:?}");
    }

    // Too many grant tokens.
    let err = MultiKeyring::aws_kms()
        .sdk_config(offline_config())
        .generator(KEY_ARN)
        .set_grant_tokens(Some(vec!["t".to_string(); 11]))
        .build()
        .await
        .unwrap_err();
    assert!(err.is_validation(), "{err:?}");

    // Two replicas of one multi-Region key.
    let err = MultiKeyring::aws_kms_mrk()
        .sdk_config(offline_config())
        .generator("arn:aws:kms:us-west-2:111122223333:key/mrk-1234abcd12ab34cd56ef1234567890ab")
        .kms_key_ids("arn:aws:kms:eu-west-1:111122223333:key/mrk-1234abcd12ab34cd56ef1234567890ab")
        .build()
        .await
        .unwrap_err();
    assert!(err.is_validation(), "{err:?}");
    assert!(
        err.to_string().contains("Related multi-Region keys"),
        "{err}"
    );
}

#[tokio::test]
async fn the_strict_builders_accept_ids_aliases_and_arns() {
    let keyring = MultiKeyring::aws_kms()
        .sdk_config(offline_config())
        .generator(KEY_ARN)
        .kms_key_ids("alias/my-key")
        .kms_key_ids("9d989aa2-2f9c-438c-a745-cc57d3ad0126")
        .grant_tokens("token")
        .build()
        .await
        .unwrap();
    assert!(keyring.generator().is_some());
    assert_eq!(keyring.child_keyrings().len(), 2);

    let keyring = MultiKeyring::aws_kms_mrk()
        .set_sdk_config(Some(offline_config()))
        .set_generator(None)
        .set_kms_key_ids(Some(vec![
            "arn:aws:kms:us-west-2:111122223333:key/mrk-1234abcd12ab34cd56ef1234567890ab".into(),
            KEY_ARN.into(),
        ]))
        .set_grant_tokens(None)
        .build()
        .await
        .unwrap();
    assert!(keyring.generator().is_none());
    assert_eq!(keyring.child_keyrings().len(), 2);
    assert!(format!("{:?}", MultiKeyring::aws_kms_mrk()).contains("AwsKmsMrkMultiKeyringBuilder"));
}

#[tokio::test]
async fn the_discovery_builders_validate_their_regions() {
    let err = MultiKeyring::aws_kms_discovery()
        .sdk_config(offline_config())
        .build()
        .await
        .unwrap_err();
    assert!(err.is_validation(), "{err:?}");
    let err = MultiKeyring::aws_kms_discovery()
        .sdk_config(offline_config())
        .regions("")
        .build()
        .await
        .unwrap_err();
    assert!(err.is_validation(), "{err:?}");
    let err = MultiKeyring::aws_kms_mrk_discovery()
        .sdk_config(offline_config())
        .build()
        .await
        .unwrap_err();
    assert!(err.is_validation(), "{err:?}");
    let err = MultiKeyring::aws_kms_mrk_discovery()
        .sdk_config(offline_config())
        .set_regions(Some(vec![String::new()]))
        .build()
        .await
        .unwrap_err();
    assert!(err.is_validation(), "{err:?}");

    let keyring = MultiKeyring::aws_kms_discovery()
        .set_sdk_config(Some(offline_config()))
        .regions("us-west-2")
        .regions("eu-west-1")
        .discovery_filter(filter(ACCOUNT))
        .grant_tokens("token")
        .build()
        .await
        .unwrap();
    assert_eq!(keyring.child_keyrings().len(), 2);
    let keyring = MultiKeyring::aws_kms_mrk_discovery()
        .set_sdk_config(Some(offline_config()))
        .set_regions(Some(vec!["us-west-2".into(), "us-east-1".into()]))
        .set_discovery_filter(Some(filter(ACCOUNT)))
        .set_grant_tokens(Some(vec!["token".into()]))
        .build()
        .await
        .unwrap();
    assert_eq!(keyring.child_keyrings().len(), 2);
    assert!(
        format!("{:?}", MultiKeyring::aws_kms_discovery())
            .contains("AwsKmsDiscoveryMultiKeyringBuilder")
    );
}

#[test]
fn the_discovery_filter_needs_a_partition_and_accounts() {
    assert!(
        DiscoveryFilter::builder()
            .account_ids(ACCOUNT)
            .build()
            .unwrap_err()
            .is_validation()
    );
    assert!(
        DiscoveryFilter::builder()
            .partition("aws")
            .build()
            .unwrap_err()
            .is_validation()
    );
    let f = DiscoveryFilter::builder()
        .set_partition(Some("aws".into()))
        .set_account_ids(Some(vec![ACCOUNT.into()]))
        .build()
        .unwrap();
    assert_eq!(f.partition(), "aws");
    assert_eq!(f.account_ids(), &[ACCOUNT.to_string()]);
}

#[tokio::test]
async fn a_kms_multi_keyring_round_trips_and_discovery_decrypts_it() {
    let sdk_config = config().await;
    let strict = MultiKeyring::aws_kms()
        .sdk_config(sdk_config.clone())
        .generator(KEY_ARN)
        .build()
        .await
        .unwrap();
    let (pdk, edks) = encrypt(&strict).await;
    assert_eq!(edks.len(), 1);
    assert_eq!(edks[0].key_provider_id(), "aws-kms");
    assert_eq!(decrypt(&strict, edks.clone()).await.unwrap(), pdk);

    // Discovery decrypts with and without a filter that allows the key's account.
    for f in [Some(filter(ACCOUNT)), None] {
        let discovery = MultiKeyring::aws_kms_discovery()
            .sdk_config(sdk_config.clone())
            .regions("us-west-2")
            .set_discovery_filter(f)
            .build()
            .await
            .unwrap();
        assert_eq!(decrypt(&discovery, edks.clone()).await.unwrap(), pdk);
    }

    // A filter for another account skips the data key.
    let other = MultiKeyring::aws_kms_discovery()
        .sdk_config(sdk_config.clone())
        .regions("us-west-2")
        .discovery_filter(filter("111122223333"))
        .build()
        .await
        .unwrap();
    assert!(decrypt(&other, edks.clone()).await.is_err());

    // A discovery keyring in another region does not decrypt a us-west-2 key.
    let elsewhere = MultiKeyring::aws_kms_discovery()
        .sdk_config(sdk_config.clone())
        .regions("eu-west-1")
        .build()
        .await
        .unwrap();
    assert!(decrypt(&elsewhere, edks.clone()).await.is_err());

    // An EDK from another provider is skipped.
    let foreign = EncryptedDataKey::builder()
        .key_provider_id("other")
        .key_provider_info(KEY_ARN.as_bytes().to_vec())
        .ciphertext(vec![1, 2, 3])
        .build()
        .unwrap();
    let discovery = MultiKeyring::aws_kms_discovery()
        .sdk_config(sdk_config)
        .regions("us-west-2")
        .build()
        .await
        .unwrap();
    assert!(decrypt(&discovery, vec![foreign]).await.is_err());
}

#[tokio::test]
async fn an_mrk_multi_keyring_round_trips_and_mrk_discovery_decrypts_it() {
    let sdk_config = config().await;
    let strict = MultiKeyring::aws_kms_mrk()
        .sdk_config(sdk_config.clone())
        .generator(KEY_ARN)
        .build()
        .await
        .unwrap();
    let (pdk, edks) = encrypt(&strict).await;
    assert_eq!(decrypt(&strict, edks.clone()).await.unwrap(), pdk);

    // A child-only MRK multi-keyring wraps a supplied data key and decrypts it.
    let children = MultiKeyring::aws_kms_mrk()
        .sdk_config(sdk_config.clone())
        .kms_key_ids(KEY_ARN)
        .build()
        .await
        .unwrap();
    assert_eq!(decrypt(&children, edks.clone()).await.unwrap(), pdk);

    for f in [Some(filter(ACCOUNT)), None] {
        let discovery = MultiKeyring::aws_kms_mrk_discovery()
            .sdk_config(sdk_config.clone())
            .regions("us-west-2")
            .set_discovery_filter(f)
            .build()
            .await
            .unwrap();
        assert_eq!(decrypt(&discovery, edks.clone()).await.unwrap(), pdk);
    }

    let other = MultiKeyring::aws_kms_mrk_discovery()
        .sdk_config(sdk_config.clone())
        .regions("us-west-2")
        .discovery_filter(filter("111122223333"))
        .build()
        .await
        .unwrap();
    assert!(decrypt(&other, edks.clone()).await.is_err());

    // A non-MRK key in another region is not this region's key.
    let elsewhere = MultiKeyring::aws_kms_mrk_discovery()
        .sdk_config(sdk_config)
        .regions("eu-west-1")
        .build()
        .await
        .unwrap();
    assert!(decrypt(&elsewhere, edks).await.is_err());
}

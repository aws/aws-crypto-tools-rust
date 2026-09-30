// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for KMS configuration ARN parsing, validation, and compatibility.

use aws_crypto_mpl::keystore::kms_config::{is_arn_compatible, parse_arn, validate_kms_key_arn};
use aws_crypto_mpl::keystore::{Discovery, KeystoreErrorKind, KmsConfiguration, MrDiscovery};

const VALID_KMS_ARN: &str =
    "arn:aws:kms:us-east-1:111122223333:key/abcd1234-1234-abcd-1234-1234567890ab";
const VALID_MRK_ARN: &str =
    "arn:aws:kms:us-east-1:111122223333:key/mrk-1234abcd-12ab-34cd-56ef-1234567890ab";
const MRK_DIFFERENT_REGION: &str =
    "arn:aws:kms:us-west-2:111122223333:key/mrk-1234abcd-12ab-34cd-56ef-1234567890ab";
const ALIAS_ARN: &str = "arn:aws:kms:us-east-1:111122223333:alias/test-key";
const NON_KMS_ARN: &str = "arn:aws:s3:us-east-1:111122223333:key/some-key-id";

#[test]
fn parse_arn_extracts_all_six_segments() {
    let parts = parse_arn(VALID_KMS_ARN).unwrap();
    assert_eq!(parts.partition, "aws");
    assert_eq!(parts.service, "kms");
    assert_eq!(parts.region, "us-east-1");
    assert_eq!(parts.account_id, "111122223333");
    assert_eq!(parts.resource_type, "key");
    assert_eq!(parts.resource, "abcd1234-1234-abcd-1234-1234567890ab");
}

#[test]
fn parse_arn_rejects_too_few_segments() {
    let err = parse_arn("arn:aws:kms:us-east-1:111122223333").unwrap_err();
    assert_eq!(err.kind, KeystoreErrorKind::Configuration);
    assert!(err.message.contains("Malformed ARN"));
}

#[test]
fn parse_arn_rejects_missing_resource_slash() {
    let err = parse_arn("arn:aws:kms:us-east-1:111122223333:key-no-slash").unwrap_err();
    assert_eq!(err.kind, KeystoreErrorKind::Configuration);
    assert!(err.message.contains("must contain '/'"));
}

#[test]
fn parse_arn_rejects_empty_string() {
    let err = parse_arn("").unwrap_err();
    assert_eq!(err.kind, KeystoreErrorKind::Configuration);
}

#[test]
fn parse_arn_rejects_non_arn_prefix() {
    let err = parse_arn("not:an:arn:at:all:key/foo").unwrap_err();
    assert_eq!(err.kind, KeystoreErrorKind::Configuration);
}

#[test]
fn validate_kms_key_arn_accepts_regular_arn() {
    let parts = validate_kms_key_arn(VALID_KMS_ARN).unwrap();
    assert_eq!(parts.service, "kms");
    assert_eq!(parts.resource_type, "key");
}

#[test]
fn validate_kms_key_arn_accepts_mrk_arn() {
    let parts = validate_kms_key_arn(VALID_MRK_ARN).unwrap();
    assert_eq!(parts.resource_type, "key");
}

#[test]
fn validate_kms_key_arn_rejects_alias() {
    let err = validate_kms_key_arn(ALIAS_ARN).unwrap_err();
    assert_eq!(err.kind, KeystoreErrorKind::Configuration);
    assert!(
        err.message.contains("alias"),
        "error must mention alias; got: {}",
        err.message
    );
}

#[test]
fn validate_kms_key_arn_rejects_non_kms_service() {
    let err = validate_kms_key_arn(NON_KMS_ARN).unwrap_err();
    assert_eq!(err.kind, KeystoreErrorKind::Configuration);
    assert!(
        err.message.contains("kms"),
        "error must mention kms; got: {}",
        err.message
    );
}

#[test]
fn validate_kms_key_arn_rejects_malformed_string() {
    let err = validate_kms_key_arn("not-an-arn").unwrap_err();
    assert_eq!(err.kind, KeystoreErrorKind::Configuration);
}

#[test]
fn kms_key_arn_compatible_only_when_byte_equal() {
    let config = KmsConfiguration::KmsKeyArn(VALID_KMS_ARN.to_string());
    assert!(is_arn_compatible(&config, VALID_KMS_ARN));
    assert!(!is_arn_compatible(&config, VALID_MRK_ARN));
}

#[test]
fn kms_key_arn_incompatible_with_different_region() {
    let config = KmsConfiguration::KmsKeyArn(VALID_MRK_ARN.to_string());
    assert!(!is_arn_compatible(&config, MRK_DIFFERENT_REGION));
}

#[test]
fn kms_mr_key_arn_compatible_with_same_key_different_region() {
    let config = KmsConfiguration::KmsMrKeyArn(VALID_MRK_ARN.to_string());
    assert!(is_arn_compatible(&config, MRK_DIFFERENT_REGION));
}

#[test]
fn kms_mr_key_arn_compatible_with_byte_equal_arn() {
    let config = KmsConfiguration::KmsMrKeyArn(VALID_MRK_ARN.to_string());
    assert!(is_arn_compatible(&config, VALID_MRK_ARN));
}

#[test]
fn kms_mr_key_arn_incompatible_with_different_account() {
    let config = KmsConfiguration::KmsMrKeyArn(VALID_MRK_ARN.to_string());
    let different_account =
        "arn:aws:kms:us-east-1:999988887777:key/mrk-1234abcd-12ab-34cd-56ef-1234567890ab";
    assert!(!is_arn_compatible(&config, different_account));
}

#[test]
fn discovery_compatible_with_any_arn() {
    let config = KmsConfiguration::Discovery(Discovery::builder().build());
    assert!(is_arn_compatible(&config, VALID_KMS_ARN));
    assert!(is_arn_compatible(&config, VALID_MRK_ARN));
    assert!(is_arn_compatible(&config, ALIAS_ARN));
}

#[test]
fn mrdiscovery_compatible_with_any_arn() {
    let config =
        KmsConfiguration::MrDiscovery(MrDiscovery::builder().region("us-west-2").build().unwrap());
    assert!(is_arn_compatible(&config, VALID_KMS_ARN));
    assert!(is_arn_compatible(&config, VALID_MRK_ARN));
}

#[test]
fn kms_key_arn_validate_accepts_valid_arn() {
    let config = KmsConfiguration::KmsKeyArn(VALID_KMS_ARN.to_string());
    assert!(config.validate().is_ok());
}

#[test]
fn kms_key_arn_validate_rejects_alias() {
    let config = KmsConfiguration::KmsKeyArn(ALIAS_ARN.to_string());
    let err = config.validate().unwrap_err();
    assert_eq!(err.kind, KeystoreErrorKind::Configuration);
}

#[test]
fn discovery_validate_is_always_ok() {
    let config = KmsConfiguration::Discovery(Discovery::builder().build());
    assert!(config.validate().is_ok());
}

#[test]
fn mrdiscovery_validate_is_always_ok() {
    let config =
        KmsConfiguration::MrDiscovery(MrDiscovery::builder().region("eu-west-1").build().unwrap());
    assert!(config.validate().is_ok());
}

#[test]
fn mrdiscovery_builder_requires_region() {
    let err = MrDiscovery::builder().build().unwrap_err();
    assert_eq!(err.kind, KeystoreErrorKind::Configuration);
}

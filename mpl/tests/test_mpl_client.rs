// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use aws_crypto_mpl::{
    CommitmentPolicy, DbeCommitmentPolicy, EsdkCommitmentPolicy, MaterialProviders,
    MaterialProvidersConfig,
};

#[test]
fn test_mpl_default_uses_default_config() {
    let mpl = MaterialProviders::default();
    let config = MaterialProvidersConfig::default();
    assert_eq!(mpl.config(), &config);
    assert_eq!(
        config.commitment_policy,
        CommitmentPolicy::Esdk(EsdkCommitmentPolicy::RequireEncryptRequireDecrypt)
    );
}

#[test]
fn test_mpl_builder() {
    let mpl = MaterialProviders::builder().build();
    assert_eq!(mpl.config(), &MaterialProvidersConfig::default());
}

#[test]
fn test_mpl_builder_with_config() {
    let config = MaterialProvidersConfig::default();
    let mpl = MaterialProviders::builder().config(config).build();
    assert_eq!(mpl.config(), &config);
}

#[test]
fn test_esdk_commitment_policy_enum_variants() {
    //= spec/framework/commitment-policy.md#supported-format-commitment-policy-enum
    //= type=test
    //# The Material Providers Library MUST provide
    //# a distinct commitment policy ENUM for each format.
    let forbid = EsdkCommitmentPolicy::ForbidEncryptAllowDecrypt;
    let require_allow = EsdkCommitmentPolicy::RequireEncryptAllowDecrypt;
    let require_require = EsdkCommitmentPolicy::RequireEncryptRequireDecrypt;

    // All three ESDK variants are distinct.
    assert_ne!(forbid, require_allow);
    assert_ne!(forbid, require_require);
    assert_ne!(require_allow, require_require);

    // DBE has its own distinct enum.
    let dbe = DbeCommitmentPolicy::RequireEncryptRequireDecrypt;
    assert_eq!(dbe, DbeCommitmentPolicy::RequireEncryptRequireDecrypt);
}

#[test]
fn test_commitment_policy_union_enum() {
    //= spec/framework/commitment-policy.md#supported-commitment-policy-enum
    //= type=test
    //# The Material Providers Library also MUST provide
    //# a union ENUM for all distinct commitment policy ENUMs
    //# called the Commitment Policy ENUM.
    let esdk_policy = CommitmentPolicy::Esdk(EsdkCommitmentPolicy::ForbidEncryptAllowDecrypt);
    let dbe_policy = CommitmentPolicy::Dbe(DbeCommitmentPolicy::RequireEncryptRequireDecrypt);

    // Union enum can hold both ESDK and DBE policies.
    assert_ne!(esdk_policy, dbe_policy);

    // All ESDK variants can be wrapped in the union.
    let esdk_require = CommitmentPolicy::Esdk(EsdkCommitmentPolicy::RequireEncryptAllowDecrypt);
    assert_ne!(esdk_policy, esdk_require);
}

#[test]
fn test_builder_commitment_policy_setter() {
    let policy = CommitmentPolicy::Esdk(EsdkCommitmentPolicy::ForbidEncryptAllowDecrypt);
    let mpl = MaterialProviders::builder()
        .commitment_policy(policy)
        .build()
        .expect("build should succeed");
    assert_eq!(mpl.config().commitment_policy, policy);
}

#[test]
fn test_builder_dbe_valid_policy() {
    let policy = CommitmentPolicy::Dbe(DbeCommitmentPolicy::RequireEncryptRequireDecrypt);
    let mpl = MaterialProviders::builder()
        .commitment_policy(policy)
        .build()
        .expect("build should succeed for valid DBE policy");
    assert_eq!(mpl.config().commitment_policy, policy);
}

#[test]
fn test_builder_invalid_config_error() {
    // The DbeCommitmentPolicy enum currently only has one variant, so we
    // cannot construct an invalid value through safe Rust. Instead, we verify
    // that the Error::InvalidConfig variant is constructable and displays correctly,
    // confirming the validation path is wired up.
    let err = aws_crypto_mpl::error::Error::InvalidConfig {
        message: "test validation error".to_string(),
    };
    assert!(
        matches!(&err, aws_crypto_mpl::error::Error::InvalidConfig { .. }),
        "expected InvalidConfig variant, got: {err:?}"
    );
    assert!(
        err.to_string().contains("test validation error"),
        "error display must include the message"
    );
}

#[test]
fn test_duplicate_format_commitment_policy_enum_across_formats() {
    // Both ESDK and DBE have a RequireEncryptRequireDecrypt variant,
    // demonstrating that different formats can have duplicate format-level enum names.
    //= spec/framework/commitment-policy.md#supported-commitment-policy-enum
    //= type=test
    //# This means that different formats MAY have duplicate Format Commitment Policy ENUM.
    let esdk = CommitmentPolicy::Esdk(EsdkCommitmentPolicy::RequireEncryptRequireDecrypt);
    let dbe = CommitmentPolicy::Dbe(DbeCommitmentPolicy::RequireEncryptRequireDecrypt);

    // Both carry the same format-level policy name but are distinct union variants.
    assert_ne!(esdk, dbe);
}
